"""Fail-closed patch boundary for Keyverse's autonomous product workflow.

The model-facing job is intentionally untrusted. This module turns its working
copy into a bounded textual patch, validates that patch again on fresh checkouts,
and carries only sanitized pull-request metadata across job boundaries.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path, PurePosixPath

ALLOWED_ROOTS = (
    "services/account_unification/app/",
    "services/account_unification/tests/",
    "services/account_unification/tools/",
    "deploy/templates/",
    "docs/",
)
ALLOWED_FILES = frozenset({"README.md", "CHANGELOG.md"})
PRODUCTION_ROOTS = (
    "services/account_unification/app/",
    "services/account_unification/tools/",
    "deploy/templates/",
)
TEST_ROOT = "services/account_unification/tests/"
PROPOSAL_FILENAME = "PR_MESSAGE.md"
SAFE_PATH = re.compile(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*")
COMMIT_SHA = re.compile(r"[0-9a-f]{40}")
MAX_FILES = 12
MAX_FILE_BYTES = 524_288
MAX_TOTAL_BYTES = 2_000_000
MAX_PATCH_BYTES = 2_000_000
MAX_CHANGED_LINES = 1_500
MAX_TITLE_CHARACTERS = 120
MAX_BODY_BYTES = 65_536
DIFF_SAFETY = ("--no-ext-diff", "--no-textconv", "--no-renames")


class BoundaryError(RuntimeError):
    """Raised when an autonomous proposal crosses a trusted boundary."""


def _run(
    args: Sequence[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    text: bool = False,
    check: bool = True,
) -> subprocess.CompletedProcess[str] | subprocess.CompletedProcess[bytes]:
    """Run one trusted command without a shell and capture its output."""
    return subprocess.run(
        list(args),
        cwd=cwd,
        env=env,
        check=check,
        capture_output=True,
        text=text,
    )


def _git_command(*, git_dir: Path, work_tree: Path) -> list[str]:
    """Return a literal-pathspec Git command for one repository view."""
    return [
        "git",
        "--literal-pathspecs",
        f"--git-dir={git_dir}",
        f"--work-tree={work_tree}",
    ]


def _nul_names(
    git: Sequence[str],
    args: Sequence[str],
    *,
    env: dict[str, str],
) -> list[str]:
    """Decode strict UTF-8 names from one NUL-delimited Git response."""
    raw = _run([*git, *args, "-z"], env=env).stdout
    assert isinstance(raw, bytes)
    return [part.decode("utf-8", errors="strict") for part in raw.split(b"\0") if part]


def _path_allowed(path: str) -> bool:
    """Return whether ``path`` is inside the autonomous product boundary."""
    pure = PurePosixPath(path)
    return (
        SAFE_PATH.fullmatch(path) is not None
        and not pure.is_absolute()
        and all(part not in {"", ".", ".."} for part in pure.parts)
        and (path in ALLOWED_FILES or path.startswith(ALLOWED_ROOTS))
    )


def _prepare_diff_index(
    *,
    git: Sequence[str],
    head: str,
    index_file: Path,
) -> dict[str, str]:
    """Create an alternate index that exposes safe untracked files to Git diff."""
    index_file.unlink(missing_ok=True)
    env = os.environ.copy()
    env["GIT_INDEX_FILE"] = str(index_file)
    _run([*git, "read-tree", head], env=env)
    untracked = _run(
        [*git, "ls-files", "--others", "--exclude-standard", "-z"],
        env=env,
    ).stdout
    assert isinstance(untracked, bytes)
    if untracked:
        pathspec = index_file.with_suffix(".pathspec")
        pathspec.write_bytes(untracked)
        _run(
            [
                *git,
                "add",
                "-N",
                f"--pathspec-from-file={pathspec}",
                "--pathspec-file-nul",
            ],
            env=env,
        )
    return env


def _changed_paths(
    git: Sequence[str],
    *,
    env: dict[str, str],
) -> tuple[list[str], list[str]]:
    """Return changed and deleted paths from an alternate-index view."""
    changed = _nul_names(
        git,
        ["diff", *DIFF_SAFETY, "--name-only", "--diff-filter=ACMRTUXB"],
        env=env,
    )
    deleted = _nul_names(
        git,
        ["diff", *DIFF_SAFETY, "--name-only", "--diff-filter=D"],
        env=env,
    )
    return changed, deleted


def _forbidden_tokens() -> tuple[bytes, ...]:
    """Return raw and common encoded forms when the raw credential is available."""
    secret = os.environ.get("KEYVERSE_FORBIDDEN_SECRET", "").encode("utf-8")
    if not secret:
        return ()
    return tuple(
        token
        for token in {
            secret,
            base64.b64encode(secret),
            base64.urlsafe_b64encode(secret),
            secret.hex().encode("ascii"),
        }
        if token
    )


def _forbidden_fingerprints() -> tuple[tuple[int, bytes], ...]:
    """Parse broker-derived ``length:sha256`` credential fingerprints."""
    specification = os.environ.get("KEYVERSE_FORBIDDEN_SECRET_FINGERPRINT", "")
    if not specification:
        return ()
    fingerprints: list[tuple[int, bytes]] = []
    for item in specification.split(","):
        parts = item.split(":")
        if len(parts) != 2 or not parts[0].isdigit() or not re.fullmatch(
            r"[0-9a-f]{64}", parts[1]
        ):
            raise BoundaryError("Malformed protected-credential fingerprint")
        length = int(parts[0])
        if length < 1 or length > MAX_FILE_BYTES:
            raise BoundaryError("Protected-credential fingerprint length is unsafe")
        fingerprints.append((length, bytes.fromhex(parts[1])))
    return tuple(fingerprints)


def _contains_fingerprinted_token(
    data: bytes, *, length: int, digest: bytes
) -> bool:
    """Find an exact non-whitespace token using only its one-way fingerprint."""
    for chunk in data.split():
        if len(chunk) < length:
            continue
        for offset in range(len(chunk) - length + 1):
            if hashlib.sha256(chunk[offset : offset + length]).digest() == digest:
                return True
    return False


def _reject_forbidden_tokens(data: bytes, *, label: str) -> None:
    """Reject raw, encoded, or broker-fingerprinted protected credentials."""
    if any(token in data for token in _forbidden_tokens()):
        raise BoundaryError(f"Autonomous proposal exposed a protected credential in {label}")
    if any(
        _contains_fingerprinted_token(data, length=length, digest=digest)
        for length, digest in _forbidden_fingerprints()
    ):
        raise BoundaryError(f"Autonomous proposal exposed a protected credential in {label}")


def _read_proposal(workspace: Path) -> tuple[str, str]:
    """Read, sanitize, and remove optional model-authored pull-request metadata."""
    proposal_path = workspace / PROPOSAL_FILENAME
    default_title = "Keyverse autonomous product increment"
    default_body = (
        "Autonomous product increment; see the bounded diff, tests, and "
        "CHANGELOG.md for evidence."
    )
    if not proposal_path.exists():
        return default_title, default_body

    file_stat = proposal_path.lstat()
    if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_nlink != 1:
        raise BoundaryError("PR_MESSAGE.md must be one regular, non-linked file")
    if file_stat.st_size > MAX_BODY_BYTES + 1_024:
        raise BoundaryError("PR_MESSAGE.md exceeded the metadata byte limit")
    raw = proposal_path.read_bytes()
    _reject_forbidden_tokens(raw, label=PROPOSAL_FILENAME)
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise BoundaryError("PR_MESSAGE.md must be strict UTF-8") from exc
    proposal_path.unlink()

    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = normalized.split("\n")
    candidate = lines[0].lstrip("#").strip() if lines else ""
    title = candidate or default_title
    if len(title) > MAX_TITLE_CHARACTERS:
        raise BoundaryError("Pull-request title exceeded the character limit")
    if any(ord(character) < 32 or ord(character) == 127 for character in title):
        raise BoundaryError("Pull-request title contained an ASCII control character")

    body = "\n".join(lines[1:]).strip() or default_body
    body_bytes = body.encode("utf-8")
    if len(body_bytes) > MAX_BODY_BYTES:
        raise BoundaryError("Pull-request body exceeded the byte limit")
    if any(ord(character) < 32 and character not in "\n\t" for character in body):
        raise BoundaryError("Pull-request body contained an unsafe control character")
    _reject_forbidden_tokens(body_bytes, label="proposal body")
    return title, body


def _require_product_vertical(paths: Sequence[str]) -> None:
    """Require production code, tests, and the changelog in every proposal."""
    if not any(path.startswith(PRODUCTION_ROOTS) for path in paths):
        raise BoundaryError("Autonomous proposal contained no production code")
    if not any(path.startswith(TEST_ROOT) for path in paths):
        raise BoundaryError("Autonomous proposal contained no changed tests")
    if "CHANGELOG.md" not in paths:
        raise BoundaryError("Autonomous proposal did not update CHANGELOG.md")


def validate_worktree_diff(
    *,
    workspace: Path,
    git: Sequence[str],
    env: dict[str, str],
) -> list[str]:
    """Validate a materialized diff and return its bounded changed paths."""
    names, deleted = _changed_paths(git, env=env)
    if deleted:
        raise BoundaryError(f"Autonomous development must not delete files: {deleted}")
    if not names:
        raise BoundaryError("A dirty tree contained no reviewable text changes")
    if len(names) > MAX_FILES:
        raise BoundaryError(f"Autonomous development touched too many files: {len(names)}")

    total_bytes = 0
    for name in names:
        if not _path_allowed(name):
            raise BoundaryError(f"Autonomous development crossed its path boundary: {name!r}")
        path = workspace / name
        file_stat = path.lstat()
        if not stat.S_ISREG(file_stat.st_mode):
            raise BoundaryError(f"Autonomous development created a non-regular file: {name}")
        if file_stat.st_nlink != 1:
            raise BoundaryError(f"Autonomous development created a hard link: {name}")
        if file_stat.st_mode & 0o111:
            raise BoundaryError(f"Autonomous development created an executable file: {name}")
        if file_stat.st_size > MAX_FILE_BYTES:
            raise BoundaryError(f"Autonomous development exceeded the per-file limit: {name}")
        data = path.read_bytes()
        if b"\x00" in data:
            raise BoundaryError(f"Autonomous development created a binary file: {name}")
        _reject_forbidden_tokens(data, label=name)
        total_bytes += len(data)
    if total_bytes > MAX_TOTAL_BYTES:
        raise BoundaryError("Autonomous development exceeded the changed-file byte limit")

    _require_product_vertical(names)
    summary = _run([*git, "diff", *DIFF_SAFETY, "--summary"], env=env, text=True)
    assert isinstance(summary.stdout, str)
    if " mode change " in summary.stdout:
        raise BoundaryError("Autonomous development must not change file modes")

    numstat = _run([*git, "diff", *DIFF_SAFETY, "--numstat", "-z"], env=env).stdout
    assert isinstance(numstat, bytes)
    changed_lines = 0
    for record in (part for part in numstat.split(b"\0") if part):
        additions, deletions, _ = record.split(b"\t", 2)
        if additions == b"-" or deletions == b"-":
            raise BoundaryError("Autonomous development produced a binary diff")
        changed_lines += int(additions) + int(deletions)
    if changed_lines > MAX_CHANGED_LINES:
        raise BoundaryError(
            f"Autonomous development exceeded the changed-line budget: {changed_lines}"
        )

    _run([*git, "diff", "--no-ext-diff", "--no-textconv", "--check"], env=env)
    return names


def validate_patch_text(patch_file: Path) -> list[str]:
    """Validate patch metadata before Git writes any untrusted content."""
    if patch_file.stat().st_size > MAX_PATCH_BYTES:
        raise BoundaryError("Patch exceeded the byte limit")
    raw = patch_file.read_bytes()
    _reject_forbidden_tokens(raw, label="patch")
    try:
        patch = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise BoundaryError("Patch must be strict UTF-8 text") from exc

    headers = re.findall(r"^diff --git a/([^\n]+) b/([^\n]+)$", patch, re.MULTILINE)
    if not headers:
        raise BoundaryError("Patch has no reviewable diff headers")
    if len(headers) > MAX_FILES:
        raise BoundaryError(f"Patch touched too many files: {len(headers)}")

    seen: set[str] = set()
    for left, right in headers:
        if left != right or not _path_allowed(left) or left in seen:
            raise BoundaryError(f"Patch contains an unsafe or duplicate path: {left!r}, {right!r}")
        seen.add(left)

    for marker, path in re.findall(r"^(---|\+\+\+) (.+)$", patch, re.MULTILINE):
        if path == "/dev/null":
            continue
        prefix = "a/" if marker == "---" else "b/"
        if not path.startswith(prefix) or path[2:] not in seen:
            raise BoundaryError(f"Patch contains an unsafe file marker: {marker} {path}")

    forbidden = (
        "deleted file mode ",
        "old mode ",
        "new mode ",
        "rename from ",
        "rename to ",
        "copy from ",
        "copy to ",
        "GIT binary patch",
        "Binary files ",
        "new file mode 120000",
    )
    if any(token in patch for token in forbidden):
        raise BoundaryError(
            "Patch contains a forbidden deletion, rename, mode, link, or binary directive"
        )
    new_modes = re.findall(r"^new file mode ([0-7]{6})$", patch, re.MULTILINE)
    if any(mode != "100644" for mode in new_modes):
        raise BoundaryError(f"Patch contains a forbidden new-file mode: {new_modes}")
    paths = sorted(seen)
    _require_product_vertical(paths)
    return paths


def _write_outputs(values: dict[str, str]) -> None:
    """Append simple key-value outputs when running inside GitHub Actions."""
    output = os.environ.get("GITHUB_OUTPUT")
    if not output:
        return
    with Path(output).open("a", encoding="utf-8") as stream:
        stream.writelines(f"{key}={value}\n" for key, value in values.items())


def capture(args: argparse.Namespace) -> int:
    """Capture a bounded patch against an immutable trusted baseline."""
    workspace = args.workspace.resolve()
    baseline = args.baseline.resolve()
    baseline_git = baseline / ".git"
    expected_head = args.base_sha_file.read_text(encoding="utf-8").strip()
    if COMMIT_SHA.fullmatch(expected_head) is None:
        raise BoundaryError("Base SHA file did not contain one lowercase commit SHA")
    baseline_head = _run(
        ["git", f"--git-dir={baseline_git}", "rev-parse", "HEAD"], text=True
    ).stdout.strip()
    if baseline_head != expected_head:
        raise BoundaryError("The immutable diff baseline changed during model execution")

    title, body = _read_proposal(workspace)
    index_file = args.patch_file.with_suffix(".index")
    git = _git_command(git_dir=baseline_git, work_tree=workspace)
    env = _prepare_diff_index(git=git, head=expected_head, index_file=index_file)
    quiet = _run(
        [*git, "diff", "--no-ext-diff", "--no-textconv", "--quiet"],
        env=env,
        check=False,
    )
    if quiet.returncode == 0:
        _write_outputs({"changed": "false", "base_sha": expected_head})
        return 0
    if quiet.returncode != 1:
        raise BoundaryError("Git could not determine whether the model changed the workspace")

    names = validate_worktree_diff(workspace=workspace, git=git, env=env)
    patch = _run([*git, "diff", *DIFF_SAFETY, "--binary"], env=env).stdout
    stat_text = _run([*git, "diff", *DIFF_SAFETY, "--stat"], env=env, text=True).stdout
    assert isinstance(patch, bytes)
    assert isinstance(stat_text, str)
    if len(patch) > MAX_PATCH_BYTES:
        raise BoundaryError("Autonomous development exceeded the patch byte limit")
    _reject_forbidden_tokens(patch, label="patch")
    args.patch_file.write_bytes(patch)
    args.stat_file.write_text(stat_text, encoding="utf-8")
    patch_sha256 = hashlib.sha256(patch).hexdigest()
    proposal = {
        "base_sha": expected_head,
        "body": body,
        "changed_paths": sorted(names),
        "patch_sha256": patch_sha256,
        "title": title,
    }
    args.proposal_file.write_text(
        json.dumps(proposal, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    _write_outputs(
        {
            "changed": "true",
            "base_sha": expected_head,
            "patch_sha256": patch_sha256,
        }
    )
    return 0


def _load_proposal(proposal_file: Path) -> dict[str, object]:
    """Load and validate the trusted cross-job proposal envelope."""
    if proposal_file.stat().st_size > MAX_BODY_BYTES + 4_096:
        raise BoundaryError("Proposal envelope exceeded the byte limit")
    try:
        proposal = json.loads(proposal_file.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BoundaryError("Proposal envelope must be strict UTF-8 JSON") from exc
    if not isinstance(proposal, dict) or set(proposal) != {
        "base_sha",
        "body",
        "changed_paths",
        "patch_sha256",
        "title",
    }:
        raise BoundaryError("Proposal envelope has an unexpected schema")
    base_sha = proposal["base_sha"]
    patch_sha = proposal["patch_sha256"]
    title = proposal["title"]
    body = proposal["body"]
    paths = proposal["changed_paths"]
    if not isinstance(base_sha, str) or COMMIT_SHA.fullmatch(base_sha) is None:
        raise BoundaryError("Proposal base SHA is invalid")
    if not isinstance(patch_sha, str) or re.fullmatch(r"[0-9a-f]{64}", patch_sha) is None:
        raise BoundaryError("Proposal patch digest is invalid")
    if not isinstance(title, str) or not title or len(title) > MAX_TITLE_CHARACTERS:
        raise BoundaryError("Proposal title is invalid")
    if not isinstance(body, str) or len(body.encode("utf-8")) > MAX_BODY_BYTES:
        raise BoundaryError("Proposal body is invalid")
    if (
        not isinstance(paths, list)
        or not paths
        or any(not isinstance(path, str) or not _path_allowed(path) for path in paths)
        or paths != sorted(set(paths))
    ):
        raise BoundaryError("Proposal changed-path inventory is invalid")
    _require_product_vertical(paths)
    _reject_forbidden_tokens(title.encode(), label="proposal title")
    _reject_forbidden_tokens(body.encode(), label="proposal body")
    return proposal


def apply_patch(args: argparse.Namespace) -> int:
    """Validate and apply one sealed patch on a fresh protected checkout."""
    workspace = args.workspace.resolve()
    proposal = _load_proposal(args.proposal_file.resolve())
    patch_file = args.patch_file.resolve()
    patch_bytes = patch_file.read_bytes()
    observed_digest = hashlib.sha256(patch_bytes).hexdigest()
    if observed_digest != proposal["patch_sha256"]:
        raise BoundaryError("Patch digest did not match the proposal envelope")
    current_head = _run(["git", "rev-parse", "HEAD"], cwd=workspace, text=True).stdout.strip()
    if current_head != proposal["base_sha"]:
        raise BoundaryError("Protected branch moved after the proposal was captured")

    patch_paths = validate_patch_text(patch_file)
    if patch_paths != proposal["changed_paths"]:
        raise BoundaryError("Patch paths did not match the proposal envelope")
    _run(["git", "apply", "--check", str(patch_file)], cwd=workspace)
    _run(["git", "apply", str(patch_file)], cwd=workspace)

    git = _git_command(git_dir=workspace / ".git", work_tree=workspace)
    env = _prepare_diff_index(
        git=git,
        head=current_head,
        index_file=args.proposal_file.with_suffix(".apply.index"),
    )
    materialized_paths = sorted(validate_worktree_diff(workspace=workspace, git=git, env=env))
    if materialized_paths != patch_paths:
        raise BoundaryError("Materialized paths did not match the sealed patch")
    _write_outputs(
        {
            "base_sha": current_head,
            "patch_sha256": observed_digest,
            "publish": "true",
        }
    )
    return 0


def self_test() -> int:
    """Exercise one valid round trip and one unsafe-path rejection."""
    with tempfile.TemporaryDirectory() as root_text:
        root = Path(root_text)
        source = root / "source"
        baseline = root / "baseline"
        workspace = root / "workspace"
        source.mkdir()
        _run(["git", "init", "-q"], cwd=source)
        _run(["git", "config", "user.name", "Guard Test"], cwd=source)
        _run(["git", "config", "user.email", "guard@example.invalid"], cwd=source)
        (source / "README.md").write_text("before\n", encoding="utf-8")
        (source / "CHANGELOG.md").write_text("base\n", encoding="utf-8")
        (source / TEST_ROOT).mkdir(parents=True)
        (source / f"{TEST_ROOT}test_sample.py").write_text("assert True\n", encoding="utf-8")
        (source / PRODUCTION_ROOTS[0]).mkdir(parents=True)
        (source / f"{PRODUCTION_ROOTS[0]}sample.py").write_text(
            '"""Sample."""\n', encoding="utf-8"
        )
        _run(["git", "add", "."], cwd=source)
        _run(["git", "commit", "-qm", "base"], cwd=source)
        _run(["git", "clone", "-q", "--local", "--no-hardlinks", str(source), str(baseline)])
        _run(["git", "clone", "-q", "--local", "--no-hardlinks", str(source), str(workspace)])
        (workspace / ".git").rename(root / "discarded-git")
        (workspace / f"{PRODUCTION_ROOTS[0]}sample.py").write_text(
            '"""Sample."""\nVALUE = 1\n', encoding="utf-8"
        )
        (workspace / f"{TEST_ROOT}test_sample.py").write_text(
            "assert 1 == 1\n", encoding="utf-8"
        )
        (workspace / "CHANGELOG.md").write_text("base\nchanged\n", encoding="utf-8")
        (workspace / PROPOSAL_FILENAME).write_text(
            "Improve sample\n\nVerified product change.\n", encoding="utf-8"
        )
        base_sha = _run(["git", "rev-parse", "HEAD"], cwd=source, text=True).stdout.strip()
        base_file = root / "base-sha"
        base_file.write_text(base_sha + "\n", encoding="utf-8")
        patch_file = root / "change.patch"
        stat_file = root / "change.stat"
        proposal_file = root / "proposal.json"
        capture(
            argparse.Namespace(
                workspace=workspace,
                baseline=baseline,
                base_sha_file=base_file,
                patch_file=patch_file,
                stat_file=stat_file,
                proposal_file=proposal_file,
            )
        )
        apply_target = root / "apply-target"
        _run(["git", "clone", "-q", "--local", "--no-hardlinks", str(source), str(apply_target)])
        apply_patch(
            argparse.Namespace(
                workspace=apply_target,
                patch_file=patch_file,
                proposal_file=proposal_file,
            )
        )
        assert "VALUE = 1" in (
            apply_target / f"{PRODUCTION_ROOTS[0]}sample.py"
        ).read_text(encoding="utf-8")

        unsafe = root / "unsafe.patch"
        unsafe.write_text(
            "diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml\n"
            "--- a/.github/workflows/ci.yml\n"
            "+++ b/.github/workflows/ci.yml\n"
            "@@ -1 +1 @@\n-a\n+b\n",
            encoding="utf-8",
        )
        try:
            validate_patch_text(unsafe)
        except BoundaryError:
            pass
        else:
            raise AssertionError("Unsafe workflow patch was accepted")
    print("hourly product guard self-test passed")
    return 0


def _parser() -> argparse.ArgumentParser:
    """Build the command-line parser for trusted workflow entry points."""
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    capture_parser = subparsers.add_parser("capture")
    capture_parser.add_argument("--workspace", type=Path, required=True)
    capture_parser.add_argument("--baseline", type=Path, required=True)
    capture_parser.add_argument("--base-sha-file", type=Path, required=True)
    capture_parser.add_argument("--patch-file", type=Path, required=True)
    capture_parser.add_argument("--stat-file", type=Path, required=True)
    capture_parser.add_argument("--proposal-file", type=Path, required=True)
    capture_parser.set_defaults(handler=capture)

    apply_parser = subparsers.add_parser("apply")
    apply_parser.add_argument("--workspace", type=Path, required=True)
    apply_parser.add_argument("--patch-file", type=Path, required=True)
    apply_parser.add_argument("--proposal-file", type=Path, required=True)
    apply_parser.set_defaults(handler=apply_patch)

    self_test_parser = subparsers.add_parser("self-test")
    self_test_parser.set_defaults(handler=lambda _args: self_test())
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run one trusted guard command and convert boundary failures to exit 2."""
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except BoundaryError as exc:
        print(f"hourly product guard: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

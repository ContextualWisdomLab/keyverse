"""Fail-closed routing contracts for read-only-token CI on self-hosted runners."""
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[3]
SAME_REPOSITORY_ADMISSION = (
    "if: ${{ github.event_name != 'pull_request' || "
    "(github.event.action != 'closed' && github.event.pull_request.draft == false && "
    "github.event.pull_request.head.repo.full_name == github.repository) }}"
)


def _workflow() -> dict:
    """Load ci.yml; YAML 1.1 parses the bare ``on`` key as boolean True."""
    return yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())


def test_product_ci_uses_only_the_dedicated_isolated_runner_group() -> None:
    """Source pins the isolated group and labels (static check, not runtime proof)."""
    workflow = _workflow()
    assert set(workflow["jobs"]) == {
        "account-unification-tests", "realm-config-validates", "compose-config-validates"
    }
    assert workflow["permissions"] == {"contents": "read"}
    for job in workflow["jobs"].values():
        assert job["runs-on"] == {
            "group": "CWL CI isolated",
            "labels": ["self-hosted", "linux", "x64", "cwlab-ci-isolated"],
        }


def test_fork_pull_requests_never_run_on_persistent_self_hosted_runners() -> None:
    """Every job admits pull requests only from branches of this repository."""
    text = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert text.count(SAME_REPOSITORY_ADMISSION) == 3
    for job in _workflow()["jobs"].values():
        condition = job["if"]
        assert "github.event.pull_request.head.repo.full_name == github.repository" in condition


def test_ci_triggers_exclude_privileged_pull_request_target() -> None:
    """A base-token trigger must never check out PR code on a self-hosted runner."""
    workflow = _workflow()
    triggers = workflow.get("on", workflow.get(True))
    assert set(triggers) == {"push", "pull_request"}
    assert "pull_request_target" not in triggers
    assert "workflow_run" not in triggers



def test_isolated_ci_checkout_does_not_persist_its_read_token() -> None:
    """Checked-out PR test code must not inherit a stored GitHub credential."""
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    for job in workflow["jobs"].values():
        checkouts = [
            step for step in job["steps"]
            if str(step.get("uses", "")).startswith("actions/checkout@")
        ]
        assert len(checkouts) == 1
        assert checkouts[0].get("with", {}).get("persist-credentials") is False

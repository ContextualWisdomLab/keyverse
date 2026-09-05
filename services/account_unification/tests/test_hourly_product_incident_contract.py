"""Incident regressions for the fail-closed hourly product-development workflow."""
from __future__ import annotations

from pathlib import Path

import yaml


EXPECTED_ENDPOINTS = {
    "develop-product-gap": (
        "api.bytez.com:443",
        "api.github.com:443",
        "api.openai.com:443",
        "cafe.github.com:443",
        "codeload.github.com:443",
        "github.com:443",
        "integrate.api.nvidia.com:443",
        "models.dev:443",
        "objects.githubusercontent.com:443",
        "openrouter.ai:443",
        "raw.githubusercontent.com:443",
        "registry.npmjs.org:443",
        "release-assets.githubusercontent.com:443",
        "releases.astral.sh:443",
        "results-receiver.actions.githubusercontent.com:443",
        "*.actions.githubusercontent.com:443",
        "*.blob.core.windows.net:443",
        "files.pythonhosted.org:443",
        "pypi.org:443",
    ),
    "reverify-product-gap": (
        "api.github.com:443",
        "cafe.github.com:443",
        "github.com:443",
        "objects.githubusercontent.com:443",
        "raw.githubusercontent.com:443",
        "release-assets.githubusercontent.com:443",
        "releases.astral.sh:443",
        "results-receiver.actions.githubusercontent.com:443",
        "*.actions.githubusercontent.com:443",
        "*.blob.core.windows.net:443",
        "files.pythonhosted.org:443",
        "pypi.org:443",
    ),
    "publish-product-gap": (
        "api.github.com:443",
        "cafe.github.com:443",
        "github.com:443",
        "objects.githubusercontent.com:443",
        "results-receiver.actions.githubusercontent.com:443",
        "*.actions.githubusercontent.com:443",
        "*.blob.core.windows.net:443",
    ),
}


def _repository_root() -> Path:
    """Return the Keyverse repository root from this test module."""
    return Path(__file__).resolve().parents[3]


def _workflow_source() -> str:
    """Return the hourly product-development workflow as reviewed text."""
    return (
        _repository_root()
        / ".github"
        / "workflows"
        / "hourly-product-development.yml"
    ).read_text(encoding="utf-8")


def _workflow_document() -> dict[str, object]:
    """Parse the hourly workflow into a mapping for structural assertions."""
    document = yaml.safe_load(_workflow_source())
    assert isinstance(document, dict)
    return document


def _job(job_name: str) -> dict[str, object]:
    """Return one named workflow job as a mapping."""
    jobs = _workflow_document().get("jobs")
    assert isinstance(jobs, dict)
    job = jobs.get(job_name)
    assert isinstance(job, dict)
    return job


def _steps(job_name: str) -> list[dict[str, object]]:
    """Return mapping-valued steps for one named job."""
    steps = _job(job_name).get("steps")
    assert isinstance(steps, list)
    return [step for step in steps if isinstance(step, dict)]


def _step_by_id(job_name: str, step_id: str) -> dict[str, object]:
    """Return the exact step carrying ``step_id`` in ``job_name``."""
    for step in _steps(job_name):
        if step.get("id") == step_id:
            return step
    raise AssertionError(f"{job_name} has no step id {step_id}")


def _step_by_name(job_name: str, step_name: str) -> dict[str, object]:
    """Return the exact step named ``step_name`` in ``job_name``."""
    for step in _steps(job_name):
        if step.get("name") == step_name:
            return step
    raise AssertionError(f"{job_name} has no step named {step_name}")


def _harden_runner_endpoint_scalar(job_name: str) -> str:
    """Return the serialized Harden Runner endpoint input for one workflow job."""
    for step in _steps(job_name):
        action = step.get("uses")
        if not isinstance(action, str) or not action.startswith(
            "step-security/harden-runner@"
        ):
            continue
        inputs = step.get("with")
        assert isinstance(inputs, dict)
        assert inputs.get("egress-policy") == "block"
        endpoint_block = inputs.get("allowed-endpoints")
        assert isinstance(endpoint_block, str)
        return endpoint_block
    raise AssertionError(f"{job_name} has no Harden Runner step")


def _harden_runner_endpoints(job_name: str) -> tuple[str, ...]:
    """Return the exact ordered Harden Runner endpoint allowlist for a job."""
    return tuple(_harden_runner_endpoint_scalar(job_name).split())


def test_github_api_jobs_use_exact_fail_closed_endpoint_sets() -> None:
    """Every GitHub-API phase permits only its reviewed exact endpoint set."""
    for job_name, expected in EXPECTED_ENDPOINTS.items():
        actual = _harden_runner_endpoints(job_name)
        assert actual == expected
        assert "api.github.com:443.evil" not in actual
        assert "*.github.com:443" not in actual


def test_harden_runner_endpoint_input_is_space_delimited_for_runtime() -> None:
    """Harden Runner receives one folded, space-delimited endpoint scalar per job."""
    for job_name, expected in EXPECTED_ENDPOINTS.items():
        endpoint_scalar = _harden_runner_endpoint_scalar(job_name)
        assert endpoint_scalar == " ".join(expected)
        assert "\n" not in endpoint_scalar


def test_deterministic_repository_gates_precede_optional_model_credential() -> None:
    """Queue, main, release evidence, and dry-run gates run before model access."""
    gate = _step_by_id("develop-product-gap", "gate")
    gate_run = gate.get("run")
    gate_env = gate.get("env")
    assert isinstance(gate_run, str)
    assert isinstance(gate_env, dict)

    ordered_markers = (
        "pulls?state=open&per_page=1",
        "commits/${DEFAULT_BRANCH}",
        "actions/runs?branch=${DEFAULT_BRANCH}",
        "commits/${base_sha}/check-runs?per_page=100",
        'if [ "$DRY_RUN" = "true" ]; then',
    )
    positions = tuple(gate_run.index(marker) for marker in ordered_markers)
    assert positions == tuple(sorted(positions))
    for credential_name in (
        "BYTEZ_API_KEY",
        "NVIDIA_NIM_API_KEY",
        "NVIDIA_NIM_API_KEY_SUB",
        "OPENROUTER_API_KEY",
        "OPENAI_API_KEY",
    ):
        assert credential_name not in gate_env
        assert credential_name not in gate_run


def test_github_inventory_transport_failures_are_not_false_green() -> None:
    """GitHub inventory transport/shape failures terminate the gate unsuccessfully."""
    gate = _step_by_id("develop-product-gap", "gate")
    gate_run = gate.get("run")
    assert isinstance(gate_run, str)

    failure_messages = (
        "Unable to list open pull requests",
        "Unable to interpret the open pull-request response",
        "Unable to resolve the default-branch head",
        "The default-branch head was malformed",
        "Unable to read default-branch workflow evidence",
        "Unable to read default-branch check evidence",
    )
    for message in failure_messages:
        marker = f'echo "::error::{message}'
        start = gate_run.index(marker)
        branch_tail = gate_run[start : start + 320]
        assert "exit 1" in branch_tail
        assert f"::warning::{message}" not in gate_run

    malformed_evidence_contracts = (
        (
            "if not isinstance(pages, list) or not required:",
            "raise SystemExit(2)",
            "workflow_evidence_status",
            "Unable to interpret default-branch workflow evidence",
        ),
        (
            "if not isinstance(pages, list):",
            "raise SystemExit(2)",
            "check_evidence_status",
            "Unable to interpret default-branch check evidence",
        ),
    )
    for parser_marker, malformed_exit, status_name, error_message in (
        malformed_evidence_contracts
    ):
        parser_start = gate_run.index(parser_marker)
        parser_tail = gate_run[parser_start : parser_start + 180]
        assert malformed_exit in parser_tail
        assert f"{status_name}=$?" in gate_run
        assert f"::error::{error_message}" in gate_run

    assert 'workflow_evidence_status=3' not in gate_run
    assert 'check_evidence_status=3' not in gate_run
    assert "Missing required default-branch workflow evidence" in gate_run
    assert "Default branch has pending or unsuccessful required workflow evidence" in gate_run
    assert "Missing latest default-branch check evidence" in gate_run
    assert "Default branch has pending or unsuccessful latest check evidence" in gate_run


def test_default_branch_check_evidence_requires_success() -> None:
    """Neutral or skipped default-main checks never qualify as healthy evidence."""
    gate = _step_by_id("develop-product-gap", "gate")
    gate_run = gate.get("run")
    assert isinstance(gate_run, str)

    accepted_start = gate_run.index("accepted =")
    accepted_block = gate_run[accepted_start : accepted_start + 120]
    assert 'accepted = {"success"}' in accepted_block
    assert '"neutral"' not in accepted_block
    assert '"skipped"' not in accepted_block


def test_single_gateway_attempt_budget_fits_outer_job_timeout() -> None:
    """The one orchestrator/free attempt plus setup reserve fits the job deadline.

    Unlike the retired per-model retry loop, `orchestrator/free` is a single
    virtual pool id: the gateway's own routing picks a live candidate from
    whichever provider secrets are registered, so only one `opencode run`
    attempt budget needs to fit, not N sequential model attempts.
    """
    document = _workflow_document()
    env = document.get("env")
    assert isinstance(env, dict)
    assert env.get("OPENCODE_MODEL") == "contextual_orchestrator_gateway/orchestrator/free"
    run_seconds = int(str(env.get("OPENCODE_RUN_TIMEOUT_SECONDS", "0")))
    timeout_minutes = int(str(_job("develop-product-gap").get("timeout-minutes", 0)))
    agent_run = _step_by_id("develop-product-gap", "agent").get("run")
    assert isinstance(agent_run, str)

    assert run_seconds > 0
    assert agent_run.count("opencode run") == 1
    assert 'timeout --kill-after=30s "${OPENCODE_RUN_TIMEOUT_SECONDS}s"' in agent_run
    setup_and_packaging_reserve_seconds = 15 * 60
    assert timeout_minutes * 60 >= (
        run_seconds + setup_and_packaging_reserve_seconds
    )


def test_provider_secrets_are_materialized_only_by_the_gateway_step() -> None:
    """Each raw provider secret exists only in the conditional gateway step."""
    gateway_step_name = "Vendor and start the contextual-orchestrator gateway"
    for credential_name in (
        "BYTEZ_API_KEY",
        "NVIDIA_NIM_API_KEY",
        "NVIDIA_NIM_API_KEY_SUB",
        "OPENROUTER_API_KEY",
        "OPENAI_API_KEY",
    ):
        secret_expression = f"${{{{ secrets.{credential_name} }}}}"
        materializing_steps: list[str] = []
        for step in _steps("develop-product-gap"):
            env = step.get("env")
            if not isinstance(env, dict) or secret_expression not in env.values():
                continue
            name = step.get("name")
            assert isinstance(name, str)
            materializing_steps.append(name)
        assert materializing_steps == [gateway_step_name]


def test_provider_secret_fingerprints_cross_the_gateway_boundary() -> None:
    """Packaging receives only gateway-derived fingerprints for leak scanning."""
    gateway = _step_by_name(
        "develop-product-gap",
        "Vendor and start the contextual-orchestrator gateway",
    )
    package = _step_by_name(
        "develop-product-gap",
        "Capture the bounded credential-free patch",
    )
    gateway_run = gateway.get("run")
    package_env = package.get("env")
    assert isinstance(gateway_run, str)
    assert isinstance(package_env, dict)
    assert gateway.get("id") == "orchestrator_gateway"
    assert "sha256" in gateway_run
    assert "GITHUB_OUTPUT" in gateway_run
    assert gateway_run.index("unset gateway_token") > gateway_run.index(
        "scripts.ci.serve_seeded_gateway"
    )
    assert package_env.get("KEYVERSE_FORBIDDEN_SECRET_FINGERPRINT") == (
        "${{ steps.orchestrator_gateway.outputs.secret_fingerprint }}"
    )
    for credential_name in (
        "BYTEZ_API_KEY",
        "NVIDIA_NIM_API_KEY",
        "NVIDIA_NIM_API_KEY_SUB",
        "OPENROUTER_API_KEY",
        "OPENAI_API_KEY",
    ):
        assert f"KEYVERSE_FORBIDDEN_SECRET: ${{{{ secrets.{credential_name} }}}}" not in (
            _workflow_source()
        )


def test_provider_secrets_are_required_only_on_the_model_backed_path() -> None:
    """Provider secrets are checked only after deterministic gates select development."""
    gateway = _step_by_name(
        "develop-product-gap",
        "Vendor and start the contextual-orchestrator gateway",
    )
    gateway_env = gateway.get("env")
    gateway_run = gateway.get("run")
    assert isinstance(gateway_env, dict)
    assert isinstance(gateway_run, str)

    for credential_name in (
        "BYTEZ_API_KEY",
        "NVIDIA_NIM_API_KEY",
        "NVIDIA_NIM_API_KEY_SUB",
        "OPENROUTER_API_KEY",
        "OPENAI_API_KEY",
    ):
        assert gateway_env.get(credential_name) == f"${{{{ secrets.{credential_name} }}}}"
    assert 'if [ "$provider_secret_count" -lt 1 ]; then' in gateway_run
    assert "is required only for model-backed development" in gateway_run
    assert "exit 1" in gateway_run

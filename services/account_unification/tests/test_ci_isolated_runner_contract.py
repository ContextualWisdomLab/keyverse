"""Fail-closed routing contracts for the repository's credential-free CI."""
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[3]


def test_product_ci_uses_only_the_dedicated_isolated_runner_group() -> None:
    """Public PR code must never run on persistent privileged control capacity."""
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    assert set(workflow["jobs"]) == {
        "account-unification-tests", "realm-config-validates", "compose-config-validates"
    }
    assert workflow["permissions"] == {"contents": "read"}
    for job in workflow["jobs"].values():
        assert job["runs-on"] == {
            "group": "CWL CI isolated",
            "labels": ["self-hosted", "linux", "x64", "cwlab-ci-isolated"],
        }


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

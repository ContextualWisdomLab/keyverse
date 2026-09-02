"""Regression contracts for multi-provider secret leak fingerprints."""

from __future__ import annotations

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
WORKFLOW_PATH = REPOSITORY_ROOT / ".github" / "workflows" / "hourly-product-development.yml"
PROVIDER_SECRET_NAMES = (
    "BYTEZ_API_KEY",
    "NVIDIA_NIM_API_KEY",
    "NVIDIA_NIM_API_KEY_SUB",
    "OPENROUTER_API_KEY",
    "OPENAI_API_KEY",
)


def test_gateway_fingerprints_every_registered_provider_secret() -> None:
    """Keep every provider credential inside the patch-leak denylist input."""
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
    start = "          secret_fingerprint=\"$(\n"
    end = "          printf 'secret_fingerprint=%s\\n' \"$secret_fingerprint\" >>\"$GITHUB_OUTPUT\"\n"
    assert workflow.count(start) == 1
    assert workflow.count(end) == 1
    fingerprint_block = workflow.split(start, 1)[1].split(end, 1)[0]

    for secret_name in PROVIDER_SECRET_NAMES:
        assert f'              \"{secret_name}\",' in fingerprint_block
    assert "hashlib.sha256(value).hexdigest()" in fingerprint_block
    assert "base64.b64encode(secret)" in fingerprint_block
    assert "base64.urlsafe_b64encode(secret)" in fingerprint_block
    assert "secret.hex().encode(\"ascii\")" in fingerprint_block

"""Generate the public subject-assertion v1 conformance fixture catalog.

Each run creates a fresh, throwaway P-256 signing key, signs realistic
Keycloak-shaped ID tokens, and writes only the public key, the tokens, and the
expected receipts to ``docs/contracts/subject-assertion-v1.fixtures.json``.
The private key is never written. Consumers in other languages can replay the
catalog to prove that their verifier makes the same decisions.

Usage (from ``services/account_unification``)::

    python tools/generate_subject_assertion_fixtures.py
"""
from __future__ import annotations

import base64
import json
import sys
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.subject_assertion import (  # noqa: E402
    SubjectAssertionProfile,
    verify_subject_assertion,
)

ISSUER = "https://id.contextualwisdom.example/realms/cwl"
AUDIENCE = "orgmetra-web"
NOW = 1_790_000_000
KEY_ID = "fixture-es256-v1"
OUTPUT = Path(__file__).resolve().parents[3] / "docs/contracts/subject-assertion-v1.fixtures.json"


def _b64url(raw: bytes) -> str:
    """Return unpadded base64url text."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _segment(value: dict[str, Any]) -> str:
    """Return one base64url JSON segment."""
    return _b64url(json.dumps(value, separators=(",", ":")).encode())


def _sign(key: ec.EllipticCurvePrivateKey, header: dict[str, Any], claims: dict[str, Any]) -> str:
    """Return a compact ES256 JWS with a raw R||S signature."""
    signing_input = f"{_segment(header)}.{_segment(claims)}"
    r, s = decode_dss_signature(key.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256())))
    return signing_input + "." + _b64url(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def build_catalog() -> dict[str, Any]:
    """Return the complete fixture catalog with expected receipts."""
    key = ec.generate_private_key(ec.SECP256R1())
    other = ec.generate_private_key(ec.SECP256R1())
    numbers = key.public_key().public_numbers()
    jwk = {
        "kty": "EC", "crv": "P-256", "kid": KEY_ID, "use": "sig", "alg": "ES256",
        "x": _b64url(numbers.x.to_bytes(32, "big")),
        "y": _b64url(numbers.y.to_bytes(32, "big")),
    }
    header = {"alg": "ES256", "typ": "JWT", "kid": KEY_ID}
    claims = {
        "iss": ISSUER, "sub": "f3b0c9a2-6d1e-4c55-9b7a-2f0e8d1c4b6a", "aud": AUDIENCE,
        "azp": AUDIENCE, "exp": NOW + 300, "iat": NOW - 10, "org": "tenant-acme",
    }
    cases = {
        "valid_public_subject": _sign(key, header, claims),
        "wrong_issuer": _sign(key, header, {**claims, "iss": ISSUER + "-staging"}),
        "wrong_audience": _sign(key, header, {**claims, "aud": "naruon-web", "azp": "naruon-web"}),
        "expired": _sign(key, header, {**claims, "exp": NOW - 61, "iat": NOW - 400}),
        "not_yet_valid": _sign(key, header, {**claims, "nbf": NOW + 61}),
        "forged_signature_same_kid": _sign(other, header, claims),
        "unknown_kid": _sign(key, {**header, "kid": "rotated-away"}, claims),
        "access_token_type": _sign(key, {**header, "typ": "at+jwt"}, claims),
        "critical_header": _sign(key, {**header, "crit": ["exp"]}, claims),
        "alg_none": f"{_segment({**header, 'alg': 'none'})}.{_segment(claims)}.",
        "cross_tenant_missing_org": _sign(
            key, header, {name: value for name, value in claims.items() if name != "org"}
        ),
        "empty_subject": _sign(key, header, {**claims, "sub": ""}),
        "untrusted_extra_audience": _sign(key, header, {**claims, "aud": [AUDIENCE, "naruon-web"]}),
        "trusted_extra_audience": _sign(key, header, {**claims, "aud": ["account", AUDIENCE]}),
        "lowercase_typ": _sign(key, {**header, "typ": "jwt"}, claims),
        "expiry_before_issue": _sign(key, header, {**claims, "exp": NOW - 20}),
    }
    profile_data = {
        "issuer": ISSUER,
        "audience": AUDIENCE,
        "allowed_algorithms": ["ES256"],
        "trusted_keys": {"keys": [jwk]},
        "subject_type": "public",
        "required_tenant_claim": "org",
        "leeway_seconds": 60,
        "trusted_additional_audiences": ["account"],
    }
    profile = SubjectAssertionProfile(
        **{  # type: ignore[arg-type]
            **profile_data,
            "allowed_algorithms": ("ES256",),
            "trusted_additional_audiences": ("account",),
        }
    )
    return {
        "contract_version": "keyverse.subject-assertion/v1",
        "description": (
            "Synthetic conformance cases. The signing key is throwaway test material; "
            "it is not a Keyverse deployment key."
        ),
        "now": NOW,
        "profile": profile_data,
        "cases": [
            {
                "name": name,
                "token": token,
                "expected_receipt": verify_subject_assertion(token, profile, now=NOW).receipt(),
            }
            for name, token in cases.items()
        ],
    }


def main() -> None:
    """Write the catalog to the published contract directory."""
    OUTPUT.write_text(json.dumps(build_catalog(), indent=2) + "\n", encoding="utf-8")
    print(f"wrote {OUTPUT}")


if __name__ == "__main__":
    main()

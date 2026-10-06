"""Subject-assertion trust contract tests (issue #155).

The tests sign realistic Keycloak-shaped ID tokens with freshly generated
ES256 and RS256 keys, then check the offline verifier's durable-versus-session
correlation decision and its fail-closed rejection categories.
"""
from __future__ import annotations

import base64
import json
import re
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from app.subject_assertion import (
    CONTRACT_VERSION,
    REJECTION_REASONS,
    SUBJECT_TYPES,
    SubjectAssertionProfile,
    verify_subject_assertion,
)

ISSUER = "https://id.contextualwisdom.example/realms/cwl"
AUDIENCE = "orgmetra-web"
NOW = 1_790_000_000


def _b64url(raw: bytes) -> str:
    """Return unpadded base64url text, as JWS compact serialization uses."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _int_b64(value: int, length: int | None = None) -> str:
    """Return a big-endian base64url integer for one JWK member."""
    size = length or (value.bit_length() + 7) // 8
    return _b64url(value.to_bytes(size, "big"))


class _Signer:
    """One test signing key plus its public JWK."""

    def __init__(self, alg: str, kid: str) -> None:
        """Generate a fresh key for ``alg`` and remember its key id."""
        self.alg = alg
        self.kid = kid
        if alg == "ES256":
            self.key = ec.generate_private_key(ec.SECP256R1())
            numbers = self.key.public_key().public_numbers()
            self.jwk: dict[str, Any] = {
                "kty": "EC",
                "crv": "P-256",
                "x": _int_b64(numbers.x, 32),
                "y": _int_b64(numbers.y, 32),
            }
        else:
            self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            numbers = self.key.public_key().public_numbers()
            self.jwk = {"kty": "RSA", "n": _int_b64(numbers.n), "e": _int_b64(numbers.e)}
        self.jwk.update({"kid": kid, "use": "sig", "alg": alg})

    def sign(self, signing_input: bytes) -> bytes:
        """Return the JWS signature bytes for ``signing_input``."""
        if self.alg == "ES256":
            r, s = decode_dss_signature(self.key.sign(signing_input, ec.ECDSA(hashes.SHA256())))
            return r.to_bytes(32, "big") + s.to_bytes(32, "big")
        return self.key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())


def _claims(**overrides: Any) -> dict[str, Any]:
    """Return a Keycloak-shaped ID token claim set with optional overrides."""
    claims: dict[str, Any] = {
        "iss": ISSUER,
        "sub": "f3b0c9a2-6d1e-4c55-9b7a-2f0e8d1c4b6a",
        "aud": AUDIENCE,
        "azp": AUDIENCE,
        "exp": NOW + 300,
        "iat": NOW - 10,
        "auth_time": NOW - 12,
        "nonce": "n-0S6_WzA2Mj",
        "org": "tenant-acme",
    }
    for name, value in overrides.items():
        if value is _DROP:
            claims.pop(name, None)
        else:
            claims[name] = value
    return claims


_DROP = object()


def _token(signer: _Signer, claims: dict[str, Any], **header: Any) -> str:
    """Return a compact JWS signed by ``signer`` with an optional header override."""
    base_header: dict[str, Any] = {"alg": signer.alg, "typ": "JWT", "kid": signer.kid}
    for name, value in header.items():
        if value is _DROP:
            base_header.pop(name, None)
        else:
            base_header[name] = value
    encoded = (
        _b64url(json.dumps(base_header).encode())
        + "."
        + _b64url(json.dumps(claims).encode())
    )
    return encoded + "." + _b64url(signer.sign(encoded.encode("ascii")))


def _profile(signers: list[_Signer], **overrides: Any) -> SubjectAssertionProfile:
    """Return one deployment profile trusting the public keys of ``signers``."""
    values: dict[str, Any] = {
        "issuer": ISSUER,
        "audience": AUDIENCE,
        "allowed_algorithms": ("ES256", "RS256"),
        "trusted_keys": {"keys": [signer.jwk for signer in signers]},
        "subject_type": "public",
        "required_tenant_claim": "org",
    }
    values.update(overrides)
    return SubjectAssertionProfile(**values)


@pytest.fixture(scope="module")
def es_signer() -> _Signer:
    """Return one ES256 realm signing key."""
    return _Signer("ES256", "realm-es256-2026-10")


@pytest.fixture(scope="module")
def rs_signer() -> _Signer:
    """Return one RS256 realm signing key."""
    return _Signer("RS256", "realm-rs256-2026-10")


# Slice 1: a verified public subject is durable; an ephemeral one is not.


@pytest.mark.parametrize("which", ["es", "rs"])
def test_verified_public_subject_is_eligible_for_durable_binding(
    which: str, es_signer: _Signer, rs_signer: _Signer
) -> None:
    """A valid ID token under a public-subject profile yields a durable receipt."""
    signer = es_signer if which == "es" else rs_signer
    result = verify_subject_assertion(
        _token(signer, _claims()),
        _profile([es_signer, rs_signer]),
        now=NOW,
        expected_nonce="n-0S6_WzA2Mj",
    )

    assert result.outcome == "verified"
    assert result.reason is None
    assert result.contract_version == CONTRACT_VERSION == "keyverse.subject-assertion/v1"
    assert result.issuer == ISSUER
    assert result.subject == "f3b0c9a2-6d1e-4c55-9b7a-2f0e8d1c4b6a"
    assert result.audience == AUDIENCE
    assert result.tenant == "tenant-acme"
    assert result.key_id == signer.kid
    assert result.algorithm == signer.alg
    assert result.expires_at == NOW + 300
    assert result.correlation == "durable"
    assert result.correlation_key is not None and len(result.correlation_key) == 64


def test_correlation_key_binds_issuer_audience_tenant_and_subject(
    es_signer: _Signer,
) -> None:
    """The durable key changes when any bound coordinate changes, never otherwise."""
    profile = _profile([es_signer])
    first = verify_subject_assertion(_token(es_signer, _claims()), profile, now=NOW)
    again = verify_subject_assertion(
        _token(es_signer, _claims(iat=NOW - 5, nonce="other")), profile, now=NOW
    )
    other_tenant = verify_subject_assertion(
        _token(es_signer, _claims(org="tenant-globex")), profile, now=NOW
    )
    other_subject = verify_subject_assertion(
        _token(es_signer, _claims(sub="0d4a")), profile, now=NOW
    )
    other_rp = verify_subject_assertion(
        _token(es_signer, _claims(aud="calendarweave-web", azp="calendarweave-web")),
        _profile([es_signer], audience="calendarweave-web"),
        now=NOW,
    )

    pairwise = verify_subject_assertion(
        _token(es_signer, _claims()), _profile([es_signer], subject_type="pairwise"), now=NOW
    )
    assert first.correlation_key == again.correlation_key
    assert pairwise.correlation_key != first.correlation_key
    keys = {
        first.correlation_key,
        other_tenant.correlation_key,
        other_subject.correlation_key,
        other_rp.correlation_key,
    }
    assert len(keys) == 4


def test_ephemeral_subject_profile_authenticates_session_only(es_signer: _Signer) -> None:
    """An ephemeral-subject profile verifies the login but forbids persistence."""
    result = verify_subject_assertion(
        _token(es_signer, _claims()),
        _profile([es_signer], subject_type="ephemeral"),
        now=NOW,
    )

    assert result.outcome == "verified"
    assert result.correlation == "session_only"
    assert result.correlation_key is None
    assert result.receipt()["correlation"] == "session_only"
    assert "correlation_key" not in result.receipt()


def test_pairwise_profile_is_durable_and_receipt_has_no_token_material(
    es_signer: _Signer,
) -> None:
    """A pairwise profile is durable; the receipt never echoes the raw token."""
    token = _token(es_signer, _claims())
    result = verify_subject_assertion(
        token, _profile([es_signer], subject_type="pairwise"), now=NOW
    )
    receipt = result.receipt()

    assert result.correlation == "durable"
    assert receipt == {
        "contract_version": CONTRACT_VERSION,
        "outcome": "verified",
        "issuer": ISSUER,
        "subject": "f3b0c9a2-6d1e-4c55-9b7a-2f0e8d1c4b6a",
        "audience": AUDIENCE,
        "tenant": "tenant-acme",
        "subject_type": "pairwise",
        "correlation": "durable",
        "correlation_key": result.correlation_key,
        "key_id": es_signer.kid,
        "algorithm": "ES256",
        "issued_at": NOW - 10,
        "expires_at": NOW + 300,
    }
    assert token.split(".")[2] not in json.dumps(receipt)


# Slice 2: every hostile or ambiguous input is rejected with one closed reason.


def _resign(signer: _Signer, header_part: str, payload_part: str) -> str:
    """Return a compact JWS over raw encoded parts, signed by ``signer``."""
    signing_input = f"{header_part}.{payload_part}"
    return signing_input + "." + _b64url(signer.sign(signing_input.encode("ascii")))


def _raw(obj: Any) -> str:
    """Return one base64url JSON segment."""
    return _b64url(json.dumps(obj).encode())


def _hostile_tokens(es: _Signer, rs: _Signer) -> dict[str, tuple[str, str]]:
    """Return named hostile tokens with the closed reason each must produce."""
    attacker = _Signer("ES256", es.kid)
    good = _token(es, _claims())
    head, body, sig = good.split(".")
    header = {"alg": "ES256", "typ": "JWT", "kid": es.kid}
    return {
        "two_segments": (f"{head}.{body}", "malformed_token"),
        "four_segments": (good + ".x", "malformed_token"),
        "bad_base64": (f"{head}.{body}!.{sig}", "malformed_token"),
        "header_not_json": (_resign(es, _b64url(b"{"), body), "malformed_token"),
        "header_array": (_resign(es, _raw(["ES256"]), body), "malformed_token"),
        "payload_array": (_resign(es, head, _raw([1])), "malformed_token"),
        "duplicate_header_member": (
            _resign(es, _b64url(b'{"alg":"none","alg":"ES256","typ":"JWT","kid":"%s"}'
                                % es.kid.encode()), body),
            "malformed_token",
        ),
        "oversized": ("a" * 20_000 + "." + body + "." + sig, "malformed_token"),
        "non_ascii": (good + "\u00e9", "malformed_token"),
        "alg_none": (_raw({**header, "alg": "none"}) + "." + body + ".", "algorithm_not_allowed"),
        "alg_hs256": (_resign(es, _raw({**header, "alg": "HS256"}), body),
                      "algorithm_not_allowed"),
        "alg_key_mismatch": (_resign(es, _raw({**header, "kid": rs.kid}), body),
                             "algorithm_not_allowed"),
        "crit_header": (_resign(es, _raw({**header, "crit": ["exp"], "exp": 1}), body),
                        "unsupported_header"),
        "jku_header": (_resign(es, _raw({**header, "jku": "https://evil.example/jwks"}), body),
                       "unsupported_header"),
        "embedded_jwk": (_resign(attacker, _raw({**header, "jwk": attacker.jwk}), body),
                         "unsupported_header"),
        "access_token_typ": (_resign(es, _raw({**header, "typ": "at+jwt"}), body),
                             "token_type_mismatch"),
        "keycloak_bearer_payload": (_token(es, _claims(typ="Bearer")), "token_type_mismatch"),
        "missing_kid": (_token(es, _claims(), kid=_DROP), "unknown_key"),
        "unknown_kid": (_token(es, _claims(), kid="rotated-away"), "unknown_key"),
        "forged_same_kid": (_token(attacker, _claims()), "invalid_signature"),
        "truncated_es_signature": (f"{head}.{body}.{_b64url(b'0' * 63)}", "invalid_signature"),
        "payload_swapped": (f"{head}.{_raw(_claims(sub='victim'))}.{sig}", "invalid_signature"),
        "wrong_issuer": (_token(es, _claims(iss=ISSUER + "-staging")), "issuer_mismatch"),
        "issuer_trailing_slash": (_token(es, _claims(iss=ISSUER + "/")), "issuer_mismatch"),
        "wrong_audience": (_token(es, _claims(aud="naruon-web", azp="naruon-web")),
                           "audience_mismatch"),
        "audience_list_without_azp": (
            _token(es, _claims(aud=[AUDIENCE, "naruon-web"], azp=_DROP)), "audience_mismatch"),
        "foreign_azp": (_token(es, _claims(azp="naruon-web")), "audience_mismatch"),
        "audience_object": (_token(es, _claims(aud={"x": AUDIENCE})), "audience_mismatch"),
        "expired": (_token(es, _claims(exp=NOW - 61, iat=NOW - 400)), "expired"),
        "not_yet_valid": (_token(es, _claims(nbf=NOW + 61)), "not_yet_valid"),
        "issued_in_future": (_token(es, _claims(iat=NOW + 61)), "not_yet_valid"),
        "missing_exp": (_token(es, _claims(exp=_DROP)), "invalid_claim"),
        "missing_iat": (_token(es, _claims(iat=_DROP)), "invalid_claim"),
        "boolean_exp": (_token(es, _claims(exp=True)), "invalid_claim"),
        "string_iat": (_token(es, _claims(iat=str(NOW))), "invalid_claim"),
        "missing_sub": (_token(es, _claims(sub=_DROP)), "invalid_claim"),
        "empty_sub": (_token(es, _claims(sub="")), "invalid_claim"),
        "numeric_sub": (_token(es, _claims(sub=42)), "invalid_claim"),
        "overlong_sub": (_token(es, _claims(sub="s" * 256)), "invalid_claim"),
        "missing_tenant": (_token(es, _claims(org=_DROP)), "tenant_missing"),
        "array_tenant": (_token(es, _claims(org=["tenant-acme", "tenant-globex"])),
                         "tenant_missing"),
        "blank_tenant": (_token(es, _claims(org="  ")), "tenant_missing"),
    }


_HOSTILE_NAMES = sorted(_hostile_tokens(_Signer("ES256", "k"), _Signer("RS256", "r")))


@pytest.mark.parametrize("name", _HOSTILE_NAMES)
def test_hostile_assertion_is_rejected_with_closed_reason(
    name: str, es_signer: _Signer, rs_signer: _Signer
) -> None:
    """Each hostile token is rejected; no identity field leaks into the result."""
    token, reason = _hostile_tokens(es_signer, rs_signer)[name]
    result = verify_subject_assertion(token, _profile([es_signer, rs_signer]), now=NOW)

    assert (result.outcome, result.reason) == ("rejected", reason)
    assert result.receipt() == {
        "contract_version": CONTRACT_VERSION,
        "outcome": "rejected",
        "reason": reason,
    }


def test_clock_leeway_is_bounded_and_inclusive(es_signer: _Signer) -> None:
    """A token inside the 60-second skew passes; one second beyond is rejected."""
    profile = _profile([es_signer])
    inside_expiry = _token(es_signer, _claims(exp=NOW - 60, iat=NOW - 400))
    inside_start = _token(es_signer, _claims(iat=NOW + 60, nbf=NOW + 60))
    outside = _token(es_signer, _claims(exp=NOW - 61, iat=NOW - 400))

    assert verify_subject_assertion(inside_expiry, profile, now=NOW).outcome == "verified"
    assert verify_subject_assertion(inside_start, profile, now=NOW).outcome == "verified"
    assert verify_subject_assertion(outside, profile, now=NOW).reason == "expired"


def test_nonce_is_compared_exactly_when_expected(es_signer: _Signer) -> None:
    """A replayed callback with another nonce, or none, is rejected."""
    profile = _profile([es_signer])
    no_nonce = _token(es_signer, _claims(nonce=_DROP))

    assert verify_subject_assertion(
        _token(es_signer, _claims()), profile, now=NOW, expected_nonce="other"
    ).reason == "nonce_mismatch"
    assert verify_subject_assertion(
        no_nonce, profile, now=NOW, expected_nonce="n-0S6_WzA2Mj"
    ).reason == "nonce_mismatch"
    assert verify_subject_assertion(no_nonce, profile, now=NOW).outcome == "verified"


def test_audience_list_with_matching_azp_is_accepted(es_signer: _Signer) -> None:
    """Multiple audiences pass only when every extra one is trusted and ``azp`` is this RP."""
    token = _token(es_signer, _claims(aud=["account", AUDIENCE], azp=AUDIENCE))
    trusting = _profile([es_signer], trusted_additional_audiences=("account",))
    result = verify_subject_assertion(token, trusting, now=NOW)

    assert result.outcome == "verified"
    assert result.audience == AUDIENCE


def test_untrusted_additional_audience_is_rejected(es_signer: _Signer) -> None:
    """OIDC Core 3.1.3.7: an ID token with an untrusted extra audience is rejected."""
    token = _token(es_signer, _claims(aud=[AUDIENCE, "naruon-web"], azp=AUDIENCE))
    trusting_other = _profile([es_signer], trusted_additional_audiences=("account",))

    assert verify_subject_assertion(token, _profile([es_signer]), now=NOW).reason == (
        "audience_mismatch"
    )
    assert verify_subject_assertion(token, trusting_other, now=NOW).reason == (
        "audience_mismatch"
    )
    trusted_without_azp = _token(es_signer, _claims(aud=["account", AUDIENCE], azp=_DROP))
    assert verify_subject_assertion(trusted_without_azp, trusting_other, now=NOW).reason == (
        "audience_mismatch"
    )


@pytest.mark.parametrize("typ", ["JWT", "jwt", "application/jwt", "Application/JWT"])
def test_jwt_media_type_is_case_insensitive(typ: str, es_signer: _Signer) -> None:
    """RFC 7515 4.1.9: ``typ`` is a case-insensitive media type with implied prefix."""
    result = verify_subject_assertion(
        _token(es_signer, _claims(), typ=typ), _profile([es_signer]), now=NOW
    )

    assert result.outcome == "verified"


@pytest.mark.parametrize("typ", ["AT+JWT", "application/at+jwt", "logout+jwt", "JOSE", 7])
def test_other_media_types_are_not_id_tokens(typ: object, es_signer: _Signer) -> None:
    """Access, logout, and generic JOSE types are refused as subject assertions."""
    result = verify_subject_assertion(
        _token(es_signer, _claims(), typ=typ), _profile([es_signer]), now=NOW
    )

    assert result.reason == "token_type_mismatch"


def test_profile_without_tenant_claim_returns_no_tenant(es_signer: _Signer) -> None:
    """A tenant-free profile verifies and binds the key with a null tenant."""
    result = verify_subject_assertion(
        _token(es_signer, _claims(org=_DROP)),
        _profile([es_signer], required_tenant_claim=None),
        now=NOW,
    )

    assert result.outcome == "verified"
    assert result.tenant is None
    assert result.correlation == "durable"


def test_rotation_keeps_old_key_until_profile_removes_it(es_signer: _Signer) -> None:
    """A token signed by a retired key fails once the profile drops that key."""
    successor = _Signer("ES256", "realm-es256-2027-01")
    old_token = _token(es_signer, _claims())

    both = _profile([es_signer, successor])
    rotated = _profile([successor])

    assert verify_subject_assertion(old_token, both, now=NOW).outcome == "verified"
    assert verify_subject_assertion(old_token, rotated, now=NOW).reason == "unknown_key"
    assert verify_subject_assertion(
        _token(successor, _claims()), rotated, now=NOW
    ).outcome == "verified"


# Slice 3: an unsafe deployment profile is refused before any token is read.


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"issuer": "http://id.contextualwisdom.example/realms/cwl"}, "issuer"),
        ({"issuer": ISSUER + "?q=1"}, "issuer"),
        ({"audience": ""}, "audience"),
        ({"allowed_algorithms": ()}, "allowed_algorithms"),
        ({"allowed_algorithms": ("HS256",)}, "allowed_algorithms"),
        ({"allowed_algorithms": ("none",)}, "allowed_algorithms"),
        ({"subject_type": "opaque"}, "subject_type"),
        ({"leeway_seconds": 301}, "leeway_seconds"),
        ({"leeway_seconds": -1}, "leeway_seconds"),
        ({"trusted_keys": {"keys": []}}, "trusted_keys"),
        ({"trusted_keys": []}, "trusted_keys"),
        ({"required_tenant_claim": "groups"}, "required_tenant_claim"),
        ({"trusted_additional_audiences": ["account"]}, "trusted_additional_audiences"),
        ({"trusted_additional_audiences": ("",)}, "trusted_additional_audiences"),
        ({"trusted_additional_audiences": (AUDIENCE,)}, "trusted_additional_audiences"),
    ],
)
def test_unsafe_profile_is_refused(
    overrides: dict[str, Any], message: str, es_signer: _Signer
) -> None:
    """Profile construction fails closed and names the unsafe field."""
    with pytest.raises(ValueError, match=message):
        _profile([es_signer], **overrides)


def test_profile_refuses_duplicate_private_weak_and_mislabeled_keys(es_signer: _Signer) -> None:
    """Ambiguous, private, short RSA, and wrong-use keys are refused."""
    weak = rsa.generate_private_key(public_exponent=65537, key_size=1024).public_key()
    weak_jwk = {"kty": "RSA", "kid": "weak", "alg": "RS256",
                "n": _int_b64(weak.public_numbers().n), "e": _int_b64(65537)}
    cases = [
        [es_signer.jwk, dict(es_signer.jwk)],
        [{**es_signer.jwk, "d": "c2VjcmV0"}],
        [weak_jwk],
        [{**es_signer.jwk, "use": "enc"}],
        [{**es_signer.jwk, "kid": ""}],
        [{**es_signer.jwk, "crv": "P-384"}],
        [{**es_signer.jwk, "x": "!!"}],
        [{**es_signer.jwk, "alg": "RS256"}],
        [{"kty": "oct", "kid": "hmac", "k": "c2VjcmV0"}],
    ]
    for keys in cases:
        with pytest.raises(ValueError, match="trusted_keys"):
            _profile([es_signer], trusted_keys={"keys": keys})


def test_invalid_base64_length_and_nan_payload_are_malformed(es_signer: _Signer) -> None:
    """A 4n+1 base64url segment and a NaN claim value are malformed, not errors."""
    head, body, sig = _token(es_signer, _claims()).split(".")
    nan_body = _b64url(b'{"iss":"x","exp":NaN}')
    profile = _profile([es_signer])

    assert verify_subject_assertion(f"{head}.{body}.a", profile, now=NOW).reason == (
        "malformed_token"
    )
    assert verify_subject_assertion(
        _resign(es_signer, head, nan_body), profile, now=NOW
    ).reason == "malformed_token"


def test_profile_refuses_non_string_issuer_non_object_key_and_disallowed_key_type(
    es_signer: _Signer, rs_signer: _Signer
) -> None:
    """Profile loading refuses wrong shapes and key types outside its algorithms."""
    with pytest.raises(ValueError, match="issuer"):
        _profile([es_signer], issuer=None)
    with pytest.raises(ValueError, match="trusted_keys"):
        _profile([es_signer], trusted_keys={"keys": ["not-a-jwk"]})
    with pytest.raises(ValueError, match="trusted_keys"):
        _profile([rs_signer], allowed_algorithms=("ES256",))
    with pytest.raises(ValueError, match="trusted_keys"):
        _profile([es_signer], trusted_keys={"keys": [{"kty": "OKP", "kid": "ed"}]})


# Slice 4: the published JSON Schema and conformance fixtures match the code.

_CONTRACT_DIR = Path(__file__).resolve().parents[3] / "docs" / "contracts"


def _schema() -> dict[str, Any]:
    """Load the published receipt schema."""
    return json.loads((_CONTRACT_DIR / "subject-assertion-v1.schema.json").read_text())


_SCHEMA_KEYWORDS = frozenset(
    {"$schema", "$id", "title", "description", "type", "additionalProperties", "properties",
     "required", "oneOf", "not", "anyOf", "const", "enum", "minLength", "maxLength", "pattern",
     "format"}
)


def _valid(instance: Any, schema: dict[str, Any]) -> bool:
    """Evaluate the JSON Schema 2020-12 keyword subset this contract uses.

    Unknown keywords raise, so a schema edit cannot silently weaken this oracle.
    ``format`` is annotation-only in 2020-12 and is therefore not asserted.
    """
    unknown = set(schema) - _SCHEMA_KEYWORDS
    if unknown:
        raise AssertionError(f"unsupported schema keywords: {sorted(unknown)}")
    checks = [
        "const" not in schema or instance == schema["const"],
        "enum" not in schema or instance in schema["enum"],
    ]
    kind = schema.get("type")
    if kind == "object":
        checks.append(isinstance(instance, dict))
    elif kind == "string":
        checks.append(isinstance(instance, str))
    elif kind == "integer":
        checks.append(isinstance(instance, int) and not isinstance(instance, bool))
    if not all(checks):
        return False
    if isinstance(instance, str):
        if len(instance) < schema.get("minLength", 0):
            return False
        if len(instance) > schema.get("maxLength", len(instance)):
            return False
        if "pattern" in schema and not re.search(schema["pattern"], instance):
            return False
    if isinstance(instance, dict):
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False and set(instance) - set(properties):
            return False
        if set(schema.get("required", [])) - set(instance):
            return False
        for name, rule in properties.items():
            if name in instance and not _valid(instance[name], rule):
                return False
    if "anyOf" in schema and not any(_valid(instance, item) for item in schema["anyOf"]):
        return False
    if "oneOf" in schema and sum(_valid(instance, item) for item in schema["oneOf"]) != 1:
        return False
    return not ("not" in schema and _valid(instance, schema["not"]))


def _conforms(receipt: dict[str, Any], schema: dict[str, Any]) -> bool:
    """Return whether ``receipt`` validates against the published schema."""
    return _valid(receipt, schema)


def test_schema_enumerates_exact_contract_constants() -> None:
    """Schema enums equal the module's closed reason and subject-type sets."""
    schema = _schema()

    assert schema["$id"] == "https://keyverse.contextualwisdom.dev/contracts/subject-assertion-v1"
    assert schema["properties"]["contract_version"]["const"] == CONTRACT_VERSION
    assert set(schema["properties"]["reason"]["enum"]) == REJECTION_REASONS
    assert set(schema["properties"]["subject_type"]["enum"]) == SUBJECT_TYPES
    assert schema["additionalProperties"] is False


def test_receipts_conform_to_schema(es_signer: _Signer, rs_signer: _Signer) -> None:
    """Verified, session-only, and every hostile receipt conforms to the schema."""
    schema = _schema()
    receipts = [
        verify_subject_assertion(_token(es_signer, _claims()), _profile([es_signer]),
                                 now=NOW).receipt(),
        verify_subject_assertion(_token(es_signer, _claims()),
                                 _profile([es_signer], subject_type="ephemeral"),
                                 now=NOW).receipt(),
    ] + [
        verify_subject_assertion(token, _profile([es_signer, rs_signer]), now=NOW).receipt()
        for token, _ in _hostile_tokens(es_signer, rs_signer).values()
    ]

    assert all(_conforms(receipt, schema) for receipt in receipts)
    forged = dict(receipts[1], correlation="durable", correlation_key="0" * 64)
    assert not _conforms(forged, schema)
    assert not _conforms(dict(receipts[0], authenticated=True), schema)
    assert not _conforms(dict(receipts[2], subject="victim"), schema)
    assert not _conforms(dict(receipts[0], reason="expired"), schema)
    assert not _conforms(dict(receipts[0], subject_type="ephemeral"), schema)
    assert not _conforms({k: v for k, v in receipts[0].items() if k != "correlation_key"}, schema)
    with pytest.raises(AssertionError, match="unsupported"):
        _valid({}, {"minProperties": 1})


def test_conformance_fixture_catalog_matches_verifier_outcomes() -> None:
    """Every published fixture case reproduces its declared outcome offline."""
    catalog = json.loads((_CONTRACT_DIR / "subject-assertion-v1.fixtures.json").read_text())
    profile = SubjectAssertionProfile(
        trusted_additional_audiences=tuple(catalog["profile"]["trusted_additional_audiences"]),
        issuer=catalog["profile"]["issuer"],
        audience=catalog["profile"]["audience"],
        allowed_algorithms=tuple(catalog["profile"]["allowed_algorithms"]),
        trusted_keys=catalog["profile"]["trusted_keys"],
        subject_type=catalog["profile"]["subject_type"],
        required_tenant_claim=catalog["profile"]["required_tenant_claim"],
        leeway_seconds=catalog["profile"]["leeway_seconds"],
    )

    assert catalog["contract_version"] == CONTRACT_VERSION
    assert len(catalog["cases"]) >= 10
    for case in catalog["cases"]:
        result = verify_subject_assertion(case["token"], profile, now=catalog["now"])
        assert result.receipt() == case["expected_receipt"], case["name"]


# Slice 5: independent adversarial review findings (reproduced before repair).


def test_lone_surrogate_strings_are_malformed_not_exceptions(es_signer: _Signer) -> None:
    """A signed lone-surrogate nonce or subject is rejected without raising."""
    profile = _profile([es_signer])
    nonce_token = _token(es_signer, _claims(nonce="\ud800"))
    subject_token = _token(es_signer, _claims(sub="user-\udfff"))

    assert verify_subject_assertion(
        nonce_token, profile, now=NOW, expected_nonce="n-1"
    ).reason == "malformed_token"
    assert verify_subject_assertion(subject_token, profile, now=NOW).reason == (
        "malformed_token"
    )


@pytest.mark.parametrize("now", [float("nan"), float(NOW), True, None, str(NOW)])
def test_non_integer_clock_is_a_caller_error(now: object, es_signer: _Signer) -> None:
    """A NaN, float, boolean, or text clock cannot disable time checks."""
    with pytest.raises(TypeError, match="now"):
        verify_subject_assertion(
            _token(es_signer, _claims(exp=NOW - 10_000)), _profile([es_signer]), now=now
        )


@pytest.mark.parametrize("nonce", [123, b"n-0S6_WzA2Mj"])
def test_non_text_expected_nonce_is_a_caller_error(nonce: object, es_signer: _Signer) -> None:
    """``expected_nonce`` must be text or ``None``."""
    with pytest.raises(TypeError, match="expected_nonce"):
        verify_subject_assertion(
            _token(es_signer, _claims()), _profile([es_signer]), now=NOW, expected_nonce=nonce
        )


def test_profile_keys_are_an_immutable_snapshot(es_signer: _Signer) -> None:
    """Caller mutation cannot change trust; rotation means building a new profile."""
    key_set = {"keys": [dict(es_signer.jwk)]}
    profile = _profile([es_signer], trusted_keys=key_set)
    key_set["keys"].clear()

    assert [key["kid"] for key in profile.trusted_keys["keys"]] == [es_signer.kid]
    with pytest.raises((TypeError, AttributeError)):
        profile.trusted_keys["keys"].clear()  # type: ignore[union-attr]
    with pytest.raises((TypeError, AttributeError)):
        profile._keys.clear()  # type: ignore[attr-defined]
    with pytest.raises(TypeError):
        profile._keys["forged"] = ("ES256", None)  # type: ignore[index]
    with pytest.raises(TypeError):
        profile.trusted_keys["keys"][0]["kid"] = "other"  # type: ignore[index]


def test_payload_must_be_strict_utf8_json(es_signer: _Signer) -> None:
    """UTF-16 and BOM-prefixed JSON are malformed (RFC 8259 section 8.1)."""
    head = _raw({"alg": "ES256", "typ": "JWT", "kid": es_signer.kid})
    text = json.dumps(_claims())
    profile = _profile([es_signer])
    for raw in (text.encode("utf-16"), b"\xef\xbb\xbf" + text.encode()):
        token = _resign(es_signer, head, _b64url(raw))
        assert verify_subject_assertion(token, profile, now=NOW).reason == "malformed_token"


@pytest.mark.parametrize(
    "subject", ["a\x85b", "a\u2028b", "a\u2029b", "\u202eabc", "\ufeffabc", " sub ", "\xa0sub"]
)
def test_invisible_or_padded_subject_is_invalid(subject: str, es_signer: _Signer) -> None:
    """Control, format, separator, and edge-whitespace subjects are refused."""
    result = verify_subject_assertion(
        _token(es_signer, _claims(sub=subject)), _profile([es_signer]), now=NOW
    )

    assert result.reason == "invalid_claim"


@pytest.mark.parametrize("tenant", ["ac\u2028me", "\u200bacme", "ac\x85me"])
def test_invisible_tenant_characters_are_refused(tenant: str, es_signer: _Signer) -> None:
    """Tenant keys reject invisible format and separator characters."""
    result = verify_subject_assertion(
        _token(es_signer, _claims(org=tenant)), _profile([es_signer]), now=NOW
    )

    assert result.reason == "tenant_missing"


def test_non_canonical_base64url_is_malformed(es_signer: _Signer) -> None:
    """Only one string spelling of each segment is accepted (RFC 4648 section 3.5)."""
    head, body, sig = _token(es_signer, _claims()).split(".")
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    last = alphabet.index(sig[-1])
    variant = sig[:-1] + alphabet[last ^ 1]
    profile = _profile([es_signer])

    assert verify_subject_assertion(f"{head}.{body}.{sig}", profile, now=NOW).outcome == (
        "verified"
    )
    assert verify_subject_assertion(f"{head}.{body}.{variant}", profile, now=NOW).reason == (
        "malformed_token"
    )


@pytest.mark.parametrize(
    "overrides",
    [{"exp": 10**4000}, {"exp": 2**53}, {"iat": -1}, {"nbf": 2**60}, {"iat": NOW + 400,
                                                                     "exp": NOW + 300}],
)
def test_numeric_dates_are_bounded_and_ordered(
    overrides: dict[str, Any], es_signer: _Signer
) -> None:
    """NumericDates stay in 0..2**53-1 and ``exp`` is not before ``iat``."""
    result = verify_subject_assertion(
        _token(es_signer, _claims(**overrides)), _profile([es_signer], leeway_seconds=300),
        now=NOW,
    )

    assert result.reason == "invalid_claim"


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"allowed_algorithms": (["ES256"],)}, "allowed_algorithms"),
        ({"issuer": ISSUER + " "}, "issuer"),
        ({"issuer": "https://id.example:99999999/realms/cwl"}, "issuer"),
        ({"trusted_additional_audiences": ("a\x00b",)}, "trusted_additional_audiences"),
        ({"trusted_additional_audiences": ("a" * 256,)}, "trusted_additional_audiences"),
        ({"trusted_additional_audiences": ("account", "account")},
         "trusted_additional_audiences"),
    ],
)
def test_reviewed_profile_gaps_are_refused(
    overrides: dict[str, Any], message: str, es_signer: _Signer
) -> None:
    """Profile inputs found unsafe in review raise ValueError naming the field."""
    with pytest.raises(ValueError, match=message):
        _profile([es_signer], **overrides)


def test_reviewed_key_gaps_are_refused(es_signer: _Signer) -> None:
    """Oversized or low-exponent RSA, padded EC coordinates, and non-verify ops fail."""
    big = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
    n = big.public_numbers().n
    cases = [
        {"kty": "RSA", "kid": "e3", "n": _int_b64(n), "e": _int_b64(3)},
        {"kty": "RSA", "kid": "huge", "n": _int_b64((1 << 8200) - 1), "e": _int_b64(65537)},
        {**es_signer.jwk, "x": _b64url(b"\x00" + base64.urlsafe_b64decode(
            es_signer.jwk["x"] + "="))},
        {**es_signer.jwk, "key_ops": ["encrypt"]},
    ]
    for jwk in cases:
        with pytest.raises(ValueError, match="trusted_keys"):
            _profile([es_signer], trusted_keys={"keys": [jwk]})
    assert _profile(
        [es_signer], trusted_keys={"keys": [{**es_signer.jwk, "key_ops": ["verify"]}]}
    )


def test_schema_correlation_key_is_exactly_64_characters() -> None:
    """A trailing newline after 64 hex characters is not a valid correlation key."""
    rule = _schema()["properties"]["correlation_key"]

    assert not _valid("0" * 64 + "\n", rule)
    assert _valid("0" * 64, rule)


def test_fixture_catalog_covers_audience_and_media_type_rules() -> None:
    """The published catalog carries the extra-audience and ``typ`` rules."""
    catalog = json.loads((_CONTRACT_DIR / "subject-assertion-v1.fixtures.json").read_text())
    names = {case["name"] for case in catalog["cases"]}

    assert catalog["profile"]["trusted_additional_audiences"] == ["account"]
    assert {"untrusted_extra_audience", "trusted_extra_audience", "lowercase_typ"} <= names

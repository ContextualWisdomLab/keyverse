"""Verify Keyverse subject assertions and classify durable RP correlation.

A relying party (RP) receives an OpenID Connect ID token from Keyverse. Before
the RP stores ``(issuer, subject)`` as a long-lived link to one of its own
records, it must know two things: the token is genuine, and the subject is
stable enough to persist. This module answers both questions offline.

The verifier uses only a deployment-pinned profile: the exact issuer, the exact
audience, allowed algorithms, and the trusted public keys. It never fetches
discovery documents or JWKS, never follows header-supplied key locations, and
never returns raw token material. A subject is ``durable`` only when the
profile declares a public or pairwise subject type; an ephemeral profile still
authenticates the session but returns ``session_only``.

Every rejection uses one closed reason code from ``REJECTION_REASONS`` so that
an RP can distinguish a bad credential from an incompatible profile without
parsing free text. Hostile input never raises; an unsafe profile raises
``ValueError`` at construction time, before any token is read.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

CONTRACT_VERSION = "keyverse.subject-assertion/v1"
SUPPORTED_ALGORITHMS = frozenset({"ES256", "RS256"})
SUBJECT_TYPES = frozenset({"public", "pairwise", "ephemeral"})
TENANT_CLAIMS = frozenset({"org"})
REJECTION_REASONS = frozenset(
    {
        "malformed_token",
        "algorithm_not_allowed",
        "unsupported_header",
        "token_type_mismatch",
        "unknown_key",
        "invalid_signature",
        "issuer_mismatch",
        "audience_mismatch",
        "invalid_claim",
        "expired",
        "not_yet_valid",
        "nonce_mismatch",
        "tenant_missing",
    }
)

_DURABLE_SUBJECT_TYPES = frozenset({"public", "pairwise"})
_KEY_ALGORITHM_BY_TYPE = {"EC": "ES256", "RSA": "RS256"}
_ALLOWED_HEADER_MEMBERS = frozenset({"alg", "typ", "kid"})
_PRIVATE_JWK_MEMBERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})
_MAX_TOKEN_LENGTH = 16_384
_MAX_SUBJECT_LENGTH = 255
_MAX_TENANT_LENGTH = 128
_MAX_AUDIENCE_LENGTH = 255
_MAX_LEEWAY_SECONDS = 300
_MIN_RSA_BITS = 2_048
_MAX_RSA_BITS = 8_192
_MIN_RSA_EXPONENT = 65_537
_EC_COORDINATE_LENGTH = 32
_MAX_NUMERIC_DATE = 2**53 - 1
_INVISIBLE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp"})
_ES256_SIGNATURE_LENGTH = 64
_BASE64URL = re.compile(r"^[A-Za-z0-9_-]*$")
_CONTROL = re.compile(r"[\x00-\x1F\x7F]")


class _Rejected(Exception):
    """Internal signal that carries one closed rejection reason."""

    def __init__(self, reason: str) -> None:
        """Remember the closed ``reason`` code."""
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class SubjectAssertionProfile:
    """Deployment-pinned trust profile for one RP audience.

    ``trusted_keys`` is a public JWK Set (``{"keys": [...]}``) supplied by the
    deployment, never fetched by this module. ``subject_type`` states the
    subject identifier semantics the issuer guarantees for this RP: ``public``
    and ``pairwise`` subjects may be persisted, ``ephemeral`` ones may not.
    ``leeway_seconds`` bounds clock skew for ``exp``, ``nbf``, and ``iat``.
    ``trusted_additional_audiences`` lists the only other ``aud`` values this
    RP accepts beside itself; OIDC Core 3.1.3.7 rejects any other audience.
    """

    issuer: str
    audience: str
    allowed_algorithms: tuple[str, ...]
    trusted_keys: Mapping[str, Any]
    subject_type: str = "public"
    required_tenant_claim: str | None = None
    leeway_seconds: int = 60
    trusted_additional_audiences: tuple[str, ...] = ()
    _keys: Mapping[str, tuple[str, Any]] = field(
        init=False, repr=False, compare=False, default_factory=dict
    )

    def __post_init__(self) -> None:
        """Refuse an unsafe profile and pre-load its public verification keys."""
        _validate_issuer(self.issuer)
        if not _is_client_identifier(self.audience):
            raise ValueError("audience must be one non-empty client identifier")
        algorithms = self.allowed_algorithms
        if (
            not isinstance(algorithms, tuple)
            or not algorithms
            or not all(isinstance(item, str) for item in algorithms)
            or not set(algorithms) <= SUPPORTED_ALGORITHMS
        ):
            raise ValueError("allowed_algorithms must be a non-empty subset of ES256/RS256")
        extra = self.trusted_additional_audiences
        if (
            not isinstance(extra, tuple)
            or len(set(extra)) != len(extra)
            or any(not _is_client_identifier(item) or item == self.audience for item in extra)
        ):
            raise ValueError(
                "trusted_additional_audiences must be a tuple of other unique client IDs"
            )
        if self.subject_type not in SUBJECT_TYPES:
            raise ValueError("subject_type must be public, pairwise, or ephemeral")
        if self.required_tenant_claim is not None and (
            self.required_tenant_claim not in TENANT_CLAIMS
        ):
            raise ValueError("required_tenant_claim must be null or the canonical 'org' claim")
        leeway = self.leeway_seconds
        if isinstance(leeway, bool) or not isinstance(leeway, int) or not (
            0 <= leeway <= _MAX_LEEWAY_SECONDS
        ):
            raise ValueError("leeway_seconds must be an integer from 0 to 300")
        loaded = _load_key_set(self.trusted_keys, frozenset(algorithms))
        object.__setattr__(self, "trusted_keys", _frozen_key_set(self.trusted_keys))
        object.__setattr__(self, "_keys", MappingProxyType(loaded))


@dataclass(frozen=True)
class SubjectAssertionResult:
    """Outcome of one verification; rejected results carry only a reason."""

    outcome: str
    reason: str | None = None
    contract_version: str = CONTRACT_VERSION
    issuer: str | None = None
    subject: str | None = None
    audience: str | None = None
    tenant: str | None = None
    subject_type: str | None = None
    correlation: str | None = None
    correlation_key: str | None = None
    key_id: str | None = None
    algorithm: str | None = None
    issued_at: int | None = None
    expires_at: int | None = None

    def receipt(self) -> dict[str, Any]:
        """Return a JSON-safe receipt that omits absent fields and token bytes."""
        names = (
            "contract_version", "outcome", "reason", "issuer", "subject", "audience",
            "tenant", "subject_type", "correlation", "correlation_key", "key_id",
            "algorithm", "issued_at", "expires_at",
        )
        return {name: getattr(self, name) for name in names if getattr(self, name) is not None}


def verify_subject_assertion(
    token: str,
    profile: SubjectAssertionProfile,
    *,
    now: int,
    expected_nonce: str | None = None,
) -> SubjectAssertionResult:
    """Verify ``token`` against ``profile`` at time ``now`` (seconds since epoch).

    When ``expected_nonce`` is given, the token's ``nonce`` must equal it
    exactly. The function never raises for hostile token input; it returns a
    rejected result with one closed reason code instead. A caller error (a
    non-integer ``now`` or non-text ``expected_nonce``) raises ``TypeError``,
    because a NaN or float clock would silently disable the time checks.
    """
    if isinstance(now, bool) or not isinstance(now, int):
        raise TypeError("now must be an integer number of seconds since the epoch")
    if expected_nonce is not None and not isinstance(expected_nonce, str):
        raise TypeError("expected_nonce must be text or None")
    try:
        return _verify(token, profile, now=now, expected_nonce=expected_nonce)
    except _Rejected as rejected:
        return SubjectAssertionResult(outcome="rejected", reason=rejected.reason)


def _verify(
    token: str, profile: SubjectAssertionProfile, *, now: int, expected_nonce: str | None
) -> SubjectAssertionResult:
    """Run every check in a fixed order and build the verified result."""
    header_part, payload_part, signature_part = _split_token(token)
    header = _decode_json_object(header_part)
    claims = _decode_json_object(payload_part)
    signature = _b64decode(signature_part)

    algorithm = header.get("alg")
    if algorithm not in profile.allowed_algorithms:
        raise _Rejected("algorithm_not_allowed")
    if not set(header) <= _ALLOWED_HEADER_MEMBERS:
        raise _Rejected("unsupported_header")
    if not _is_jwt_media_type(header.get("typ", "JWT")):
        raise _Rejected("token_type_mismatch")
    key_id = header.get("kid")
    if not isinstance(key_id, str) or key_id not in profile._keys:
        raise _Rejected("unknown_key")
    key_algorithm, public_key = profile._keys[key_id]
    if key_algorithm != algorithm:
        raise _Rejected("algorithm_not_allowed")
    _verify_signature(
        algorithm, public_key, f"{header_part}.{payload_part}".encode("ascii"), signature
    )

    if claims.get("typ", "ID") != "ID":
        raise _Rejected("token_type_mismatch")
    if claims.get("iss") != profile.issuer:
        raise _Rejected("issuer_mismatch")
    _check_audience(claims, profile.audience, profile.trusted_additional_audiences)
    subject = _check_subject(claims.get("sub"))
    issued_at, expires_at = _check_times(claims, now, profile.leeway_seconds)
    if expected_nonce is not None:
        nonce = claims.get("nonce")
        if not isinstance(nonce, str) or not hmac.compare_digest(
            nonce.encode("utf-8"), expected_nonce.encode("utf-8")
        ):
            raise _Rejected("nonce_mismatch")
    tenant = (
        _check_tenant(claims.get(profile.required_tenant_claim))
        if profile.required_tenant_claim
        else None
    )

    durable = profile.subject_type in _DURABLE_SUBJECT_TYPES
    return SubjectAssertionResult(
        outcome="verified",
        issuer=profile.issuer,
        subject=subject,
        audience=profile.audience,
        tenant=tenant,
        subject_type=profile.subject_type,
        correlation="durable" if durable else "session_only",
        correlation_key=(
            _correlation_key(
                profile.issuer, profile.audience, profile.subject_type, tenant, subject
            )
            if durable
            else None
        ),
        key_id=key_id,
        algorithm=algorithm,
        issued_at=issued_at,
        expires_at=expires_at,
    )


def _split_token(token: object) -> tuple[str, str, str]:
    """Return the three bounded ASCII base64url segments of a compact JWS."""
    if (
        not isinstance(token, str)
        or len(token) > _MAX_TOKEN_LENGTH
        or not token.isascii()
    ):
        raise _Rejected("malformed_token")
    parts = token.split(".")
    if len(parts) != 3 or not all(_BASE64URL.fullmatch(part) for part in parts):
        raise _Rejected("malformed_token")
    return parts[0], parts[1], parts[2]


def _b64decode(segment: str) -> bytes:
    """Decode one canonical unpadded base64url segment (RFC 4648 section 3.5).

    Non-zero padding bits are refused so that each token has one spelling.
    """
    try:
        raw = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    except (binascii.Error, ValueError) as error:
        raise _Rejected("malformed_token") from error
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != segment:
        raise _Rejected("malformed_token")
    return raw


def _reject_duplicate_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Build a JSON object, refusing duplicate member names (RFC 7515 §4)."""
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate JSON member")
        result[name] = value
    return result


def _reject_constant(name: str) -> None:
    """Refuse the non-standard JSON constants NaN and Infinity."""
    raise ValueError(f"non-standard JSON constant {name}")


def _decode_json_object(segment: str) -> dict[str, Any]:
    """Decode one segment into a strict JSON object or reject the token."""
    raw = _b64decode(segment)
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_members,
            parse_constant=_reject_constant,
        )
        # Re-encoding refuses lone surrogates that a \\uD800 escape can create.
        json.dumps(value, ensure_ascii=False).encode("utf-8")
    except (ValueError, RecursionError) as error:
        raise _Rejected("malformed_token") from error
    if not isinstance(value, dict):
        raise _Rejected("malformed_token")
    return value


def _verify_signature(
    algorithm: str, public_key: Any, signing_input: bytes, signature: bytes
) -> None:
    """Verify one ES256 (raw R||S) or RS256 signature with a trusted key."""
    try:
        if algorithm == "ES256":
            if len(signature) != _ES256_SIGNATURE_LENGTH:
                raise InvalidSignature
            der = encode_dss_signature(
                int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
            )
            public_key.verify(der, signing_input, ec.ECDSA(hashes.SHA256()))
        else:
            public_key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature as error:
        raise _Rejected("invalid_signature") from error


def _is_jwt_media_type(value: object) -> bool:
    """Return whether ``typ`` names the ``application/jwt`` media type.

    RFC 7515 4.1.9 makes media types case-insensitive and implies an
    ``application/`` prefix when the value contains no ``/``.
    """
    if not isinstance(value, str):
        return False
    lowered = value.lower()
    return (lowered if "/" in lowered else "application/" + lowered) == "application/jwt"


def _check_audience(
    claims: dict[str, Any], audience: str, trusted_additional: tuple[str, ...]
) -> None:
    """Require this RP in ``aud``, only trusted extras, and ``azp`` for many audiences."""
    value = claims.get("aud")
    if isinstance(value, str):
        audiences = [value]
    elif isinstance(value, list) and all(isinstance(item, str) for item in value):
        audiences = value
    else:
        raise _Rejected("audience_mismatch")
    if audience not in audiences:
        raise _Rejected("audience_mismatch")
    if not set(audiences) <= {audience, *trusted_additional}:
        raise _Rejected("audience_mismatch")
    authorized_party = claims.get("azp")
    if len(audiences) > 1 and authorized_party is None:
        raise _Rejected("audience_mismatch")
    if authorized_party is not None and authorized_party != audience:
        raise _Rejected("audience_mismatch")


def _check_subject(value: object) -> str:
    """Return one non-empty, bounded, visible, unpadded opaque subject."""
    if (
        not isinstance(value, str)
        or not value
        or len(value) > _MAX_SUBJECT_LENGTH
        or value != value.strip()
        or _has_invisible(value)
    ):
        raise _Rejected("invalid_claim")
    return value


def _has_invisible(value: str) -> bool:
    """Return whether ``value`` has control, format, surrogate, or line characters."""
    return any(unicodedata.category(character) in _INVISIBLE_CATEGORIES for character in value)


def _numeric_date(value: object) -> int:
    """Return an integer NumericDate in 0..2**53-1; other values are refused."""
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value <= _MAX_NUMERIC_DATE
    ):
        raise _Rejected("invalid_claim")
    return value


def _check_times(claims: dict[str, Any], now: int, leeway: int) -> tuple[int, int]:
    """Check ``exp``, ``iat``, and optional ``nbf`` with bounded leeway."""
    expires_at = _numeric_date(claims.get("exp"))
    issued_at = _numeric_date(claims.get("iat"))
    not_before = _numeric_date(claims["nbf"]) if "nbf" in claims else None
    if expires_at < issued_at:
        raise _Rejected("invalid_claim")
    if now > expires_at + leeway:
        raise _Rejected("expired")
    if now + leeway < issued_at or (not_before is not None and now + leeway < not_before):
        raise _Rejected("not_yet_valid")
    return issued_at, expires_at


def _check_tenant(value: object) -> str:
    """Return one canonical non-empty opaque tenant key."""
    if (
        not isinstance(value, str)
        or not value.strip()
        or value != value.strip()
        or len(value) > _MAX_TENANT_LENGTH
        or _has_invisible(value)
    ):
        raise _Rejected("tenant_missing")
    return value


def _correlation_key(
    issuer: str, audience: str, subject_type: str, tenant: str | None, subject: str
) -> str:
    """Return a stable SHA-256 key over the canonical bound coordinates."""
    canonical = json.dumps(
        [CONTRACT_VERSION, issuer, audience, subject_type, tenant, subject],
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _validate_issuer(issuer: object) -> None:
    """Require one absolute HTTPS issuer without query, fragment, or userinfo."""
    if not isinstance(issuer, str) or any(
        character.isspace() or unicodedata.category(character) in _INVISIBLE_CATEGORIES
        for character in issuer
    ):
        raise ValueError("issuer must be an absolute HTTPS URL")
    parts = urlsplit(issuer)
    try:
        parts.port
    except ValueError as error:
        raise ValueError("issuer must use a valid TCP port") from error
    if (
        parts.scheme != "https"
        or not parts.hostname
        or parts.query
        or parts.fragment
        or "@" in parts.netloc
    ):
        raise ValueError("issuer must be an absolute HTTPS URL without query or fragment")


def _is_client_identifier(value: object) -> bool:
    """Return whether ``value`` is one bounded, visible client identifier."""
    return (
        isinstance(value, str)
        and 0 < len(value) <= _MAX_AUDIENCE_LENGTH
        and value == value.strip()
        and not _has_invisible(value)
    )


def _frozen_key_set(key_set: Mapping[str, Any]) -> Mapping[str, Any]:
    """Return a read-only deep snapshot of an already validated JWK Set."""
    return MappingProxyType(
        {
            "keys": tuple(
                MappingProxyType(
                    {
                        name: tuple(value) if isinstance(value, list) else value
                        for name, value in jwk.items()
                    }
                )
                for jwk in key_set["keys"]
            )
        }
    )


def _profile_b64bytes(value: object) -> bytes:
    """Decode one base64url JWK member for profile loading."""
    if not isinstance(value, str) or not value or not _BASE64URL.fullmatch(value):
        raise ValueError("trusted_keys contains a malformed key integer")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _profile_b64int(value: object) -> int:
    """Decode one base64url JWK integer for profile loading."""
    return int.from_bytes(_profile_b64bytes(value), "big")


def _load_key(jwk: object, allowed: frozenset[str]) -> tuple[str, tuple[str, Any]]:
    """Validate one public JWK and return ``(kid, (algorithm, public_key))``."""
    if not isinstance(jwk, dict):
        raise ValueError("trusted_keys entries must be JWK objects")
    key_id = jwk.get("kid")
    if not isinstance(key_id, str) or not key_id or _CONTROL.search(key_id):
        raise ValueError("trusted_keys entries need a non-empty kid")
    if _PRIVATE_JWK_MEMBERS & set(jwk):
        raise ValueError("trusted_keys must contain public keys only")
    algorithm = _KEY_ALGORITHM_BY_TYPE.get(jwk.get("kty"))
    if algorithm is None or algorithm not in allowed:
        raise ValueError("trusted_keys key type is not allowed by this profile")
    if jwk.get("use", "sig") != "sig" or jwk.get("alg", algorithm) != algorithm:
        raise ValueError("trusted_keys key use/alg does not match a signature key")
    if "key_ops" in jwk and jwk["key_ops"] != ["verify"]:
        raise ValueError("trusted_keys key_ops must be exactly ['verify'] when present")
    try:
        if algorithm == "ES256":
            if jwk.get("crv") != "P-256":
                raise ValueError("trusted_keys EC keys must use P-256")
            x_bytes = _profile_b64bytes(jwk.get("x"))
            y_bytes = _profile_b64bytes(jwk.get("y"))
            if len(x_bytes) != _EC_COORDINATE_LENGTH or len(y_bytes) != _EC_COORDINATE_LENGTH:
                raise ValueError("trusted_keys EC coordinates must be exactly 32 bytes")
            public_key: Any = ec.EllipticCurvePublicNumbers(
                int.from_bytes(x_bytes, "big"), int.from_bytes(y_bytes, "big"), ec.SECP256R1()
            ).public_key()
        else:
            exponent = _profile_b64int(jwk.get("e"))
            modulus = _profile_b64int(jwk.get("n"))
            if not _MIN_RSA_BITS <= modulus.bit_length() <= _MAX_RSA_BITS:
                raise ValueError("trusted_keys RSA keys must have 2048 to 8192 bits")
            if exponent < _MIN_RSA_EXPONENT:
                raise ValueError("trusted_keys RSA public exponent must be at least 65537")
            public_key = rsa.RSAPublicNumbers(exponent, modulus).public_key()
    except ValueError as error:
        raise ValueError(f"trusted_keys contains an invalid key: {error}") from error
    return key_id, (algorithm, public_key)


def _load_key_set(key_set: object, allowed: frozenset[str]) -> dict[str, tuple[str, Any]]:
    """Validate a non-empty public JWK Set with unique key ids."""
    if not isinstance(key_set, dict) or not isinstance(key_set.get("keys"), list):
        raise ValueError("trusted_keys must be a JWK Set object")
    if not key_set["keys"]:
        raise ValueError("trusted_keys must contain at least one key")
    loaded: dict[str, tuple[str, Any]] = {}
    for jwk in key_set["keys"]:
        key_id, entry = _load_key(jwk, allowed)
        if key_id in loaded:
            raise ValueError("trusted_keys contains a duplicate kid")
        loaded[key_id] = entry
    return loaded

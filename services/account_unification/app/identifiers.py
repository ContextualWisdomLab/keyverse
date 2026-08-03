"""Opaque-identifier validation for Keycloak Admin REST path segments.

Every caller-supplied identifier (user id, provider alias, audit id) is
interpolated into an Admin API URL path. A value like ``../users/victim`` or a
percent-encoded separator would let a caller escape the intended resource, so
identifiers are validated as a single opaque path segment before any URL is
built. This is the defense-in-depth layer applied inside the Admin client
itself, independent of any boundary validation.
"""
from __future__ import annotations

# Keycloak ids are UUIDs and aliases are slugs, so URI delimiters and encoding
# markers are never legitimate inside one opaque identifier.
_MAX_IDENTIFIER_LENGTH = 255
_FORBIDDEN_IDENTIFIER_CHARACTERS = frozenset({"/", "\\", "%", "?", "#"})


class InvalidIdentifierError(ValueError):
    """Raised when an identifier is not a single safe path segment."""


def validate_path_segment(value: str, *, field_name: str = "identifier") -> str:
    """Return ``value`` if it is one safe opaque path segment, else raise.

    Rejects empty/oversized values, path and URI delimiters, dot navigation,
    percent-encoding, and control characters.
    """
    if not isinstance(value, str) or not value:
        raise InvalidIdentifierError(f"{field_name} must be a non-empty string")
    if len(value) > _MAX_IDENTIFIER_LENGTH:
        raise InvalidIdentifierError(f"{field_name} is too long")
    if value in {".", ".."}:
        raise InvalidIdentifierError(
            f"{field_name} must not be a path navigation token"
        )
    for character in value:
        if character in _FORBIDDEN_IDENTIFIER_CHARACTERS:
            raise InvalidIdentifierError(
                f"{field_name} must not contain path, encoding, query, or fragment delimiters"
            )
        if ord(character) < 0x20 or ord(character) == 0x7F:
            raise InvalidIdentifierError(
                f"{field_name} must not contain control characters"
            )
    return value

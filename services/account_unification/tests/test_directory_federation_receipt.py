"""Canonical receipt tests for private LDAP desired-state revisions."""
from __future__ import annotations

from app.directory_federation_state import _desired_digest

from .test_directory_federation_desired_state import (
    _active_directory_registration,
)


def test_desired_digest_is_independent_of_json_key_order() -> None:
    """Equivalent private desired state produces one stable apply receipt."""
    first = _active_directory_registration()
    second = first.model_copy(deep=True)
    second.config = dict(reversed(tuple(second.config.items())))

    assert _desired_digest(first) == _desired_digest(second)

"""Typed errors for the unification service."""
from __future__ import annotations


class UnificationError(Exception):
    """Base class for all unification failures."""


class UserNotFoundError(UnificationError):
    """A referenced Keycloak user does not exist."""


class SameUserError(UnificationError):
    """Survivor and duplicate are the same account."""


class UnverifiedEmailMergeError(UnificationError):
    """Refused: the only tie between the accounts is an unverified email."""


class NoMatchError(UnificationError):
    """Refused: the accounts do not satisfy any matching rule."""


class InactiveAccountError(UnificationError):
    """Refused: an account is not active (already merged/deactivated)."""


class AuthorizationPolicyError(UnificationError):
    """Closed authorization-plane input or policy failure."""

    def __init__(self, message: str, *, status_code: int = 400) -> None:
        """Record one operator-safe policy failure and its HTTP status."""
        super().__init__(message)
        self.status_code = status_code

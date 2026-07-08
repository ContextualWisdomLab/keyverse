"""Typed errors for the unification service."""
from __future__ import annotations


class UnificationError(Exception):
    """Base class for all unification failures."""


class UserNotFoundError(UnificationError):
    """A referenced ZITADEL user does not exist."""


class SameUserError(UnificationError):
    """Survivor and duplicate are the same account."""


class UnverifiedEmailMergeError(UnificationError):
    """Refused: the only tie between the accounts is an unverified email."""


class NoMatchError(UnificationError):
    """Refused: the accounts do not satisfy any matching rule."""


class InactiveAccountError(UnificationError):
    """Refused: an account is not active (already merged/deactivated)."""

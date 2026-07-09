"""Identity matching rules.

Precedence (highest first), per ecosystem policy:
  1. exact (idp_id, external subject/nameID) shared between the two accounts
  2. verified-email equality on BOTH accounts
  3. explicit operator-asserted link

Hard rule: NEVER treat an unverified-email coincidence as a match. Verified
email counts only when both sides have ``is_email_verified`` true.
"""
from __future__ import annotations

from .models import MatchDecision, MatchReason, UserAccount


def _normalize_email(email: str | None) -> str | None:
    """Return a comparable email value or ``None`` for blank input."""
    if not email:
        return None
    return email.strip().lower() or None


def shares_exact_idp_subject(a: UserAccount, b: UserAccount) -> str | None:
    """Return an identifier if the two accounts share an (idp, subject) pair."""
    b_pairs = {
        (link.identity_provider, link.external_user_id)
        for link in b.federated_identities
    }
    for link in a.federated_identities:
        if (link.identity_provider, link.external_user_id) in b_pairs:
            return f"{link.identity_provider}:{link.external_user_id}"
    return None


def have_matching_verified_email(a: UserAccount, b: UserAccount) -> bool:
    """Return true when both accounts share the same verified email."""
    email_a = _normalize_email(a.email)
    email_b = _normalize_email(b.email)
    if email_a is None or email_b is None:
        return False
    if email_a != email_b:
        return False
    return a.is_email_verified and b.is_email_verified


def decide_match(
    survivor: UserAccount,
    duplicate: UserAccount,
    *,
    explicit_link: bool = False,
) -> MatchDecision:
    """Decide whether ``survivor`` and ``duplicate`` are the same human."""
    shared = shares_exact_idp_subject(survivor, duplicate)
    if shared is not None:
        return MatchDecision(
            matched=True,
            reason=MatchReason.EXACT_IDP_SUBJECT,
            detail=f"shared idp subject {shared}",
        )

    if have_matching_verified_email(survivor, duplicate):
        return MatchDecision(
            matched=True,
            reason=MatchReason.VERIFIED_EMAIL,
            detail=f"verified email {_normalize_email(survivor.email)}",
        )

    if explicit_link:
        # Operator asserts the link out-of-band. This is permitted, but it is
        # NOT justified by an unverified email coincidence — that path is closed
        # above by requiring verification. Record it as an explicit decision.
        return MatchDecision(
            matched=True,
            reason=MatchReason.EXPLICIT_LINK,
            detail="operator-asserted explicit link",
        )

    return MatchDecision(
        matched=False,
        reason=MatchReason.NO_MATCH,
        detail="no exact idp subject, no matching verified email, no explicit link",
    )

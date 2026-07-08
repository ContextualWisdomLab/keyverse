"""Matching precedence + the unverified-email guardrail."""
from __future__ import annotations

from app.matching import decide_match
from app.models import IdentityLink, MatchReason, UserAccount


def _user(uid, email=None, verified=False, links=None):
    return UserAccount(
        user_id=uid, email=email, is_email_verified=verified, idp_links=links or []
    )


def test_exact_idp_subject_wins():
    link = IdentityLink(idp_id="adfs", external_user_id="jane@corp")
    a = _user("a", links=[link])
    b = _user("b", links=[link])
    decision = decide_match(a, b)
    assert decision.matched
    assert decision.reason is MatchReason.EXACT_IDP_SUBJECT


def test_verified_email_matches_when_both_verified():
    a = _user("a", email="Jane@Corp.com", verified=True)
    b = _user("b", email="jane@corp.com", verified=True)
    decision = decide_match(a, b)
    assert decision.matched
    assert decision.reason is MatchReason.VERIFIED_EMAIL


def test_unverified_email_is_never_a_match():
    a = _user("a", email="jane@corp.com", verified=True)
    b = _user("b", email="jane@corp.com", verified=False)
    decision = decide_match(a, b)
    assert not decision.matched
    assert decision.reason is MatchReason.NO_MATCH


def test_explicit_link_is_lowest_precedence():
    a = _user("a", email="jane@corp.com", verified=False)
    b = _user("b", email="other@corp.com", verified=False)
    decision = decide_match(a, b, explicit_link=True)
    assert decision.matched
    assert decision.reason is MatchReason.EXPLICIT_LINK


def test_exact_subject_beats_explicit_flag():
    link = IdentityLink(idp_id="ldap", external_user_id="guid-1")
    a = _user("a", links=[link])
    b = _user("b", links=[link])
    decision = decide_match(a, b, explicit_link=True)
    assert decision.reason is MatchReason.EXACT_IDP_SUBJECT

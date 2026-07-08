"""MERGE two pre-existing accounts into one survivor."""
from __future__ import annotations

import pytest

from app.errors import (
    InactiveAccountError,
    NoMatchError,
    SameUserError,
    UnverifiedEmailMergeError,
    UserNotFoundError,
)
from app.models import IdentityLink, Membership, MergeRequest, MatchReason, UserGrant
from app.service import TOMBSTONE_METADATA_KEY


def _merge(survivor="survivor", duplicate="dup", explicit=False):
    return MergeRequest(
        survivor_user_id=survivor,
        duplicate_user_id=duplicate,
        explicit_link=explicit,
        actor="admin@cwl",
    )


def test_merge_moves_links_grants_memberships_and_tombstones(service, api):
    api.create_user(
        "survivor",
        email="jane@corp.com",
        is_email_verified=True,
        idp_links=[IdentityLink(idp_id="adfs", external_user_id="jane@corp")],
        grants=[UserGrant(grant_id="g-s", project_id="naruon", role_keys=["viewer"])],
        memberships=[Membership(membership_type="org", aggregate_id="org-1", roles=["owner"])],
    )
    api.create_user(
        "dup",
        email="jane@corp.com",
        is_email_verified=True,
        idp_links=[IdentityLink(idp_id="google", external_user_id="jane@gmail")],
        grants=[UserGrant(grant_id="g-d", project_id="clearfolio", role_keys=["editor"])],
        memberships=[Membership(membership_type="project", aggregate_id="pg-erd", roles=["admin"])],
    )

    result = service.merge_accounts(_merge())

    assert result.match_reason is MatchReason.VERIFIED_EMAIL
    assert result.duplicate_tombstoned is True
    # survivor gained the duplicate's external identity...
    survivor_idps = {link.external_user_id for link in api.list_idp_links("survivor")}
    assert "jane@gmail" in survivor_idps and "jane@corp" in survivor_idps
    # ...its project grant...
    assert {g.project_id for g in api.list_user_grants("survivor")} == {"naruon", "clearfolio"}
    # ...and its membership.
    assert {m.aggregate_id for m in api.list_memberships("survivor")} == {"org-1", "pg-erd"}
    # duplicate is emptied + tombstoned + deactivated.
    assert api.list_idp_links("dup") == []
    assert "dup" in api.deactivated
    assert api.metadata[("dup", TOMBSTONE_METADATA_KEY)] == "survivor"


def test_merge_by_exact_idp_subject(service, api):
    shared = IdentityLink(idp_id="adfs", external_user_id="jane@corp")
    api.create_user("survivor", email="a@x.com", idp_links=[shared])
    api.create_user("dup", email="b@y.com", idp_links=[shared])
    result = service.merge_accounts(_merge())
    assert result.match_reason is MatchReason.EXACT_IDP_SUBJECT
    # shared link stays on survivor exactly once (survivor-wins conflict).
    assert [link.external_user_id for link in api.list_idp_links("survivor")] == ["jane@corp"]
    assert any(c.kind == "idp_link" for c in result.conflicts)


def test_grant_conflict_is_survivor_wins(service, api):
    api.create_user(
        "survivor", email="j@x.com", is_email_verified=True,
        grants=[UserGrant(grant_id="g-s", project_id="naruon", role_keys=["admin"])],
    )
    api.create_user(
        "dup", email="j@x.com", is_email_verified=True,
        grants=[UserGrant(grant_id="g-d", project_id="naruon", role_keys=["viewer"])],
    )
    result = service.merge_accounts(_merge())
    survivor_grants = api.list_user_grants("survivor")
    # only the survivor's grant on naruon survives.
    assert len(survivor_grants) == 1
    assert survivor_grants[0].role_keys == ["admin"]
    assert any(c.kind == "grant" and c.resolution == "survivor_wins" for c in result.conflicts)


def test_refuse_merge_on_unverified_email(service, api):
    api.create_user("survivor", email="jane@corp.com", is_email_verified=True)
    api.create_user("dup", email="jane@corp.com", is_email_verified=False)
    with pytest.raises(UnverifiedEmailMergeError):
        service.merge_accounts(_merge())
    # nothing mutated: duplicate not tombstoned.
    assert "dup" not in api.deactivated


def test_refuse_merge_when_no_match(service, api):
    api.create_user("survivor", email="a@x.com", is_email_verified=True)
    api.create_user("dup", email="b@y.com", is_email_verified=True)
    with pytest.raises(NoMatchError):
        service.merge_accounts(_merge())


def test_explicit_link_allows_merge_without_shared_signal(service, api):
    api.create_user("survivor", email="a@x.com")
    api.create_user("dup", email="b@y.com")
    result = service.merge_accounts(_merge(explicit=True))
    assert result.match_reason is MatchReason.EXPLICIT_LINK
    assert result.duplicate_tombstoned


def test_refuse_self_merge(service, api):
    api.create_user("same", email="a@x.com", is_email_verified=True)
    with pytest.raises(SameUserError):
        service.merge_accounts(_merge(survivor="same", duplicate="same"))


def test_refuse_merge_missing_user(service, api):
    api.create_user("survivor", email="a@x.com", is_email_verified=True)
    with pytest.raises(UserNotFoundError):
        service.merge_accounts(_merge())


def test_refuse_merge_inactive_duplicate(service, api):
    api.create_user("survivor", email="j@x.com", is_email_verified=True)
    api.create_user("dup", email="j@x.com", is_email_verified=True)
    api.deactivate_user("dup")
    with pytest.raises(InactiveAccountError):
        service.merge_accounts(_merge())

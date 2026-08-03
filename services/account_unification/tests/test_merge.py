"""MERGE two pre-existing accounts into one survivor (Keycloak-backed)."""
from __future__ import annotations

import pytest

from app.errors import (
    InactiveAccountError,
    NoMatchError,
    SameUserError,
    UnverifiedEmailMergeError,
    UserNotFoundError,
)
from app.models import (
    FederatedIdentity,
    GroupMembership,
    MatchReason,
    MergeRequest,
    RoleMapping,
)
from app.service import TOMBSTONE_ATTRIBUTE_KEY


def _merge(survivor="survivor", duplicate="dup", explicit=False):
    return MergeRequest(
        survivor_user_id=survivor,
        duplicate_user_id=duplicate,
        explicit_link=explicit,
        actor="admin@cwl",
    )


def test_merge_moves_links_roles_groups_and_tombstones(service, api):
    api.create_test_user(
        "survivor",
        email="jane@corp.com",
        is_email_verified=True,
        federated_identities=[
            FederatedIdentity(
                identity_provider="employer-adfs", external_user_id="jane@corp"
            )
        ],
        role_mappings=[
            RoleMapping(role_id="r-s", role_name="viewer", client_id="naruon")
        ],
        group_memberships=[GroupMembership(group_id="g-org", group_path="/org")],
    )
    api.create_test_user(
        "dup",
        email="jane@corp.com",
        is_email_verified=True,
        federated_identities=[
            FederatedIdentity(
                identity_provider="google", external_user_id="jane@gmail"
            )
        ],
        role_mappings=[
            RoleMapping(role_id="r-d", role_name="editor", client_id="clearfolio")
        ],
        group_memberships=[GroupMembership(group_id="g-proj", group_path="/pg-erd")],
    )

    result = service.merge_accounts(_merge())

    assert result.match_reason is MatchReason.VERIFIED_EMAIL
    assert result.duplicate_tombstoned is True
    survivor_idps = {
        identity.identity_provider
        for identity in api.list_federated_identities("survivor")
    }
    assert survivor_idps == {"employer-adfs", "google"}
    survivor_roles = {role.role_name for role in api.list_role_mappings("survivor")}
    assert survivor_roles == {"viewer", "editor"}
    survivor_groups = {
        group.group_id for group in api.list_group_memberships("survivor")
    }
    assert survivor_groups == {"g-org", "g-proj"}
    assert api.list_federated_identities("dup") == []
    assert "dup" in api.deactivated
    assert api.attributes[("dup", TOMBSTONE_ATTRIBUTE_KEY)] == "survivor"


def test_merge_by_exact_idp_subject(service, api):
    shared = FederatedIdentity(
        identity_provider="employer-adfs", external_user_id="jane@corp"
    )
    api.create_test_user("survivor", email="a@x.com", federated_identities=[shared])
    api.create_test_user("dup", email="b@y.com", federated_identities=[shared])
    result = service.merge_accounts(_merge())
    assert result.match_reason is MatchReason.EXACT_IDP_SUBJECT
    assert [
        identity.external_user_id
        for identity in api.list_federated_identities("survivor")
    ] == ["jane@corp"]
    assert any(conflict.kind == "federated_identity" for conflict in result.conflicts)


def test_federated_identity_provider_conflict_is_survivor_wins(service, api):
    api.create_test_user(
        "survivor",
        email="j@x.com",
        is_email_verified=True,
        federated_identities=[
            FederatedIdentity(
                identity_provider="employer-adfs", external_user_id="jane@corp"
            )
        ],
    )
    api.create_test_user(
        "dup",
        email="j@x.com",
        is_email_verified=True,
        federated_identities=[
            FederatedIdentity(
                identity_provider="employer-adfs", external_user_id="jane2@corp"
            )
        ],
    )
    result = service.merge_accounts(_merge())
    survivor_links = api.list_federated_identities("survivor")
    assert [identity.external_user_id for identity in survivor_links] == ["jane@corp"]
    assert any(conflict.kind == "federated_identity" for conflict in result.conflicts)


def test_role_conflict_is_survivor_wins(service, api):
    api.create_test_user(
        "survivor",
        email="j@x.com",
        is_email_verified=True,
        role_mappings=[
            RoleMapping(role_id="r-s", role_name="admin", client_id="naruon")
        ],
    )
    api.create_test_user(
        "dup",
        email="j@x.com",
        is_email_verified=True,
        role_mappings=[
            RoleMapping(role_id="r-d", role_name="admin", client_id="naruon")
        ],
    )
    result = service.merge_accounts(_merge())
    survivor_roles = api.list_role_mappings("survivor")
    assert len(survivor_roles) == 1
    assert survivor_roles[0].role_id == "r-s"
    assert any(
        conflict.kind == "role_mapping"
        and conflict.resolution == "survivor_wins"
        for conflict in result.conflicts
    )


def test_realm_role_moves(service, api):
    api.create_test_user("survivor", email="j@x.com", is_email_verified=True)
    api.create_test_user(
        "dup",
        email="j@x.com",
        is_email_verified=True,
        role_mappings=[
            RoleMapping(
                role_id="r-realm", role_name="ecosystem-user", client_id=None
            )
        ],
    )
    result = service.merge_accounts(_merge())
    assert "realm:ecosystem-user" in result.moved_role_mappings
    assert any(
        role.client_id is None for role in api.list_role_mappings("survivor")
    )


def test_group_conflict_is_survivor_wins(service, api):
    api.create_test_user(
        "survivor",
        email="j@x.com",
        is_email_verified=True,
        group_memberships=[GroupMembership(group_id="g1", group_path="/owners")],
    )
    api.create_test_user(
        "dup",
        email="j@x.com",
        is_email_verified=True,
        group_memberships=[GroupMembership(group_id="g1", group_path="/owners")],
    )
    result = service.merge_accounts(_merge())
    assert len(api.list_group_memberships("survivor")) == 1
    assert any(conflict.kind == "group_membership" for conflict in result.conflicts)


def test_refuse_merge_on_unverified_email(service, api):
    api.create_test_user("survivor", email="jane@corp.com", is_email_verified=True)
    api.create_test_user("dup", email="jane@corp.com", is_email_verified=False)
    with pytest.raises(UnverifiedEmailMergeError):
        service.merge_accounts(_merge())
    assert "dup" not in api.deactivated


def test_refuse_merge_when_no_match(service, api):
    api.create_test_user("survivor", email="a@x.com", is_email_verified=True)
    api.create_test_user("dup", email="b@y.com", is_email_verified=True)
    with pytest.raises(NoMatchError):
        service.merge_accounts(_merge())


def test_explicit_link_allows_merge_without_shared_signal(service, api):
    api.create_test_user("survivor", email="a@x.com")
    api.create_test_user("dup", email="b@y.com")
    result = service.merge_accounts(_merge(explicit=True))
    assert result.match_reason is MatchReason.EXPLICIT_LINK
    assert result.duplicate_tombstoned


def test_explicit_link_cannot_override_shared_unverified_email(service, api):
    api.create_test_user("survivor", email="jane@corp.com", is_email_verified=False)
    api.create_test_user("dup", email="jane@corp.com", is_email_verified=False)
    with pytest.raises(UnverifiedEmailMergeError):
        service.merge_accounts(_merge(explicit=True))
    assert "dup" not in api.deactivated


def test_explicit_link_cannot_override_case_variant_unverified_email(service, api):
    api.create_test_user("survivor", email="Jane@Corp.com", is_email_verified=True)
    api.create_test_user("dup", email="jane@corp.com", is_email_verified=False)
    with pytest.raises(UnverifiedEmailMergeError):
        service.merge_accounts(_merge(explicit=True))
    assert "dup" not in api.deactivated


def test_refuse_self_merge(service, api):
    api.create_test_user("same", email="a@x.com", is_email_verified=True)
    with pytest.raises(SameUserError):
        service.merge_accounts(_merge(survivor="same", duplicate="same"))


def test_refuse_merge_missing_user(service, api):
    api.create_test_user("survivor", email="a@x.com", is_email_verified=True)
    with pytest.raises(UserNotFoundError):
        service.merge_accounts(_merge())


def test_refuse_merge_inactive_duplicate(service, api):
    api.create_test_user("survivor", email="j@x.com", is_email_verified=True)
    api.create_test_user("dup", email="j@x.com", is_email_verified=True)
    api.deactivate_user("dup")
    with pytest.raises(InactiveAccountError):
        service.merge_accounts(_merge())

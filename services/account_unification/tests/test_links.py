"""One-user-to-many-external-identities: list/inspect federated identities."""
from __future__ import annotations

import pytest

from app.errors import UserNotFoundError
from app.models import FederatedIdentity


def test_list_identities_returns_all_links(service, api):
    api.create_test_user(
        "u1",
        email="jane@corp.com",
        is_email_verified=True,
        federated_identities=[
            FederatedIdentity(identity_provider="employer-adfs", external_user_id="jane@corp"),
            FederatedIdentity(identity_provider="corp-ldap", external_user_id="guid-42"),
        ],
    )
    links = service.list_identities("u1")
    assert {link.identity_provider for link in links} == {"employer-adfs", "corp-ldap"}


def test_get_account_hydrates_links(service, api):
    api.create_test_user(
        "u1",
        federated_identities=[
            FederatedIdentity(identity_provider="employer-adfs", external_user_id="jane@corp")
        ],
    )
    account = service.get_account("u1")
    assert account.user_id == "u1"
    assert len(account.federated_identities) == 1


def test_list_identities_unknown_user_raises(service):
    with pytest.raises(UserNotFoundError):
        service.list_identities("missing")

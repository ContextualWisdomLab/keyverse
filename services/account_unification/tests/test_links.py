"""One-user-to-many-external-identities: list/inspect idp_links."""
from __future__ import annotations

import pytest

from app.errors import UserNotFoundError
from app.models import IdentityLink


def test_list_identities_returns_all_links(service, api):
    api.create_user(
        "u1",
        email="jane@corp.com",
        is_email_verified=True,
        idp_links=[
            IdentityLink(idp_id="adfs", external_user_id="jane@corp", idp_name="Employer ADFS"),
            IdentityLink(idp_id="ldap", external_user_id="guid-42", idp_name="Corp LDAP"),
        ],
    )
    links = service.list_identities("u1")
    assert {link.idp_id for link in links} == {"adfs", "ldap"}


def test_get_account_hydrates_links(service, api):
    api.create_user(
        "u1",
        idp_links=[IdentityLink(idp_id="adfs", external_user_id="jane@corp")],
    )
    account = service.get_account("u1")
    assert account.user_id == "u1"
    assert len(account.idp_links) == 1


def test_list_identities_unknown_user_raises(service):
    with pytest.raises(UserNotFoundError):
        service.list_identities("missing")

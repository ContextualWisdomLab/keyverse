"""LDAP desired-state persistence and reconciliation tests."""
from __future__ import annotations

from app.directory_federation import (
    DIRECTORY_FEDERATION_NAMESPACE,
    DirectoryConvergenceState,
    DirectoryFederationRegistration,
    DirectoryFederationService,
)
from app.kv_store import InMemoryKvStore


def _active_directory_registration() -> DirectoryFederationRegistration:
    """Return one realistic read-only Active Directory registration."""
    return DirectoryFederationRegistration(
        name="corp-ldap",
        providerId="ldap",
        providerType="org.keycloak.storage.UserStorageProvider",
        config={
            "enabled": ["true"],
            "priority": ["1"],
            "editMode": ["READ_ONLY"],
            "importEnabled": ["true"],
            "syncRegistrations": ["false"],
            "vendor": ["ad"],
            "connectionUrl": [
                "ldaps://ad-01.corp.example:636 "
                "ldaps://ad-02.corp.example:636"
            ],
            "usersDn": ["OU=Users,DC=corp,DC=example"],
            "bindDn": [
                "CN=svc-keycloak,OU=ServiceAccounts,DC=corp,DC=example"
            ],
            "bindCredential": ["rendered-private-value"],
            "usernameLDAPAttribute": ["sAMAccountName"],
            "rdnLDAPAttribute": ["cn"],
            "uuidLDAPAttribute": ["objectGUID"],
            "userObjectClasses": ["person, organizationalPerson, user"],
            "searchScope": ["2"],
            "trustEmail": ["false"],
            "useTruststoreSpi": ["always"],
            "connectionPooling": ["true"],
            "connectionTimeout": ["10000"],
            "readTimeout": ["10000"],
            "allowKerberosAuthentication": ["false"],
        },
    )


def test_put_persists_creates_and_returns_redacted_status(api) -> None:
    """A validated directory becomes durable desired state and one component."""
    store = InMemoryKvStore()
    service = DirectoryFederationService(store, api)

    status = service.put_registration(
        "corp-ldap",
        _active_directory_registration(),
    )

    stored = store.get(DIRECTORY_FEDERATION_NAMESPACE, "corp-ldap")
    assert stored is not None
    assert "rendered-private-value" in stored
    assert status.desired_state_stored is True
    assert status.convergence_state is DirectoryConvergenceState.IN_SYNC
    assert status.secret_observation == "not_observable"
    assert status.registration.config["bindCredential"] == ["<redacted>"]
    assert status.registration.config["bindDn"] == ["<redacted>"]
    assert "rendered-private-value" not in status.model_dump_json(by_alias=True)
    assert status.component_id is not None
    assert len(api.user_storage_components) == 1

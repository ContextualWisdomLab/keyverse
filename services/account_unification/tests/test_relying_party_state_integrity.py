"""Integrity regressions for relying-party desired-state identity boundaries."""
from __future__ import annotations

import pytest
from fastapi import HTTPException

from app.kv_store import InMemoryKvStore
from app.relying_party_state import RELYING_PARTY_NAMESPACE, RelyingPartyService

from .test_relying_party_desired_state import _registration


def test_inventory_rejects_miskeyed_stored_registration(api) -> None:
    """A KV key cannot silently inventory another client's desired identity."""
    store = InMemoryKvStore()
    store.put(
        RELYING_PARTY_NAMESPACE,
        "naruon-web",
        _registration("other-web").model_dump_json(by_alias=True),
    )
    service = RelyingPartyService(store, api)

    with pytest.raises(HTTPException) as error:
        service.list_registrations()

    assert error.value.status_code == 500
    assert error.value.detail == "stored_state_invalid"


def test_status_rejects_unsafe_live_client_uuid(api) -> None:
    """An unsafe Keycloak identifier is never returned or reused as status data."""
    store = InMemoryKvStore()
    registration = _registration()
    store.put(
        RELYING_PARTY_NAMESPACE,
        registration.client_id,
        registration.model_dump_json(by_alias=True),
    )
    unsafe_client = registration.model_dump(by_alias=True)
    unsafe_client["id"] = "../escape"
    api.relying_party_clients["unsafe-record"] = unsafe_client
    service = RelyingPartyService(store, api)

    with pytest.raises(HTTPException) as error:
        service.get_registration("naruon-web")

    assert error.value.status_code == 500
    assert error.value.detail == "keycloak client identifier is invalid"

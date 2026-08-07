"""OIDC relying-party mapper observation and reconciliation regressions."""
from __future__ import annotations

from copy import deepcopy
from collections.abc import Callable

import pytest

from app.kv_store import InMemoryKvStore
from app.relying_party_state import (
    RELYING_PARTY_RECEIPT_NAMESPACE,
    RelyingPartyConvergenceState,
    RelyingPartyService,
    parse_relying_party_registration,
)

from .test_relying_party_claim_mappers import _naruon_registration_with_mappers


def _registration(role_value: str = "member"):
    """Return one valid Naruon registration with a selectable role value."""
    payload = _naruon_registration_with_mappers()
    mappers = payload["protocolMappers"]
    assert isinstance(mappers, list)
    role_mapper = mappers[1]
    assert isinstance(role_mapper, dict)
    config = role_mapper["config"]
    assert isinstance(config, dict)
    config["claim.value"] = role_value
    return parse_relying_party_registration(payload)


def _live_client(api, client_uuid: str) -> dict:
    """Return the mutable live client held by the deterministic test double."""
    client = api.relying_party_clients[client_uuid]
    assert isinstance(client, dict)
    return client


def _live_mappers(api, client_uuid: str) -> list[dict]:
    """Return the mutable mapper list for one deterministic live client."""
    mappers = _live_client(api, client_uuid)["protocolMappers"]
    assert isinstance(mappers, list)
    assert all(isinstance(mapper, dict) for mapper in mappers)
    return mappers


def test_generated_mapper_ids_and_vendor_order_do_not_create_false_drift(api) -> None:
    """Opaque mapper IDs and returned order are normalized before comparison."""
    service = RelyingPartyService(InMemoryKvStore(), api)
    created = service.put_registration("naruon-web", _registration())
    mappers = _live_mappers(api, created.client_uuid)
    for index, mapper in enumerate(mappers):
        mapper["id"] = f"mapper-{index}"
    mappers.reverse()

    status = service.get_registration("naruon-web")

    assert status.convergence_state is RelyingPartyConvergenceState.IN_SYNC
    assert status.last_apply_receipt_matches is True


def _remove_mapper_field(client: dict) -> None:
    """Remove the whole optional mapper collection from the live client."""
    client.pop("protocolMappers")


def _replace_with_non_list(client: dict) -> None:
    """Replace the mapper collection with an invalid scalar."""
    client["protocolMappers"] = "not-a-list"


def _replace_with_non_object(client: dict) -> None:
    """Replace one mapper with a non-object value."""
    client["protocolMappers"] = ["not-an-object"]


def _replace_with_too_many(client: dict) -> None:
    """Exceed the closed four-mapper profile."""
    mapper = deepcopy(_live_mappers_from_client(client)[0])
    client["protocolMappers"] = [deepcopy(mapper) for _ in range(5)]


def _set_non_string_mapper_id(client: dict) -> None:
    """Attach a malformed vendor-generated mapper identifier."""
    _live_mappers_from_client(client)[0]["id"] = 7


def _add_unknown_mapper_field(client: dict) -> None:
    """Attach an unowned mapper-level field that cannot be normalized away."""
    _live_mappers_from_client(client)[0]["private"] = "not-owned"


def _set_non_mapping_config(client: dict) -> None:
    """Replace mapper configuration with an invalid scalar."""
    _live_mappers_from_client(client)[0]["config"] = []


def _set_unsupported_mapper_type(client: dict) -> None:
    """Replace a reviewed mapper plugin with an unsupported plugin."""
    _live_mappers_from_client(client)[0]["protocolMapper"] = (
        "oidc-script-based-protocol-mapper"
    )


def _duplicate_mapper_identity(client: dict) -> None:
    """Make two live mappers claim the same canonical identity."""
    mappers = _live_mappers_from_client(client)
    mappers[2] = deepcopy(mappers[1])


def _live_mappers_from_client(client: dict) -> list[dict]:
    """Return a type-checked mapper list from a mutable client object."""
    mappers = client["protocolMappers"]
    assert isinstance(mappers, list)
    assert all(isinstance(mapper, dict) for mapper in mappers)
    return mappers


@pytest.mark.parametrize(
    "mutate",
    [
        _remove_mapper_field,
        _replace_with_non_list,
        _replace_with_non_object,
        _replace_with_too_many,
        _set_non_string_mapper_id,
        _add_unknown_mapper_field,
        _set_non_mapping_config,
        _set_unsupported_mapper_type,
        _duplicate_mapper_identity,
    ],
)
def test_malformed_or_unowned_live_mapper_state_is_drift(
    api,
    mutate: Callable[[dict], None],
) -> None:
    """Malformed, duplicate, or unsupported live mappers fail closed as drift."""
    service = RelyingPartyService(InMemoryKvStore(), api)
    created = service.put_registration("naruon-web", _registration())
    mutate(_live_client(api, created.client_uuid))

    status = service.get_registration("naruon-web")

    assert status.convergence_state is RelyingPartyConvergenceState.DRIFTED


def test_changed_claim_value_is_repaired_from_desired_state(api) -> None:
    """A changed product-routing claim is restored by reconciliation."""
    service = RelyingPartyService(InMemoryKvStore(), api)
    created = service.put_registration("naruon-web", _registration())
    role_config = _live_mappers(api, created.client_uuid)[1]["config"]
    assert isinstance(role_config, dict)
    role_config["claim.value"] = "administrator"

    before = service.get_registration("naruon-web")
    repaired = service.reconcile_all()[0]

    assert before.convergence_state is RelyingPartyConvergenceState.DRIFTED
    assert repaired.convergence_state is RelyingPartyConvergenceState.IN_SYNC
    repaired_config = _live_mappers(api, created.client_uuid)[1]["config"]
    assert isinstance(repaired_config, dict)
    assert repaired_config["claim.value"] == "member"


def test_post_update_mapper_mismatch_withholds_new_receipt(
    api,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A mismatched post-update observation returns failure without a receipt."""
    store = InMemoryKvStore()
    service = RelyingPartyService(store, api)
    created = service.put_registration("naruon-web", _registration())
    original_update = api.update_relying_party_client

    def corrupt_update(client_uuid: str, payload: dict) -> None:
        """Apply the update and then corrupt the observed role claim."""
        original_update(client_uuid, payload)
        config = _live_mappers(api, client_uuid)[1]["config"]
        assert isinstance(config, dict)
        config["claim.value"] = "unexpected"

    monkeypatch.setattr(api, "update_relying_party_client", corrupt_update)

    status = service.put_registration("naruon-web", _registration("editor"))

    assert status.convergence_state is RelyingPartyConvergenceState.APPLY_FAILED
    assert status.last_convergence_error_code == "client_state_mismatch_after_apply"
    assert status.last_apply_receipt_matches is False
    assert store.get(RELYING_PARTY_RECEIPT_NAMESPACE, "naruon-web") is not None
    assert status.client_uuid == created.client_uuid

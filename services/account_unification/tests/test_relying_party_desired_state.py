"""OIDC relying-party desired-state lifecycle tests."""
from __future__ import annotations

from app.kv_store import InMemoryKvStore
from app.relying_party_state import (
    RELYING_PARTY_NAMESPACE,
    RelyingPartyConvergenceState,
    RelyingPartyService,
)

from .test_relying_party_preflight import _confidential_web_client


def test_put_persists_creates_and_returns_in_sync_status(api) -> None:
    """A validated secret-free relying party becomes durable and observable."""
    store = InMemoryKvStore()
    service = RelyingPartyService(store, api)

    status = service.put_registration(
        "naruon-web",
        _confidential_web_client(),
    )

    assert store.get(RELYING_PARTY_NAMESPACE, "naruon-web") is not None
    assert status.desired_state_stored is True
    assert status.convergence_state is RelyingPartyConvergenceState.IN_SYNC
    assert status.client_uuid is not None
    assert len(api.relying_party_clients) == 1
    assert "secret" not in status.model_dump_json(by_alias=True).lower()

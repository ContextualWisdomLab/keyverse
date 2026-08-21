"""Programmable application token issue, verify, revoke, and rotate contracts."""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from app.application_tokens import (
    APPLICATION_TOKEN_NAMESPACE,
    ApplicationTokenIssueRequest,
    ApplicationTokenRecord,
    ApplicationTokenService,
    ApplicationTokenVerifyRequest,
    application_token_router,
    application_token_runtime_router,
    get_application_token_service,
)
from app.audit import AuditLogger, InMemoryAuditSink
from app.errors import AuthorizationPolicyError
from app.kv_store import InMemoryKvStore
from app.main import create_app


class _FailingStore(InMemoryKvStore):
    """Inject one storage failure at a chosen write."""

    def __init__(self, *, fail_on_put: int) -> None:
        """Create a store that fails on the requested one-based write."""
        super().__init__()
        self._fail_on_put = fail_on_put
        self._put_count = 0

    def put(self, namespace: str, entry_key: str, entry_value: str) -> None:
        """Raise once at the configured write and otherwise persist normally."""
        self._put_count += 1
        if self._put_count == self._fail_on_put:
            raise RuntimeError("injected token storage failure")
        super().put(namespace, entry_key, entry_value)

    def put_many(self, namespace: str, entries: dict[str, str]) -> None:
        """Raise once at the configured atomic write and otherwise persist normally."""
        self._put_count += 1
        if self._put_count == self._fail_on_put:
            raise RuntimeError("injected token storage failure")
        super().put_many(namespace, entries)


class _AtomicTrackingStore(InMemoryKvStore):
    """Record whether a multi-record write uses one store operation."""

    def __init__(self) -> None:
        """Create an empty store with an atomic-write counter."""
        super().__init__()
        self.put_calls = 0
        self.put_many_calls = 0
        self.replace_many_calls = 0
        self.delete_calls = 0

    def put(self, namespace: str, entry_key: str, entry_value: str) -> None:
        """Count single-record writes before delegating to the store."""
        self.put_calls += 1
        super().put(namespace, entry_key, entry_value)

    def put_many(self, namespace: str, entries: dict[str, str]) -> None:
        """Count and perform one atomic multi-record write."""
        self.put_many_calls += 1
        super().put_many(namespace, entries)

    def replace_many(
        self,
        namespace: str,
        entries: dict[str, str],
        delete_keys: set[str],
    ) -> None:
        """Count atomic compensation operations before delegating."""
        self.replace_many_calls += 1
        super().replace_many(namespace, entries, delete_keys)

    def delete(self, namespace: str, entry_key: str) -> None:
        """Count single-record deletes before delegating to the store."""
        self.delete_calls += 1
        super().delete(namespace, entry_key)


class _FailingAuditSink(InMemoryAuditSink):
    """Inject an audit persistence failure."""

    def record(self, event) -> None:
        """Reject every event to exercise lifecycle compensation."""
        raise RuntimeError("audit unavailable")


class _Clock:
    """Deterministic clock for expiry tests."""

    def __init__(self, now: float = 1_700_000_000.0) -> None:
        """Start the clock at a fixed unix timestamp."""
        self.now = now

    def __call__(self) -> float:
        """Return the current test timestamp."""
        return self.now


@pytest.fixture
def store() -> InMemoryKvStore:
    """Return an empty token store."""
    return InMemoryKvStore()


@pytest.fixture
def audit() -> AuditLogger:
    """Return an in-memory audit logger."""
    return AuditLogger(InMemoryAuditSink())


@pytest.fixture
def clock() -> _Clock:
    """Return a controllable clock."""
    return _Clock()


@pytest.fixture
def token_service(store, audit, clock) -> ApplicationTokenService:
    """Return a token service with a frozen clock."""
    return ApplicationTokenService(store, audit, clock=clock)


@pytest.fixture
def client(token_service, auth_header):
    """Return an authenticated app with the token service wired."""
    app = create_app(wire=False)
    app.state.application_token_service = token_service
    app.state.operator_api_token = "test-operator-token"
    app.state.runtime_api_token = "test-runtime-token"
    with TestClient(
        app,
        headers={**auth_header, "X-Keyverse-Runtime-Token": "test-runtime-token"},
    ) as test_client:
        yield test_client


ISSUE_BODY = {
    "software_unit_id": "naruon-web",
    "purpose_code": "machine_api",
    "capability_codes": ["api.invoices.read", "api.invoices.write"],
    "lifetime_seconds": 3600,
    "actor_identity_id": "operator-ida",
    "tenant_deployment_id": "default-deployment",
}


def test_issue_verify_revoke_and_secret_omission(client, audit) -> None:
    """Plaintext is returned once; verify works; revoke and list stay secret-free."""
    issued = client.post("/application-tokens", json=ISSUE_BODY)
    assert issued.status_code == 200
    body = issued.json()
    plaintext = body["plaintext_token"]
    token_id = body["application_token_id"]
    assert plaintext.startswith("kvt_")
    assert body["token_substitute_for_password"] is False
    assert body["inherits_org_grants"] is False
    assert "Store the plaintext token" in body["application_next_action"]

    listed = client.get("/application-tokens")
    fetched = client.get(f"/application-tokens/{token_id}")
    assert "plaintext_token" not in listed.json()[0]
    assert "token_hash" not in listed.json()[0]
    assert listed.json()[0]["token_prefix"] == body["token_prefix"]
    assert fetched.json()["application_token_id"] == token_id
    assert plaintext not in listed.text
    assert "token_hash" not in fetched.text

    verified = client.post(
        "/application-tokens:verify",
        json={
            "presented_token": plaintext,
            "tenant_deployment_id": "default-deployment",
            "software_unit_id": "naruon-web",
            "requested_capability_codes": ["api.invoices.read"],
        },
    )
    assert verified.json()["active"] is True
    assert verified.json()["effect"] == "allow"
    assert plaintext not in verified.text

    revoked = client.post(
        f"/application-tokens/{token_id}:revoke",
        json={"actor_identity_id": "operator-ida"},
    )
    after = client.post(
        "/application-tokens:verify",
        json={
            "presented_token": plaintext,
            "tenant_deployment_id": "default-deployment",
            "software_unit_id": "naruon-web",
            "requested_capability_codes": ["api.invoices.read"],
        },
    )
    assert revoked.json()["lifecycle_status_code"] == "revoked"
    assert after.json()["active"] is False
    assert after.json()["denial_code"] == "revoked_token"
    events = audit.events_for(token_id)
    assert {event.event_type for event in events} >= {
        "application_token_issued",
        "application_token_revoked",
    }


def test_embedded_application_token_router_requires_operator_authentication(
    token_service: ApplicationTokenService,
) -> None:
    """A directly embedded management router cannot be mounted open."""
    app = FastAPI()
    app.state.application_token_service = token_service
    app.state.operator_api_token = "test-operator-token"
    app.include_router(application_token_router)
    with TestClient(app) as embedded_client:
        denied = embedded_client.get("/application-tokens")
        allowed = embedded_client.get(
            "/application-tokens",
            headers={"Authorization": "Bearer test-operator-token"},
        )
    assert denied.status_code == 401
    assert allowed.status_code == 200


def test_runtime_verify_does_not_require_operator_bearer(
    token_service: ApplicationTokenService,
) -> None:
    """Runtime verification accepts its own service credential only."""
    issued = token_service.issue(ApplicationTokenIssueRequest.model_validate(ISSUE_BODY))
    app = FastAPI()
    app.state.application_token_service = token_service
    app.state.runtime_api_token = "test-runtime-token"
    app.include_router(application_token_runtime_router)
    with TestClient(
        app,
        headers={"X-Keyverse-Runtime-Token": "test-runtime-token"},
    ) as runtime_client:
        response = runtime_client.post(
            "/application-tokens:verify",
            json={
                "presented_token": issued.plaintext_token,
                "tenant_deployment_id": "default-deployment",
                "software_unit_id": "naruon-web",
            },
        )
    assert response.status_code == 200
    assert response.json()["active"] is True


def test_verify_denies_malformed_unknown_expired_and_capability(
    client, clock: _Clock
) -> None:
    """Verification is fail-closed and never inherits org-tree grants."""
    issued = client.post("/application-tokens", json=ISSUE_BODY).json()
    plaintext = issued["plaintext_token"]
    prefix = issued["token_prefix"]
    malformed = client.post(
        "/application-tokens:verify",
        json={
            "presented_token": "not-a-token",
            "tenant_deployment_id": "default-deployment",
            "software_unit_id": "naruon-web",
        },
    )
    unknown = client.post(
        "/application-tokens:verify",
        json={
            "presented_token": f"kvt_{prefix}_wrong-secret-material-value",
            "tenant_deployment_id": "default-deployment",
            "software_unit_id": "naruon-web",
        },
    )
    wrong_unit = client.post(
        "/application-tokens:verify",
        json={
            "presented_token": plaintext,
            "tenant_deployment_id": "default-deployment",
            "software_unit_id": "clearfolio-web",
        },
    )
    capability = client.post(
        "/application-tokens:verify",
        json={
            "presented_token": plaintext,
            "tenant_deployment_id": "default-deployment",
            "software_unit_id": "naruon-web",
            "requested_capability_codes": ["api.payroll.admin"],
        },
    )
    wrong_tenant = client.post(
        "/application-tokens:verify",
        json={
            "presented_token": plaintext,
            "tenant_deployment_id": "other-deployment",
            "software_unit_id": "naruon-web",
        },
    )
    clock.now += 3601
    expired = client.post(
        "/application-tokens:verify",
        json={
            "presented_token": plaintext,
            "tenant_deployment_id": "default-deployment",
            "software_unit_id": "naruon-web",
        },
    )
    invalid_unit = client.post(
        "/application-tokens:verify",
        json={
            "presented_token": plaintext,
            "tenant_deployment_id": "default-deployment",
            "software_unit_id": "Not a slug",
        },
    )
    assert invalid_unit.status_code == 400
    assert malformed.json()["denial_code"] == "malformed_token"
    assert unknown.json()["denial_code"] == "unknown_token"
    assert wrong_unit.json()["denial_code"] == "software_unit_mismatch"
    assert capability.json()["denial_code"] == "capability_denied"
    assert wrong_tenant.json()["denial_code"] == "tenant_mismatch"
    assert expired.json()["denial_code"] == "expired_token"
    assert all(item.json()["inherits_org_grants"] is False for item in (
        malformed, unknown, wrong_unit, capability, expired
    ))


def test_rotate_replaces_token_and_rejects_software_unit_change(client) -> None:
    """Rotation revokes the old secret and issues a same-unit replacement."""
    issued = client.post("/application-tokens", json=ISSUE_BODY).json()
    tenant_mismatch = client.post(
        f"/application-tokens/{issued['application_token_id']}:rotate",
        json={**ISSUE_BODY, "tenant_deployment_id": "other-deployment"},
    )
    rotated = client.post(
        f"/application-tokens/{issued['application_token_id']}:rotate",
        json=ISSUE_BODY,
    )
    assert rotated.status_code == 200
    assert rotated.json()["plaintext_token"] != issued["plaintext_token"]
    old = client.post(
        "/application-tokens:verify",
        json={
            "presented_token": issued["plaintext_token"],
            "tenant_deployment_id": "default-deployment",
            "software_unit_id": "naruon-web",
        },
    )
    new = client.post(
        "/application-tokens:verify",
        json={
            "presented_token": rotated.json()["plaintext_token"],
            "tenant_deployment_id": "default-deployment",
            "software_unit_id": "naruon-web",
        },
    )
    assert old.json()["denial_code"] == "revoked_token"
    assert new.json()["active"] is True
    assert tenant_mismatch.status_code == 400
    mismatch = client.post(
        f"/application-tokens/{rotated.json()['application_token_id']}:rotate",
        json={**ISSUE_BODY, "software_unit_id": "clearfolio-web"},
    )
    assert mismatch.status_code == 400


@pytest.mark.parametrize("retirement", ["revoke", "rotate", "expire"])
def test_rotate_rejects_a_retired_or_expired_predecessor(
    token_service: ApplicationTokenService,
    clock: _Clock,
    retirement: str,
) -> None:
    """Rotation cannot revive a revoked, rotated, or expired credential."""
    request = ApplicationTokenIssueRequest.model_validate(ISSUE_BODY)
    issued = token_service.issue(request)

    if retirement == "revoke":
        token_service.revoke(issued.application_token_id, actor_identity_id="operator-ida")
    elif retirement == "rotate":
        token_service.rotate(issued.application_token_id, request)
    else:
        clock.now += request.lifetime_seconds

    with pytest.raises(AuthorizationPolicyError, match="not active") as error:
        token_service.rotate(issued.application_token_id, request)

    assert error.value.status_code == 409
    predecessor = token_service.get_token(issued.application_token_id)
    assert predecessor.lifecycle_status_code == {
        "revoke": "revoked",
        "rotate": "rotated",
        "expire": "active",
    }[retirement]


@pytest.mark.parametrize(
    "invalid_update",
    [
        {"purpose_code": "password"},
        {"capability_codes": []},
        {"lifetime_seconds": 30},
        {"lifetime_seconds": 91 * 24 * 60 * 60},
    ],
)
def test_invalid_rotation_preserves_the_active_token(
    client, invalid_update: dict[str, object]
) -> None:
    """Invalid replacement settings cannot destroy the active credential."""
    issued = client.post("/application-tokens", json=ISSUE_BODY).json()

    response = client.post(
        f"/application-tokens/{issued['application_token_id']}:rotate",
        json={**ISSUE_BODY, **invalid_update},
    )
    still_active = client.post(
        "/application-tokens:verify",
        json={
            "presented_token": issued["plaintext_token"],
            "tenant_deployment_id": "default-deployment",
            "software_unit_id": "naruon-web",
        },
    )

    assert response.status_code == 400
    assert still_active.json()["active"] is True


def test_issue_audit_failure_does_not_leave_an_active_token() -> None:
    """An audit failure compensates the newly persisted issue record."""
    store = InMemoryKvStore()
    service = ApplicationTokenService(
        store,
        AuditLogger(_FailingAuditSink()),
        clock=_Clock(),
    )
    with pytest.raises(RuntimeError, match="audit unavailable"):
        service.issue(ApplicationTokenIssueRequest.model_validate(ISSUE_BODY))
    assert store.get_all(APPLICATION_TOKEN_NAMESPACE) == {}


def test_issue_storage_failure_does_not_persist_a_token() -> None:
    """A failed initial storage write leaves no token record behind."""
    store = _FailingStore(fail_on_put=1)
    service = ApplicationTokenService(
        store,
        AuditLogger(InMemoryAuditSink()),
        clock=_Clock(),
    )
    with pytest.raises(RuntimeError, match="storage"):
        service.issue(ApplicationTokenIssueRequest.model_validate(ISSUE_BODY))
    assert store.get_all(APPLICATION_TOKEN_NAMESPACE) == {}


def test_revoke_audit_failure_restores_the_active_token() -> None:
    """A revoke audit failure compensates the lifecycle update."""
    store = InMemoryKvStore()
    service = ApplicationTokenService(
        store,
        AuditLogger(InMemoryAuditSink()),
        clock=_Clock(),
    )
    issued = service.issue(ApplicationTokenIssueRequest.model_validate(ISSUE_BODY))
    service._audit = AuditLogger(_FailingAuditSink())
    with pytest.raises(RuntimeError, match="audit unavailable"):
        service.revoke(issued.application_token_id, actor_identity_id="operator-ida")
    verified = service.verify(
        ApplicationTokenVerifyRequest(
            presented_token=issued.plaintext_token,
            tenant_deployment_id="default-deployment",
            software_unit_id="naruon-web",
        )
    )
    assert verified.active is True


def test_rotate_storage_failure_preserves_the_active_predecessor() -> None:
    """A replacement write failure cannot rotate away the predecessor."""
    store = _FailingStore(fail_on_put=2)
    service = ApplicationTokenService(
        store,
        AuditLogger(InMemoryAuditSink()),
        clock=_Clock(),
    )
    issued = service.issue(ApplicationTokenIssueRequest.model_validate(ISSUE_BODY))
    with pytest.raises(RuntimeError, match="storage"):
        service.rotate(
            issued.application_token_id,
            ApplicationTokenIssueRequest.model_validate(ISSUE_BODY),
        )
    verified = service.verify(
        ApplicationTokenVerifyRequest(
            presented_token=issued.plaintext_token,
            tenant_deployment_id="default-deployment",
            software_unit_id="naruon-web",
        )
    )
    assert verified.active is True


def test_rotate_uses_one_atomic_store_write_for_both_records() -> None:
    """Rotation persists the replacement and predecessor in one store operation."""
    store = _AtomicTrackingStore()
    service = ApplicationTokenService(
        store,
        AuditLogger(InMemoryAuditSink()),
        clock=_Clock(),
    )
    issued = service.issue(ApplicationTokenIssueRequest.model_validate(ISSUE_BODY))

    service.rotate(
        issued.application_token_id,
        ApplicationTokenIssueRequest.model_validate(ISSUE_BODY),
    )

    assert store.put_many_calls == 1


def test_rotate_audit_failure_restores_the_active_predecessor() -> None:
    """An audit failure rolls back both replacement and predecessor state."""
    store = InMemoryKvStore()
    service = ApplicationTokenService(
        store,
        AuditLogger(InMemoryAuditSink()),
        clock=_Clock(),
    )
    issued = service.issue(ApplicationTokenIssueRequest.model_validate(ISSUE_BODY))
    service._audit = AuditLogger(_FailingAuditSink())
    with pytest.raises(RuntimeError, match="audit unavailable"):
        service.rotate(
            issued.application_token_id,
            ApplicationTokenIssueRequest.model_validate(ISSUE_BODY),
        )
    verified = service.verify(
        ApplicationTokenVerifyRequest(
            presented_token=issued.plaintext_token,
            tenant_deployment_id="default-deployment",
            software_unit_id="naruon-web",
        )
    )
    assert verified.active is True
    assert len(store.get_all(APPLICATION_TOKEN_NAMESPACE)) == 1


def test_rotate_audit_failure_uses_one_atomic_compensation() -> None:
    """Audit failure restores and removes rotation records in one operation."""
    store = _AtomicTrackingStore()
    service = ApplicationTokenService(
        store,
        AuditLogger(InMemoryAuditSink()),
        clock=_Clock(),
    )
    issued = service.issue(ApplicationTokenIssueRequest.model_validate(ISSUE_BODY))
    initial_put_calls = store.put_calls
    initial_delete_calls = store.delete_calls
    service._audit = AuditLogger(_FailingAuditSink())

    with pytest.raises(RuntimeError, match="audit unavailable"):
        service.rotate(
            issued.application_token_id,
            ApplicationTokenIssueRequest.model_validate(ISSUE_BODY),
        )

    assert store.replace_many_calls == 1
    assert store.put_calls == initial_put_calls
    assert store.delete_calls == initial_delete_calls


def test_issue_rejects_password_purposes_and_bounds(client) -> None:
    """PATs cannot be password substitutes and stay purpose-bounded."""
    password = client.post(
        "/application-tokens",
        json={**ISSUE_BODY, "purpose_code": "password"},
    )
    unknown_purpose = client.post(
        "/application-tokens",
        json={**ISSUE_BODY, "purpose_code": "custom"},
    )
    empty_caps = client.post(
        "/application-tokens",
        json={**ISSUE_BODY, "capability_codes": []},
    )
    short_life = client.post(
        "/application-tokens",
        json={**ISSUE_BODY, "lifetime_seconds": 30},
    )
    long_life = client.post(
        "/application-tokens",
        json={**ISSUE_BODY, "lifetime_seconds": 91 * 24 * 60 * 60},
    )
    assert password.status_code == 400
    assert "password" in password.json()["detail"]
    assert unknown_purpose.status_code == 400
    assert empty_caps.status_code == 400
    assert short_life.status_code == 400
    assert long_life.status_code == 400


def test_missing_and_inactive_token_paths(client, store: InMemoryKvStore) -> None:
    """Unknown, malformed, and already-revoked token ids fail closed."""
    missing = client.get("/application-tokens/tok-0123456789abcdef")
    malformed = client.get("/application-tokens/not-a-token-id")
    issued = client.post("/application-tokens", json=ISSUE_BODY).json()
    client.post(
        f"/application-tokens/{issued['application_token_id']}:revoke",
        json={"actor_identity_id": "operator-ida"},
    )
    again = client.post(
        f"/application-tokens/{issued['application_token_id']}:revoke",
        json={"actor_identity_id": "operator-ida"},
    )
    store.put(APPLICATION_TOKEN_NAMESPACE, "broken", "{")
    corrupt_list = client.get("/application-tokens")
    assert missing.status_code == 404
    assert malformed.status_code == 400
    assert again.status_code == 409
    assert corrupt_list.status_code == 500


def test_corrupt_single_record_and_control_characters(
    token_service: ApplicationTokenService, store: InMemoryKvStore
) -> None:
    """Single-record corruption and control characters do not verify."""
    issued = token_service.issue(ApplicationTokenIssueRequest.model_validate(ISSUE_BODY))
    store.put(APPLICATION_TOKEN_NAMESPACE, issued.application_token_id, "{")
    with pytest.raises(Exception, match="corrupt"):
        token_service.get_token(issued.application_token_id)
    denied = token_service.verify(
        ApplicationTokenVerifyRequest(
            presented_token="kvt_deadbeefcafe_\x00secret",
            tenant_deployment_id="default-deployment",
            software_unit_id="naruon-web",
        )
    )
    assert denied.denial_code == "malformed_token"


def test_stored_hash_length_mismatch_is_unknown(
    token_service: ApplicationTokenService, store: InMemoryKvStore
) -> None:
    """A stored hash of the wrong length cannot verify as a match."""
    issued = token_service.issue(ApplicationTokenIssueRequest.model_validate(ISSUE_BODY))
    record = ApplicationTokenRecord.model_validate_json(
        store.get(APPLICATION_TOKEN_NAMESPACE, issued.application_token_id)
    )
    store.put(
        APPLICATION_TOKEN_NAMESPACE,
        issued.application_token_id,
        record.model_copy(update={"token_hash": "short"}).model_dump_json(),
    )
    denied = token_service.verify(
        ApplicationTokenVerifyRequest(
            presented_token=issued.plaintext_token,
            tenant_deployment_id="default-deployment",
            software_unit_id="naruon-web",
        )
    )
    assert denied.denial_code == "unknown_token"


def test_missing_token_service_is_unavailable() -> None:
    """Unwired token routes fail closed with HTTP 503."""
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace()))
    with pytest.raises(HTTPException) as captured:
        get_application_token_service(request)
    assert captured.value.status_code == 503

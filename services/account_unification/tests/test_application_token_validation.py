"""Secret-safe validation at the factory and directly embedded token router."""

from __future__ import annotations

import pytest
from fastapi import APIRouter, FastAPI
from fastapi.exceptions import RequestValidationError, ResponseValidationError
from fastapi.testclient import TestClient
from pydantic import BaseModel

from app.application_tokens import (
    ApplicationTokenIssueRequest,
    ApplicationTokenService,
    application_token_runtime_router,
)
from app.audit import AuditLogger, InMemoryAuditSink
from app.kv_store import SqliteKvStore
from app.main import create_app


@pytest.fixture(params=["factory", "embedded"])
def verification_client(request):
    """Use actual SQLite and both public ASGI construction paths."""
    store = SqliteKvStore(":memory:")
    service = ApplicationTokenService(store, AuditLogger(InMemoryAuditSink()))
    issued = service.issue(
        ApplicationTokenIssueRequest(
            tenant_deployment_id="fixture-deployment",
            software_unit_id="fixture-rp",
            purpose_code="machine_api",
            capability_codes=["api.read"],
            lifetime_seconds=3600,
            actor_identity_id="fixture-operator",
        )
    )
    app = create_app(wire=False) if request.param == "factory" else FastAPI()
    if request.param == "embedded":
        app.include_router(application_token_runtime_router)
    app.state.application_token_service = service
    app.state.runtime_api_token = "fixture-runtime"
    body = dict(
        presented_token=issued.plaintext_token,
        tenant_deployment_id="fixture-deployment",
        software_unit_id="fixture-rp",
    )
    try:
        with TestClient(app, headers={"X-Keyverse-Runtime-Token": "fixture-runtime"}) as client:
            yield client, body
    finally:
        store.close()


def _require(condition: bool, message: str) -> None:
    """Fail generically without placing request or response data in pytest output."""
    if not condition:
        pytest.fail(message, pytrace=False)


def test_validation_rejects_token_list_without_echo(verification_client) -> None:
    """A real issued token verifies, but wrapping it in a list must not echo it."""
    client, body = verification_client
    valid = client.post("/application-tokens:verify", json=body)
    _require(valid.status_code == 200 and valid.json()["active"] is True, "valid token denied")
    _require(body["presented_token"] not in valid.text, "valid response disclosed input")
    invalid = client.post(
        "/application-tokens:verify", json={**body, "presented_token": [body["presented_token"]]}
    )
    _require(invalid.status_code == 422, "invalid token container admitted")
    _require(body["presented_token"] not in invalid.text, "validation response disclosed input")


@pytest.mark.parametrize(
    "case",
    [
        "token-object",
        "token-null",
        "token-short",
        "token-long",
        "unknown-field",
        "unknown-key",
        "tenant-object",
        "software-list",
        "capability-object",
        "capability-item-object",
        "missing-token",
        "body-list",
        "body-string",
        "json-syntax",
        "invalid-utf8",
    ],
)
def test_validation_envelope_is_closed(verification_client, caplog, case) -> None:
    """Every invalid shape omits all submitted values, keys, and schema diagnostics."""
    client, body = verification_client
    secret = body["presented_token"]
    marker = "synthetic-private-field-marker"
    payload = dict(body)
    cases = {
        "token-object": {"presented_token": {marker: secret}},
        "token-null": {"presented_token": None},
        "token-short": {"presented_token": "shrt"},
        "token-long": {"presented_token": secret * 8},
        "unknown-field": {"unrecognized": {marker: secret}},
        "unknown-key": {secret: marker},
        "tenant-object": {"tenant_deployment_id": {marker: secret}},
        "software-list": {"software_unit_id": [secret]},
        "capability-object": {"requested_capability_codes": {marker: secret}},
        "capability-item-object": {"requested_capability_codes": [{marker: secret}]},
    }
    payload.update(cases.get(case, {}))
    caplog.clear()
    if case == "missing-token":
        payload.pop("presented_token")
    elif case == "body-list":
        payload = [secret]
    elif case == "body-string":
        payload = secret
    if case == "json-syntax":
        response = client.post(
            "/application-tokens:verify",
            content='{"' + marker + '":"' + secret + '",}',
            headers={"Content-Type": "application/json"},
        )
    elif case == "invalid-utf8":
        response = client.post(
            "/application-tokens:verify",
            content=b"\xff",
            headers={"Content-Type": "application/json"},
        )
    else:
        response = client.post("/application-tokens:verify", json=payload)
    # Unreadable UTF-8 is a pre-existing HTTP400 transport failure, not schema validation.
    expected = 400 if case == "invalid-utf8" else 422
    _require(response.status_code == expected, "unexpected invalid-request status")
    if expected == 422:
        _require(
            response.json() == {"detail": "Invalid application token verification request"},
            "validation envelope is not closed",
        )
    _require(
        all(value not in response.text for value in (secret, marker, "shrt")),
        "validation response disclosed submitted data",
    )
    _require(
        all(value not in caplog.text for value in (secret, marker)),
        "validation logs disclosed submitted data",
    )


@pytest.mark.parametrize(
    "auth_case,expected", [("missing", 401), ("wrong", 403), ("unconfigured", 503)]
)
def test_validation_preserves_runtime_authentication(
    verification_client, auth_case, expected
) -> None:
    """Malformed schema does not replace runtime authentication failure statuses."""
    client, body = verification_client
    client.headers.pop("X-Keyverse-Runtime-Token")
    if auth_case == "wrong":
        client.headers["X-Keyverse-Runtime-Token"] = "synthetic-wrong-runtime"
    elif auth_case == "unconfigured":
        client.app.state.runtime_api_token = None
    response = client.post(
        "/application-tokens:verify", json={**body, "presented_token": [body["presented_token"]]}
    )
    _require(response.status_code == expected, "authentication behavior changed")
    _require(
        body["presented_token"] not in response.text, "authentication response disclosed input"
    )


def test_validation_preserves_semantic_and_service_errors(verification_client) -> None:
    """Semantic 400, inactive 200, unwired 503, and non-request errors stay distinct."""
    client, body = verification_client
    malformed = client.post(
        "/application-tokens:verify", json={**body, "presented_token": "not-a-token"}
    )
    _require(
        malformed.status_code == 200 and malformed.json()["denial_code"] == "malformed_token",
        "malformed-token decision changed",
    )
    semantic = client.post(
        "/application-tokens:verify", json={**body, "software_unit_id": "Not a slug"}
    )
    _require(semantic.status_code == 400, "semantic policy error changed")
    client.app.state.application_token_service = None
    unavailable = client.post("/application-tokens:verify", json=body)
    _require(unavailable.status_code == 503, "unwired service error changed")


class _UnrelatedRequest(BaseModel):
    """Supply one ordinary schema for a non-PAT sibling route."""

    count: int


def test_validation_boundary_survives_nested_embedding() -> None:
    """Prefix nesting preserves the route-owned guard, not a factory-only handler."""
    outer = APIRouter(prefix="/module")
    outer.include_router(application_token_runtime_router)
    app = FastAPI()
    app.include_router(outer)
    app.state.runtime_api_token = "fixture-runtime"
    app.state.application_token_service = object()
    with TestClient(app, headers={"X-Keyverse-Runtime-Token": "fixture-runtime"}) as client:
        response = client.post(
            "/module/application-tokens:verify", json={"presented_token": ["synthetic-input"]}
        )
    _require(response.status_code == 422, "nested guard absent")
    _require(
        response.json() == {"detail": "Invalid application token verification request"},
        "nested envelope changed",
    )


def test_validation_boundary_does_not_replace_host_handler(verification_client) -> None:
    """Host validation behavior remains available to unrelated routes only."""
    client, body = verification_client
    calls = []

    @client.app.exception_handler(RequestValidationError)
    async def host_validation_handler(request, error):
        """Record handler invocation without observing untrusted validation details."""
        from starlette.responses import JSONResponse

        calls.append(True)
        return JSONResponse(status_code=422, content={"detail": "host validation"})

    @client.app.post("/unrelated-schema")
    def unrelated_schema(body: _UnrelatedRequest):
        """Keep a non-secret endpoint outside the token router guard."""
        return {"count": body.count}

    # The fixture's lifespan has already built Starlette's middleware stack.
    # Rebuild only this fixture-owned app so the newly registered host handler is real.
    client.app.middleware_stack = None
    guarded = client.post(
        "/application-tokens:verify", json={**body, "presented_token": [body["presented_token"]]}
    )
    _require(
        guarded.json() == {"detail": "Invalid application token verification request"},
        "host handler intercepted token validation",
    )
    sibling = client.post("/unrelated-schema", json={"count": "invalid"})
    _require(
        sibling.json() == {"detail": "host validation"} and calls == [True],
        "sibling handler behavior changed",
    )


@pytest.mark.parametrize("failure", ["runtime", "response"])
def test_validation_boundary_does_not_swallow_service_failures(
    verification_client, failure
) -> None:
    """Response-schema and unexpected service exceptions are not request 422s."""
    client, body = verification_client

    class BrokenService:
        """Use a fixture-owned service fault without request or error data logging."""

        def verify(self, request):
            """Either fail unexpectedly or produce an invalid response schema."""
            if failure == "runtime":
                raise RuntimeError("synthetic service unavailable")
            return {"active": []}

    client.app.state.application_token_service = BrokenService()
    with pytest.raises(RuntimeError if failure == "runtime" else ResponseValidationError):
        client.post("/application-tokens:verify", json=body)

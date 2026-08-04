"""Coverage regressions for core API, storage, config, and lifecycle branches."""
from __future__ import annotations

import asyncio
import runpy
import sqlite3
import urllib.request
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from app import api as api_routes
from app import healthcheck, main
from app.audit import AuditEvent, AuditLogger
from app.bootstrap import (
    BOOTSTRAP_ENV_VAR,
    BootstrapDescriptor,
    UnsupportedConfigBackendError,
    load_bootstrap_descriptor,
    open_config_store,
)
from app.config import (
    KEY_REGISTRATION_CLIENT_ID,
    _as_bool,
    _registration_settings,
)
from app.errors import (
    InactiveAccountError,
    NoMatchError,
    SameUserError,
    UnverifiedEmailMergeError,
    UserNotFoundError,
)
from app.identifiers import InvalidIdentifierError, validate_path_segment
from app.kv_store import InMemoryKvStore, SqliteKvStore
from app.models import MergeRequest
from app.user_locks import (
    SqliteUserOperationLocks,
    UserOperationLockTimeout,
    _normalise_user_ids,
)


class _RaisingLookupService:
    """Raise a configured lookup error from both account read methods."""

    def get_account(self, user_id: str):
        """Raise the configured missing-user error."""
        raise UserNotFoundError(user_id)

    def list_identities(self, user_id: str):
        """Raise the configured missing-user error."""
        raise UserNotFoundError(user_id)


class _RaisingMergeService:
    """Raise one configured merge-policy exception."""

    def __init__(self, error: Exception) -> None:
        """Store the exception raised by ``merge_accounts``."""
        self.error = error

    def merge_accounts(self, body: MergeRequest):
        """Raise the configured exception without mutating state."""
        raise self.error


class _EmptyAudit:
    """Return no events for every requested audit identifier."""

    def events_for(self, audit_id: str) -> list[AuditEvent]:
        """Return an empty audit trail."""
        return []


class _CloseTrackingSink:
    """Minimal sink proving that ``AuditLogger.close`` delegates."""

    def __init__(self) -> None:
        """Create an open sink."""
        self.closed = False

    def record(self, event: AuditEvent) -> None:
        """Accept an event without persistence."""

    def events_for(self, audit_id: str) -> list[AuditEvent]:
        """Return no events."""
        return []

    def close(self) -> None:
        """Record resource closure."""
        self.closed = True


class _StaticResponse:
    """Context-managed stdlib response for module-entrypoint coverage."""

    def __enter__(self):
        """Return this response to the healthcheck context manager."""
        return self

    def __exit__(self, exc_type, exc, traceback) -> bool:
        """Propagate any exception from the context body."""
        return False

    def read(self) -> bytes:
        """Return a healthy JSON document."""
        return b'{"status":"ok"}'


class _StaticOpener:
    """Return one deterministic response from ``open``."""

    def __init__(self) -> None:
        """Create an opener with no prior call."""
        self.call: tuple[str, int] | None = None

    def open(self, url: str, timeout: int):
        """Record the URL and return a healthy response."""
        self.call = (url, timeout)
        return _StaticResponse()


class _Closeable:
    """Track whether application lifecycle cleanup called ``close``."""

    def __init__(self) -> None:
        """Create an open resource."""
        self.closed = False

    def close(self) -> None:
        """Record closure."""
        self.closed = True


class _NonLockedConnection:
    """Raise a non-contention SQLite error from ``BEGIN IMMEDIATE``."""

    in_transaction = False

    def execute(self, statement: str, parameters=()):
        """Raise an operational error that must not be translated."""
        raise sqlite3.OperationalError("disk I/O error")

    def close(self) -> None:
        """Release no-op fake resources."""


def test_read_routes_translate_missing_users() -> None:
    """Both account read routes translate a missing user to HTTP 404."""
    service = _RaisingLookupService()

    with pytest.raises(HTTPException) as account_error:
        api_routes.get_user("missing", service=service)
    with pytest.raises(HTTPException) as identity_error:
        api_routes.list_identities("missing", service=service)

    assert account_error.value.status_code == 404
    assert identity_error.value.status_code == 404


@pytest.mark.parametrize(
    ("error", "status_code"),
    [
        (UserNotFoundError("missing"), 404),
        (SameUserError("same"), 400),
        (UnverifiedEmailMergeError("unverified"), 422),
        (NoMatchError("no match"), 409),
        (InactiveAccountError("inactive"), 409),
        (UserOperationLockTimeout("busy"), 503),
    ],
)
def test_merge_route_translates_every_domain_error(
    error: Exception, status_code: int
) -> None:
    """The merge route preserves its documented HTTP error mapping."""
    body = MergeRequest(
        survivor_user_id="survivor",
        duplicate_user_id="duplicate",
        actor="coverage-test",
    )

    with pytest.raises(HTTPException) as translated:
        api_routes.merge_accounts(
            body,
            service=_RaisingMergeService(error),
        )

    assert translated.value.status_code == status_code


def test_empty_merge_audit_is_not_found() -> None:
    """An unknown audit correlation identifier returns HTTP 404."""
    with pytest.raises(HTTPException) as error:
        api_routes.get_merge_audit("unknown", audit=_EmptyAudit())

    assert error.value.status_code == 404


def test_audit_logger_closes_its_sink() -> None:
    """Logger lifecycle cleanup delegates to the configured sink."""
    sink = _CloseTrackingSink()

    AuditLogger(sink).close()

    assert sink.closed is True


def test_bootstrap_requires_a_pointer(monkeypatch) -> None:
    """Startup fails closed when no bootstrap path is configured."""
    monkeypatch.delenv(BOOTSTRAP_ENV_VAR, raising=False)

    with pytest.raises(RuntimeError, match=BOOTSTRAP_ENV_VAR):
        load_bootstrap_descriptor()


def test_sqlite_bootstrap_requires_database_path() -> None:
    """The SQLite backend refuses an omitted database path."""
    descriptor = BootstrapDescriptor(
        backend="sqlite",
        namespace="account_unification",
    )

    with pytest.raises(RuntimeError, match="sqlite backend requires"):
        open_config_store(descriptor)


def test_unknown_bootstrap_backend_is_explicitly_unsupported() -> None:
    """Standalone images reject a backend with no packaged adapter."""
    descriptor = BootstrapDescriptor(
        backend="postgres",
        namespace="account_unification",
        postgres_dsn_secret_ref="secret/postgres",
    )

    with pytest.raises(UnsupportedConfigBackendError, match="postgres"):
        open_config_store(descriptor)


def test_config_boolean_rejects_ambiguous_text() -> None:
    """Boolean configuration never guesses at ambiguous input."""
    with pytest.raises(RuntimeError, match="must be a boolean"):
        _as_bool("perhaps", False, entry_key="feature_toggle")


def test_registration_settings_reject_ambiguous_client_id() -> None:
    """Registration client identifiers cannot contain whitespace."""
    store = InMemoryKvStore(
        {
            "runtime": {
                KEY_REGISTRATION_CLIENT_ID: "client with spaces",
            }
        }
    )

    with pytest.raises(RuntimeError, match="bounded client ID"):
        _registration_settings(store, "runtime", "registration-token")


def test_health_opener_helper_uses_bounded_timeout(monkeypatch) -> None:
    """The helper delegates through the restricted opener with five seconds."""
    opener = _StaticOpener()
    monkeypatch.setattr(healthcheck, "_build_http_only_opener", lambda: opener)

    response = healthcheck._open_health_url("https://health.example/ready")

    assert isinstance(response, _StaticResponse)
    assert opener.call == ("https://health.example/ready", 5)


def test_healthcheck_module_entrypoint_exits_zero(monkeypatch) -> None:
    """The executable module exits successfully for a healthy endpoint."""
    monkeypatch.setattr(
        urllib.request.OpenerDirector,
        "open",
        lambda self, url, timeout: _StaticResponse(),
    )

    with pytest.raises(SystemExit) as exit_error:
        runpy.run_path(str(Path(healthcheck.__file__)), run_name="__main__")

    assert exit_error.value.code == 0


def test_identifier_rejects_oversized_segments() -> None:
    """Opaque Admin API path segments retain the 255-character ceiling."""
    with pytest.raises(InvalidIdentifierError, match="too long"):
        validate_path_segment("a" * 256, field_name="user_id")


def test_sqlite_store_close_releases_connection(tmp_path) -> None:
    """Closing the durable KV store makes its SQLite connection unusable."""
    store = SqliteKvStore(str(tmp_path / "config.sqlite3"))

    store.close()

    with pytest.raises(sqlite3.ProgrammingError):
        store.get("runtime", "missing")


def test_main_helpers_cover_memory_and_persistent_paths(tmp_path) -> None:
    """Filesystem helpers cover in-memory and persistent database modes."""
    main._ensure_parent_directory(":memory:")
    target = tmp_path / "nested" / "audit.sqlite3"
    main._ensure_parent_directory(str(target))
    assert target.parent.is_dir()

    persistent, persistent_is_temporary = main._user_operation_lock_path(
        str(target)
    )
    temporary, temporary_is_temporary = main._user_operation_lock_path(
        ":memory:"
    )
    try:
        assert persistent == f"{target}.user-operation-locks.sqlite3"
        assert persistent_is_temporary is False
        assert Path(temporary).is_file()
        assert temporary_is_temporary is True
    finally:
        Path(temporary).unlink(missing_ok=True)


def test_build_service_wires_all_state(monkeypatch) -> None:
    """Live dependency wiring publishes every service and product setting."""
    app = FastAPI()
    store = _Closeable()
    api = _Closeable()
    audit = _Closeable()
    locks = object()
    unification = object()
    federation = object()
    descriptor = SimpleNamespace(namespace="runtime")
    config = SimpleNamespace(
        keycloak_server_url="https://keycloak.example",
        keycloak_realm="cwl",
        keycloak_client_id="service-client",
        keycloak_client_secret="secret",
        request_timeout_seconds=3.0,
        audit_database_path=":memory:",
        operator_api_token="operator",
        registration_api_token="registration",
        registration_client_id="naruon-web",
        registration_redirect_uri="https://naruon.example/auth/callback",
        registration_action_lifespan_seconds=900,
    )
    lock_path = str(Path.cwd() / "coverage-lock.sqlite3")

    monkeypatch.setattr(main, "load_bootstrap_descriptor", lambda: descriptor)
    monkeypatch.setattr(main, "open_config_store", lambda current: store)
    monkeypatch.setattr(
        main,
        "load_service_config",
        lambda current_store, namespace: config,
    )
    monkeypatch.setattr(main, "_ensure_parent_directory", lambda path: None)
    monkeypatch.setattr(main, "ProductHttpAdminApi", lambda **kwargs: api)
    monkeypatch.setattr(main, "SqliteAuditSink", lambda path: object())
    monkeypatch.setattr(main, "AuditLogger", lambda sink: audit)
    monkeypatch.setattr(
        main,
        "_user_operation_lock_path",
        lambda path: (lock_path, True),
    )
    monkeypatch.setattr(main, "SqliteUserOperationLocks", lambda path: locks)
    monkeypatch.setattr(
        main,
        "UnificationService",
        lambda *args: unification,
    )
    monkeypatch.setattr(
        main,
        "FederationService",
        lambda *args: federation,
    )

    main.build_service(app)

    assert app.state.config_store is store
    assert app.state.unification_service is unification
    assert app.state.audit_logger is audit
    assert app.state.keycloak_api is api
    assert app.state.user_operation_locks is locks
    assert app.state.federation_service is federation
    assert app.state.operator_api_token == "operator"
    assert app.state.registration_api_token == "registration"
    assert app.state.ready is True
    assert app.state.temporary_user_operation_lock_database is True


def test_close_and_temporary_database_helpers(tmp_path) -> None:
    """Cleanup helpers handle callable, absent, persistent, and temporary state."""
    closeable = _Closeable()
    main._close_resource(closeable)
    main._close_resource(object())
    assert closeable.closed is True

    app = FastAPI()
    app.state.temporary_user_operation_lock_database = False
    main._remove_temporary_lock_database(app)

    lock_path = tmp_path / "temporary-lock.sqlite3"
    lock_path.write_text("lock", encoding="utf-8")
    app.state.temporary_user_operation_lock_database = True
    app.state.user_operation_lock_database_path = str(lock_path)
    main._remove_temporary_lock_database(app)
    assert lock_path.exists() is False


def test_lifespan_cleans_resources_after_context_error(monkeypatch, tmp_path) -> None:
    """Lifecycle cleanup runs even when request-serving context exits by error."""
    app = FastAPI()
    api = _Closeable()
    audit = _Closeable()
    store = _Closeable()
    lock_path = tmp_path / "temporary-lock.sqlite3"
    lock_path.write_text("lock", encoding="utf-8")

    def wire(current_app: FastAPI) -> None:
        """Publish deterministic resources for the lifecycle test."""
        current_app.state.keycloak_api = api
        current_app.state.audit_logger = audit
        current_app.state.config_store = store
        current_app.state.user_operation_lock_database_path = str(lock_path)
        current_app.state.temporary_user_operation_lock_database = True
        current_app.state.ready = True

    monkeypatch.setattr(main, "build_service", wire)

    async def exercise() -> None:
        """Enter the lifespan and fail inside its yielded context."""
        with pytest.raises(RuntimeError, match="request failure"):
            async with main.lifespan(app):
                assert app.state.ready is True
                raise RuntimeError("request failure")

    asyncio.run(exercise())

    assert app.state.ready is False
    assert api.closed is True
    assert audit.closed is True
    assert store.closed is True
    assert lock_path.exists() is False


def test_healthz_reports_starting_state() -> None:
    """The readiness endpoint exposes a starting state before live wiring."""
    app = main.create_app(wire=False)
    app.state.ready = False

    with TestClient(app) as client:
        response = client.get("/healthz")

    assert response.status_code == 200
    assert response.json()["status"] == "starting"


@pytest.mark.parametrize(
    ("database_path", "timeout_seconds", "message"),
    [
        ("", 1.0, "database_path is required"),
        (":memory:", 0.0, "timeout_seconds must be positive"),
    ],
)
def test_sqlite_user_locks_validate_constructor(
    database_path: str,
    timeout_seconds: float,
    message: str,
) -> None:
    """The cross-process lock manager refuses unusable constructor values."""
    with pytest.raises(ValueError, match=message):
        SqliteUserOperationLocks(
            database_path,
            timeout_seconds=timeout_seconds,
        )


def test_user_id_normalisation_rejects_empty_members() -> None:
    """User-operation locking requires only non-empty identifiers."""
    with pytest.raises(ValueError, match="non-empty"):
        _normalise_user_ids(("valid", ""))


def test_sqlite_user_locks_preserve_non_contention_operational_errors(
    monkeypatch,
) -> None:
    """Only SQLite lock contention is translated to the retryable timeout."""
    manager = object.__new__(SqliteUserOperationLocks)
    connection = _NonLockedConnection()
    monkeypatch.setattr(manager, "_connect", lambda: connection)

    with pytest.raises(sqlite3.OperationalError, match="disk I/O"):
        with manager.hold("user-1"):
            pytest.fail("the lock body must not run")

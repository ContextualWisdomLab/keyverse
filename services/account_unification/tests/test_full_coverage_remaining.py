"""Final production statement and branch coverage regressions."""
from __future__ import annotations

from fastapi import FastAPI

from app import main, scim
from app.config import _as_bool
from app.kv_store import SqliteKvStore
from app.models import UserAccount
from app.user_locks import InMemoryUserOperationLocks


class _ActiveProvisioner:
    """Provide one active user without deactivating it on truthy PATCH input."""

    def __init__(self) -> None:
        """Create one active user and an empty deactivation log."""
        self.user = UserAccount(
            user_id="user-1",
            user_name="active-user",
            state="active",
        )
        self.deactivated = False

    def get_user(self, user_id: str) -> UserAccount:
        """Return the one active user."""
        return self.user

    def deactivate_user(self, user_id: str) -> None:
        """Record an unexpected deactivation."""
        self.deactivated = True


def test_config_boolean_parses_explicit_false_text() -> None:
    """Explicit false spellings take the false branch, not the default."""
    assert _as_bool("false", True, entry_key="feature_toggle") is False


def test_sqlite_store_delete_is_idempotent(tmp_path) -> None:
    """Durable KV deletion handles present and already-absent entries."""
    store = SqliteKvStore(str(tmp_path / "config.sqlite3"))
    try:
        store.put("runtime", "entry_key", "entry_value")
        store.delete("runtime", "entry_key")
        store.delete("runtime", "entry_key")
        assert store.get("runtime", "entry_key") is None
    finally:
        store.close()


def test_temporary_lock_cleanup_handles_missing_path() -> None:
    """Temporary-lock cleanup tolerates state without a published path."""
    app = FastAPI()
    app.state.temporary_user_operation_lock_database = True

    main._remove_temporary_lock_database(app)


def test_scim_patch_keeps_user_active_for_truthy_value() -> None:
    """A truthy active PATCH value covers the non-deprovision branch."""
    provisioner = _ActiveProvisioner()

    response = scim.patch_user(
        "user-1",
        {
            "Operations": [
                {"op": "replace", "path": "active", "value": True}
            ]
        },
        provisioner=provisioner,
        user_operation_locks=InMemoryUserOperationLocks(),
    )

    assert response.status_code == 200
    assert provisioner.deactivated is False

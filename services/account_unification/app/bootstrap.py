"""Bootstrap: the single, clearly-marked place an environment variable is read.

``CWL_IDP_BOOTSTRAP`` is *bootstrap transport only* — it names a small YAML file
that locates the existing configuration store. The vault root credential is
separate: a supervisor supplies a private file, and only its non-secret locator
may be stored in configuration. This legacy bootstrap transport does not make
the ordinary config DB a Key Vault, nor does it implement KMS/HSM custody.
"""
from __future__ import annotations

import os
import stat
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path

import yaml

from .kv_store import KvStore, SqliteKvStore

BOOTSTRAP_ENV_VAR = "CWL_IDP_BOOTSTRAP"


@dataclass(frozen=True)
class BootstrapDescriptor:
    """Where the config store lives and under which namespace to read it."""

    backend: str
    namespace: str
    sqlite_path: str | None = None
    postgres_dsn_secret_ref: str | None = None


class UnsupportedConfigBackendError(RuntimeError):
    """Raised when the selected standalone image lacks a config-store adapter."""


def load_bootstrap_descriptor(bootstrap_path: str | None = None) -> BootstrapDescriptor:
    """Read the bootstrap YAML named by ``CWL_IDP_BOOTSTRAP`` (or an override)."""
    resolved = bootstrap_path or os.environ.get(BOOTSTRAP_ENV_VAR)
    if not resolved:
        raise RuntimeError(
            f"{BOOTSTRAP_ENV_VAR} is not set; it must point at the bootstrap "
            "YAML that locates the config store."
        )
    document = yaml.safe_load(Path(resolved).read_text(encoding="utf-8")) or {}
    store = document.get("config_store", {})
    backend = store.get("backend", "sqlite")
    namespace = store.get("namespace", "account_unification")
    sqlite_path = (store.get("sqlite") or {}).get("path")
    postgres_dsn_secret_ref = (store.get("postgres") or {}).get("dsn_secret_ref")
    return BootstrapDescriptor(
        backend=backend,
        namespace=namespace,
        sqlite_path=sqlite_path,
        postgres_dsn_secret_ref=postgres_dsn_secret_ref,
    )


def open_config_store(descriptor: BootstrapDescriptor) -> KvStore:
    """Open the KV/DB config store described by ``descriptor``."""
    if descriptor.backend == "sqlite":
        if not descriptor.sqlite_path:
            raise RuntimeError("sqlite backend requires config_store.sqlite.path")
        return SqliteKvStore(descriptor.sqlite_path)
    # The postgres backend is wired the same way (a PgKvStore reading
    # idp_config_entries); its DSN is fetched from the platform secret manager
    # via descriptor.postgres_dsn_secret_ref. Kept out of the standalone image
    # to avoid a hard psycopg dependency for local runs.
    raise UnsupportedConfigBackendError(
        f"config store backend '{descriptor.backend}' is unavailable in the "
        "standalone image; use the sqlite backend or ship a PgKvStore adapter "
        "with this deployment image."
    )


MAX_BOOTSTRAP_CREDENTIAL_BYTES = 4096
_BOOTSTRAP_CREDENTIAL_ERROR = "bootstrap credential is unavailable or unsafe"


def read_bootstrap_credential(credential_path: str) -> str:
    """Read a supervisor-owned POSIX credential without dotenv or DB fallback.

    All path components are opened relative to held directory descriptors with
    no symlink following. Validate ownership, permissions, type and size on the
    actual file descriptor, not on an earlier path lookup. The only allowed
    plaintext-file exception is Keyverse's own root bootstrap: application
    secrets still require the separately released workload-resolution API.
    """
    try:
        required_flags = ("O_NOFOLLOW", "O_DIRECTORY", "O_CLOEXEC", "O_NONBLOCK")
        if not all(hasattr(os, flag_name) for flag_name in required_flags):
            raise ValueError
        if (
            not isinstance(credential_path, str)
            or not credential_path.startswith("/")
            or "\x00" in credential_path
        ):
            raise ValueError
        path_parts = credential_path.split("/")[1:]
        if any(part in {"", ".", ".."} for part in path_parts):
            raise ValueError
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        file_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
        with ExitStack() as descriptor_stack:
            parent_descriptor = os.open("/", directory_flags)
            descriptor_stack.callback(os.close, parent_descriptor)
            for path_part in path_parts[:-1]:
                parent_descriptor = os.open(
                    path_part, directory_flags, dir_fd=parent_descriptor
                )
                descriptor_stack.callback(os.close, parent_descriptor)
            file_descriptor = os.open(
                path_parts[-1], file_flags, dir_fd=parent_descriptor
            )
            descriptor_stack.callback(os.close, file_descriptor)
            file_state = os.fstat(file_descriptor)
            if (
                not stat.S_ISREG(file_state.st_mode)
                or stat.S_IMODE(file_state.st_mode) not in {0o400, 0o600}
                or file_state.st_uid not in {0, os.geteuid()}
                or file_state.st_nlink != 1
                or not 0 < file_state.st_size <= MAX_BOOTSTRAP_CREDENTIAL_BYTES
            ):
                raise ValueError
            credential_bytes = bytearray()
            while len(credential_bytes) <= MAX_BOOTSTRAP_CREDENTIAL_BYTES:
                chunk_bytes = os.read(
                    file_descriptor,
                    MAX_BOOTSTRAP_CREDENTIAL_BYTES + 1 - len(credential_bytes),
                )
                if not chunk_bytes:
                    break
                credential_bytes.extend(chunk_bytes)
            final_state = os.fstat(file_descriptor)
            stable_fields = (
                "st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
                "st_size", "st_mtime_ns", "st_ctime_ns",
            )
            if len(credential_bytes) != file_state.st_size or any(
                getattr(final_state, field_name) != getattr(file_state, field_name)
                for field_name in stable_fields
            ):
                raise ValueError
            credential_value = credential_bytes.decode("utf-8")
            if credential_value.endswith("\r\n"):
                credential_value = credential_value[:-2]
            elif credential_value.endswith("\n"):
                credential_value = credential_value[:-1]
            if not credential_value.strip() or "\x00" in credential_value:
                raise ValueError
            return credential_value
    except (OSError, ValueError):
        # OS and decoder diagnostics may contain a private path or raw bytes.
        raise RuntimeError(_BOOTSTRAP_CREDENTIAL_ERROR) from None

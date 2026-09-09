"""Root credential transport rejects plaintext config and unsafe file objects."""
from __future__ import annotations

import dataclasses
import os
import traceback
from types import SimpleNamespace

import pytest

from app import bootstrap, config
from app.kv_store import InMemoryKvStore


@pytest.fixture
def config_store():
    """Seed only the existing account-unification startup requirements."""
    return InMemoryKvStore({"service_config": {
        "keycloak_server_url": "https://identity.example.invalid",
        "keycloak_realm": "cwl",
        "keycloak_client_id": "account_unification",
        "keycloak_client_secret": "fixture-client-secret",
        "operator_api_token": "fixture-operator-token",
    }})


@pytest.fixture
def credential_path(tmp_path):
    """Represent a supervisor-provided private credential mount."""
    credential_file = tmp_path / "vault_credential"
    credential_file.write_bytes(b"fixture-vault-credential\n")
    credential_file.chmod(0o400)
    return credential_file


def read_credential(credential_path):
    """Invoke the existing bootstrap boundary with a deliberately public locator."""
    assert hasattr(bootstrap, "read_bootstrap_credential"), (
        "bootstrap needs a protected-credential reader, not a plaintext DB secret"
    )
    return bootstrap.read_bootstrap_credential(str(credential_path))


@pytest.mark.parametrize("raw_secret", ["fixture-legacy-secret", ""])
def test_plaintext_config_entry_is_rejected(config_store, raw_secret):
    """Even an empty legacy entry requires explicit migration rather than fallback."""
    config_store.put("service_config", "keyvault_passphrase", raw_secret)
    with pytest.raises(RuntimeError, match="plaintext Keyvault bootstrap"):
        config.load_service_config(config_store, "service_config")


def test_config_resolves_only_the_protected_reference(config_store, credential_path):
    """The typed value reaches the existing vault constructor without persisting it."""
    config_store.put("service_config", "keyvault_passphrase_file", str(credential_path))
    service_config = config.load_service_config(config_store, "service_config")
    assert service_config.keyvault_passphrase == "fixture-vault-credential"
    assert "fixture-vault-credential" not in str(config_store.get_all("service_config"))


def test_legacy_value_cannot_override_a_valid_reference(config_store, credential_path):
    """A conflicting root credential has no silent precedence rule."""
    config_store.put("service_config", "keyvault_passphrase_file", str(credential_path))
    config_store.put("service_config", "keyvault_passphrase", "fixture-legacy-secret")
    with pytest.raises(RuntimeError, match="plaintext Keyvault bootstrap"):
        config.load_service_config(config_store, "service_config")


def test_process_environment_is_not_a_credential_fallback(config_store, monkeypatch):
    """Scattered environment values cannot silently enable an unconfigured vault."""
    monkeypatch.setenv("KEYVAULT_PASSPHRASE", "fixture-environment-secret")
    monkeypatch.setenv("KEYVAULT_PASSPHRASE_FILE", "/ignored/credential")
    assert config.load_service_config(config_store, "service_config").keyvault_passphrase is None


def test_dataclass_repr_hides_all_credential_fields(config_store):
    """Logging the typed config must not leak unrelated bootstrap credentials either."""
    service_config = dataclasses.replace(
        config.load_service_config(config_store, "service_config"),
        registration_api_token="fixture-registration-token",
        keyvault_passphrase="fixture-vault-secret",
    )
    rendered = repr(service_config)
    for value in ["fixture-client-secret", "fixture-operator-token",
                  "fixture-registration-token", "fixture-vault-secret"]:
        assert value not in rendered
    assert "account_unification" in rendered


@pytest.mark.parametrize("file_mode", [0o400, 0o600])
def test_private_regular_file_can_be_read(credential_path, file_mode):
    """Read-only and owner-writable supervisor files are both supported."""
    credential_path.chmod(file_mode)
    assert read_credential(credential_path) == "fixture-vault-credential"


@pytest.mark.parametrize("file_mode", [0o644, 0o640, 0o604, 0o660, 0o444])
def test_group_or_other_permissions_are_rejected(credential_path, file_mode):
    """A readable credential is insufficient when another principal can access it."""
    credential_path.chmod(file_mode)
    with pytest.raises(RuntimeError, match="bootstrap credential is unavailable or unsafe"):
        read_credential(credential_path)


@pytest.mark.parametrize("raw_bytes", [b"", b"\n", b" \t\n", b"invalid\x00secret", b"\xff", b"x" * 4097])
def test_invalid_credential_content_is_rejected(credential_path, raw_bytes):
    """Malformed or oversized credential bytes fail without reflecting content."""
    credential_path.chmod(0o600)
    credential_path.write_bytes(raw_bytes)
    with pytest.raises(RuntimeError, match="bootstrap credential is unavailable or unsafe"):
        read_credential(credential_path)


@pytest.mark.parametrize("raw_bytes,expected", [
    (b" exact-spaces ", " exact-spaces "),
    (b"exact\r\n", "exact"),
    (b"exact\n\n", "exact\n"),
    (b"x" * 4096, "x" * 4096),
    ("비밀-시험".encode(), "비밀-시험"),
])
def test_only_one_terminal_newline_is_removed(credential_path, raw_bytes, expected):
    """Do not normalize away meaningful credential bytes."""
    credential_path.chmod(0o600)
    credential_path.write_bytes(raw_bytes)
    assert read_credential(credential_path) == expected


def test_symlink_leaf_is_rejected(credential_path, tmp_path):
    """Checking and opening the same descriptor prevents leaf-link races."""
    link_path = tmp_path / "credential_link"
    link_path.symlink_to(credential_path)
    with pytest.raises(RuntimeError):
        read_credential(link_path)


def test_symlink_parent_is_rejected(credential_path, tmp_path):
    """No path component may redirect the bootstrap credential to another tree."""
    link_path = tmp_path / "directory_link"
    link_path.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(RuntimeError):
        read_credential(link_path / credential_path.name)


def test_hardlinked_file_is_rejected(credential_path, tmp_path):
    """The credential cannot also be exposed under an ungoverned second name."""
    link_path = tmp_path / "second_name"
    os.link(credential_path, link_path)
    with pytest.raises(RuntimeError):
        read_credential(credential_path)


@pytest.mark.parametrize("unsafe_path", ["relative_secret", "/", "/tmp/../secret", "", "/tmp/secret\x00"])
def test_invalid_locator_is_rejected(unsafe_path):
    """Reject ambiguous path syntax before opening any object."""
    with pytest.raises(RuntimeError):
        read_credential(unsafe_path)


def test_directory_is_not_a_credential(tmp_path):
    """Directories and other non-regular objects cannot enter the key derivation."""
    with pytest.raises(RuntimeError):
        read_credential(tmp_path)


def test_fifo_is_rejected_without_waiting_for_a_writer(tmp_path):
    """O_NONBLOCK permits fstat rejection instead of a blocking FIFO open."""
    fifo_path = tmp_path / "credential_fifo"
    os.mkfifo(fifo_path, 0o600)
    with pytest.raises(RuntimeError):
        read_credential(fifo_path)


def test_missing_file_and_parent_fail_without_path_disclosure(tmp_path):
    """Operational failures do not echo private path components."""
    private_path = tmp_path / "private_customer_name" / "credential"
    with pytest.raises(RuntimeError) as raised_error:
        read_credential(private_path)
    rendered = "".join(traceback.format_exception(raised_error.value))
    assert "private_customer_name" not in rendered.split("RuntimeError:")[-1]


def test_foreign_owner_is_rejected(credential_path, monkeypatch):
    """Permission bits alone do not establish the credential owner."""
    real_fstat = os.fstat
    def foreign_owner(file_descriptor):
        """Vary only ownership in the already-open file metadata."""
        result = real_fstat(file_descriptor)
        return SimpleNamespace(st_mode=result.st_mode, st_uid=os.geteuid() + 10001,
                               st_nlink=result.st_nlink, st_size=result.st_size)
    monkeypatch.setattr(os, "fstat", foreign_owner)
    with pytest.raises(RuntimeError):
        read_credential(credential_path)


def test_read_error_closes_descriptors(credential_path, monkeypatch):
    """An interrupted read releases all opened descriptors and exposes no raw error."""
    before_count = len(os.listdir("/proc/self/fd"))
    def interrupted_read(file_descriptor, byte_count):
        """Represent a kernel read failure with a sensitive diagnostic payload."""
        raise OSError("fixture-private-diagnostic")
    monkeypatch.setattr(os, "read", interrupted_read)
    with pytest.raises(RuntimeError) as raised_error:
        read_credential(credential_path)
    assert "fixture-private-diagnostic" not in "".join(traceback.format_exception(raised_error.value))
    assert len(os.listdir("/proc/self/fd")) == before_count


def test_dotenv_in_working_directory_is_not_loaded(config_store, tmp_path, monkeypatch):
    """A local dotenv file cannot silently become Keyverse's root credential source."""
    (tmp_path / ".env").write_text("KEYVAULT_PASSPHRASE=fixture-dotenv-secret\n")
    monkeypatch.chdir(tmp_path)
    assert config.load_service_config(config_store, "service_config").keyvault_passphrase is None


def test_platform_without_no_follow_fails_closed(credential_path, monkeypatch):
    """Unsupported platforms need another reviewed transport, not weaker file I/O."""
    monkeypatch.delattr(os, "O_NOFOLLOW")
    with pytest.raises(RuntimeError):
        read_credential(credential_path)


def test_file_growth_after_open_is_rejected(credential_path, monkeypatch):
    """The reader detects a file that grows past the maximum after fstat."""
    real_read = os.read
    def growing_read(file_descriptor, byte_count):
        """Model growth between fstat and read without allocating unbounded data."""
        if byte_count == 4097:
            return b"x" * byte_count
        return real_read(file_descriptor, byte_count)
    monkeypatch.setattr(os, "read", growing_read)
    with pytest.raises(RuntimeError):
        read_credential(credential_path)


def test_non_atomic_same_size_rewrite_is_rejected(credential_path, monkeypatch):
    """An in-place rotation cannot produce a mixed but plausible credential."""
    real_read = os.read
    did_replace = False
    def replaced_read(file_descriptor, byte_count):
        """Represent a supervisor incorrectly rewriting instead of replacing."""
        nonlocal did_replace
        result = real_read(file_descriptor, byte_count)
        if not did_replace:
            did_replace = True
            old_time = credential_path.stat().st_mtime_ns
            os.utime(credential_path, ns=(old_time + 1_000_000, old_time + 1_000_000))
        return result
    monkeypatch.setattr(os, "read", replaced_read)
    with pytest.raises(RuntimeError):
        read_credential(credential_path)


def test_access_time_update_is_not_mistaken_for_credential_rotation(credential_path):
    """Reading a file may update atime without changing its protected content."""
    current_modified = credential_path.stat().st_mtime_ns
    os.utime(credential_path, ns=(0, current_modified))
    assert read_credential(credential_path) == "fixture-vault-credential"

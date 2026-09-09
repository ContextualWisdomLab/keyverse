"""Parent-directory trust tests for the vault root bootstrap path."""
from __future__ import annotations

import os
import stat

import pytest

from app.bootstrap import read_bootstrap_credential


def _private_credential(directory_path):
    """Create one private regular credential below the supplied directory."""
    credential_path = directory_path / "vault_credential"
    credential_path.write_text("fixture-vault-credential\n", encoding="utf-8")
    credential_path.chmod(0o400)
    return credential_path


def test_group_writable_parent_directory_is_rejected(tmp_path):
    """A group member must not be able to replace a trusted path component."""
    credential_path = _private_credential(tmp_path)
    tmp_path.chmod(0o770)

    with pytest.raises(RuntimeError, match="bootstrap credential is unavailable or unsafe"):
        read_bootstrap_credential(str(credential_path))


def test_world_writable_parent_directory_is_rejected(tmp_path):
    """World-writable application-owned directories are not trusted bootstrap roots."""
    credential_path = _private_credential(tmp_path)
    tmp_path.chmod(0o777)

    with pytest.raises(RuntimeError, match="bootstrap credential is unavailable or unsafe"):
        read_bootstrap_credential(str(credential_path))


def test_owner_private_parent_directory_remains_supported(tmp_path):
    """An owner-controlled directory retains the intended standalone bootstrap path."""
    credential_path = _private_credential(tmp_path)
    tmp_path.chmod(0o700)

    assert read_bootstrap_credential(str(credential_path)) == "fixture-vault-credential"


def test_root_sticky_tmp_component_does_not_break_private_descendant(tmp_path):
    """A root-owned sticky /tmp ancestor is allowed when descendants are private."""
    if not str(tmp_path).startswith("/tmp/"):
        pytest.skip("runner temporary directory is not below /tmp")
    tmp_state = os.stat("/tmp")
    if tmp_state.st_uid != 0 or not stat.S_ISVTX & tmp_state.st_mode:
        pytest.skip("runner /tmp is not the root-owned sticky-directory profile")
    credential_path = _private_credential(tmp_path)
    tmp_path.chmod(0o700)

    assert read_bootstrap_credential(str(credential_path)) == "fixture-vault-credential"

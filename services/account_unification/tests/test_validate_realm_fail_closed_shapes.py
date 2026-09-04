"""Fail-closed regression tests for Keycloak user-profile validation."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest


def _repository_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _load_validate_realm():
    script_path = _repository_root() / "scripts" / "validate_realm.py"
    spec = importlib.util.spec_from_file_location("validate_realm_shapes", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _committed_realm() -> dict:
    return json.loads(
        (_repository_root() / "deploy/keycloak/cwl-realm.json").read_text(encoding="utf-8")
    )


def _committed_profile() -> dict:
    return json.loads(
        (_repository_root() / "deploy/keycloak/lineageweave-user-profile.json").read_text(
            encoding="utf-8"
        )
    )


@pytest.mark.parametrize("profile", [None, [], "profile", 7])
def test_user_profile_rejects_non_object_top_level_without_raising(profile: object) -> None:
    validator = _load_validate_realm()

    errors = validator.validate_user_profile(profile)

    assert "user profile must be a JSON object" in errors


@pytest.mark.parametrize("attributes", [None, {}, "attributes", 7])
def test_user_profile_rejects_non_array_attributes_without_raising(attributes: object) -> None:
    validator = _load_validate_realm()
    profile = _committed_profile()
    profile["attributes"] = attributes

    errors = validator.validate_user_profile(profile)

    assert "user profile attributes must be an array" in errors


def test_user_profile_rejects_non_object_attribute_entries() -> None:
    validator = _load_validate_realm()
    profile = _committed_profile()
    profile["attributes"].append(None)

    errors = validator.validate_user_profile(profile)

    assert "user profile attribute entries must be JSON objects" in errors


def test_user_profile_rejects_extra_and_duplicate_attribute_names() -> None:
    validator = _load_validate_realm()
    profile = _committed_profile()
    profile["attributes"].append({"name": "department"})
    profile["attributes"].append(dict(profile["attributes"][0]))

    errors = validator.validate_user_profile(profile)

    assert "user profile attributes must match the reviewed attribute-name set" in errors
    assert "user profile attribute names must not be duplicated" in errors


@pytest.mark.parametrize("profile", [None, [], "profile", 7, {"attributes": None}])
def test_cli_reports_malformed_profile_as_invalid_without_traceback(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    profile: object,
) -> None:
    validator = _load_validate_realm()
    realm_path = tmp_path / "cwl-realm.json"
    profile_path = tmp_path / "lineageweave-user-profile.json"
    realm_path.write_text(json.dumps(_committed_realm()), encoding="utf-8")
    profile_path.write_text(json.dumps(profile), encoding="utf-8")

    result = validator.main(["validate_realm.py", str(realm_path), str(profile_path)])

    captured = capsys.readouterr()
    assert result == 1
    assert "INVALID:" in captured.err
    assert "Traceback" not in captured.err

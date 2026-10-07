"""Locked dependency surfaces stay above published security fix versions.

The development dependency graph contains ``httpx2`` and its exact-coupled
``httpcore2``. The graph had two HIGH advisories: CVE-2026-84381 (``wss``
through SOCKS5 sent in cleartext, fixed in 2.10.0) and CVE-2026-84382
(streaming decompression memory amplification, fixed in 2.12.0). These tests
read every matching entry from the reviewed declaration, the universal
``uv.lock`` resolution, and the generated hash-locked development
requirements. They verify the dependency graph, not execution of HTTPX2
request or WebSocket consumers.
"""
from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

SERVICE_ROOT = Path(__file__).resolve().parents[1]

SECURITY_FLOORS = {
    "httpx2": (2, 12, 0),
    "httpcore2": (2, 12, 0),
}


def _version_tuple(version: str) -> tuple[int, ...]:
    """Convert a plain release version such as ``2.12.0`` into comparable integers."""
    return tuple(int(part) for part in version.split("."))


def _versions_from_lock(
    lock: dict[str, list[dict[str, str]]],
) -> dict[str, list[str]]:
    """Collect every resolved version, including platform-specific lock rows."""
    versions: dict[str, list[str]] = {}
    for package in lock["package"]:
        versions.setdefault(package["name"], []).append(package["version"])
    return versions


def _versions_from_requirements(text: str) -> dict[str, list[str]]:
    """Collect every exact requirement pin, including conditional pins."""
    versions: dict[str, list[str]] = {}
    for match in re.finditer(
        r"^([A-Za-z0-9_.-]+)==([0-9.]+)", text, re.MULTILINE
    ):
        versions.setdefault(match.group(1).lower(), []).append(match.group(2))
    return versions


def _locked_versions() -> dict[str, list[str]]:
    """Return every resolved version for each package name in ``uv.lock``."""
    lock = tomllib.loads((SERVICE_ROOT / "uv.lock").read_text(encoding="utf-8"))
    return _versions_from_lock(lock)


def _requirements_dev_versions() -> dict[str, list[str]]:
    """Return every exact pin for each package in generated dev requirements."""
    text = (SERVICE_ROOT / "requirements-dev.txt").read_text(encoding="utf-8")
    return _versions_from_requirements(text)


def _assert_security_floor(
    package_name: str, versions: dict[str, list[str]]
) -> None:
    """Reject every package version below its published security floor."""
    assert package_name in versions
    assert all(
        _version_tuple(version) >= SECURITY_FLOORS[package_name]
        for version in versions[package_name]
    )


def test_security_floor_checks_every_conditional_requirement_pin() -> None:
    """A safe final pin must not hide an earlier vulnerable conditional pin."""
    versions = _versions_from_requirements(
        """
httpx2==2.9.1 ; sys_platform == 'win32'
httpx2==2.12.0 ; sys_platform != 'win32'
httpcore2==2.9.1 ; sys_platform == 'win32'
httpcore2==2.12.0 ; sys_platform != 'win32'
"""
    )
    assert versions["httpx2"] == ["2.9.1", "2.12.0"]
    assert versions["httpcore2"] == ["2.9.1", "2.12.0"]
    with pytest.raises(AssertionError):
        _assert_security_floor("httpx2", versions)
    with pytest.raises(AssertionError):
        _assert_security_floor("httpcore2", versions)


@pytest.mark.parametrize("package_name", sorted(SECURITY_FLOORS))
def test_universal_lock_resolves_patched_transport(package_name: str) -> None:
    """``uv.lock`` must not resolve a release affected by the HTTPX2 advisories."""
    _assert_security_floor(package_name, _locked_versions())


@pytest.mark.parametrize("package_name", sorted(SECURITY_FLOORS))
def test_generated_dev_requirements_pin_patched_transport(package_name: str) -> None:
    """The hash-locked pip surface must agree with the patched universal lock."""
    pinned = _requirements_dev_versions()
    locked = _locked_versions()
    assert pinned[package_name] == locked[package_name]
    _assert_security_floor(package_name, pinned)


def test_direct_declaration_pins_patched_httpx2() -> None:
    """The reviewed ``pyproject.toml`` dev pin is the patched release, not the lock alone."""
    project = tomllib.loads((SERVICE_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    pins = [
        requirement
        for requirement in project["project"]["optional-dependencies"]["dev"]
        if requirement.startswith("httpx2==")
    ]
    assert len(pins) == 1
    assert _version_tuple(pins[0].split("==", 1)[1]) >= SECURITY_FLOORS["httpx2"]

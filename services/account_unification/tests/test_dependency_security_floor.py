"""Locked dependency surfaces stay above published security fix versions.

The development transport ``httpx2`` and its exact-coupled ``httpcore2``
had two HIGH advisories: CVE-2026-84381 (``wss`` through SOCKS5 sent in
cleartext, fixed in 2.10.0) and CVE-2026-84382 (streaming decompression
memory amplification, fixed in 2.12.0). These tests read the reviewed
declaration, the universal ``uv.lock`` resolution, and the generated
hash-locked development requirements, so a regenerated lock cannot quietly
fall back to a vulnerable release on any installation surface.
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


def _locked_versions() -> dict[str, str]:
    """Return every package name and version resolved in ``uv.lock``."""
    lock = tomllib.loads((SERVICE_ROOT / "uv.lock").read_text(encoding="utf-8"))
    return {package["name"]: package["version"] for package in lock["package"]}


def _requirements_dev_versions() -> dict[str, str]:
    """Return exact pins from the generated ``requirements-dev.txt`` surface."""
    text = (SERVICE_ROOT / "requirements-dev.txt").read_text(encoding="utf-8")
    return {
        match.group(1).lower(): match.group(2)
        for match in re.finditer(r"^([A-Za-z0-9_.-]+)==([0-9.]+)", text, re.MULTILINE)
    }


@pytest.mark.parametrize("package_name", sorted(SECURITY_FLOORS))
def test_universal_lock_resolves_patched_transport(package_name: str) -> None:
    """``uv.lock`` must not resolve a release affected by the HTTPX2 advisories."""
    locked = _locked_versions()
    assert package_name in locked
    assert _version_tuple(locked[package_name]) >= SECURITY_FLOORS[package_name]


@pytest.mark.parametrize("package_name", sorted(SECURITY_FLOORS))
def test_generated_dev_requirements_pin_patched_transport(package_name: str) -> None:
    """The hash-locked pip surface must agree with the patched universal lock."""
    pinned = _requirements_dev_versions()
    assert pinned[package_name] == _locked_versions()[package_name]
    assert _version_tuple(pinned[package_name]) >= SECURITY_FLOORS[package_name]


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

"""Keycloak Admin REST transport tests for LDAP user-storage components."""
from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from app.product_keycloak_client import ProductHttpAdminApi


@dataclass
class _FakeResponse:
    """Minimal HTTP response used by the component adapter tests."""

    payload: object | None = None
    headers: dict[str, str] = field(default_factory=dict)

    def json(self) -> object:
        """Return the configured JSON payload."""
        return self.payload


class _RecordingClient:
    """Record component requests without network access or credential material."""

    def __init__(self) -> None:
        """Initialize an empty request ledger."""
        self.requests: list[tuple[str, str, object | None]] = []
        self.list_payload: object = []
        self.location: str | None = None
        self.auth_headers: list[dict[str, str]] = []

    def get(
        self,
        url: str,
        *,
        params: dict[str, str],
        headers: dict[str, str],
    ) -> _FakeResponse:
        """Record one list request."""
        self.requests.append(("GET", url, dict(params)))
        self.auth_headers.append(dict(headers))
        return _FakeResponse(payload=self.list_payload)

    def post(
        self,
        url: str,
        *,
        json: dict,
        headers: dict[str, str],
    ) -> _FakeResponse:
        """Record one create request."""
        self.requests.append(("POST", url, dict(json)))
        self.auth_headers.append(dict(headers))
        response_headers = {"Location": self.location} if self.location else {}
        return _FakeResponse(headers=response_headers)

    def put(
        self,
        url: str,
        *,
        json: dict,
        headers: dict[str, str],
    ) -> _FakeResponse:
        """Record one replacement request."""
        self.requests.append(("PUT", url, dict(json)))
        self.auth_headers.append(dict(headers))
        return _FakeResponse()

    def delete(self, url: str, *, headers: dict[str, str]) -> _FakeResponse:
        """Record one delete request."""
        self.requests.append(("DELETE", url, None))
        self.auth_headers.append(dict(headers))
        return _FakeResponse()


def _client() -> tuple[ProductHttpAdminApi, _RecordingClient]:
    """Return a product client whose authenticated send seam is deterministic."""
    api = ProductHttpAdminApi(
        server_url="https://keycloak.internal",
        realm="cwl",
        client_id="account-unification-svc",
        client_secret="private-client-value",
        timeout_seconds=5.0,
    )
    recorder = _RecordingClient()
    api._client = recorder  # type: ignore[assignment]
    api._token = "test-access-token"
    api._send_with_reauth = lambda request: request()  # type: ignore[method-assign]
    return api, recorder


def _component_payload() -> dict:
    """Return one bounded Keycloak LDAP component representation."""
    return {
        "name": "corp-ldap",
        "providerId": "ldap",
        "providerType": "org.keycloak.storage.UserStorageProvider",
        "config": {"enabled": ["true"]},
    }


def test_component_list_uses_fixed_type_and_name_query() -> None:
    """Directory discovery reaches only the fixed realm component collection."""
    api, recorder = _client()
    recorder.list_payload = [_component_payload()]

    components = api.list_user_storage_components("corp-ldap")

    assert components == [_component_payload()]
    method, url, params = recorder.requests[0]
    assert method == "GET"
    assert url.endswith("/admin/realms/cwl/components")
    assert params == {
        "name": "corp-ldap",
        "type": "org.keycloak.storage.UserStorageProvider",
    }
    assert recorder.auth_headers == [
        {"Authorization": "Bearer test-access-token"}
    ]


def test_component_create_parses_only_a_safe_location_identifier() -> None:
    """Create returns a validated opaque component identifier from Location."""
    api, recorder = _client()
    recorder.location = (
        "https://keycloak.internal/admin/realms/cwl/components/"
        "directory-component-1"
    )

    component_id = api.create_user_storage_component(_component_payload())

    assert component_id == "directory-component-1"
    assert recorder.requests[0][0] == "POST"
    assert recorder.requests[0][1].endswith("/admin/realms/cwl/components")


def test_component_create_tolerates_missing_location_without_guessing() -> None:
    """A successful create without Location never fabricates a component ID."""
    api, _recorder = _client()

    assert api.create_user_storage_component(_component_payload()) is None


@pytest.mark.parametrize(
    "component_id",
    ["", ".", "..", "../escape", "encoded%2fid", "query?id", "x" * 256],
)
def test_component_update_and_delete_reject_unsafe_dynamic_ids(
    component_id: str,
) -> None:
    """Unsafe generated identifiers never enter a Keycloak Admin REST URL."""
    api, recorder = _client()

    with pytest.raises(ValueError):
        api.update_user_storage_component(component_id, _component_payload())
    with pytest.raises(ValueError):
        api.delete_user_storage_component(component_id)

    assert recorder.requests == []


def test_component_update_and_delete_use_exact_resource_path() -> None:
    """Mutation methods target one validated component and preserve the payload."""
    api, recorder = _client()
    payload = _component_payload()

    api.update_user_storage_component("directory-component-1", payload)
    api.delete_user_storage_component("directory-component-1")

    assert recorder.requests == [
        (
            "PUT",
            "https://keycloak.internal/admin/realms/cwl/components/"
            "directory-component-1",
            payload,
        ),
        (
            "DELETE",
            "https://keycloak.internal/admin/realms/cwl/components/"
            "directory-component-1",
            None,
        ),
    ]
    assert recorder.auth_headers == [
        {"Authorization": "Bearer test-access-token"},
        {"Authorization": "Bearer test-access-token"},
    ]


def test_component_list_rejects_invalid_response_shapes() -> None:
    """Malformed Keycloak list responses fail closed instead of being coerced."""
    api, recorder = _client()
    recorder.list_payload = {"id": "not-a-list"}

    with pytest.raises(RuntimeError):
        api.list_user_storage_components("corp-ldap")


def test_component_list_rejects_unbounded_directory_name() -> None:
    """The adapter rejects empty and oversized names before transport."""
    api, recorder = _client()

    for name in ("", "x" * 64, "Bad Alias", "-leading", "trailing-"):
        with pytest.raises(ValueError):
            api.list_user_storage_components(name)

    assert recorder.requests == []

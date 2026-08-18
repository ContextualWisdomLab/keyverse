"""App-side start-login helper for brokered Keyverse federation.

Relying parties call this helper to discover enabled identity providers and
receive a Keycloak authorization URL with ``kc_idp_hint``. The helper never
fetches OIDC discovery or SAML metadata, never becomes an IdP, and never
moves federation ownership into the application.
"""
from __future__ import annotations

from urllib.parse import urlencode, urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .config import ServiceConfig
from .errors import AuthorizationPolicyError
from .federation import (
    FEDERATION_PROVIDER_NAMESPACE,
    IdentityProviderRegistration,
    IdentityProviderView,
)
from .kv_store import KvStore
from .org_authorization import validate_slug

start_login_router = APIRouter(prefix="/federation", tags=["federation"])
_HTTPS_SCHEME = "https"
_HTTP_SCHEME = "http"
_MAX_REDIRECT_URI_LENGTH = 2_048
_FORBIDDEN_HINTS = frozenset({"fromUrl", "discoveryEndpoint", "metadataUrl"})


class StartLoginRequest(BaseModel):
    """Ask Keyverse how one relying party should start brokered login."""

    model_config = ConfigDict(extra="forbid")

    software_unit_id: str
    client_id: str
    redirect_uri: str
    provider_alias_hint: str | None = None
    public_issuer_url: str | None = Field(
        default=None,
        description="Optional public realm issuer; never a discovery document URL.",
    )


class DiscoveredIdentityProvider(BaseModel):
    """Redacted enabled identity provider an RP may hint."""

    model_config = ConfigDict(extra="forbid")

    provider_alias: str
    display_name: str
    provider_id: str
    enabled: bool


class StartLoginResponse(BaseModel):
    """Discovery and start-login instruction owned by Keyverse, not the app."""

    model_config = ConfigDict(extra="forbid")

    software_unit_id: str
    client_id: str
    identity_providers: list[DiscoveredIdentityProvider]
    selected_provider_alias: str | None = None
    kc_idp_hint_parameter: str = "kc_idp_hint"
    authorization_endpoint: str
    start_login_url: str | None = None
    metadata_fetch_performed: bool = False
    federation_ownership: str = "keyverse"
    application_next_action: str = (
        "Add PKCE S256, state, and nonce locally, then redirect the browser "
        "to start_login_url. Do not fetch IdP metadata from the application."
    )


class StartLoginService:
    """Build start-login instructions from the local federation registry."""

    def __init__(self, store: KvStore, config: ServiceConfig) -> None:
        """Create one helper around the KV registry and local issuer config."""
        self._store = store
        self._config = config

    def start_login(self, request: StartLoginRequest) -> StartLoginResponse:
        """Return redacted discovery and an optional start URL without network I/O."""
        software_unit_id = validate_slug(
            request.software_unit_id, field_name="software_unit_id"
        )
        client_id = validate_slug(request.client_id, field_name="client_id")
        if request.client_id != request.software_unit_id:
            raise AuthorizationPolicyError(
                "client_id and software_unit_id must match in this slice"
            )
        _reject_discovery_request(request)
        redirect_uri = _validated_redirect_uri(request.redirect_uri)
        authorization_endpoint = _authorization_endpoint(
            request.public_issuer_url,
            self._config,
        )
        providers = self.discover_enabled_providers()
        selected = _select_provider(providers, request.provider_alias_hint)
        start_login_url = None
        if selected is not None:
            start_login_url = _build_start_login_url(
                authorization_endpoint,
                client_id=client_id,
                redirect_uri=redirect_uri,
                provider_alias=selected,
            )
        return StartLoginResponse(
            software_unit_id=software_unit_id,
            client_id=client_id,
            identity_providers=providers,
            selected_provider_alias=selected,
            authorization_endpoint=authorization_endpoint,
            start_login_url=start_login_url,
        )

    def discover_enabled_providers(self) -> list[DiscoveredIdentityProvider]:
        """Return enabled providers from KV without calling Keycloak."""
        discovered: list[DiscoveredIdentityProvider] = []
        for raw_value in self._store.get_all(FEDERATION_PROVIDER_NAMESPACE).values():
            try:
                registration = IdentityProviderRegistration.model_validate_json(
                    raw_value
                )
            except ValidationError as exc:
                raise AuthorizationPolicyError(
                    "federation provider store is corrupt",
                    status_code=500,
                ) from exc
            if not registration.enabled:
                continue
            view = IdentityProviderView.from_registration(registration)
            discovered.append(
                DiscoveredIdentityProvider(
                    provider_alias=view.provider_alias,
                    display_name=view.display_name,
                    provider_id=view.provider_id,
                    enabled=view.enabled,
                )
            )
        return sorted(discovered, key=lambda item: item.provider_alias)


def _reject_discovery_request(request: StartLoginRequest) -> None:
    """Refuse fields that would imply a metadata or discovery fetch."""
    public_issuer_url = request.public_issuer_url or ""
    lowered = public_issuer_url.lower()
    if any(marker.lower() in lowered for marker in _FORBIDDEN_HINTS):
        raise AuthorizationPolicyError(
            "start-login must not receive discovery or metadata URLs"
        )
    if ".well-known" in lowered:
        raise AuthorizationPolicyError(
            "start-login must not receive discovery or metadata URLs"
        )


def _validated_redirect_uri(redirect_uri: str) -> str:
    """Return one absolute HTTPS application redirect URI."""
    if len(redirect_uri) > _MAX_REDIRECT_URI_LENGTH:
        raise AuthorizationPolicyError("redirect_uri exceeds the closed bound")
    parsed = urlsplit(redirect_uri)
    if (
        parsed.scheme != _HTTPS_SCHEME
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise AuthorizationPolicyError(
            "redirect_uri must be an absolute HTTPS URI without credentials "
            "or fragments"
        )
    return redirect_uri


def _authorization_endpoint(
    public_issuer_url: str | None, config: ServiceConfig
) -> str:
    """Build the local Keycloak authorization endpoint without discovery."""
    if public_issuer_url:
        parsed = urlsplit(public_issuer_url)
        if (
            parsed.scheme not in {_HTTP_SCHEME, _HTTPS_SCHEME}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or parsed.query
        ):
            raise AuthorizationPolicyError(
                "public_issuer_url must be an absolute issuer URL without "
                "credentials, query, or fragment"
            )
        issuer = public_issuer_url.rstrip("/")
    else:
        issuer = (
            f"{config.keycloak_server_url.rstrip('/')}/realms/{config.keycloak_realm}"
        )
    if issuer.endswith("/protocol/openid-connect/auth"):
        return issuer
    return f"{issuer}/protocol/openid-connect/auth"


def _select_provider(
    providers: list[DiscoveredIdentityProvider],
    provider_alias_hint: str | None,
) -> str | None:
    """Select one enabled provider or require an explicit hint."""
    aliases = {provider.provider_alias for provider in providers}
    if provider_alias_hint is not None:
        validate_slug(provider_alias_hint, field_name="provider_alias_hint")
        if provider_alias_hint not in aliases:
            raise AuthorizationPolicyError(
                "provider_alias_hint does not match an enabled identity provider",
                status_code=404,
            )
        return provider_alias_hint
    if len(providers) == 1:
        return providers[0].provider_alias
    return None


def _build_start_login_url(
    authorization_endpoint: str,
    *,
    client_id: str,
    redirect_uri: str,
    provider_alias: str,
) -> str:
    """Compose a Keycloak authorization URL with kc_idp_hint."""
    query = urlencode(
        {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": "openid",
            "kc_idp_hint": provider_alias,
        }
    )
    return f"{authorization_endpoint}?{query}"


def get_start_login_service(request: Request) -> StartLoginService:
    """Return the wired start-login helper from application state."""
    service = getattr(request.app.state, "start_login_service", None)
    if service is None:
        raise HTTPException(status_code=503, detail="start-login service not ready")
    return service


@start_login_router.post(
    "/identity-providers:start-login",
    response_model=StartLoginResponse,
)
def start_login_endpoint(
    body: StartLoginRequest,
    service: StartLoginService = Depends(get_start_login_service),
) -> StartLoginResponse:
    """Discover enabled IdPs and return a Keyverse-owned start-login URL."""
    try:
        return service.start_login(body)
    except AuthorizationPolicyError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc

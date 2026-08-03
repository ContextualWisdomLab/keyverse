"""Path-parameter validation dependencies for privileged API routers.

FastAPI decodes route parameters before endpoint execution. Validating every
decoded value as one opaque segment prevents traversal, encoded-separator, and
control-character payloads from reaching Keycloak Admin REST path builders.
"""
from __future__ import annotations

from fastapi import Depends, HTTPException, Request
from fastapi.responses import JSONResponse

from .identifiers import InvalidIdentifierError, validate_path_segment

SCIM_ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"
SCIM_MEDIA_TYPE = "application/scim+json"


class ScimPathValidationError(ValueError):
    """Represent one unsafe decoded SCIM path parameter."""


def _validate_path_parameters(request: Request) -> None:
    """Validate every decoded route parameter as one opaque path segment."""
    for field_name, value in request.path_params.items():
        validate_path_segment(str(value), field_name=field_name)


def require_safe_admin_path_parameters(request: Request) -> None:
    """Reject unsafe privileged API path parameters with HTTP 400."""
    try:
        _validate_path_parameters(request)
    except InvalidIdentifierError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error


def require_safe_scim_path_parameters(request: Request) -> None:
    """Raise a SCIM-specific error for an unsafe decoded path parameter."""
    try:
        _validate_path_parameters(request)
    except InvalidIdentifierError as error:
        raise ScimPathValidationError(str(error)) from error


def scim_path_validation_exception_handler(
    request: Request,
    error: ScimPathValidationError,
) -> JSONResponse:
    """Render one RFC 7644 error at the response body root."""
    del request
    return JSONResponse(
        status_code=400,
        media_type=SCIM_MEDIA_TYPE,
        content={
            "schemas": [SCIM_ERROR_SCHEMA],
            "detail": str(error),
            "status": "400",
        },
    )


admin_path_security_dependency = Depends(require_safe_admin_path_parameters)
scim_path_security_dependency = Depends(require_safe_scim_path_parameters)

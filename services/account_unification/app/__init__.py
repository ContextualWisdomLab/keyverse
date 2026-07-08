"""cwl-idp account-unification admin service.

Fills the gap neither Keycloak nor an external ADFS covers natively: linking one
human to many external identities and MERGING two pre-existing accounts into a
single survivor, with a survivor-wins conflict policy and a full audit trail.
Also serves a minimal inbound SCIM 2.0 provisioning shim into Keycloak.
"""

__version__ = "0.1.0"

# Federation & client registration templates

These are **request-body templates** for the ZITADEL Management API. They are
applied as-code (idempotently) by your provisioning tooling, which resolves
`{{placeholders}}` from the ecosystem KV config store and posts them with a
management PAT (also from KV). Nothing here contains a secret.

| Template | Direction | ZITADEL endpoint |
| --- | --- | --- |
| `saml-idp-employer-adfs.json` | inbound (external IdP → cwl-idp) | `POST /management/v1/idps/saml` |
| `ldap-source.json` | inbound (external directory → cwl-idp) | `POST /management/v1/idps/ldap` |
| `oidc-rp-client.json` | outbound (cwl-idp → RP) | `POST /management/v1/projects/{projectId}/apps/oidc` |

## Apply pattern

```bash
# 1. Get a management PAT from KV (bootstrap transport only).
PAT="$(kv get secret/idp/mgmt-pat)"
ORG="$(kv get config/idp/org-id)"

# 2. Render placeholders from KV, then POST.
render deploy/templates/saml-idp-employer-adfs.json \
  | curl -sS -X POST "https://idp.example/management/v1/idps/saml" \
      -H "Authorization: Bearer ${PAT}" \
      -H "x-zitadel-orgid: ${ORG}" \
      -H "Content-Type: application/json" \
      --data @-
```

## Auto-linking policy (important)

Both federation templates set `autoLinking: AUTO_LINKING_OPTION_EMAIL`. ZITADEL
will only auto-link when the incoming assertion carries a **verified** email
that matches exactly one existing account. The account-unification service
(this repo) enforces the stricter rule end-to-end: **never link or merge on an
unverified email** — see `docs/merge-unification-flow.md`.

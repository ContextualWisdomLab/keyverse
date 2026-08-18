# Authorization-plane onboarding

Keyverse issues identity plus authorization attributes and decisions. Orgmetra
remains the employment-tree system of record. Each relying party remains the
PEP and must validate the Keyverse token (ADR-0008) before enforcing a local
decision.

This page is the buyer-facing next action for the six capabilities in
ADR-0010, ADR-0011, and ADR-0012. It does not claim production federation or
login acceptance.

## 1. Bind a subject, do not copy the org tree

Ask Orgmetra for the current `assignment_record` and send Keyverse a snapshot:

```json
{
  "keyverse_subject": "opaque-keyverse-subject",
  "org_path": "/group_company/acme/legal_entity/holdco/business_unit/sales/team/alpha/person/jdoe",
  "assignment_record_id": "assignment-record-77",
  "request_attributes": {"purpose": "hr-review"}
}
```

Hierarchical names are `group_company`, `legal_entity`, `business_unit`,
`team`, `person`, and `org_path`. Do not send LineageWeave `role`, `org`, or
`workspace` as path levels; those names stay reserved for PR #100.

## 2. Software-unit ACL

```bash
curl --config "$AUTH_CONFIG" --request PUT \
  --header "Content-Type: application/json" \
  --data-binary @software-unit-grant.json \
  "$KEYVERSE_ADMIN/authorization/software-unit-grants/acme-naruon"

curl --config "$AUTH_CONFIG" --request POST \
  --header "Content-Type: application/json" \
  --data-binary @software-unit-decide.json \
  "$KEYVERSE_ADMIN/authorization/software-units:decide"
```

A grant at `/group_company/acme` allows descendants unless a more-specific
deny exists. Default is deny.

## 3. Menu ABAC + RBAC

PUT a menu grant with `capability_codes` and optional `purpose` /
`sensitivity` / `clearance` / `residency` constraints, then
`POST /authorization/menus:decide`. Software-unit allow is required first.
The RP still enforces the decision locally.

## 4. SSO combination

PUT `/authorization/sso-combination-scopes/finance-suite` with two or more
software units. `POST /authorization/sso-combinations:decide` allows the
combination only when every member software unit is allowed. The Keycloak
session stays in Keycloak; this only authorizes the selected RP set.

## 5. How an RP starts federation

1. Register the employer IdP through the existing federation desired-state
   APIs (`docs/federation-onboarding.md`).
2. From the application (or its deployment helper) call:

```bash
curl --config "$AUTH_CONFIG" --request POST \
  --header "Content-Type: application/json" \
  --data '{"software_unit_id":"naruon-web","client_id":"naruon-web","redirect_uri":"https://naruon.example/callback","provider_alias_hint":"employer-adfs"}' \
  "$KEYVERSE_ADMIN/federation/identity-providers:start-login"
```

3. Add PKCE `S256`, `state`, and `nonce` in the application.
4. Redirect the browser to `start_login_url`. Do not fetch IdP metadata from
   the app. Federation ownership stays in Keyverse.

## 6. How a PAT is minted and scoped

```bash
curl --config "$AUTH_CONFIG" --request POST \
  --header "Content-Type: application/json" \
  --data '{"software_unit_id":"naruon-web","purpose_code":"machine_api","capability_codes":["api.invoices.read"],"lifetime_seconds":3600,"actor_identity_id":"operator-ida"}' \
  "$KEYVERSE_ADMIN/application-tokens"
```

Store `plaintext_token` in the application's secret manager and discard the
response. Present the token only to `POST /application-tokens:verify` with
the same software unit and requested API capabilities. Rotate or revoke
instead of treating the token as a password. Tokens never inherit org-tree
grants.

Keep bearer tokens out of `curl` process arguments; use a private `--config`
file as in `docs/rp-onboarding.md`.

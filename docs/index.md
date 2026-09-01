# Keyverse

Keyverse is ContextualWisdomLab's passwordless identity, federation, provisioning, and account-unification service. It provides standards-based identity for ecosystem applications while keeping relying-party authorization and organization-of-record responsibilities explicit.

## Start here

- [Repository overview and standalone quickstart](https://github.com/ContextualWisdomLab/keyverse#readme)
- [Architecture and trust boundaries](https://github.com/ContextualWisdomLab/keyverse/blob/main/ARCHITECTURE.md)
- [Relying-party onboarding](rp-onboarding.md)
- [Federation onboarding](federation-onboarding.md)
- [LDAP directory onboarding](ldap-directory-onboarding.md)
- [Passwordless policy](passwordless-policy.md)
- [Architecture decisions](adr/README.md)
- [Standards references](REFERENCES.md)
- [Product and technical gap baseline](product-technical-gap-baseline.md)
- [Repository releases](https://github.com/ContextualWisdomLab/keyverse/releases)
- [Ask DeepWiki](https://deepwiki.com/ContextualWisdomLab/keyverse)

## Product responsibility

Keyverse owns the ecosystem identity boundary: passwordless local accounts, inbound identity federation, inbound SCIM provisioning, relying-party registration, identity linking and account unification, and issuance of OIDC/OAuth tokens to registered applications. It supports SAML, LDAP/Active Directory, OIDC, SCIM 2.0, FIDO2/WebAuthn passkeys, and Keycloak-backed deployment profiles.

Organization and employment truth remains outside this service; relying applications remain responsible for validating issued credentials and enforcing their own resource and tenant authorization policy. Keyverse integrates those authorities without duplicating them.

## Onboarding

For a local evaluation, follow the root README to start the repository's Docker or Podman Compose stack. Production-shaped deployments use the repository Helm chart. Application teams should begin with the relying-party onboarding guide; federation operators should use the federation and directory onboarding guides and keep customer-specific credentials in the deployment secret boundary.

## Security and evidence

Keyverse is passwordless-first and treats each relying party and external identity source as a separate trust boundary. Published capability claims should be read against protected-branch implementation and release evidence; active pull requests are not treated as shipped product behavior.

## License

Keyverse source is licensed under the [Apache License 2.0](https://github.com/ContextualWisdomLab/keyverse/blob/main/LICENSE). Third-party components retain their own license obligations.

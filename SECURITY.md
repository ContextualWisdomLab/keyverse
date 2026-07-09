# Security Policy

## Supported Versions

The `main` branch receives security fixes. Tagged releases are supported until
their successor is published.

## Reporting a Vulnerability

Please report suspected vulnerabilities privately through the repository's
[GitHub Security Advisory intake](https://github.com/ContextualWisdomLab/keyverse/security/advisories/new)
rather than opening a public issue. The direct reporting URL is:

https://github.com/ContextualWisdomLab/keyverse/security/advisories/new

Include affected version, reproduction steps, and impact.

Disclosure handling SLA: we aim to acknowledge vulnerability reports within 3
business days, provide a status update within 30 days when a fix needs longer
coordination, and ship a fix or mitigation for confirmed high/critical issues as
quickly as practical.

## Scope

This is the central identity provider (Keycloak-based) for the ecosystem. Secrets
are sourced from the KV/secret manager at deploy time, never committed. Dependency
and filesystem findings are tracked by the organization's central `osv-scan` and
`trivy-fs` gates. Confirmed vulnerabilities and runtime hardening findings are
fixed at the source. Registry allow-list policy for digest-pinned upstream images
is documented in `.trivyignore` and should be enforced centrally with Trivy
`--config-data` or admission control in production.

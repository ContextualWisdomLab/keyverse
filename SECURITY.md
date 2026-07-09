# Security Policy

## Supported Versions

The `main` branch receives security fixes. Tagged releases are supported until
their successor is published.

## Reporting a Vulnerability

Please report suspected vulnerabilities privately via GitHub Security Advisories
at https://github.com/ContextualWisdomLab/keyverse/security/advisories/new rather
than opening a public issue. Include affected version, reproduction steps, and
impact.

We aim to acknowledge reports within 3 business days and to ship a fix or
mitigation for confirmed high/critical issues as quickly as practical.

## Scope

This is the central identity provider (Keycloak-based) for the ecosystem. Secrets
are sourced from the KV/secret manager at deploy time, never committed. Dependency
and filesystem findings are tracked by the organization's central `osv-scan` and
`trivy-fs` gates. Confirmed vulnerabilities and runtime hardening findings are
fixed at the source. Registry allow-list policy for digest-pinned upstream images
is documented in `.trivyignore` and should be enforced centrally with Trivy
`--config-data` or admission control in production.

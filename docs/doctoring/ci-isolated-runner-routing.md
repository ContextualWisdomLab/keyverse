# Local CI isolated-runner routing

**Date:** 2026-10-04 (updated 2026-10-06)
**Status:** Active source routing; runner ephemerality and egress allowlist pending

## Measured cause and bounded repair

PR143 head `0066598098263bd0064e199c9ddb6279913e1ba0` Ready event produced
CI run `37183133580`. GraphQL check annotations for each of the three jobs
state that the job did not start because the account was locked for a billing
issue. That is pre-execution admission failure, not a product test failure.

The existing organization self-hosted migration direction supplies a safe
source contract: `.github#2565` at `ab0c865989012c88d2c10c717f6649a76ea49e27`
uses dedicated group `CWL CI isolated` plus isolation/platform labels. The
current Keyverse proposal uses that exact group and Linux/x64 capability shape,
not a label-only match or privileged central control pool. All three check
names, command blocks, Python 3.12 contract, pins, permissions and event guards
are retained. Checkout explicitly disables credential persistence.

Two source-contract tests failed before changes: hosted selector instead of
exact group/labels, and missing `persist-credentials: false`. Both pass after
changes. These static controls prove intended source selection, not successful
GitHub runner assignment or execution. Existing full gates must run on the
complete final candidate and hosted current head.

## Authority and operation boundary

GitHub documents groups as runner-access organization boundaries; labels narrow
capability selection within the group. Neither selected labels nor YAML proves
machine isolation. Public/fork PR code must not use persistent privileged
runners. `persist-credentials: false` prevents checkout from retaining its
read token for later Git use; it is not a claim that a runner is credential-free
or that trusted GitHub actions never receive their normal job token.

Existing operator issue `linux-cluster-ops#326` retains disposable capacity,
private-service denial, clean-per-job state, registration custody, minimum
repository access, tool-image and real canary requirements. Its observed
credential-free point probes do not establish complete kernel-enforced denial
or a registered eligible pool.
No billing purchase, credential change, protected-gate weakening or release is
performed by this source repair.

## Observed activation and fork boundary (2026-10-06)

The group `CWL CI isolated` now holds runner VMs `keyverse-ci-01` and
`orgmetra-ci-01` on host S1. Each VM runs QEMU as an unprivileged user under an
egress firewall that rejects loopback, link-local and RFC 1918 destinations.
On PR143 head `2728b04493f17eb5256533448875398fb1325056`, CI run `37441958351`
ran all three jobs on these runners, and all three succeeded.

These runners are persistent, not ephemeral, and public internet egress is
open. Code from one job can therefore leave state that a later job observes.
GitHub states that self-hosted runners "can be persistently compromised by
untrusted code in a workflow" and "should almost never be used for public
repositories" (GitHub, n.d., Secure use reference). The workflow consequently
admits a pull request only when
`github.event.pull_request.head.repo.full_name == github.repository`; fork pull
request code never runs on these runners. A contract test pins this guard on
all three jobs and rejects `pull_request_target` and `workflow_run` triggers.
Ephemeral (`--ephemeral`) registration with per-job VM reset and a destination
allowlist remain operator follow-ups before fork contributions can be tested
on this capacity.

The separate hourly product-development workflow is unchanged and is not part
of this three-job routing claim; do not claim organization-wide migration.

## References — APA 7th

GitHub. (n.d.). *Managing access to self-hosted runners using groups*. GitHub
Docs. Retrieved October 4, 2026, from
https://docs.github.com/en/actions/how-tos/manage-runners/self-hosted-runners/manage-access

GitHub. (n.d.). *Choosing the runner for a job*. GitHub Docs. Retrieved October
4, 2026, from
https://docs.github.com/en/actions/how-tos/write-workflows/choose-where-workflows-run/choose-the-runner-for-a-job

GitHub. (n.d.). *Checkout* [Source code documentation]. Retrieved October 4,
2026, from https://github.com/actions/checkout/blob/main/README.md

GitHub. (n.d.). *Secure use reference: Hardening for self-hosted runners*.
GitHub Docs. Retrieved October 6, 2026, from
https://docs.github.com/en/actions/reference/security/secure-use#hardening-for-self-hosted-runners

ContextualWisdomLab. (2026). *All self-hosted runner routing* (.github PR #2565,
source snapshot `ab0c865989012c88d2c10c717f6649a76ea49e27`).
https://github.com/ContextualWisdomLab/.github/pull/2565

ContextualWisdomLab. (2026). *Register isolated ContextualWisdomLab Actions runner
on s1 (not b1-b5)* (linux-cluster-ops issue #326).
https://github.com/ContextualWisdomLab/linux-cluster-ops/issues/326

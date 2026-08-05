# Keyverse Hourly OpenCode Product Development Implementation Plan

**Goal:** Create one independently verified NVIDIA NIM OpenCode draft PR per
eligible hour without changing review-agent credentials or protected merge
criteria.

- [x] Replace cloud-agent task creation with a three-job OpenCode pipeline.
- [x] Broker `NVIDIA_NIM_API_KEY` outside the untrusted model environment.
- [x] Run OpenCode from a no-`.git`, UID/GID 65532, `env -i` workspace.
- [x] Bound paths, files, lines, bytes, modes, links, binary content, and secret
  representations in both worktree and patch validation.
- [x] Require each autonomous proposal to include production code, tests, and
  `CHANGELOG.md`.
- [x] Reverify the sealed patch on a fresh exact-main checkout.
- [x] Enforce 100% production docstring, statement, and branch coverage.
- [x] Permit exact PyPI package endpoints in both jobs that execute locked
  dependency installation.
- [x] Use exact parsed endpoint equality in workflow security contracts.
- [x] Publish only one draft PR through a dedicated development token.
- [x] Preserve standalone and CWL/Naruon module compatibility.
- [x] Add APA 7th standards traceability under `docs/doctoring`.
- [ ] Obtain successful exact-head CI, CodeQL, Semgrep, Security Scan, and
  current-head review evidence.
- [ ] Resolve every actionable review thread.
- [ ] Merge without administrative bypass.
- [ ] Confirm the schedule exists on `main`, configure the two dedicated
  development secrets, and re-list the PR queue.
- [ ] When the queue is empty, let the hourly loop select the next buyer-visible
  product gap and return it through the normal protected PR path.

# PAT rotation-lineage implementation plan

Scope: successor of the sealed one-event metadata candidate, underlying base
6074908c37be1c82a492bfaeef30086cf37768a6. Production edits only audit.py and
application_tokens.py; no generic API, auth, KV, schema, issuer or PDP change.

- [x] Real one-rotation missing-callable AssertionError RED on memory and SQLite.
- [x] Minimal service/logger/sink implementation; unchanged one-rotation GREEN.
- [x] Vertical strict query RED→GREEN before capability access.
- [x] Legacy projection/coverage RED→GREEN, no inferred predecessor.
- [x] Global rotation decoder corruption RED→GREEN with real sinks.
- [x] Optional unsupported capability RED→GREEN, original protocol unchanged.
- [x] Custom facade/DTO semantic validation RED→GREEN.
- [x] Fixed storage error and direct sink failure RED→GREEN.
- [x] Real snapshot barrier, adjacent chain/order, lifecycle/secret/profile controls
      recorded as first-GREEN characterization where already satisfied.
- [x] Service revalidation and memory capture failure RED→GREEN.
- [ ] Final exact-source focused/full, production statement/branch100, Ruff,
      docstrings100, compile and independent whole-union review.
- [ ] Protected integration/release (outside this private implementation scope).

Use existing pinned Python3.12.13 with direct python -B -m pytest from the private
service, no runpy or installs. Strip GIT* and PYTHONPATH from workload environment;
retain launch PID/group, exact waits, source hashes and raw logs. Owned loopback
fixture only, no external provider/network or native DB service. Tests and docs
remain repository-discoverable; private receipts are evidence, not CI adoption.

## F1/F2 first fix-and-reverify successor

- [x] F1 direct logger/injected-service intended AssertionError RED8 -> GREEN8.
- [x] F2 four exact stored-field intended AssertionError RED4 -> GREEN12.
- [x] Discriminator sibling RED3 plus first-GREEN foreign-class control -> GREEN16.
- [x] Additional known-code/unsafe formatting/property/interruption controls are
      first-GREEN characterization, not new behavioral RED.
- [ ] Exact-final focused/full/coverage100/lint/docstrings100/compile/build.
- [ ] Fresh independent whole accumulated-source review by the parent.

The first F2 launch failed on a fixture module import before reaching behavior;
its receipt is retained and excluded from intended RED. No live adoption,
commit, push, provision, external provider or dependency installation is allowed.

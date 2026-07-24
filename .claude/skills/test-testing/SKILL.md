---
name: test-testing
description: Validate that an expensive integration/upgrade test actually catches the failure it claims to — by injecting a minimal, targeted fault and confirming the EXPECTED evidence appears in the logs, then reverting. Guards against tests that pass vacuously. Key idea most people miss: the injected failure is often RECOVERABLE (the system detects and excludes it and the test still PASSES), so the log evidence — not the exit code — is the real assertion. Use before trusting a green cluster / upgrade-suite run as proof of wire/state compatibility or malicious-party detection.
user-invocable: true
---

Validate that a slow, opaque integration test (upgrade-suite scenarios,
cluster/simtest) actually catches the failure it claims to:
inject a minimal fault that *should* trip the property, confirm the
**predicted log evidence** appears, then revert. A green run alone proves
nothing — the catch is often recoverable, so the test passes either way and
the log line is the real assertion.

Target: $ARGUMENTS (the property/test to validate, e.g. "upgrade-suite state
continuity" or "honest validators reject a faulty one"). If empty, ask which
test and which property.

Full methodology — the two outcome shapes (hard-fail vs recoverable), the
7-step loop, which side to inject, the specificity control, and two worked
ika examples (historical: cross_binary state continuity; cross-binary malicious-party
detection) — lives in [`dev-docs/playbooks/test-testing.md`](../../../dev-docs/playbooks/test-testing.md).
Read it and follow it; don't reinvent the methodology ad hoc.

The non-negotiables:

- **The log is the assertion, not the exit code.** Predict the exact log
  string and which node's log it lands in *before* running; gate on grepping
  for it at `$UPGRADE_TEST_DIR/validator-*/node.log`.
- **Pick the injection side deliberately** — producer output vs a party's
  outgoing round message are not interchangeable.
- **Check specificity** — only the faulty output/party should be rejected
  while the rest stays healthy; blanket failure means you're measuring
  collateral breakage, not the property.
- **Revert every fault artifact** — mark edits `// TEST-TESTING FAULT
  (temporary — DO NOT MERGE)`; afterwards `git status` is clean and
  `grep -r "TEST-TESTING FAULT"` is empty.

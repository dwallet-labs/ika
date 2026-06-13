---
name: stall-postmortem
description: Ordered diagnosis for "MPC stopped making progress" — wedged epochs, cascading SDK timeouts, quorum silence. Runs the dev-docs playbook checks against a localnet/validator log.
user-invocable: true
---

Diagnose the MPC stall in the log at `$ARGUMENTS` (a localnet/validator
log file, or a CI run ID whose `localnet-logs` artifact should be
downloaded first).

Execute `dev-docs/playbooks/mpc-stall-postmortem.md` — the checks are
ORDERED and each either identifies the stall class or eliminates it; do
not skip ahead, and do not stop at the first anomaly without finishing
the cheap checks (co-resident bugs have occurred):

0. Timeline anchors (highest epoch, lock/EOP lines, last quorum).
1. Malicious conviction FIRST (`recognized itself as malicious`).
2. Started-vs-completed computation balance per validator.
3. Epoch-entry key-gap warns (`Adopted network key epoch does not match`).
4. Chain counters: completed vs frozen lock target (over/undershoot).
5. Which pipeline stages still flow (votes / admission / serving / sync).
6. Trace ONE stuck session end-to-end across all validators.

Report: stall onset timestamp, the first check that fired, the
mechanism with log-line evidence, and whether it matches a known class —
issue #1736 (epoch-entry stale-mpc_data race) or a fixed class in
`dev-docs/learnings/pitfalls.md`. State explicitly what the evidence
CANNOT determine (e.g. debug-level lines absent at info-level logging).

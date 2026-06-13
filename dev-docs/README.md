# dev-docs — engineering context for humans and AI agents

`docs/` is the public docs website; this folder is the engineering
knowledge base: protocol specs, debugging playbooks, conventions, and
hard-won pitfalls. It is written to be **agent-legible** — concrete,
copy-pasteable commands and decision rules rather than prose — because
both engineers and AI coding agents consume it.

## How this relates to CLAUDE.md / AGENTS.md

`CLAUDE.md` (and `AGENTS.md`, a symlink to it for other AI tools) is
loaded into every agent session, so it carries only the always-applicable
rules and points here for everything else. Files in this folder are read
**on demand** — when a task touches the relevant subsystem. Keep it that
way: adding a file here costs nothing per-session; adding a section to
CLAUDE.md costs every session and dilutes the rules already there.

Maintenance rule (same as specs): documentation here is part of the
change, not documentation debt. A PR that changes behavior described
here updates the file in the same PR.

## Index

### specs/ — protocol behavioral contracts
The protocol-level contract per subsystem: actors, messages, decision
rules, invariants, failure modes. **Read the relevant spec before
changing a subsystem it covers.** When spec and code disagree, one of
them has a bug — determine which before changing either.

- [`specs/validator-mpc-data-announcements.md`](specs/validator-mpc-data-announcements.md)
  — off-chain mpc_data pipeline: announcements, P2P, ready signals,
  the freeze decision, next-committee assembly.
- [`specs/handoff.md`](specs/handoff.md) — cross-epoch handoff:
  attestation, EndOfPublish V2, certificate, joiner bootstrap, the
  prepare-then-start barrier, network-key adoption guards.
- [`specs/epoch-close-session-lock.md`](specs/epoch-close-session-lock.md)
  — the frozen session-completion target, the strict-equality close
  predicate, the gate-consensus-submission rule, batch-processing rules.

### playbooks/ — how to run and debug this system
- [`playbooks/ci-suites.md`](playbooks/ci-suites.md) — running the heavy
  test suites on CI instead of locally: dispatch commands, runtimes,
  artifact recovery, runner facts.
- [`playbooks/mpc-stall-postmortem.md`](playbooks/mpc-stall-postmortem.md)
  — the check-ordered diagnosis procedure for "MPC stopped making
  progress", distilled from real wedge investigations.
- [`playbooks/localnet.md`](playbooks/localnet.md) — running a
  Sui+ika localnet for SDK/integration testing without the traps.
- [`playbooks/production-alerts.md`](playbooks/production-alerts.md) —
  the alert rules for the designed halt/block modes (barrier wait,
  wedged assembly, bootstrap fail-closed) that look healthy from
  outside, plus secondary dashboard signals.

### conventions/ — repo-specific procedures
- [`conventions/sui-version-bump.md`](conventions/sui-version-bump.md)
  — every location the Sui version lives and the bump procedure
  (enforced by `scripts/check-sui-version-consistency.sh` in CI).
- [`conventions/simtest.md`](conventions/simtest.md) — what simtest is,
  why it is slow by design, when to use it vs `#[tokio::test]`, and the
  msim gotcha catalogue.
- [`conventions/dead-code-cleanup.md`](conventions/dead-code-cleanup.md) —
  auditing/removing unused Rust: why the compiler can't see unused `pub`
  items, how to classify candidates in a Sui fork, and gating dependency
  removals on a build (with that build's blind spots).

### learnings/ — pitfalls that cost real debugging time
- [`learnings/pitfalls.md`](learnings/pitfalls.md) — non-obvious failure
  classes found in this codebase, each with the general rule it taught.

### plans/ — implementation plans worth keeping in the repo
Multi-PR / multi-session efforts with an explicit status lifecycle
(`active → landed/superseded/abandoned`). Intent and sequencing live
here; once landed, durable behavior moves to `specs/`. See
[`plans/README.md`](plans/README.md).

### reviews/ — written reviews worth keeping in the repo
Long-form PR reviews, design reviews, and audits — point-in-time
RECORDS with per-finding resolutions, not maintained truth (that's
`specs/`). See [`reviews/README.md`](reviews/README.md).

## Writing style for this folder

- Lead with the decision rule or command, not background.
- Commands must be copy-pasteable as written.
- Anchor claims to code (`file.rs:symbol`) or to a PR/issue, so a reader
  can verify rather than trust.
- Record the *general class* of a bug, not just the instance — the next
  occurrence will wear a different costume.

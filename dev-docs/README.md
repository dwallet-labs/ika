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

### Top-level audits
- [`preserved-epoch-state-audit.md`](preserved-epoch-state-audit.md) — what
  the per-epoch store still keeps on disk and what a replay would have to
  redo to rebuild each of it, plus the non-determinism audit of the fold.
  Everything else an epoch derives is in memory by construction. Read with
  [`specs/event-sourced-epoch.md`](specs/event-sourced-epoch.md).

### specs/ — protocol behavioral contracts
The protocol-level contract per subsystem: actors, messages, decision
rules, invariants, failure modes. **Read the relevant spec before
changing a subsystem it covers.** When spec and code disagree, one of
them has a bug — determine which before changing either.

- [`specs/event-sourced-epoch.md`](specs/event-sourced-epoch.md) — the
  consensus store as the only truth for epoch-scoped state: derived state
  held in memory, the bounded-batch replay that rebuilds it, why there is no
  watermark, the determinism contract, what the fold accumulates and what
  bounds it, the settled-state rule for replay-silent emission, and what a
  mid-epoch rollback measurably cost at v1.4.0 (historical — that gate is
  gone).
- [`specs/validator-mpc-data-announcements.md`](specs/validator-mpc-data-announcements.md)
  — off-chain mpc_data pipeline: announcements, P2P, ready signals,
  the freeze decision, next-committee assembly.
- [`specs/handoff.md`](specs/handoff.md) — cross-epoch handoff:
  attestation, EndOfPublish V2, certificate, joiner bootstrap, the
  prepare-then-start barrier, network-key adoption guards.
- [`specs/epoch-close-session-lock.md`](specs/epoch-close-session-lock.md)
  — the frozen session-completion target, the strict-equality close
  predicate, the gate-consensus-submission rule, batch-processing rules.
- [`specs/checkpoint-sync-floor.md`](specs/checkpoint-sync-floor.md)
  — why pull-mode checkpoint sync starts from the on-chain processed
  cursor (a fresh-DB notifier can never fetch deep history from peers),
  the cold-start deferral, why a validator's aggregator floors at the
  previous epoch's last checkpoint, and the gap-tolerant store invariants.
- [`specs/checkpoint-writer-observability.md`](specs/checkpoint-writer-observability.md)
  — the deliberate single-notifier write path, why a stalled writer
  blocks the epoch close, and the two stall signals (the notifier's
  sync-stall self-report; validators' `checkpoint_writer_lag`
  blocked-reason attribution).
- [`specs/notifier-balance-gas.md`](specs/notifier-balance-gas.md)
  — the writer's two gas modes: default gas-coin payment (and the
  stale-gas caching apparatus it requires) vs. opt-in SIP-58
  address-balance gas (`ValidDuring`, no gas objects, no stale-version
  failure class), with rollout preconditions.
- [`specs/cross-binary-upgrade.md`](specs/cross-binary-upgrade.md) —
  the in-place protocol-version upgrade contract: the stake-weighted
  version vote, the wire/on-disk compatibility invariants for mixed
  committees, the session-completion wedge, and when a rolling swap is
  valid vs. when the crypto boundary forces an atomic restart.
- [`specs/fast-schnorr-vss.md`](specs/fast-schnorr-vss.md) — the Fast
  Schnorr (VSS) signing feature: the three VSS algorithms and their
  curve/algorithm numbering, the version-3 PVSS key bundle and its
  off-chain transport, the V3 presign/sign flow, the retired
  `fast_schnorr_supported` gate, and what is internal-NOA-only vs. the
  still-gated external path.
- [`specs/committee-consensus-keys.md`](specs/committee-consensus-keys.md)
  — a validator's identity IS its Ed25519 consensus key; the BLS key is a
  separate, non-derivable fact `Committee` must carry. The same-snapshot
  rule binding a signer's key to its stake, what consensus-key rotation
  still costs, and the mainnet-v1.1.8 on-disk migration for the mid-struct
  field.
- [`specs/ocs-verified-sui-reads.md`](specs/ocs-verified-sui-reads.md) —
  object-checkpoint-state: reading Sui without trusting the relay
  (genesis-rooted committee trust root, the epoch ratchet,
  dynamic-field/parent binding), what each read is actually bound to, and
  why the opt-in keys off config SHAPE rather than a protocol version.
- [`specs/trusted-peer-discovery.md`](specs/trusted-peer-discovery.md) —
  how a peer-only validator gets dialed and boots with no static seed
  peers: the continuous feed of active/next/previous committee +
  `pending_active_set` into anemo `known_peers`, the inbound-dial
  bootstrap, and the `ExtendedField` BCS framing the read depends on.
- [`specs/internal-presign-pool.md`](specs/internal-presign-pool.md) —
  the internal presign pool: fill and drain paths, why out-of-sequence
  fills make a restart's full-epoch round replay bind different presigns
  than never-crashed peers, and the fill/serve idempotency rule that
  keeps a restarted validator's checkpoint messages byte-identical.

### playbooks/ — how to run and debug this system
- [`playbooks/ci-suites.md`](playbooks/ci-suites.md) — running the heavy
  test suites on CI instead of locally: dispatch commands, runtimes,
  artifact recovery, runner facts.
- [`playbooks/mpc-stall-postmortem.md`](playbooks/mpc-stall-postmortem.md)
  — the check-ordered diagnosis procedure for "MPC stopped making
  progress", distilled from real wedge investigations.
- [`playbooks/mpc-anomaly-diagnostics.md`](playbooks/mpc-anomaly-diagnostics.md)
  — anomaly-only MPC session snapshots: trigger conditions, malicious-source
  attribution, bounded/redacted fields, example output, and library limits.
- [`playbooks/test-testing.md`](playbooks/test-testing.md) — prove an
  expensive integration/upgrade test actually catches its failure: inject a
  minimal fault, grep the predicted log evidence (the exit code is not the
  assertion — the catch is often recoverable), then revert. Backs the
  `/test-testing` skill.
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
- [`conventions/sui-client-dependencies.md`](conventions/sui-client-dependencies.md)
  — which Sui client layer to use: standalone `sui-rust-sdk` for network
  RPC, the narrow wallet/consensus cases that still require Sui main, why
  gRPC is the only Sui transport (JSON-RPC is gone), and the node-wide
  shared rate-limit gate every call passes.
- [`conventions/naming.md`](conventions/naming.md) — naming things that
  outlive their context: always the full word "reconfiguration", and no
  internal labels (plan/phase names, ticket shorthands, invented test IDs)
  in anything durable — with the line that makes the rule usable, since an
  issue or PR number is fine.
- [`conventions/simtest.md`](conventions/simtest.md) — what simtest is,
  why it is slow by design, when to use it vs `#[tokio::test]`, and the
  msim gotcha catalogue.
- [`conventions/dead-code-cleanup.md`](conventions/dead-code-cleanup.md) —
  auditing/removing unused Rust: why the compiler can't see unused `pub`
  items, how to classify candidates in a Sui fork, and gating dependency
  removals on a build (with that build's blind spots).
- [`conventions/metrics.md`](conventions/metrics.md) — the Prometheus
  metric-name ratchet (`ika_` prefix, CI-enforced via
  `scripts/check-metric-names.sh`), the counter `_total` / gauge / label
  conventions (new protocols auto-instrument through the exhaustive
  `[curve, signature_algorithm, key_role]` labels), and a generated name
  inventory.
- [`conventions/consensus-output-consumption.md`](conventions/consensus-output-consumption.md)
  — the rules for getting data out of consensus: the store is the only
  durable truth, the fold is its only reader, consumers receive rounds over
  bounded blocking channels, and the two commit sinks that are fed at
  deliberately opposite points. Read before adding any consumer of
  per-commit data.
- [`conventions/epoch-table-write-discipline.md`](conventions/epoch-table-write-discipline.md)
  — every `AuthorityEpochTables` field declares whether it is written
  through the commit boundary or directly (and, if directly, the
  reason its consumers survive that); the reader-side rule that #1917 was
  actually born on, and the one table whose argument does not close.
  CI-enforced via `scripts/check-epoch-table-write-discipline.sh`.
- [`conventions/chain-mirror-layout.md`](conventions/chain-mirror-layout.md)
  — the three Rust structs that are UNTAGGED mirrors of deployed Move
  structs, why a verified read proves provenance but never shape, and the
  six things that move together when one of them changes. CI-enforced via
  `scripts/check-chain-mirror-layout.sh` plus golden layout tests in
  `ika-types`.
- [`conventions/logging.md`](conventions/logging.md) — the `tracing`
  log-level discipline: hot MPC paths are `debug!`, once-per-epoch
  lifecycle events are `info!`; why an `info!` on the per-computation
  path makes validator logs unreadable under load.
- [`conventions/enforce-minimum-cpu.md`](conventions/enforce-minimum-cpu.md)
  — the 16-core minimum's decision rule (feature compiled in + validator
  mode + ika testnet/mainnet), which builds must KEEP the old
  `--no-default-features` workaround, and the chain-override interaction.

### learnings/ — pitfalls that cost real debugging time
- [`learnings/pitfalls.md`](learnings/pitfalls.md) — non-obvious failure
  classes found in this codebase, each with the general rule it taught.

### reference/ — pointers to external sources worth consulting
- [`reference/sui-upstream.md`](reference/sui-upstream.md) — ika is forked
  from Sui; how to find the pinned Sui source (locally + on GitHub) and
  what to read in it for forked subsystems and consensus (Mysticeti =
  Sui's `consensus/core`).

### plans/ — implementation plans worth keeping in the repo
Multi-PR / multi-session efforts with an explicit status lifecycle. Intent
and sequencing live here; once landed, durable behavior moves to `specs/`
and the plan moves to `plans/archive/`. Two plans are currently live, both
deferred: the handoff-barrier escape and the OCS subscription changeset
stream. See [`plans/README.md`](plans/README.md).

### reviews/ — written reviews worth keeping in the repo
Long-form PR reviews, design reviews, and audits — point-in-time
RECORDS with per-finding resolutions, not maintained truth (that's
`specs/`). All of them are closed and live under `reviews/archive/`. See
[`reviews/README.md`](reviews/README.md).

**Nothing under `plans/archive/` or `reviews/archive/` is current truth.**
Each archived file opens with a note saying what it was, when, and where the
behavior it describes is specified now. Read the note before the file — some
archived documents are deliberately preserved records of designs that were
later reversed.

## Writing style for this folder

- Lead with the decision rule or command, not background.
- Commands must be copy-pasteable as written.
- Anchor claims to code (`file.rs:symbol`) or to a PR/issue, so a reader
  can verify rather than trust.
- Record the *general class* of a bug, not just the instance — the next
  occurrence will wear a different costume.

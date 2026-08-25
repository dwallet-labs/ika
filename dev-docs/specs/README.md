# Ika protocol specs

Behavioral specifications for ika subsystems — the protocol-level
contract (actors, messages, decision rules, invariants, failure modes),
written to be readable without the code open. Code references are
anchors, not the content: when the spec and the code disagree, one of
them has a bug — figure out which before "fixing" either.

## Maintenance rule

These specs are part of the change, not documentation debt. A PR that
changes the behavior described in a spec updates that spec in the same
PR. A PR that adds a new consensus message, a new cross-epoch invariant,
or a new decision rule either extends an existing spec or adds a file
here.

## Files

- [`ocs-verified-sui-reads.md`](ocs-verified-sui-reads.md) — OCS
  verified Sui reads: the committee-BLS → artifacts-digest → Merkle
  trust chain, node roles and the config-shape transport gate, the
  trust-anchor bootstrap and committee ratchet, freshness/rollback
  protection, the verified bag-walk + event pump, and the untrusted
  relay protocol (peer-only validators included).
- [`event-sourced-epoch.md`](event-sourced-epoch.md) — the consensus store
  as the only truth for epoch-scoped state: derived state held in memory,
  the bounded-batch boot replay that rebuilds it, why there is no
  watermark, the determinism contract, what the fold accumulates and what
  bounds it, the settled-state rule for replay-silent emission, and what a
  mid-epoch rollback actually cost at v1.4.0 (historical — that gate is
  gone).
- [`validator-mpc-data-announcements.md`](validator-mpc-data-announcements.md)
  — the off-chain validator MPC-data pipeline: blob derivation,
  consensus announcements, P2P propagation, ready signals, the freeze
  decision, and next-committee assembly.
- [`handoff.md`](handoff.md) — the cross-epoch handoff: the attestation,
  EndOfPublish V2, certificate aggregation and persistence, joiner
  bootstrap, and the prepare-then-start barrier.
- [`epoch-close-session-lock.md`](epoch-close-session-lock.md) — the
  epoch-close session lock: the frozen completion target, the
  strict-equality close predicate, the gate-consensus-submission rule
  every user-session completion path must follow, and the
  batch-processing rule for computation results.
- [`committee-consensus-keys.md`](committee-consensus-keys.md) — the two
  per-validator keys (BLS identity vs Ed25519 consensus key), why the
  mapping is carried as `Committee` data rather than derived, the
  same-snapshot rule for key and stake, and the 1.1.8 on-disk migration.
- [`cross-binary-upgrade.md`](cross-binary-upgrade.md) — the in-place
  protocol-version upgrade contract: the stake-weighted version vote, the
  wire/on-disk compatibility invariants a mixed committee must preserve,
  the session-completion wedge, and when a rolling swap is valid vs. when
  the crypto boundary forces an atomic restart.
- [`fast-schnorr-vss.md`](fast-schnorr-vss.md) — Fast Schnorr (VSS)
  signing: the three VSS algorithms and their curve/algorithm numbering,
  the version-3 PVSS key bundle and its off-chain transport, the V3
  presign/sign flow, and what is internal-NOA-only vs. still gated.
- [`checkpoint-sync-floor.md`](checkpoint-sync-floor.md) — why pull-mode
  checkpoint sync starts from the on-chain processed cursor (a fresh-DB
  notifier can never fetch deep history from peers), the cold-start
  deferral, and the gap-tolerant store invariants.
- [`checkpoint-writer-observability.md`](checkpoint-writer-observability.md)
  — the deliberate single-notifier write path, why a stalled writer blocks
  the epoch close, and the two stall signals.
- [`trusted-peer-discovery.md`](trusted-peer-discovery.md) — how a
  peer-only validator gets dialed and boots with no static seed peers:
  the continuous committee + `pending_active_set` feed into anemo
  `known_peers`, the inbound-dial bootstrap, and the `ExtendedField` BCS
  framing the read depends on.
- [`internal-presign-pool.md`](internal-presign-pool.md) — how the
  internal presign pool is filled and drained, why out-of-sequence fills
  make a restart's full-epoch replay bind different presigns than peers,
  and the fill/serve idempotency rule that keeps a restarted validator's
  checkpoint messages byte-identical.

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

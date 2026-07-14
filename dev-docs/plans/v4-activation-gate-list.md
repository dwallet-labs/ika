Status: active (updated 2026-07-12) — all in-scope fixes are now open PRs
awaiting review (#1820–#1827); the barrier/close-gate cluster is deliberately
deferred with its own plan (see below). Flip to `landed` when the fix PRs
merge and the deferred cluster has an owner.

# Protocol-v4 activation gate list

Every issue here ships **dark** in 1.2.0 (the paths are v4-gated) but protocol
v4 **activates automatically** ~one epoch after enough stake runs a
v4-advertising binary — validators advertise `SupportedProtocolVersions::SYSTEM_DEFAULT`
(= MIN..=MAX = v3..=v4), capabilities are tallied at every epoch close
(`choose_highest_protocol_version_and_move_contracts_upgrades_v1`, `authority.rs:571`),
and `SetNextConfigVersion(4)` is emitted once quorum+buffer stake supports it.
There is **no separate vote**. So this whole list must be sound before any
v4-advertising binary rolls out fleet-wide — or the 1.2.0 default advertisement
must be capped at v3 and lifted in the release that closes this list
(decision pending; the mixed-binary caveat below strengthens the cap option).

Source: the 1.2.0 pre-release code review, re-verified at head `c7cfd03f4c`
by a 14-item design pass (2026-07-12).

## Fix PRs (open, awaiting review)

- **#1820** (`fix/v4-gate-list`): pubkey-provider `refresh()` per-member
  verify-skip; prior-committee consensus-key map keyed by snapshot name;
  `read_bls_committee_lossy` for the bootstrap anchor; `get_committee`
  unwrap→propagate; SDK 0.5.0 changeset.
- **#1821** (`fix/v4-committee-legacy-decode`): mainnet-v1.1.8
  `committee_map` records decode via a `LegacyCommittee` fallback, so the
  v3→v4 transition epoch cannot panic on a 1.1.8-written record.
- **#1822** (`fix/v4-vss-cache-tristate`): the VSS Shamir-cache derivation
  outcome is an explicit, epoch-tagged tri-state
  (`Derived`/`NotApplicable`/`Failed`); stale terminal entries read as
  not-ready.
- **#1823** (`fix/v4-ready-signal-determinism`): ready-signal
  canonicalization is a pure function of the sequenced bytes (zero-weight
  joiner pairs kept; no wall-clock provider-table filter) — the freeze
  precondition.
- **#1824** (`fix/v4-handoff-attestation-recovery`): the handoff aggregator
  recovers after a post-EndOfPublish restart (install runs before the vote
  gate, with a steady-state early-out once the aggregator is built); stale
  signature rows are batch-deleted so the interim close gate cannot count
  superseded endorsements.
- **#1825** (`fix/v4-networkkeyid-memo-retry`): a failed NetworkKeyId
  derivation retries when its input bytes change instead of being memoized
  as permanently failed.
- **#1826** (`fix/v4-presign-per-key-counters`): internal-presign
  sequence/guard counters keyed per `(NetworkKeyId, curve, algorithm)` pool
  (the shared-counter design was retired — a key adopted at different
  rounds on different validators shifted every other pool's identifiers);
  consensus-agreed NOA-key selection; adoption defers unmapped keys on
  every branch.
- **#1827** (`fix/v4-freeze-cert-read-fail-stop`): the mpc_data freeze
  fail-stops on a prior-cert read error instead of freezing a shrunken
  (divergent) carry-forward set.

## Deferred — barrier escape + sequence-pure close gate

The remaining cluster (the prepare-then-start barrier's cert-less chain
fallback, barrier coverage of the joiner-promotion and cold-startup
consensus-start paths, and the sequence-pure epoch-close tally that retires
`handoff_signatures_meet_quorum`) is designed but deliberately NOT built for
1.2.0: the escape relaxes the barrier's block-forever safety gate and needs
its own review cycle. Full design, ordering constraints, and safety
analysis: [`handoff-barrier-escape-and-pure-close-gate.md`](handoff-barrier-escape-and-pure-close-gate.md).

Recovery-mechanism note that shaped the deferred design: the handoff
signature sender's restart replay re-mints the validator's OWN attestation,
so it recovers only a NON-divergent validator; a validator whose attestation
diverged from the quorum's recovers exclusively via the barrier peer-fetch
of the quorum's certificate — confirmed to cover continuing (not just
joining) validators at head.

## Rollout caveats

- **Mixed-binary determinism (strengthens the cap-at-v3 option).** The
  ready-signal canonicalization change (#1823) is consensus-visible across
  binary versions: an old binary keeps zero-weight names only if present in
  its local announcements table, the new binary keeps them all. Under
  ACTIVE v4 a mixed-binary committee could persist divergent rows from the
  same sequenced signal — the exact fork class the fix closes. Ship
  fleet-complete before v4 activates (automatic ~1 epoch after quorum
  advertises v4), or cap the 1.2.0 default advertisement at v3.
- **SDK 0.5.0 (rollout precondition, zero code coupling).** Publish before
  any v4-advertising binary reaches quorum stake: the published
  `@ika.xyz/ika-wasm@0.2.1` cannot parse V3-tagged reconfiguration outputs.
  Changeset landed in #1820; the version bump + `npm publish` are
  release-process acts. README hash-validity row (DoubleSHA256/secp256r1)
  still needs verifying against the TS+Rust tables (deferred — correctness
  question, not a rename).

## Not on this list (further out, separate flags)

The network-owned-address (NOA) signing/checkpoint system and the
on-chain-state (OCS) verified-read hardening items sit behind their own
feature flags and are not activated by the v4 capability tally; they are
tracked in their own plans/issues.

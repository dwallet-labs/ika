# Validator MPC-data announcements (off-chain validator metadata)

Status: active under protocol v4 (`off_chain_validator_metadata_enabled`).
Under v3 the same data is read from chain; under v4 chain writes remain
(write-only) but the consensus + P2P pipeline described here is the only
read path.

## Problem

Every committee member's class-groups public key material ("mpc_data":
class-groups encryption key + proof, plus the per-curve PVSS halves) is
an input to the reconfiguration MPC and to building the next epoch's
`Committee`. It is multi-hundred-KB per validator — too large to move
through Sui as a read path at scale. The pipeline moves the *bytes*
off-chain (consensus payloads + P2P) while keeping the *agreement on
which bytes* deterministic in consensus order.

## Data model

- **Blob**: BCS-encoded `VersionedMPCData`, derived deterministically
  from the validator's root seed (`derive_mpc_data_blob`) — the same
  validator re-derives byte-identical blobs, so all references are
  content-addressed by `mpc_data_blob_hash` (Blake2b256). The canonical
  hash helper is `ika_network::mpc_artifacts::mpc_data_blob_hash`;
  producers and verifiers MUST hash identical bytes, so no inline
  re-implementations.
- **`ValidatorMpcDataAnnouncement`** `{ validator, epoch, timestamp_ms,
  blob_hash }` — the digest-only claim "my mpc_data for `epoch` is the
  blob with this hash". The bytes travel separately.
- **Blob stores**: an in-memory P2P-served store (512 MiB cap) and the
  perpetual RocksDB table `mpc_artifact_blobs` keyed by digest.
  `insert_mpc_artifact_blob` verifies `Blake2b256(bytes) == digest` at
  the write boundary; P2P fetchers MUST hash-verify fetched bytes
  against the requested digest.

## Announcement paths

1. **Current-committee member (self-submission)**:
   `ValidatorMpcDataAnnouncement` is submitted directly to consensus.
   It carries no signature — authenticity is implicit in the consensus
   block author. The full blob is submitted alongside so consensus
   replication delivers the bytes committee-wide.
   Re-submission: the per-epoch table keeps one row per validator;
   inserts require a strictly newer `timestamp_ms`, and the sender's
   announcement cache is seeded from the stored row on restart so a
   clock regression cannot wedge re-announcement.
2. **Next-epoch joiner (relay)**: a joiner is not a consensus
   participant yet, so it signs the announcement with its **consensus
   Ed25519 key** (`SignedValidatorMpcDataAnnouncement`) and fans
   `(signed announcement, blob bytes)` out over P2P to
   current-committee peers. Each receiver verifies the signature
   against the joiner's next-epoch consensus pubkey from chain, then
   relays it into consensus as `RelayedValidatorMpcDataAnnouncement`.
   Joiners announce as early as possible so peers cache the blob; the
   reconfiguration never blocks waiting for a missing joiner (see
   freeze rules below — a joiner that misses the freeze window is
   excluded, not waited for).

## Ready signals and the freeze

- **`EpochMpcDataReadySignal`** `{ authority, epoch, sequence_number,
  validated_peers }`: "these peers' blobs are locally held AND
  decode-valid" (each paired with the attested blob hash). Emitted once
  per epoch and RE-emitted whenever the locally-validated set grows
  strictly (the `sequence_number` exists so consensus dedup does not
  drop re-emits). Per-signer rows REPLACE — the latest signal from a
  signer is its current attestation.
- **Emit gate** (`decide_ready_to_finalize`, producer-side): each
  validator withholds its first ready signal until the next-epoch
  committee is published AND every one of its members is **covered** —
  blob locally validated, or digest present in the prior epoch's
  handoff certificate. A prior-cert member cannot be dropped by the
  freeze (carry-forward re-freezes it at the prior digest, see below),
  so waiting for its fresh announcement buys nothing; only uncovered
  members — a first-time joiner still propagating, or a member that has
  never announced in any epoch — hold the gate open. That wait is
  bounded by a deadline: the 3/4-epoch liveness backstop, tightened —
  once the validator first observes `V_{e+1}` published — to
  `min(backstop, first-observed-publication + grace)` with
  `grace = clamp(epoch/24, 30s, 1h)`. The `min` means the deadline can
  only ever be earlier than the historical fixed 3/4 mark (short test
  epochs keep exactly the 3/4 behavior, since the clamped grace
  overshoots them). Without the coverage rule and the tightened
  deadline, a single never-announcing committee member forces every
  validator onto the backstop every epoch, compressing the
  reconfiguration + pricing + lock pipeline into the last quarter of
  every epoch (observed live on testnet — issue #1866). The deadline
  warning names only uncovered members — carry-forward-covered members
  stay in the frozen set, so naming them would be a false exclusion
  alarm.
- **Emit-gate clock**: every time term of the gate is denominated in
  the epoch's CONSENSUS clock — "now" is the running max of processed
  `commit_timestamp_ms`, the backstop is anchored at the epoch's FIRST
  processed commit's timestamp (persisted with that commit's batch —
  replay resumes from the last processed commit, so "first" is
  otherwise unrecoverable), and the publication observation is stamped
  with the consensus "now" at the tick that first sees it. Machine
  wall-clock is never consulted. This fate-shares the deadline with
  the machinery it times: before the first commit (or during a
  consensus stall) there is no deadline — nothing can be sequenced, so
  a deadline could not have produced a freeze — and a partitioned or
  catching-up validator's deadline pauses with its consensus view
  instead of deadline-emitting a stale attestation set mid-catch-up.
  Commit timestamps are leader-proposed and manipulable at seconds
  scale — immaterial against these hours-scale terms. The first-commit
  anchor sits a consensus spin-up after the Sui epoch-start timestamp
  the backstop was historically measured from; the 3/4 slack absorbs
  normal spin-up, but a pathologically late consensus start delays the
  backstop by the same amount. All of these terms remain emit-timing
  only (the freeze snapshot stays a pure function of consensus-ordered
  signals); the publication anchor is still each validator's LOCAL
  first observation — making it a fleet-identical consensus fact
  (quorum of sequenced publication attestations) is issue #1869.
- **Receive-time canonicalization** (`canonicalize_ready_signal_peers`)
  MUST be a pure function of the sequenced signal bytes: dedup by
  authority, a current-committee quorum-coverage floor, and a
  deterministic length cap (`K × current committee size`). It MUST NOT
  consult the local announcements table or any `JoinerPubkeyProvider`
  state — those are wall-clock-populated and would fork the persisted
  canonical set across honest validators with different poll timing.
  A next-epoch joiner (zero current-committee weight) survives
  canonicalization because non-committee peers are **retained** in the
  persisted `(peer, hash)` set (up to the cap), NOT because of an
  announcement-table lookup. Coverage is measured on current-committee
  weight only, so a sparse signal still can't push the freeze trigger; a
  joiner is frozen only when a stake-quorum of signers attest it in the
  tally (`compute_freeze_partition`). Kept non-committee names cannot
  reach the frozen set without a stake-quorum of signers, and the
  assembly/reconfiguration consumers read the frozen/excluded sets by
  committee-member key only — but they are NOT fully inert: a garbage
  name lands durably in `epoch_excluded_validators` and inflates the
  `dwallet_mpc_data_excluded_validators` gauge (operators alerting on it
  should know), and each kept-but-never-quorum name holds the
  full-coverage fast path open, so the freeze fires via the grace path
  instead — one byzantine signer can force every epoch onto the grace
  latency for free. Deterministic and bounded by the grace; this is the
  price of keeping canonicalization a pure function of the sequenced
  bytes (distinguishing garbage from a legitimately-propagating joiner
  would require exactly the local state the rule above forbids). The
  strict-superset re-emit gate also means each accepted REPLACE may swap
  ALL of a signer's attested hashes — a byzantine signer buys up to
  `cap − initial` accepted re-emits by growing its set one name at a
  time; latest-row-wins keeps this deterministic.
- **Freeze decision** (the commit-boundary rule): the frozen mpc-data
  input set is decided **in the consensus handler at a commit
  boundary**, never from a wall-clock loop — two honest validators must
  freeze identical sets. The decision fires at the first commit where
  ALL of:
  1. a DKG or reconfiguration actually needs the data this epoch,
  2. ready signals reaching a stake quorum have been sequenced, and
  3. either every committee member is covered with nothing excluded
     (full coverage) or `mpc_data_freeze_grace_rounds` (protocol
     config, default 50) consensus LEADER rounds have elapsed since the
     quorum anchor round. Leader rounds advance non-monotonically, so
     the grace is a round DELTA from the persisted anchor
     (`mpc_data_ready_quorum_round`), not a count of observed commits.
- **Frozen set semantics**: `frozen: validator -> blob_hash` is written
  once per epoch (`freeze_mpc_data_if_first`) and is immutable for the
  epoch. Validators not in the frozen set are the epoch's **excluded**
  set: the reconfiguration proceeds without them.
- **Carry-forward (stable mpc_data)**: a validator's blob is a pure
  function of its root seed (`derive_mpc_data_blob`), so a continuing
  validator's blob is byte-identical every epoch. At the freeze, a
  committee member that was NOT freshly attested this epoch but IS
  present in the prior epoch's handoff certificate (its
  `ValidatorMpcData` items) is frozen at its prior-cert digest; the
  bytes resolve from perpetual `mpc_artifact_blobs`
  (`carry_forward_stable_mpc_data`). Only members with no prior-cert
  digest — first-time joiners — can be excluded for failing to announce
  (a joiner that misses the freeze is excluded, not waited for). This
  restores the v3 "always available" property for any validator ever
  frozen: a member that restarts near the epoch boundary keeps its seat
  in the frozen set instead of leaving a gap the next reconfiguration
  would reject forever. Because the carried digest re-enters this
  epoch's certificate, coverage CHAINS across epochs — a validator
  frozen even once stays covered while it is down, so even a
  permanently-down-but-staked member never wedges reconfiguration.
  Carry-forward is deterministic: the prior certificate is
  consensus-anchored and perpetual, and the prepare-then-start barrier
  holds it locally before this epoch's consensus is processed — on the
  continuing-validator reconfigure path today; the joiner-promotion and
  cold-startup consensus-start paths are pending the barrier wiring
  (see `dev-docs/plans/handoff-barrier-escape-and-pure-close-gate.md`),
  so until then a first-time joiner racing its bootstrap fetch can
  freeze without the carried map. A fresh announcement that diverged
  (landing a member in `excluded`) is overridden by the known-good
  prior digest, since the true blob cannot legitimately change between
  epochs. A cert READ ERROR at the freeze
  (`prior_epoch_mpc_data_digests`) fails the commit rather than
  degrading to announce-only: a transient read failure that silently
  dropped the carry-forward map would freeze a shrunken set on that one
  validator while peers freeze the full set — a divergent frozen set.
  The commit errors, the consensus handler panics, and the commit
  replays on restart until the read succeeds (`Ok(empty)` is reserved
  for the chain-true no-cert epochs: genesis, a v3 prior epoch, the
  first v4 epoch; a missing perpetual-tables handle also fails the
  commit — it is a local initialization fault, not a chain-true case).
- The certificate cannot backfill an announcement for a validator with
  no prior frozen blob (a first-time joiner). For joiners the only
  mechanism is announcement propagation reaching a stake quorum BEFORE
  the freeze fires: a joiner whose blob has not propagated in time is
  excluded for the epoch, with no after-the-fact recovery.

## Next-committee assembly

- `decide_assembly_inputs` is the pre/post-freeze split:
  - **Pre-freeze**: assemble from the announcement table; any
    non-excluded committee member without an announcement makes the
    assembly `Incomplete` (retry next tick — P2P may not have
    converged).
  - **Post-freeze**: the frozen map is the single source of truth;
    members absent from it are silently skipped (this is what prevents
    one never-announcing member from stalling assembly forever). The
    announcement table MUST NOT be consulted post-freeze.
- `assemble_committee_mpc_data_off_chain` resolves each `(authority,
  digest)` pair through the blob store and decodes; the gate is strict —
  one missing or undecodable blob fails the whole assembly with
  `Incomplete`. Partial maps are never returned, because the
  reconfiguration MPC reads `Committee.class_groups_public_keys_and_proofs`
  directly and a silent gap drops that validator's share.
- Assembly output is a pure function of the input pairs (blobs are
  content-addressed), so identical pairs are served from a cache and a
  post-freeze `Complete` assembly is final for the epoch: the sync loop
  sends it once and stops re-assembling (`sync_next_committee`).
- The **chain view** of the next committee (membership + stake, no
  crypto material) is published on a separate watch channel as soon as
  Sui has it. It deliberately precedes the assembled view: a joiner only
  learns that it IS a joiner (and must fan out its mpc_data) from this
  signal, and the assembled view cannot complete without the joiner's
  data — gating the joiner watcher on assembly would deadlock.
  `Committee` equality compares only epoch + voting rights, NOT the
  class-groups maps; never use it to decide whether assembled committee
  content changed.

## Key invariants

1. Freeze decisions are pure functions of the consensus sequence
   (commit-boundary, persisted anchor rounds, atomic batch writes via
   `ConsensusCommitOutput`) — restart-safe and identical across honest
   validators. This covers the **receive-time canonicalization** of each
   ready signal, not only the freeze tally: the persisted
   `validated_peers` set must be derivable from the sequenced signal
   bytes alone. Reading any wall-clock-populated local table (the
   announcements table, the `JoinerPubkeyProvider`) on this path forks
   the persisted set and, through it, the freeze partition.
2. Every blob reference is content-addressed; bytes are verified
   against their digest at every trust boundary (store insert, P2P
   fetch, assembly decode).
3. `Committee.class_groups_public_keys_and_proofs` is load-bearing for
   the reconfiguration MPC: it is never populated partially and never
   left empty for a non-excluded member. This binds every builder of
   the map, not only the off-chain assembly. The chain-view builders —
   `get_epoch_start_system` in `ika-sui-client` (feeding
   `EpochStartSystem::get_ika_committee`, the epoch store's committee
   and, pre-v4, the MPC manager's validator-key seed) and the
   sui_syncer legacy chain fallback (`new_committee`, feeding the
   reconfiguration MPC under pre-v4 protocol versions) — enforce it at
   the read boundary: an active member whose on-chain `mpc_data`
   record is missing or undecodable fails the WHOLE read (retried by
   `must_get_epoch_start_system` / the next sync tick), never a silent
   member skip. Chain state cannot legitimately lack the record (it is
   written at candidate registration and never emptied; under v4 chain
   writes remain), so absence is always a read defect — and each
   validator reads through its own fullnode, so a tolerated local gap
   would be an unagreed party-set exclusion: divergent MPC public
   inputs across honest validators. Exclusion decisions belong
   exclusively to the consensus-agreed freeze. The completeness check
   lives at the read boundary, NOT on `Committee` construction — a
   post-freeze assembled committee legitimately omits *excluded*
   members, so a type-level "map covers all members" invariant would
   be wrong.
4. Post-freeze, all mpc-data decisions read the frozen set only.

Code anchors: `crates/ika-types/src/validator_metadata.rs` (types),
`crates/ika-core/src/validator_metadata.rs` (assembly + freeze inputs),
`crates/ika-core/src/authority/authority_per_epoch_store.rs` (freeze
decision, signal tables), `crates/ika-core/src/epoch_tasks/`
(announcement sender, joiner announcements, peer blob fetcher),
`crates/ika-network/src/mpc_artifacts/` (blob store + hash),
`crates/ika-sui-client/src/lib.rs` +
`crates/ika-core/src/sui_connector/sui_syncer.rs` (chain-read
completeness gates, invariant 3).

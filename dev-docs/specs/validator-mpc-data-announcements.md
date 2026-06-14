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
  consensus-anchored, perpetual, and (by the prepare-then-start
  barrier) held by every validator before it processes this epoch's
  consensus. A fresh announcement that diverged (landing a member in
  `excluded`) is overridden by the known-good prior digest, since the
  true blob cannot legitimately change between epochs.
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
   validators.
2. Every blob reference is content-addressed; bytes are verified
   against their digest at every trust boundary (store insert, P2P
   fetch, assembly decode).
3. `Committee.class_groups_public_keys_and_proofs` is load-bearing for
   the reconfiguration MPC: it is never populated partially and never
   left empty for a non-excluded member.
4. Post-freeze, all mpc-data decisions read the frozen set only.

Code anchors: `crates/ika-types/src/validator_metadata.rs` (types),
`crates/ika-core/src/validator_metadata.rs` (assembly + freeze inputs),
`crates/ika-core/src/authority/authority_per_epoch_store.rs` (freeze
decision, signal tables), `crates/ika-core/src/epoch_tasks/`
(announcement sender, joiner announcements, peer blob fetcher),
`crates/ika-network/src/mpc_artifacts/` (blob store + hash).

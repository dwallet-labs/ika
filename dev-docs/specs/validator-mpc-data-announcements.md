# Validator MPC-data announcements (off-chain validator metadata)

Status: active and unconditional — `MIN_PROTOCOL_VERSION` and
`MAX_PROTOCOL_VERSION` are both 7, so no supported version turns this off.
The legacy chain field remains for candidate registration, but operational
MPC-data updates do not write it; the consensus + P2P pipeline described
here is the only update and read path.

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
- **CLI updates**: `ika validator set-next-epoch-mpc-data` replaces the
  local `root-seed.key` only. It MUST NOT submit the derived public data
  to Sui. After the validator installs the new file and restarts, the
  announcement sender derives the full blob and distributes it through
  consensus and P2P using the paths below. The restart also re-runs the
  per-epoch seed resolution below, which is what keeps the rotating
  validator in the epoch it restarts into.

## Seed rotation and per-epoch seed resolution (#2119)

A validator's blob is a pure function of its root seed, and the network
deals epoch `E`'s shares to the bundle recorded in the `E-1 -> E` handoff
certificate's `ValidatorMpcData` item for that validator. Rotating the seed
therefore always lands the validator in an epoch whose shares were dealt to
the seed it just replaced. **Rotating "at an epoch boundary" does not avoid
this**: the boundary is precisely where the certificate that pins the old
bundle is written.

`NodeConfig.previous_root_seed_key_pair` is an OPTIONAL second root-seed
descriptor — same type, same lazy unreadable-path semantics as
`root_seed_key_pair`, discarded unread by notifier/fullnode preparation —
that names the seed the validator was running before the rotation.

**Resolution** (`dwallet_mpc::seed_rotation::resolve_epoch_seed`, called
once per epoch from `DWalletMPCService::verify_validator_keys`, which is
itself called at every per-epoch component start):

| certified digest for this authority | decision | state label |
|---|---|---|
| absent (genesis / first-epoch joiner / cert not installed) | run the current seed | `no_certified_digest` |
| derivable from the CURRENT seed, no previous configured | run the current seed | `matches` |
| derivable from the CURRENT seed, previous still configured | run the current seed | `rotation_complete` |
| derivable only from the PREVIOUS seed | run epoch `E`'s MPC on the PREVIOUS seed | `rotating_on_previous_seed` |
| derivable from neither, no previous configured | **no MPC this epoch** | `awaiting_certification` |
| derivable from neither, previous configured | **no MPC this epoch** | `previous_seed_mismatch` |

Current is tested first, so pointing both fields at the same seed reads as
"no rotation" rather than as a rotation.

Invariants:

1. **The announcement sender ALWAYS announces the CURRENT seed's bundle**,
   including while the epoch's MPC runs on the previous seed and while the
   node is out of MPC entirely. That is the whole mechanism: it is what
   makes `E`'s freeze capture the new bundle, so `E -> E+1` deals the next
   epoch's shares to the new key and the rotation completes. The sender is
   per-epoch and re-derives from the configured current seed at every
   construction, so re-announcement across a boundary is structural, not a
   special case. A rotation that lands AFTER `E`'s freeze is therefore
   self-healing one epoch later, not lost: `E+1` resolves onto the previous
   seed again and `E+1`'s freeze captures the new bundle.
2. **There is no abort path.** A seed the certificate does not name makes
   the validator a full consensus member that takes no part in MPC: it
   decrypts nothing (no off-chain key ingestion, no network-key
   instantiation) and submits no MPC message, output or rejection. That is
   deliberately the profile of an unresponsive member. Computing with key
   material the network never dealt to it would produce divergent outputs
   and get it convicted as self-malicious (#1978), which is strictly worse
   than being absent; aborting would be worse still, because the only way
   to get a new bundle certified is to REACH the reconfiguration the abort
   refuses to boot into — the fail-closed version of this check made the
   documented rotation flow a crashloop.
3. **The comparison is set membership, not equality.** The certified digest
   covers the whole encoded bundle, so it is a function of the seed AND of
   the bundle encoding. `DerivableDigests` is the set of digests this binary
   can derive from one seed, and the certified digest is accepted if it is
   in the set for either seed. Today the set has exactly one member
   (`VersionedMPCData::V1`) and the tolerance is structural rather than
   load-bearing. A future encoding bump MUST add the new digest to the set a
   release BEFORE `derive_mpc_data_blob` starts emitting it — certificates
   are written by the previous epoch's committee running the previous
   binary, so accept-before-emit is what stops the whole fleet from
   resolving to "neither seed matches" on the same upgrade.
4. **An unreadable previous seed is treated as an absent one.** The
   descriptor is resolved through a FALLIBLE accessor
   (`RootSeedWithPath::try_root_seed`); `root_seed()` panics on an unreadable
   file, which is right for the current seed and wrong for this one. The
   documented rotation ends with the operator deleting the old seed file, and
   nothing forces them to remove the config field first, so an unreadable
   previous seed is an expected operator state rather than a corrupt config.
   It resolves to "no previous seed" with a `WARN` naming the path and the
   error — so the failure is visible rather than fatal, and a node whose
   CURRENT seed is already certified is unaffected. The failure is not
   cached, so a restored file resolves at the next epoch without a restart.
   The documented order is nonetheless: remove the field, restart, then
   delete the file.
5. **One rotation per epoch.** Rotating twice before the first is certified
   leaves neither seed matching; the validator sits out MPC until the
   certificate catches up, which is at most one extra epoch because it keeps
   announcing the current seed. This is also the shape of a wrong seed
   restored from a backup, and the repair is the same: point the
   previous-seed field at the certified seed (or restore it as the current
   seed) and restart — no boundary is involved, because resolution runs at
   every construction.

Observability: `ika_dwallet_mpc_seed_identity_state{state}` is a one-hot
gauge over the six labels above, published once per epoch from the
per-epoch component start (NOT from inside the MPC service, which is the
subsystem sitting idle in the states that matter). One alert expression
covers the non-participating condition:

```
ika_dwallet_mpc_seed_identity_state{state=~"awaiting_certification|previous_seed_mismatch"} == 1
```

paired with a once-per-epoch `error!` naming both local digests, the
certified one, and the in-epoch repair.

The per-tick off-chain check (`MpcDataAnnouncementSender::check_seed_identity`)
is unchanged in purpose and gains one verdict: a frozen digest that the
CONFIGURED PREVIOUS seed derives is `RotatedAfterFreeze` — a warning, not
the `mpc_data_frozen_digest_seed_mismatch` invariant violation, because it
is the expected shape of a late rotation and self-heals.

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
   A relayer's `Accepted` response means the relayed announcement was
   **observed in consensus output** (bounded wait; timeout →
   `Rejected`), not merely handed to the relayer's submitter — the
   joiner cannot read consensus and permanently stops fanning out
   after `min_accepts` acceptances, so a weaker ack would let a
   relayer crash silently strand the announcement (issue #1943).
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
  Restart: the sender seeds its sequence counter and last-emitted
  count from its own stored row (analogous to the announcement-cache
  seeding above), and additionally skips any sequence number already
  present in its processed-marker table before emitting — without
  both, a mid-epoch restart re-emits under an already-processed
  consensus key, which every node's dedup silently drops (issue
  #1942).
- **Emit gate** (`decide_ready_to_finalize`, producer-side): each
  validator withholds its first ready signal until the next-epoch
  committee is published AND every one of its members is **covered** —
  blob locally validated, or carried forward by the freeze. Coverage by
  carry-forward needs BOTH halves of what carry-forward actually does
  (see below): a digest in the prior epoch's handoff certificate, AND
  membership in the CURRENT committee, which is the set the freeze walks.
  Such a member cannot be dropped by the freeze, so waiting for its fresh
  announcement buys nothing. Everyone else holds the gate open — a
  first-time joiner still propagating, a member that has never announced
  in any epoch, and a member rejoining after a gap, which has a
  prior-cert digest but is absent from the current committee and so is
  NOT carried forward. Exempting that last case on its prior-cert digest
  alone stops the network waiting for a member the freeze then silently
  drops: seated next epoch with full voting weight but no class-groups
  entry, MPC-dead for that epoch, and in neither the frozen nor the
  excluded set, so nothing reports it. That wait is
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
  processed commit's timestamp (`epoch_first_commit_timestamp_ms`, held
  in memory and re-derived by the boot replay, which folds the epoch from
  its first commit), and the publication observation is stamped
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
  name lands in `epoch_excluded_validators` for the epoch and inflates the
  `ika_dwallet_mpc_data_excluded_validators` gauge (operators alerting on it
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
     the grace is a round DELTA from the anchor
     (`mpc_data_ready_quorum_round`), not a count of observed commits.
- **Frozen set semantics**: `frozen: validator -> blob_hash` is written
  once per epoch (`freeze_mpc_data_if_first`) and is immutable for the
  epoch. Validators not in the frozen set are the epoch's **excluded**
  set: the reconfiguration proceeds without them. The frozen and excluded
  sets, and the freeze commit's leader round (`mpc_data_freeze_round`),
  are all in-memory fields of the folded epoch state, applied together
  under one lock with the rest of what the freeze commit derives. The
  grouping is what a concurrent reader depends on: no reader sees the
  freeze partition without the freeze round.

  Nothing here survives a restart, and that is what closes issue #1829.
  The hazard then was a partial write latching a strict subset as frozen
  FOREVER, because the rows were durable and the idempotence guard was
  table non-emptiness, so the replayed commit dedup-skipped and left the
  validator on a divergent shrunken set. A restart now starts with no
  frozen set at all and the boot replay re-folds the epoch from its first
  commit, so the freeze re-fires from the same sequenced ready signals
  and reaches the same partition. The failure mode is structurally
  unbuildable rather than defended against.

  `mpc_data_freeze_round` remains observability only — nothing in the
  protocol reads it back; it republishes the
  `ika_dwallet_mpc_data_freeze_round` gauge as the re-fold passes the
  freeze commit. Freeze progress is scrapable end to end:
  `ika_dwallet_mpc_data_ready_quorum_round` (the quorum anchor, `-1`
  pre-quorum),
  `ika_dwallet_mpc_data_freeze_grace_rounds` (the protocol-config grace),
  `ika_last_committed_leader_consensus_round` (the commit-boundary leader round
  the grace delta is measured against — NOT
  `consensus_ika_last_committed_leader_round`, which is consensus-core's
  producer-side gauge), and
  `ika_dwallet_mpc_data_ready_signal_deadline_timestamp_seconds` (the
  sender's emit-gate deadline, consensus-clock seconds, `-1` before the
  epoch's first commit).
- **Carry-forward (stable mpc_data)**: a validator's blob is a pure
  function of its root seed (`derive_mpc_data_blob`), so a continuing
  validator's blob is byte-identical every epoch. At the freeze, a
  committee member that was NOT freshly attested this epoch but IS
  present in the prior epoch's handoff certificate (its
  `ValidatorMpcData` items) is frozen at its prior-cert digest; the
  bytes resolve from perpetual `mpc_artifact_blobs`
  (`carry_forward_stable_mpc_data`). The walk is over the CURRENT
  committee, so a prior-cert name that is not seated this epoch is not
  reached — which is why the emit gate above requires both halves.
  Among CURRENT members, only those with no prior-cert digest —
  first-time joiners — can be excluded for failing to announce
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

## Current-epoch key bundle (manager ingestion)

The MPC manager's current-epoch key set
(`validator_mpc_keys_by_party_id` — consumed by the within-epoch network
DKG and by every VSS presign/sign public input) is NOT fed by the
current epoch's freeze. Its committee-agreed value is the **prior
epoch's frozen set ∩ current committee** — the set the prior epoch's
post-freeze assembly delivered at the boundary and every continuing
validator latched for the whole epoch. Sourcing rules
(`ingest_offchain_mpc_keys`, ingested once per manager):

1. **Primary — the prior epoch's handoff certificate**: assemble the
   cert's `ValidatorMpcData` digests ∩ current committee against the
   perpetual blob store. Byte-identical to the boundary delivery (the
   cert items are built 1:1 from the frozen map; blobs are
   content-addressed) and, unlike the boundary window's process-local
   watch channel, reachable after a mid-epoch restart — the restart
   wedge of issue #1879. Members without a cert digest (prior-epoch
   excluded joiners) are skipped, exactly as the boundary assembly
   skips them.
2. **Fallback — the freeze-gated syncer delivery** (the
   `current_epoch_mpc_keys` channel): only for the chain-true no-cert
   epochs (genesis, the first off-chain-enabled epoch), where the
   epoch's own freeze is the only agreed set.
3. **Never mix**: with a cert present, the channel is not consulted —
   post-freeze it carries the CURRENT epoch's frozen set, a possible
   strict superset of the boundary set (a late-attested joiner), and
   ingesting it would byte-diverge this validator's VSS presign public
   inputs from the committee's. Cert read errors retry; missing
   cert-pinned blobs defer ingestion until propagation converges.
4. **Deferral repair — prior-cert blob refetch**: announcement-driven
   fetching cannot converge a cert-pinned blob whose owner has been
   dark for epochs — the owner never re-announces (carry-forward
   re-pins its old digest into every cert instead), so a host whose
   perpetual store post-dates the owner's last announcement holds no
   copy and has no announcement to fetch by; the deferral in rule 3
   would retry the same local store forever, MPC-wedging the validator
   for this and every following epoch (issue #1881). Each peer-blob
   fetcher pass therefore also fetches the prior cert's
   `ValidatorMpcData` digests (∩ current committee) missing locally
   from committee peers (`fetch_missing_prior_cert_mpc_data_blobs`):
   any holder is authoritative — blobs are content-addressed and
   verified (digest + structural decode) against the quorum-signed
   cert digest before the write-through persist — and the manager's
   next retry assembles from the repaired store. The missing-blob
   count is exported as the `ika_dwallet_mpc_prior_cert_blobs_missing`
   gauge (0 once assembly completes), so a stuck ingest is visible
   without log access.

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
  `Incomplete`. Partial maps are never returned, because the assembled
  bundles ARE the reconfiguration MPC's key input
  (`get_validator_mpc_keys_by_party_id` re-keys them to `PartyID`) and a
  silent gap drops that validator's share.
- Assembly output is a pure function of the input pairs (blobs are
  content-addressed), so identical pairs are served from a cache and a
  post-freeze `Complete` assembly is final for the epoch: the sync loop
  sends it once and stops re-assembling (`sync_next_committee`).
- Assembly retries are observable without exposing committee identities:
  `ika_off_chain_assembly_incomplete` and
  `ika_off_chain_assembly_consecutive_incomplete_ticks` describe current
  state, `ika_off_chain_assembly_incomplete_duration_seconds` describes the
  current period, and `ika_off_chain_assembly_missing{reason}` reports the
  latest missing count under the fixed reasons `announcement`,
  `blob_missing_or_invalid`, `source_unavailable`, `no_input`, and
  `everything_excluded`. A successful assembly clears all current-state
  gauges and updates
  `ika_off_chain_assembly_last_success_timestamp_seconds`; startup leaves the
  timestamp at zero until a real success. Ordinary convergence logs at debug.
  Five minutes of continuous incompleteness warns at most once every five
  minutes; an incomplete assembly after the 3/4-epoch backstop (or after the
  freeze is already visible locally) warns immediately. A warned period emits
  one info-level recovery transition. `EverythingExcluded`
  retains its immediate, once-per-epoch error and
  `ika_off_chain_assembly_wedged` signal. This severity-only backstop compares
  the chain-published epoch timestamps with local unix time; it does not feed
  the consensus-clock freeze decision or change any retry behavior.
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
3. The off-chain assembly's key maps are load-bearing for the
   reconfiguration MPC: they are never populated partially and never
   left empty for a non-excluded member. A silent gap would be an
   unagreed party-set exclusion — divergent MPC public inputs across
   honest validators — so the assembly fails whole and retries.

   Since #2119 this binds ONLY the off-chain assembly. No chain read
   contributes validator key material any more:
   `EpochStartSystem::get_ika_committee` and the sui_syncer's
   bootstrap-window path inside `new_committee` (which serves only the
   window before the off-chain source is installed — there is NO chain
   fallback for validator mpc_data once it is, and chain is write-only
   from then on) build committees with an EMPTY
   `Committee.class_groups_public_keys_and_proofs`. That map has no
   production reader: a `Committee` supplies the reconfiguration public
   input with an access structure (voting weights + thresholds) and
   nothing else. The on-chain `mpc_data_bytes` field it used to be
   decoded from is deprecated, and a new validator registers with a
   placeholder. Exclusion decisions belong
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

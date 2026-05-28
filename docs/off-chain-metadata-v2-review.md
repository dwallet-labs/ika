# `feat/off-chain-metadata-v2` — Review notes

Working document. Concerns accumulate here as we walk through the branch
feature by feature; at the end we compile this into PR review comments.

> **Status.** Review was written against `9a8398a6bc`; verdicts
> below each concern reflect spot-checks against the current tip
> `751e431bae` (which added 14 commits including a punch-list
> commit, dedup fix, freeze redesign, byzantine hardening).
> Verdict legend:
>
> - ✅ **ADDRESSED** — concern resolved by a specific commit.
> - ⚠️ **PARTIAL** — partly resolved; gap remains.
> - 🔁 **SUPERSEDED** — area redesigned; original concern may be
>   moot but the underlying property needs re-checking.
> - ❌ **NOT ADDRESSED** — concern unchanged in the new code.
> - 🔍 **REVISIT** — original concern may no longer apply in the
>   new design context.
>
> Review is **in progress** — Features 1–4 walked + verdicts
> added, F5 1 of 3 done, F6–F13 pending.

## Feature map

1. Foundation — types + consensus wire variants
2. P2P blob plane (Anemo blob endpoint, perpetual `mpc_artifact_blobs`, peer-blob fetcher)
3. Announcement producer / joiner relay
4. Freeze / quorum / ready signals
5. Pubkey providers (Consensus, Joiner)
6. Off-chain consumption / overlay in `sui_syncer`
7. Handoff attestation
8. `EndOfPublishV2`
9. Structural refactors (`epoch_tasks`, `mpc_artifacts`)
10. Protocol-version gating & fallback
11. Diagnostics
12. Multi-network-key correctness
13. Test infrastructure (`ika-test-cluster`)

---

## Feature 1 — Foundation: types + consensus wire variants

Commit: `313f15bf5f` — no-op groundwork.

### Concerns

_(empty — to be filled as user raises them)_

### Open questions raised during walkthrough

- **Closed `HandoffItemKey`.** New off-chain artifact types in the future
  require a new enum variant + protocol-version bump. Is that the right
  ceremony level, or do we want an extension field?
- **`timestamp_ms` as version.** Wall-clock from each validator; a
  backwards clock jump means a re-derived announcement won't supersede.
  Acceptable, or do we want a monotonic counter instead?
- **Ed25519 list, not BLS aggregate.** Committee-sized list of 64-byte
  sigs per `(key_id, epoch)`. Was the size trade-off vs BLS discussed?
- **Announcement not bound to relayer.** A malicious relayer can flood
  bumped-timestamp announcements against a victim's identity; they fail
  BLS downstream but cost consensus bandwidth first. Rate-limiting
  considered, or is downstream BLS-failure rejection enough?

---

## Feature 2 — P2P blob plane

### Concerns

- ❌ **NOT ADDRESSED.** Verified against current code: dual-write
  pattern is still present at every call site
  (`mpc_data_announcement_sender.rs:170+184`,
  `peer_blob_fetcher.rs:234+244`). The proposed single
  write-through API wasn't adopted. `2be3d94a99` #5 (digest
  assertion on insert) and #9 (`PeerBlobFetcher` in-memory
  backfill on perpetual hit) are defense-in-depth additions but
  don't consolidate the API.

  **Blob-store sync between perpetual RocksDB and the in-memory
  `InMemoryBlobStore` is by convention only, not enforced.** Each
  call site does two consecutive inserts:

  ```rust
  perpetual_tables.insert_mpc_artifact_blob(digest, &bytes)?;
  in_memory_blob_store.insert(digest, bytes);   // "mirror"
  ```

  Sites: `epoch_tasks/mpc_data_announcement_sender.rs:142–162`,
  `epoch_tasks/peer_blob_fetcher.rs:156–166`. Future call sites
  could silently forget the mirror — there's no wrapper that owns
  both stores, no write-through API, no test that holds the two in
  lockstep.

  **Proposed fix:** introduce a single `BlobCache` (or extend
  `InMemoryBlobStore`) that holds both `Arc<AuthorityPerpetualTables>`
  and the in-memory map and exposes one `insert(digest, bytes)`
  method that writes to both. Call sites then hold one handle, not
  two. The trait `MpcDataBlobStorage` already exists in
  `crates/ika-network/src/mpc_artifacts/blob_store.rs` but isn't
  used by the producer/consumer paths today — make *that* the only
  write API, with a single impl that fans out.

- ❌ **NOT ADDRESSED.** Verified at the current line number
  (`authority_per_epoch_store.rs:2178`): the perpetual insert is
  there, the in-memory mirror is still missing. Same diagnosis,
  same proposed fix. (The line number shifted because of the
  intervening commits, but no semantic change at this site.)

  **Site 3 (`authority_per_epoch_store.rs:2178`, was 2054) already
  forgot the mirror.** At Finalize the DKG/reconfiguration output bytes are
  inserted into the perpetual `mpc_artifact_blobs` table, but the
  matching `in_memory_blob_store.insert(...)` line is missing
  (`grep "in_memory_blob_store" authority_per_epoch_store.rs`
  returns nothing). Until the next node restart hydrates from
  perpetual, this validator's local Anemo server returns `None`
  when peers ask for that digest. Peers asking for the protocol-
  output blob mid-epoch — including next-epoch joiners during
  bootstrap — won't be able to fetch it from this validator. A
  restart papers over it via startup hydration; without one, the
  blob is durably stored but not P2P-servable. The proposed
  single-handle write-through API above would have caught this at
  the time the producer code was written.

- ✅ **ADDRESSED by `41bc8ba05b` step 1.** Quote: *"`PeerBlobFetcher`
  now randomly fans out across all committee peers per digest
  instead of asking only the originator. One byzantine originator
  that signs an announcement but withholds the bytes can no longer
  defeat propagation — any honest peer who has the bytes can serve
  them on the originator's behalf."* This also resolves the
  joiner-blob case as a side effect: the fetcher no longer needs
  the announcer's `PeerId`, so the missing-from-current-committee
  mapping is no longer a propagation blocker. The deeper concern
  (joiner-blob *origin* — who first puts the bytes in the network
  if the relay carries only the digest) is implicitly resolved by
  the same change: any honest current-committee peer who has
  fetched the bytes can now seed propagation.

  **`peer_blob_fetcher` can't reach next-epoch joiners.** The
  per-epoch `validator_mpc_data_announcements` table (per APES
  `validate_validator_mpc_data_announcement`) accepts **both**
  current-epoch validator self-announcements *and* next-epoch
  joiner announcements relayed through a current validator —
  verification paths differ (`self.committee()` vs.
  `joiner_pubkey_provider`) but storage is the same table. The
  fetcher iterates the combined table and resolves `AuthorityName
  → PeerId` exclusively via `epoch_start_state()
  .get_authority_names_to_peer_ids()`, which is built from
  `active_validators` of the **current** epoch only
  (`crates/ika-types/src/sui/epoch_start_system.rs:307–317`).

  Consequence: for any joiner announcement, the lookup at
  `peer_blob_fetcher.rs:135` returns `None`, the fetcher emits a
  silent `debug!("no PeerId mapping for announcer; skipping")` and
  moves on. The fetcher attempts to fetch *from the announcer*
  only — there is no fallback to "any other peer that might hold
  the blob".

  **Confirmed in Feature 3:** the `SubmitMpcDataAnnouncement` RPC
  payload (`SubmitMpcDataAnnouncementRequest` in
  `crates/ika-network/src/mpc_artifacts/announcement_relay.rs:22–25`)
  carries only `SignedValidatorMpcDataAnnouncement`, which contains
  the digest, not the blob bytes. The relayer never receives the
  joiner's bytes; it just forwards the digest claim to consensus.
  So neither (a) "relayer multicasts bytes" nor (b) "relayer is the
  single holder" is actually true — **nobody in the current
  committee holds the joiner's blob via the documented relay
  path**. Current-epoch validators that need the joiner's blob (to
  assemble next-epoch class-groups material) would have to P2P-
  fetch directly from the joiner, but `peer_blob_fetcher` doesn't
  have the joiner's `PeerId`. This is a real gap, not just a
  design question.

  Possible fix paths:
  - Have the fetcher fall back to any peer (e.g., iterate the
    committee in some order, try each) when the announcer's
    `PeerId` is unknown.
  - Have the relay-RPC server broadcast the bytes via Anemo to
    every current validator (not via consensus), making the
    fetcher unnecessary for joiner blobs.
  - Extend the `PeerId` map to include announced joiners' network
    keys (requires the joiner's network pubkey to be reachable
    via `joiner_pubkey_provider` and the joiner to be
    pre-connected to current validators' Anemo).

---

## Feature 3 — Announcement producer / joiner relay

### Concerns

- ✅ **ADDRESSED** by `cec2fc67cd` + `aaf9e10cb2`. Two parts:
  - `cec2fc67cd`: replaced `epoch_ready_signal_sent: AtomicBool`
    with `last_emitted_validated_peers_count: AtomicUsize` +
    re-emit-on-growth policy until `is_mpc_data_frozen()`.
    Honest-but-slow validators no longer locked out.
  - `aaf9e10cb2`: fixed consensus dedup that was silently
    dropping re-emits (the `ConsensusTransactionKey` for
    `EpochMpcDataReadySignal` now includes a `sequence_number`,
    so different emits have distinct keys and survive
    `verify_consensus_transaction`'s dedup).
  - Receiver-side strict-superset gate on re-emit prevents
    byzantine oscillation between attestation sets.
  - These were independently discovered post-our-walk; the bug
    we flagged was real and bigger than we knew.

  **`MpcDataAnnouncementSender` sends exactly once per epoch
  per validator** — the `announcement_sent: AtomicBool` (and the
  parallel `epoch_ready_signal_sent`) in
  `crates/ika-core/src/epoch_tasks/mpc_data_announcement_sender.rs`
  is a one-shot. Once flipped, the corresponding `send_*` is never
  re-invoked for the rest of the epoch.

  **Receiver side does NOT force once-per-epoch.** Verified:
  - Consensus key includes `timestamp_ms` — distinct timestamps are
    distinct consensus messages
    (`crates/ika-types/src/messages_consensus.rs`).
  - APES record path (`authority_per_epoch_store.rs:1873–1890`)
    drops `>= existing.timestamp_ms`, accepts strictly newer:
    "latest-by-timestamp" rule honored.
  - `validator_mpc_data_announcements` table tolerates updates.

  But the **freeze is the binding step** — once quorum triggers
  `freeze_mpc_data_if_first` (`authority_per_epoch_store.rs:2464–2484`),
  `frozen_validator_mpc_data_input_set` is snapshotted and never
  re-snapshotted in this epoch. Post-freeze re-announcements land
  in the live table but have **no effect on the current epoch's
  MPC inputs**. Whether they affect handoff depends on whether the
  handoff snapshot reads the live table or the frozen one — needs
  checking in Feature 7.

  **Recommendation:** if a future use-case wants mid-epoch updates,
  this is a small producer-side change (flip the atomic to a
  debounce or "version" tracker on a content-change predicate), but
  it requires a paired design decision on freeze + handoff
  semantics. As-is the design is internally consistent; flag this
  as a known knob with a deliberate one-shot wrapper rather than a
  receiver-side constraint.

- 🔍 **REVISIT.** Original "2s is over-aggressive" argument
  assumed the loop did nothing on most ticks after the one-shot
  emits. With `cec2fc67cd`'s re-emit-on-growth, ticks now do
  genuine work (recomputing `validated_peers`, comparing to last
  emitted count, possibly re-emitting). 2s may now be a
  reasonable cadence rather than wasteful. The original concern
  is less clear in the new design context — re-evaluate.

  **2-second heartbeat is over-aggressive** for the loop's actual
  workload. After the first epoch tick the announcement + ready
  signal are sent; subsequent ticks do nothing but check atomics
  and iterate `network_keys_receiver` (and the per-key HashSet
  filters out already-sent keys). For something that fires a
  handful of consensus messages at epoch start and otherwise idles,
  30s would be a better default — saves ~93% of pointless ticks per
  validator-epoch with no practical latency penalty. The same
  comment likely applies to `peer_blob_fetcher`'s 2s loop, though
  there the latency-to-blob-availability is more user-visible
  during joiner bootstrap; needs separate consideration.

- ❌ **NOT ADDRESSED.** Still a single `ValidatorMpcDataAnnouncement`
  consensus variant with the no-check exemption for relay. The
  recommendation (split into self + relayed kinds, drop the
  inner sig on self-submission, name the relayed sig
  `joiner_sig`) remains an open design recommendation.

  Side note: `41bc8ba05b` step 2 dropped the redundant `epoch`
  field from `ValidatorMpcDataAnnouncement` body (relying on
  `auth_sig.epoch` instead). That's an unrelated simplification,
  but worth knowing: the type has narrowed since we walked it.

  **Implicit `sender ≠ signer` exemption is a Sui-convention break;
  make it explicit via two consensus message kinds.** The
  wire-binding rule for `ValidatorMpcDataAnnouncement` in
  `AuthorityPerEpochStore::verify_consensus_transaction` deliberately
  omits the `sender_authority() == signer` check that every other
  ConsensusTransactionKind enforces (`HandoffSignature`,
  `EpochMpcDataReadySignal`, etc.). The exemption exists to permit
  joiner relay (relayer != joiner), but the design is implicit —
  a reviewer has to *infer* from the no-check comment that relay
  is the reason. This isn't a standard Sui pattern; the inherited
  convention is that the consensus sender authenticates the
  payload.

  **Decision: split into two consensus message kinds, and drop the
  inner payload sig on self-submission.** Self-submission carries
  no payload sig — the wire-binding rule `sender_authority() ==
  announcement.validator` together with Mysticeti's block-author
  authentication is sufficient. The relayed variant carries the
  joiner's BLS sig because consensus only authenticates the
  *relayer*, so the joiner's claim needs an independent payload
  sig:

  ```rust
  ValidatorMpcDataAnnouncement(ValidatorMpcDataAnnouncement),
      // sender == announcement.validator; no payload sig needed
  RelayedValidatorMpcDataAnnouncement {
      announcement: ValidatorMpcDataAnnouncement,
      joiner_sig: AuthoritySignInfo,   // BLS by the joiner's authority key
      // (relayer is implicit from sender_authority() — no field needed)
  },
  ```

  Wire-binding rule for both:
  - Self kind: `sender_authority() == announcement.validator`.
  - Relayed kind: no constraint on `sender_authority()` (any
    current-committee validator may relay); `joiner_sig` is
    verified against the joiner's BLS pubkey via
    `joiner_pubkey_provider`.

  Auditors don't need to read between the lines. Producers in
  `mpc_data_announcement_sender` emit the self-kind (no signing
  needed — cheaper); the relay Anemo path
  (`ConsensusBackedAnnouncementRelay`) emits the relayed-kind with
  the joiner's already-signed `joiner_sig`. Both feed the same
  downstream record path in APES.

  Note: this drops the "persistent payload sig" property for self-
  submitted announcements — anyone reading the
  `validator_mpc_data_announcements` table out-of-band can't
  independently verify "validator A signed this" without the
  consensus context. That's acceptable for the current consumers
  (all consumption is in-process inside the validator that
  observed the consensus delivery), but if a future feature wants
  to ship signed announcement bytes around outside that envelope,
  the sig has to come back. Document the trade-off in
  `ValidatorMpcDataAnnouncement`'s doc comment.

- ❌ **NOT ADDRESSED.** Handoff sigs remain Ed25519 list, no
  aggregation. Recommendation stands. The byzantine-hardening
  work in `2be3d94a99`, `cec2fc67cd`, `6de2abb899`, `faa9bf1cda`
  pinned strong properties on the Ed25519 aggregator (dedup,
  quorum boundary, replay commutativity, idempotency, restart
  safety) — all of which would also hold for a BLS-aggregate
  design with materially less code and ~100× smaller cert. The
  switch cost only grows the longer the Ed25519 path matures.

  **Unify handoff sigs to BLS aggregation, drop Ed25519
  `CertifiedHandoffAttestation`.** Both keys (authority BLS,
  consensus Ed25519) are equally available from chain for both
  current-committee and next-epoch-joiner verification (verified:
  `verify_certified_handoff_attestation` and
  `verify_joiner_bootstrap_cert` in
  `crates/ika-core/src/validator_metadata.rs:1000–1067` run pure
  Rust against a `ConsensusPubkeyProvider`; no Move-side verifier
  is involved). The Ed25519 path costs ~committee_size × (sig +
  AuthorityName + verify) per cert because Ed25519 doesn't
  aggregate; BLS aggregates to a single 96-byte sig + bitmap, with
  one aggregate-verify regardless of committee size. The wire +
  verify cost of the Ed25519 list is ~100× the BLS-aggregate cost
  on a committee of ~100, on a workload (handoff cert) that is
  fetched + verified by every joiner bootstrap and stored per
  epoch.

  Replace:
  ```rust
  pub struct CertifiedHandoffAttestation {
      pub attestation: HandoffAttestation,
      pub signatures: Vec<(AuthorityName, Ed25519Signature)>,
  }
  ```
  with a BLS-aggregate form:
  ```rust
  pub struct CertifiedHandoffAttestation {
      pub attestation: HandoffAttestation,
      pub aggregate_signature: BlsAggregateSignature,
      pub signers: RoaringBitmap,   // indices into the prior committee
  }
  ```
  `HandoffSignatureMessage` becomes a BLS single-sig under
  `IntentScope::HandoffAttestation` using the validator's BLS
  authority key, verified via the prior committee's
  `protocol_pubkey` (no `ConsensusPubkeyProvider` needed for
  handoff verification).

  Side benefits:
  - One signing key per artifact-class (BLS for everything signed
    at the application layer).
  - Move-side verification possible if ever needed (Sui's
    `sui::bls12381::bls12381_min_sig_verify` is available
    on-chain).
  - `ConsensusPubkeyProvider` can drop the handoff-cert
    responsibility (still needed for other Ed25519 things if
    any).

- ⚠️ **PARTIAL.** Two separate races in the original concern:
  - **Handoff signature race (receiver-side)** — peer's handoff
    sig arrives at our APES before we've installed our own
    `expected_handoff_attestation`. ✅ Addressed by `2be3d94a99`
    #3 + `cec2fc67cd`: `pending_handoff_signatures` buffer with
    per-signer dedup (bounded by committee size N via
    `committee.weight(&msg.signer) == 0` pre-check). Cleared on
    `clear_expected_handoff_attestation` per `6fed7709f1`. The
    "Option B (buffer-and-re-evaluate)" pattern we sketched
    was implemented for this case.
  - **Joiner-announcement race (relayer-side + receiver-side)** —
    joiner announcement arrives while `JoinerPubkeyProvider`
    isn't yet installed. ❌ NOT ADDRESSED. The relay's `relay()`
    in `epoch_tasks/announcement_relay.rs` still hard-rejects
    with `"joiner pubkey provider not installed"`. APES's
    `record_validator_mpc_data_announcement` still silently
    drops at `debug!` if the provider isn't installed yet. No
    buffer-and-re-evaluate or joiner-retry was added on the
    announcement path.

  **Joiner-relay availability race vs. Sui syncing.** Keep
  `V_{e+1}` as the eligible set for `JoinerPubkeyProvider` (using
  `PendingActiveSet` would broaden the attack surface — DoS
  amplification + breaks load-bearing filter-at-use-time
  invariants if a future consumer reads the frozen set unfiltered).
  But the current implementation has a race:

  1. Sui finalizes V_{e+1} at mid-epoch
     (`initiate_mid_epoch_reconfiguration` in
     `validator_set.move:590`).
  2. Joiner's local view of Sui sees the new V_{e+1} (it must, in
     order to know it's a registered joiner). Joiner fans out the
     announcement via the relay RPC.
  3. Some relayer's `sui_syncer` and
     `JoinerPubkeyProviderUpdater` (5s polling cadence) haven't
     yet observed the new V_{e+1}. The provider's
     `is_registered_joiner` returns false. `verify_joiner_announcement`
     returns `UnregisteredJoiner`. Relayer responds `Rejected`.
  4. Joiner doesn't re-fanout — they got an explicit rejection.
  5. ~5–10s later the relayer's updater catches up and installs
     the new provider with the joiner registered. But the
     announcement was already dropped.

  Two fix options, each defensible. Best is probably both
  (defense in depth):

  **Option A — joiner-retry with backoff.** The Anemo response
  `Rejected { reason: "UnregisteredJoiner" }` is already visible
  to the joiner; have the joiner retry the fanout every 30s for
  some bounded window (e.g. 5 minutes). Concentrates recovery
  logic in one place (the joiner), naturally dedupes (only the
  joiner re-fans-out), no per-relayer state. **Costs:** relies on
  joiner-side code to retry correctly — fragile if joiner binaries
  are operated by third parties whose implementation we don't
  control. A crashed joiner mid-fanout can't recover via this path.

  **Option B — relay buffers + re-evaluates.** The relayer
  buffers announcements with currently-unregistered authors
  instead of immediately rejecting, and re-evaluates whenever the
  `JoinerPubkeyProvider` is re-installed. Sketch:

  ```rust
  // ConsensusBackedAnnouncementRelay
  buffer: Mutex<VecDeque<(Instant, SignedValidatorMpcDataAnnouncement)>>,
  ```

  - On `relay(...)` with `UnregisteredJoiner`: push into buffer
    (bounded size, e.g. 1024 entries; bounded TTL, e.g. 60s).
    Return `Accepted` to the caller (or a new `Buffered` variant).
  - On `JoinerPubkeyProviderUpdater::maybe_install` after a
    successful install: drain the buffer, re-run
    `verify_joiner_announcement` for each entry, submit the
    now-valid ones to consensus, drop expired entries.

  Bounded buffer + TTL keeps the DoS surface bounded (an attacker
  spamming bogus authors fills the buffer but entries TTL out and
  are never submitted). Closes the race without depending on
  joiner-side retry. **Costs:** per-relayer state; on cluster
  catch-up, every relayer that buffered the same announcement
  re-submits to consensus (~N consensus submits collapsed by
  dedup on the consumer side, but each still costs a submit on
  the relayer).

  Without either fix, joiner relay reliability is sensitive to
  two loosely-coupled polling clocks (joiner's vs. each
  relayer's) — the kind of dependency that breaks silently in
  production exactly when you need it (during a real
  reconfiguration). Recommend implementing both for defense in
  depth.

  **The same race exists on the receiver side** of consensus, in
  `AuthorityPerEpochStore::record_validator_mpc_data_announcement`
  (`authority_per_epoch_store.rs:1846–1851`). When a joiner
  announcement is delivered by consensus to a validator whose
  `JoinerPubkeyProviderUpdater` hasn't yet installed the new
  V_{e+1} provider, the message is silently dropped at `debug!`
  level:

  ```rust
  let Some(provider) = self.joiner_pubkey_provider.load_full() else {
      debug!(validator = ?signed.announcement.validator,
             "no joiner pubkey provider installed — dropping next-epoch announcement");
      return Ok(());
  };
  ```

  Closing the race on the relay side (Option B) doesn't help if
  consensus delivers the message to the receiver during the
  receiver's own catch-up window. The receiver needs a parallel
  fix: APES should buffer joiner announcements with currently-
  absent providers and re-evaluate on provider install, mirroring
  the relay-side buffer pattern. Or: drop should be `warn!`, not
  `debug!`, so the issue is at least observable.

---

## Feature 4 — Freeze / quorum / ready signals

### Concerns

- 🔁 **SUPERSEDED — but the underlying property still needs
  verification.** The entire freeze design was overhauled across
  `41bc8ba05b`, `cec2fc67cd`, `2be3d94a99`, `6fed7709f1`,
  `39ecfc8807`, `936d2e8b50`:
  - **Attestation-tally freeze.** `EpochMpcDataReadySignal` now
    carries `validated_peers: Vec<AuthorityName>` — the set of
    validators whose blob this signer has fetched + hash-verified
    + decode-validated locally. Freeze partitions announcers into
    `frozen_validator_mpc_data_input_set` (≥quorum attested) vs.
    `epoch_excluded_validators` (<quorum attested), via the pure
    `compute_freeze_partition` function.
  - **Producer gates on local quorum coverage.** Sender only
    signals ready when `local_blob_coverage_meets_quorum` —
    stake-quorum of peer blobs locally validated. Stops fast-
    signaler premature-freeze problem.
  - **Re-emit on growth + strict-superset gate.** Producer
    re-emits as more peer blobs are validated; receiver accepts
    only strict supersets. Byzantine oscillation prevented;
    honest-but-slow validators can still be included on later
    re-emits.
  - **Per-key signal demoted to "recorded, unused".**
    `NetworkKeyDKGReadySignal` no longer triggers freeze
    (`2be3d94a99` #1). Removes the "per-key fires too early"
    surface entirely.

  **Underlying property to re-verify (NOT confirmed by the
  redesign):** the original bug's downstream consequence was
  "joiners are missing from the handoff cert". In the new
  design, joiners only enter the frozen set if a quorum of V_e
  validators include them in `validated_peers` *before* the
  freeze fires. The freeze fires when senders contributing
  quorum-by-stake have emitted ready signals — those senders
  are V_e members. Each V_e sender's `local_blob_coverage_meets_quorum`
  gate is satisfied as soon as it has *quorum coverage*, not
  *every member's blob*. So a fast V_e validator could still
  emit ready without joiners in its `validated_peers`. Whether
  joiners make it into the frozen set depends on:
    1. Whether enough V_e validators wait long enough.
    2. Whether re-emit-on-growth fires before
       `is_mpc_data_frozen()` returns true.
    3. Both being probabilistic, not guaranteed.

  Worth a targeted simtest: "joiner registers late, V_e
  validators freeze on quorum coverage of V_e only, joiner is
  excluded from handoff cert." If the test passes (joiner
  included), the redesign closes our concern. If it fails
  (joiner missing), the deeper fix is to make
  `local_blob_coverage_meets_quorum` *require* coverage of
  V_{e+1} validators specifically, not just any quorum.

  **`EpochMpcDataReadySignal` is sent before V_{e+1} exists →
  handoff cert silently drops joiners.** The producer
  (`MpcDataAnnouncementSender::run` in
  `crates/ika-core/src/epoch_tasks/mpc_data_announcement_sender.rs:114–133`)
  has exactly one precondition for emitting `EpochMpcDataReadySignal`:
  "I successfully sent my own announcement". No wait for V_{e+1},
  no wait for joiners' relayed announcements, no minimum elapsed
  time.

  Timeline on a healthy network:
  - `t=0`: epoch starts; sender task spawns on every validator.
  - `t≈0+ε`: each validator submits its own announcement.
  - `t≈2s`: each validator submits its `EpochMpcDataReadySignal`.
  - `t≈few seconds`: quorum reached → `freeze_mpc_data_if_first`
    fires → `frozen_validator_mpc_data_input_set` snapshot taken
    from `validator_mpc_data_announcements`.

  At this point V_{e+1} doesn't exist on Sui yet — it's filled
  only at `epoch_duration_ms / 2` by `initiate_mid_epoch_reconfiguration`
  in `validator_set.move:590`. No joiner could have relayed an
  announcement before the freeze fires. So the frozen set is
  **current-epoch validators only**.

  Consequence in the handoff cert path:
  `MpcDataHandoffItemsBuilder` (`validator_metadata.rs:336–340`)
  calls `get_effective_reconfig_input_set`, which reads the
  frozen set (`authority_per_epoch_store.rs:2015`) and filters by
  `V_e ∪ V_{e+1}`. Joiners are in V_{e+1} but **not** in the
  frozen set → filtered out → **not in `handoff_items`** → the
  handoff cert built at EndOfPublish doesn't pin joiners'
  `mpc_data` digests. The entire purpose of joiner-relay (prior
  epoch attests to incoming validators' material) is defeated.

  Caveat — what still works: the off-chain class-groups
  assembler (`EpochStoreClassGroupsSource::try_assemble_class_groups`)
  reads the **live** `validator_mpc_data_announcements` table,
  not the frozen set. So MPC sessions running mid-/late-epoch
  can still pick up joiner announcements after they arrive. MPC
  liveness isn't broken; only the **handoff cert's coverage of
  joiners is**. A fresh joiner bootstrapping into epoch e+1
  cannot use the prior epoch's handoff cert to verify their own
  mpc_data — the cross-epoch attestation chain has a gap for
  joiners.

  **Suggested fix shape (not yet approved):** gate
  `send_epoch_ready_signal` on (a) V_{e+1} being observed and
  (b) every joiner's announcement being present in the live
  table, OR a deadline (`MAX_JOINER_WAIT`) having elapsed. The
  deadline is needed for liveness — a registered joiner who
  never relays would otherwise block the freeze indefinitely.

---

## Feature 5 — Pubkey providers

_(pending walkthrough)_

### Concerns

---

## Feature 6 — Off-chain consumption / overlay in `sui_syncer`

_(pending walkthrough)_

### Concerns

---

## Feature 7 — Handoff attestation

_(pending walkthrough)_

### Concerns

---

## Feature 8 — `EndOfPublishV2`

_(pending walkthrough)_

### Concerns

---

## Feature 9 — Structural refactors

_(pending walkthrough)_

### Concerns

---

## Feature 10 — Protocol-version gating & fallback

_(pending walkthrough)_

### Concerns

---

## Feature 11 — Diagnostics

_(pending walkthrough)_

### Concerns

---

## Feature 12 — Multi-network-key correctness

_(pending walkthrough)_

### Concerns

---

## Feature 13 — Test infrastructure (`ika-test-cluster`)

_(pending walkthrough)_

### Concerns

---

## Cross-cutting concerns

_(things that span multiple features — fill in as they emerge)_

---

## Final PR review comments

_(compiled at the end from the per-feature concerns)_

---

## Verdict summary

After spot-checking the 14 new commits (`9a8398a6bc..751e431bae`)
against each recorded concern:

| # | Concern | Verdict | Resolving commit(s) |
|---|---|---|---|
| F2-1 | Blob-store sync by convention only | ❌ NOT ADDRESSED | — |
| F2-2 | APES Finalize site missing mirror | ❌ NOT ADDRESSED | — |
| F2-3 | `peer_blob_fetcher` can't reach joiners | ✅ ADDRESSED | `41bc8ba05b` step 1 (fanout) |
| F3-1 | Once-per-epoch is producer-only | ✅ ADDRESSED | `cec2fc67cd` + `aaf9e10cb2` |
| F3-2 | 2s heartbeat too aggressive | 🔍 REVISIT | n/a — design changed under it |
| F3-3 | Split into two consensus message kinds | ❌ NOT ADDRESSED | — |
| F3-4 | Unify handoff sigs to BLS aggregation | ❌ NOT ADDRESSED | — |
| F3-5 | Joiner-relay availability race | ⚠️ PARTIAL | `2be3d94a99` #3 + `cec2fc67cd` (handoff buffer); joiner-announcement path untouched |
| F4-1 | Ready signal sent before V_{e+1} → joiners drop | 🔁 SUPERSEDED | `41bc8ba05b`, `cec2fc67cd`, `2be3d94a99`, `6fed7709f1`, `39ecfc8807`, `936d2e8b50` — re-verify with targeted simtest |

## What the post-walk commits caught that we missed

The 14 commits independently found several bugs we didn't surface
during the walkthrough. Worth knowing for the next session's pace:

- **Consensus dedup silently dropping re-emits** (`aaf9e10cb2`).
  We noticed the once-per-epoch atomic was producer-side, but
  didn't realize that even *removing* the atomic wouldn't fix the
  re-emit problem because `verify_consensus_transaction` was
  dropping re-emits by key. Required a `sequence_number` field
  on the wire.
- **Sentinel `timestamp_ms == 0`** (`936d2e8b50`). `now_ms`
  returned `0` on `SystemTime::now()` failure via `unwrap_or(0)`;
  paired with the `>=` dedup, a single ts=0 entry could wedge a
  validator out forever. We discussed `timestamp_ms` as the
  versioning mechanism but didn't catch the sentinel.
- **`validated_peers` dup-inflation** (`6fed7709f1`). Once
  `validated_peers` was added to the ready signal, a byzantine
  signer could list the same target N times to inflate stake.
  Caught at the canonicalize layer.
- **Relay-cache poisoning** (`6fed7709f1`). `PeerBlobFetcher`
  hash-verified but didn't decode-validate; hash-matching-but-
  undecodable bytes propagated through every honest receiver.
  Fixed by `verify_peer_blob_for_relay`.
- **Empty off-chain assembly returning `Complete`** (`39ecfc8807`).
  Pure helper's `missing.is_empty()` check trivially-true on
  empty input — silent empty map dropped every share.
- **`pending_handoff_signatures` unbounded growth** (`cec2fc67cd`).
  Per-signer dedup keyed on wire-claimed `msg.signer`; byzantine
  spam with random names would grow without bound. Fixed by
  pre-checking `committee.weight(&msg.signer) == 0`.
- **`clear_expected_handoff_attestation` left buffer stale**
  (`6fed7709f1`). Reinstalls would replay stale buffered sigs and
  produce `AttestationMismatch` for every entry.

These are exactly the kinds of bugs a feature-walkthrough at our
level of abstraction tends to miss — they require running the code
in your head against specific byzantine or restart scenarios, not
just reading the design. Next session: ask "what happens if
sender is byzantine?" / "what happens after a restart?" at every
piece.

## Staleness audit (raw)

Original list of commits-vs-concerns guesses preserved for
audit-trail purposes. The verdict table above supersedes this.

| Concern | Likely-relevant new commit |
|---|---|
| F2: blob-store sync convention / site 3 missing mirror | `6fed7709f1` (decode-validate peer blobs) |
| F2: `peer_blob_fetcher` can't reach joiners | `41bc8ba05b` step 1 |
| F3: once-per-epoch is producer-only | `aaf9e10cb2` (re-emit consensus-dedup fix) |
| F3: 2s heartbeat too aggressive | n/a |
| F3: split into two consensus message kinds | n/a |
| F3: unify handoff to BLS aggregation | n/a |
| F3: joiner-relay race + receiver-side parallel | `cec2fc67cd` (handoff buffer) — joiner-announcement path untouched |
| F4: ready signal sent before V_{e+1} → handoff drops joiners | `2be3d94a99`, `39ecfc8807`, `41bc8ba05b`, `936d2e8b50`, `cec2fc67cd`, `6fed7709f1` |

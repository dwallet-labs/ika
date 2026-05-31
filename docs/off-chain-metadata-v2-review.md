# `feat/off-chain-metadata-v2` — Review notes

Working document. Concerns accumulate here as we walk through the branch
feature by feature; at the end we compile this into PR review comments.

> **Status.** Review was written against `9a8398a6bc`; verdicts
> below each concern have been refreshed twice: first against
> `751e431bae` (14 commits — punch-list, dedup fix, freeze
> redesign, byzantine hardening), then against the current tip
> `34f880b124` (24 further commits including the BlobCache fix
> we proposed, the announcement-kind split we proposed, the
> joiner fan-out task, the F4-1 ready-signal gate, and refactors
> that change the F5/F7 landscape).
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
> refreshed against `34f880b124`. F5–F13 pending.

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

- ✅ **ADDRESSED by `be254d52f9`** (commit title: *"Add
  write-through/read-through BlobCache; serve perpetual-only
  blobs"*). The proposed fix landed exactly as specified: a new
  `BlobCache` (`crates/ika-core/src/blob_cache.rs`) owns both
  `Arc<AuthorityPerpetualTables>` and the in-memory store, exposes
  one `insert` (perpetual then memory) and one `get` (memory then
  perpetual on miss). The dual-write pattern is gone from the two
  producer call sites; the `MpcDataBlobStorage` impl the Anemo
  server reads through goes through `BlobCache::get`, so the
  perpetual-only case (cache_protocol_output) is now servable
  without restart — closing F2-2 as well via the read-through.
  Verified `grep insert_mpc_artifact_blob` returns only sites
  inside `BlobCache` itself, in the perpetual-tables tests, and
  the one intentional direct write at `authority_per_epoch_store.rs:2117`.

  **Original concern, preserved for context:**

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

- ✅ **ADDRESSED by `be254d52f9`** (same commit). The read-through
  `get` in `MpcDataBlobStorage::get` (impl on `BlobCache`) checks
  in-memory first, then falls back to perpetual on a miss. So the
  site at `authority_per_epoch_store.rs:2117` (current line, was
  2178) writing only to perpetual is now servable to peers
  immediately — no restart required, no behavior gap. The commit
  message explicitly calls this out: *"`cache_protocol_output` is
  intentionally left writing to perpetual directly — read-through
  makes its output servable, so it needs no change for correctness."*
  The structural property "the Anemo server serves any durably-
  stored blob" now holds by construction, not by convention.
  Targeted test `get_reads_through_on_memory_miss` exists in
  `blob_cache.rs` covering exactly the F2-2 regression.

  **Original concern, preserved for context:**

  **Site 3 (was `authority_per_epoch_store.rs:2054`, then 2178,
  now 2117) writes only to perpetual.** At Finalize the DKG/reconfiguration output bytes are
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

- ✅ **ADDRESSED** by `cec2fc67cd` + `aaf9e10cb2`; further refined
  by `ee385e39c4`. The producer no longer marks itself done on a
  one-shot atomic at all — it now self-heals via confirmation-
  based retry. `send_announcement` re-submits the *cached*
  payload (stable `(validator, epoch, timestamp_ms)`) every tick
  until our own entry appears in `validator_mpc_data_announcements`
  — i.e. until our submission was sequenced + recorded. This
  closes a latent failure mode where `submit_to_consensus` returns
  `Ok` on handoff to a background submit task that could still
  fail to sequence (epoch boundary, crash). Three parts:
  - `cec2fc67cd`: replaced `epoch_ready_signal_sent: AtomicBool`
    with `last_emitted_validated_peers_count: AtomicUsize` +
    re-emit-on-growth policy until `is_mpc_data_frozen()`.
    Honest-but-slow validators no longer locked out.
  - `aaf9e10cb2`: fixed consensus dedup that was silently
    dropping re-emits (the `ConsensusTransactionKey` for
    `EpochMpcDataReadySignal` now includes a `sequence_number`,
    so different emits have distinct keys and survive
    `verify_consensus_transaction`'s dedup).
  - `ee385e39c4`: announcement_sent atomic dropped; replaced
    with cached-payload self-heal. Stable consensus key dedups
    instead of stacking duplicates.
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

- ✅ **OBSOLETED by `cec2fc67cd` + `ee385e39c4` + `5a241701d1`.**
  The original "wasteful idle" diagnosis is dead — every loop
  tick now does load-bearing work:
  - Cached-announcement self-heal: `send_announcement` re-checks
    confirmation on every tick (per `ee385e39c4`) and re-submits
    if our entry isn't yet in `validator_mpc_data_announcements`.
  - Ready-signal re-emit-on-growth from `cec2fc67cd`.
  - `decide_ready_to_finalize` (per F4-1 below) re-evaluates on
    every tick — V_{e+1} publication and per-member validation
    state both flip mid-loop.
  Additionally `5a241701d1` introduces `epoch_scaled_poll_interval`:
  the cadence is `epoch_duration_ms / 100`, clamped to
  `[100ms, production_default]`. Production default stays 2s
  (24h epoch ÷ 100 = 14.4min ≫ 2s, so it clamps to 2s); in
  short test epochs the cadence compresses to keep the integration
  path inside the freeze window. The same scaling now applies to
  `peer_blob_fetcher`, `pubkey_provider_updater`, and `sui_syncer`.
  Cadence is now matched to the work, not an idle heartbeat.

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

- ✅ **ADDRESSED exactly as proposed by `3c479841b9`** (commit
  title: *"Split announcement into self/relayed kinds; drop BLS
  for Ed25519"*). Two consensus message kinds now exist with
  asymmetric wire-binding rules in `verify_consensus_transaction`
  (`authority_per_epoch_store.rs:3071–3100`):
  - `ConsensusTransactionKind::ValidatorMpcDataAnnouncement(ValidatorMpcDataAnnouncement)`:
    self-submission. Wire rule enforces
    `sender_authority() == announcement.validator`. No payload
    signature — the consensus block author authenticates.
  - `ConsensusTransactionKind::RelayedValidatorMpcDataAnnouncement(SignedValidatorMpcDataAnnouncement)`:
    next-epoch joiner via relay. No sender constraint (any
    current-committee validator may relay). The joiner's Ed25519
    *consensus-key* signature on the inner announcement is
    verified at record time against the next-epoch consensus
    pubkey from `JoinerPubkeyProvider`.

  Two unexpected design choices vs. our sketch, both rationalized
  in the commit message:
  - **Ed25519 instead of BLS for the relayed inner sig.** We
    sketched `joiner_sig: AuthoritySignInfo` (BLS by joiner's
    authority key). The actual choice was Ed25519 over the joiner's
    *consensus* key, which is the right call: the joiner can
    register an Ed25519 consensus pubkey on Sui before they ever
    speak BLS, and the relay path verifies against that on-chain
    pubkey via `JoinerPubkeyProvider`. `JoinerPubkeyProvider::is_registered_joiner`
    became `joiner_consensus_pubkey(name) -> Option<Ed25519PublicKey>`
    so the verifying key is delivered alongside the membership
    check.
  - **`epoch` returned to the body, not the envelope.** We
    inherited from `41bc8ba05b`'s envelope-only design (`auth_sig.epoch`).
    With BLS removed there's no envelope to carry the epoch, so it
    moved back into `ValidatorMpcDataAnnouncement.epoch`. This
    binds the epoch into the joiner's Ed25519 signature against
    cross-epoch replay and supplies the `epoch` component of the
    consensus key. Self-submission gets a free epoch check at
    record time even without a sig.

  Worth noting: the persistent payload-sig property is now gone
  for *both* kinds at the storage layer — the table stores the
  bare `ValidatorMpcDataAnnouncement` (the relayed `joiner_sig`
  is verified at record time then discarded). Consistent with
  our earlier observation that the table is only read in-process.

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

- ❌ **NOT ADDRESSED.** Still verified at the source:
  `crates/ika-types/src/handoff.rs:94–96` — `CertifiedHandoffAttestation`
  carries `signatures: Vec<(AuthorityName, Ed25519Signature)>`,
  one entry per signer, no aggregate. The handoff path stayed
  Ed25519 across the announcement-pipeline refactor.

  **However**, `3c479841b9` ("Split announcement into self/relayed
  kinds; drop BLS for Ed25519") signals a deliberate broader
  choice to avoid BLS in the off-chain pipeline. That commit's
  reasoning — joiners have Ed25519 consensus keys registered on
  chain before they ever speak BLS — doesn't apply to the handoff
  signers (who *are* current-committee BLS-key-holders). So our
  original BLS-aggregate argument retains force *for the handoff
  cert specifically*, even if Ed25519 is now the off-chain
  pipeline convention everywhere else.

  Recommendation stands, with a stronger justification:
  consistency across the off-chain pipeline is one design value
  but cert-size and verify-cost are operationally significant
  for a per-epoch artifact every joiner fetches. The
  byzantine-hardening work in `2be3d94a99`, `cec2fc67cd`,
  `6de2abb899`, `faa9bf1cda`, plus the new `155ed58d4d` (prior-
  epoch binding) and `a480cf1d0d` / `34f880b124` (deterministic
  committee membership) pinned strong properties on the Ed25519
  aggregator (dedup, quorum boundary, replay commutativity,
  idempotency, restart safety). All of those would also hold
  for a BLS-aggregate design with materially less code and ~100×
  smaller cert. The switch cost only grows the longer the
  Ed25519 path matures.

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

- ⚠️ **PARTIAL — relayer-side closed via Option A; receiver-side
  still untreated but now observable.** Three separate races in
  the original concern:
  - **Handoff signature race (receiver-side)** — peer's handoff
    sig arrives at our APES before we've installed our own
    `expected_handoff_attestation`. ✅ Addressed by `2be3d94a99`
    #3 + `cec2fc67cd`: `pending_handoff_signatures` buffer with
    per-signer dedup (bounded by committee size N via
    `committee.weight(&msg.signer) == 0` pre-check). Cleared on
    `clear_expected_handoff_attestation` per `6fed7709f1`. The
    "Option B (buffer-and-re-evaluate)" pattern we sketched
    was implemented for this case.
  - **Joiner-announcement race (relayer-side)** — joiner's
    announcement reaches a relayer whose `JoinerPubkeyProvider`
    hasn't yet caught up to V_{e+1}. ✅ Effectively closed by
    *Option A* (joiner-side retry), via `73f4ab8048` + `5a490ef0f7`
    + `ee385e39c4` + `cc455e2a02`. `JoinerAnnouncementSender` now
    fans the signed announcement out to current-committee peers
    on a brisk cadence (3s, 100-attempt budget = ~5min), stops
    when it has `f+1` distinct accepting peers (guaranteeing at
    least one honest relayer). `UnregisteredJoiner` rejections
    are retried, not terminal. The joiner caches its own blob
    locally and *pushes* the bytes to the relayer on the fan-out
    RPC (`SubmitMpcDataAnnouncement`), so the relayer doesn't
    need to dial back to the joiner — closes the F2-3
    "joiner-blob origin" gap as a side effect.
  - **Joiner-announcement race (receiver-side)** — consensus
    delivers the relayed message to a validator whose
    `JoinerPubkeyProvider` hasn't caught up to V_{e+1}. ⚠️
    NOT TREATED by buffer-and-re-evaluate. Verified at
    `authority_per_epoch_store.rs:1862–1868`: the relayed-record
    path still drops on missing provider, returning `Ok(())`.
    Only mitigation: `d02019c214` upgraded `debug!` → `warn!`
    so the drop is operator-visible. The race window is bounded
    by `JoinerPubkeyProviderUpdater`'s polling cadence (scaled
    by `epoch_scaled_poll_interval`, typically a few seconds
    in production), and joiner-side retry doesn't help here —
    the cached payload reuses the same `(validator, epoch,
    timestamp_ms)` so consensus dedup means once delivered + 
    dropped at one receiver, no replay reaches that receiver.
    For determinism the dropped receiver is just behind and
    will catch up when (a) the joiner's slot stabilizes and (b)
    a future fan-out cycle resubmits — but the cached-payload
    `timestamp_ms` is fixed (per `ee385e39c4`), so dedup
    actually *blocks* re-delivery. This is a real but
    practically narrow gap: validators whose `JoinerPubkeyProvider`
    lags consensus delivery by even one tick lose the joiner
    forever in this epoch.

  **Recommendation:** still implement Option B (receiver-side
  buffer) for defense in depth — the joiner-side retry pattern
  closes the *submission* race but cannot close the
  *consensus-delivery* race, since the joiner can't observe
  receiver state. Alternative: drop the `timestamp_ms`-based
  dedup for a window after joiner registration becomes visible,
  forcing re-record on a refreshed message.

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

- ✅ **ADDRESSED with caveats.** The "re-verify with targeted
  simtest" follow-up I asked for is exactly what the project
  built — and it *failed* the first time, surfacing three more
  real bugs that were then fixed. The full chain:
  - `c309e75698`: added `test_joiner_lands_in_next_committee_class_groups`
    — the targeted simtest I recommended.
  - The test failed, revealing the design WAS broken: a joiner
    reached V_{e+1} as a voting member but was missing from the
    next committee's class-groups map.
  - `2a0f655c39` ("Delay the freeze until next-epoch joiners can
    be attested (F4-1)"): added `decide_ready_to_finalize` — a
    pure decision function that *gates the producer's ready
    emit* on (a) V_{e+1} being published AND (b) every V_{e+1}
    member's blob being locally validated, OR (c) the
    `3 * epoch_duration / 4` deadline elapsing as a liveness
    backstop. This is exactly the deeper fix I sketched: make
    coverage *require* V_{e+1} members specifically. The decision
    function is unit-tested (`mpc_data_announcement_sender.rs:556–593`)
    against the four scenarios (NotYet pre-V_{e+1}, NotYet
    pending joiner, Ready when complete, ReadyViaDeadlineMissing
    at deadline).
  - `fd3e0fd313` ("Break the joiner freeze deadlock"): fixed a
    circular-dependency bug introduced by 2a0f655c39 — the
    emit-gate originally keyed off the *off-chain-assembled* next-
    epoch committee, but assembly itself needed the joiner's
    mpc_data. Fix: publish a `chain_next_epoch_committee`
    channel from `sync_next_committee` (before assembly), so the
    freeze gate and the joiner watcher both read the chain view.
  - `5a241701d1` ("Make off-chain joiner integration work
    end-to-end"): the simtest still failed; three more bugs
    surfaced and were fixed:
    1. Ready-signal canonicalization filtered V_{e+1} joiners as
       weight-0 in the current committee; fix: treat *announcers*
       as valid attestation targets in canonicalization (safe
       because announcements are consensus-ordered before any
       ready signal attesting them).
    2. Joiner blob had no propagation path (current committee
       can't fetch from joiner; relay forwarded only digest);
       fix: joiner *pushes* bytes on the fan-out RPC, relayer
       caches write-through.
    3. Polling cadences (10s/5s/3s/2s) overran the freeze window
       in short test epochs; fix: `epoch_scaled_poll_interval`.
  - `cc455e2a02`: marked the test `#[ignore]` because reliably
    fitting the integration path inside a short test epoch is
    timing-sensitive (production ~24h epoch has hours of slack;
    test epoch has tens of seconds). NOT a regression — verified
    against the baseline `test_joiner_added_at_epoch_2`.
  - `69995f598f`: structured `warn!` on deadline-emit with
    missing-member list (`ReadyViaDeadlineMissing(Vec<AuthorityName>)`)
    — F4-1's deadline-tradeoff is now observable.

  **Residual concerns:**
  - The cluster test is `#[ignore]`'d. Coverage exists in
    `decide_ready_to_finalize` unit tests but not end-to-end in
    CI. The follow-up should be "fit the integration path
    inside a test-length epoch" so the test can run un-ignored.
  - The deadline-without-joiner outcome is reported but
    actionable handling (longer epoch? exclude joiner?) is
    operator-discretion. If joiners chronically miss the
    deadline at a given network's epoch length, today this would
    surface as repeated warns without automatic remediation.
  - **Determinism:** the deadline is wall-clock per validator.
    If validators' wall clocks diverge enough that some emit
    via deadline while others emit "ready", the *snapshot* taken
    at the consensus-ordered quorum point is still deterministic
    (per the commit message), but the *contents* of the snapshot
    can vary by which signals contributed to the quorum. Worth
    verifying that the partition computation is robust against
    a mix of "Ready" and "ReadyViaDeadlineMissing" signers — i.e.
    that the freeze partition's exclusion set doesn't depend on
    whether a given validator hit the deadline or not.

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

Two flavors of `Trait { fn …pubkey(name) -> Option<Ed25519PublicKey> }`,
fed by a single generic `PubkeyProviderUpdater<C>` after `2f7e6537a7`:

- `ConsensusPubkeyProvider` (in `handoff_cert.rs:102`) — active-
  committee Ed25519 consensus keys for handoff-sig verification.
- `JoinerPubkeyProvider` (in `validator_metadata.rs:94`) — next-
  epoch-committee Ed25519 consensus keys for joiner-announcement
  relay verification.

The unified updater
(`crates/ika-core/src/sui_connector/pubkey_provider_updater.rs`)
polls Sui every 5s (epoch-scaled), reads the chain-side committee
membership (`active_committee.members` or `next_epoch_committee.members`),
fetches `validator_info` for each member, calls `ValidatorInfo::verify()`
(self-consistency on bytes), and installs the
`AuthorityName -> consensus_pubkey` map via `ArcSwapOption`. Dedup
via base64-serialized `last_installed` cache.

### Concerns

_(empty — to be filled as user raises them)_

### Author candidate concerns (raised by walkthrough, awaiting review)

> These are MY candidate flags from walking the code, not verdicts.
> Accept / reject / refine as you go through them.

- **Per-epoch updater doesn't gate on the on-chain epoch field.**
  `select_active_committee` reads `system_inner.validator_set.active_committee.members`
  with no consistency check against `self.epoch_id`. If the OLD
  updater (for epoch e) is still alive past the epoch boundary
  and Sui has rolled forward — `active_committee` is now V_{e+1},
  not V_e — the updater would install V_{e+1}'s consensus keys on
  epoch e's still-live store. Handoff signatures from V_e
  validators no longer in V_{e+1} would then fail as
  `UnknownSigner` at epoch e's store.

  Correctness depends entirely on timely abort of the previous
  updater + drop of the previous `cur_epoch_store`. The
  `Weak<AuthorityPerEpochStore>` only saves us when the store has
  been dropped; nothing protects us during the window where the
  old store is still live but the on-chain active committee has
  moved on.

  **Fix:** add an epoch consistency check in `refresh()`:
  ```rust
  // After: let SystemInner::V1(system_inner) = system_inner;
  if system_inner.epoch != self.epoch_id {
      // Stale — either we lagged Sui (shouldn't happen on a
      // per-epoch task) or Sui has rolled past our epoch (the
      // previous-epoch task is about to be aborted).
      return Ok(());
  }
  ```
  Defense in depth — the abort-driven scoping is correct, but a
  loaded race needs a belt and suspenders.

- **Refresh loop spins forever when `Weak::upgrade()` fails.**
  At `pubkey_provider_updater.rs:186–189`, `refresh()` returns
  `Ok(())` when the epoch store has been dropped. The loop sleeps
  `poll_interval`, then calls `refresh()` again, which trivially
  returns. The task only exits via external `JoinHandle::abort()`.
  If the abort is missed or delayed (e.g. a code-path forgets to
  collect the handle), the task spins indefinitely doing nothing
  useful — minor resource leak, observable only as accumulated
  Tokio-task count over very long uptimes.

  **Fix:** exit the loop when `Weak::upgrade()` fails:
  ```rust
  if self.epoch_store.upgrade().is_none() {
      info!(epoch = self.epoch_id, label = self.label,
            "epoch store dropped; pubkey updater exiting");
      return;
  }
  ```
  Two extra lines; structural correctness instead of relying on
  the caller. (Same pattern shows up in other epoch-scoped tasks
  per F3-2's scope check — worth a sweep.)

- **`from_iter` silently overwrites on duplicate `AuthorityName`.**
  `StaticConsensusPubkeyProvider::from_iter` and `StaticJoinerPubkeyProvider::from_iter`
  both build a `BTreeMap` via `into_iter().collect()`. If two
  `validator_info` entries resolve to the same `AuthorityName`
  (`(&verified.protocol_pubkey).into()`) — extremely unlikely
  given on-chain uniqueness enforcement on the protocol pubkey,
  but not formally impossible — the last entry wins silently. A
  byzantine Sui state (e.g. via a hypothetical Move-level bug)
  could produce a duplicate, and the off-chain pipeline would
  install a stable but arbitrary choice.

  **Fix:** debug-assert (or full-error) on duplicate keys during
  construction. `BTreeMap::insert` returns the old value on
  collision — easy to check.

- **`JoinerPubkeyProvider` uses current `consensus_pubkey`, not
  `next_epoch_consensus_pubkey`.** A joiner's `validator_info` on
  chain has both `consensus_pubkey` (in use this epoch — for
  candidates pre-activation, this is what they registered at
  candidacy time) and `next_epoch_consensus_pubkey` (an optional
  rotation that applies at the next epoch boundary). The updater
  installs `verified.consensus_pubkey`, and `JoinerAnnouncementSender`
  signs with the local consensus keypair (which matches the
  candidate-time registration). If a joiner has set
  `next_epoch_consensus_pubkey != consensus_pubkey` *and* their
  local keypair has been rotated to match, the relayer's check
  (against on-chain `consensus_pubkey`) rejects every fan-out as
  `InvalidSignature`.

  Whether this is a real bug depends on (a) whether Sui's
  `request_set_next_epoch_consensus_pubkey` flow lets a candidate
  rotate before joining and (b) whether the operator playbook
  encourages it. If "no" to either, defer; if "yes" to both, the
  fix is to use `next_epoch_consensus_pubkey.unwrap_or(consensus_pubkey)`
  when populating the `JoinerPubkeyProvider`.

- **Dedup uses base64 of pubkey bytes.** `last_installed` stores
  `BTreeMap<AuthorityName, Vec<u8>>` of base64-encoded pubkeys.
  This works because `Ed25519PublicKey` doesn't impl `Eq`/`Hash`
  directly. Simpler: `as_bytes()` produces the canonical 32-byte
  representation already, no encode/decode needed. Pure cleanup.

- **Race: install lands at the same instant a downstream consumer
  reads.** `ArcSwapOption::store` is atomic, but downstream call
  sites like `verify_handoff_signature` do
  `provider.consensus_pubkey(signer)` and may run between the
  *old* install and the *new* one. If a signer was in the old
  committee but not the new one (committee shrinks mid-epoch —
  shouldn't happen, but in principle), they'd get
  `UnknownSigner`. Not a real concern in normal operation
  (committee is fixed per-epoch), but worth knowing that the
  arc-swap semantics expose every read to whatever was installed
  at the moment of the read.

- **Polling cadence is 5s default; `epoch_scaled_poll_interval`
  scales down to 1% of epoch.** For a 24h production epoch, 1%
  is 14.4 min ≫ 5s → clamped to 5s. So the active-committee
  provider is refreshed every 5s in production. The active
  committee doesn't change mid-epoch, so this is effectively a
  "watchdog" pattern — most refreshes are no-ops dedup'd against
  `last_installed`. Acceptable cost; not a concern, just an
  observation that the *active* committee polling could plausibly
  be a one-shot install with a re-poll on Sui-side error. The
  *next-epoch* committee polling needs to keep running because
  it can change mid-epoch (joiner registers late).

### Open questions raised during walkthrough

- **`ValidatorInfo::verify()` is structural only.** It validates
  byte lengths, Multiaddr parsability, and that the consensus
  pubkey isn't equal to the network pubkey. It does NOT validate
  that the on-chain `consensus_pubkey` was set by the actual
  validator (no proof-of-possession check). On-chain Move logic
  must enforce this via the registration path. Worth confirming
  Sui-side enforcement is sufficient — particularly for
  candidate-stage rotations.

---

---

## Feature 6 — Off-chain consumption / overlay in `sui_syncer`

Three intertwined overlay paths in
`crates/ika-core/src/sui_connector/sui_syncer.rs`:

- `sync_dwallet_network_keys` (line 517): chain reads only the
  lightweight `DWalletNetworkEncryptionKeyData` metadata; the two
  large blobs (`network_dkg_public_output`,
  `current_reconfiguration_public_output`) come from the local
  producer cache via `NetworkKeyBlobSource`. Empty-blob caching
  guard (per `95a3f5c6fb`) avoids pinning empties.
- `sync_next_committee` (line 275): publishes the *chain* view of
  V_{e+1} on `chain_next_committee_sender` (membership-only,
  empty class-groups maps) AS SOON AS Sui reports it, breaking
  the freeze-vs-assembly deadlock (`fd3e0fd313`). Then tries
  off-chain class-groups assembly via
  `EpochStoreClassGroupsSource::try_assemble_class_groups`; under
  v4 there is NO chain fallback for class-groups.
- The off-chain assembler reads the *frozen* set post-freeze, the
  *live* announcement table pre-freeze, via the pure helper
  `decide_assembly_inputs`.

### Concerns

_(empty — to be filled as user raises them)_

### Author candidate concerns (raised by walkthrough, awaiting review)

> These are MY candidate flags from walking the code, not verdicts.
> Accept / reject / refine as you go through them.

- **`chain_next_committee_sender` publishes a `Committee` with
  empty class-groups maps via `Default::default()` — a footgun.**
  At `sui_syncer.rs:320–333`, the chain committee is built with
  `Committee::new(... Default::default(), Default::default(),
  Default::default(), Default::default(), ...)` for the four
  class-groups/PVSS HashMaps. Any downstream consumer that reads
  off the *wrong channel* — i.e. consumes `chain_committee` for
  reconfig MPC instead of just for membership/threshold gating —
  silently gets empty class-groups maps and drops every share.

  The distinction "chain committee = membership only, assembled
  committee = full crypto" is enforced *by channel selection*,
  not by type. Any future call site reading the chain channel
  is one mistake away from a silent reconfig failure.

  **Fix:** introduce a separate `CommitteeMembership` type for
  the chain channel — `{ epoch, members, stake, quorum_threshold,
  validity_threshold }`, no class-groups fields. The two
  consumers of the chain channel today (freeze emit-gate via
  `decide_ready_to_finalize`; joiner watcher in
  `monitor_joiner_announcements`) only need membership +
  thresholds. Type-level separation makes "use the chain
  committee for crypto" a compile error.

- **No escalation when off-chain assembly NEVER converges.**
  `sync_next_committee` returns `OffChainAssemblyIncomplete`
  under v4 and just `continue`s on the next tick. There's no
  bounded-attempt budget, no escalation to `error!`, no halt.
  Pathological cases that produce permanent incompleteness —
  e.g. `EverythingExcluded` (every V_{e+1} member was excluded
  by the freeze partition) — would spin forever logging
  `warn!`s without any clear signal that the network is wedged.

  **Fix:** distinguish transient incompleteness ("waiting for
  P2P to converge") from permanent incompleteness
  (`AssemblyInputDecision::EverythingExcluded` — the freeze
  decided no one is attested). Permanent incompleteness should
  log `error!` and ideally trigger a metric/alert. The pure
  `decide_assembly_inputs` already returns `EverythingExcluded`
  as a typed enum variant; just surface it to the outer loop.

- **`sync_dwallet_network_keys` publishes incomplete entries to
  the channel during the overlay-not-ready window.** At line
  662–675, `overlay_incomplete = off_chain_on && merged.network_dkg_public_output.is_empty()`
  correctly skips updating the `last_fetched_network_keys`
  cache, so the next tick re-merges. But the merged value
  (with empty `network_dkg_public_output`) IS inserted into
  `all_fetched_network_keys_data` and sent on the channel on
  line 688 unconditionally. Downstream consumers see a transient
  entry whose blob is empty.

  Whether this matters depends on consumer behavior. Likely
  benign if consumers also check for empty blobs, but if any
  consumer does `data.network_dkg_public_output[0]` or BCS-decodes
  the bytes, they panic / drop / corrupt. Worth a sweep of
  consumers.

  **Fix:** filter out empty-blob entries before sending, OR
  send only when ALL fetched entries are complete (atomic
  publish). The latter is harder during startup; the former
  is a one-line change.

  ```rust
  // Before sending: filter incomplete entries
  let publishable: HashMap<_, _> = all_fetched_network_keys_data
      .iter()
      .filter(|(_, data)| !data.network_dkg_public_output.is_empty())
      .map(|(k, v)| (*k, v.clone()))
      .collect();
  if let Err(err) = network_keys_sender.send(Arc::new(publishable)) { ... }
  ```

- **No backoff on persistent chain RPC failure.**
  `sync_dwallet_network_keys` loops with `sleep(5s)` and retries
  the whole loop body on any error. `sync_next_committee` uses
  `epoch_scaled_poll_interval` but the same pattern: on error,
  `continue`. If `sui_client.get_dwallet_mpc_network_keys` or
  `get_validators_info_by_ids` fail persistently (chain RPC
  down), the loops burn CPU at 5–10s cadence forever logging
  identical errors.

  **Fix:** exponential backoff on consecutive errors, capped
  at e.g. 5 minutes, reset on success. Standard pattern for
  RPC-driven polling.

- **`Committee::new(epoch, ...)` for the chain committee uses
  `system_inner.epoch() + 1` without validating that this is
  exactly one ahead of the current epoch.** Looks correct on
  first read, but the per-epoch sync_next_committee task is
  long-lived (not respawned per epoch). If Sui rolls forward two
  epochs in a single poll window — unlikely but not impossible —
  the chain_committee for `epoch e+1` could be published when the
  current epoch is now `e+1`, not `e`. The downstream consumers
  expect the chain committee to represent the *next* epoch
  relative to *their* current view. A two-epoch jump would
  publish a "next" committee that's actually the current one.

  **Fix:** dedup the chain_committee channel against
  `last_published_epoch`, AND surface the epoch field in the
  consumer so consumers can sanity-check `chain_committee.epoch
  == self.epoch + 1`.

- **`assemble_committee_class_groups_off_chain` handles empty
  input via `saw_any` — but `assembly_pairs` is computed *after*
  `decide_assembly_inputs` already filtered.** So
  `EpochStoreClassGroupsSource::try_assemble_class_groups` is
  fine because `decide_assembly_inputs` returns `EverythingExcluded`
  before the assembler sees an empty list. But any FUTURE caller
  that bypasses `decide_assembly_inputs` and passes raw input
  must rely on `saw_any` for safety. Defense in depth is good
  here; just noting that the two-layer safety is load-bearing.

- **The `state` part of the `last_fetched_network_keys` cache
  key is `DWalletNetworkEncryptionKeyState`, an enum with
  variant-associated data.** Comment at line 528–535 explains
  that `state` is part of the cache key because chain-side state
  transitions within an epoch (e.g. `NetworkReconfigurationStarted`
  → `Completed`) change the blobs. Reasonable. But: `PartialEq`
  on enum variants with associated data compares the data too.
  If a state variant carries e.g. a `started_at_timestamp` that
  changes on every chain object refresh (without a "real" state
  transition), every poll would refetch. Probably not the case
  in practice, but worth a one-line spot-check that the state
  enum doesn't carry mutable-but-meaningless data.

- **`EpochStoreClassGroupsSource` reads `get_frozen_validator_mpc_data_input_set`
  and `get_epoch_excluded_validators` separately — non-atomic.**
  If a freeze fires between the two reads, the frozen set is
  populated but excluded is still empty (or vice versa, depending
  on the freeze code's write order). The pure helper
  `decide_assembly_inputs` would then read mismatched state.

  Practically: the freeze writes both sets at once via a single
  `freeze_mpc_data_if_first` call (per F4 review). If the
  underlying RocksDB write is in a single batch, atomicity holds.
  If not, the two reads could span the freeze instant.

  **Fix:** add a single `get_freeze_snapshot()` getter that
  returns `(frozen, excluded)` from a single locked read. The
  current two-step pattern is correct only by virtue of the
  freeze writer's atomicity, which isn't visible here.

- **The per-key `(epoch, state)` cache key resets across
  validators on restart.** Restarting a validator wipes the
  in-memory `last_fetched_network_keys` cache. The next poll
  refetches every key, calls the overlay, and republishes the
  channel. Fine for correctness; just observe that startup is
  always a full refetch — not a concern, but explains the
  cold-start cost.

### Open questions raised during walkthrough

- **No protocol-config gating on the chain-committee channel
  publish.** The chain committee is sent unconditionally
  regardless of `off_chain_validator_metadata_enabled()`. The
  consumers (freeze emit-gate, joiner watcher) ARE gated on
  off-chain mode, so this is harmless — but the channel could
  be hot under v3 too, where nothing consumes it. Either gate
  the publish on `off_chain_on` or document that the publish
  is intentional-cheap-no-op under v3.

---

## Feature 7 — Handoff attestation

Extracted into `crates/ika-core/src/handoff_cert.rs` (per
`7ecfa690cb`). The subsystem is now:

- **Build**: `build_handoff_attestation` — sort items by
  `HandoffItemKey`, reject duplicates, return canonical struct.
  Items contributed by `HandoffItemsBuilder` impls (one per
  domain: validator-mpc_data, network-key DKG outputs,
  reconfiguration outputs).
- **Sign**: `sign_handoff_attestation` — Ed25519 sign with the
  validator's consensus keypair (not BLS, per the off-chain-
  pipeline convention).
- **Verify**: `verify_handoff_signature` (per-message) +
  `verify_certified_handoff_attestation` (full cert) +
  `verify_joiner_bootstrap_cert` (joiner-side, epoch-bound).
- **Aggregate**: `HandoffAggregator` — one-shot accumulation,
  emits `CertifiedHandoffAttestation` on quorum cross.
- **Produce locally**: `HandoffSignatureSender` —
  per-epoch task that emits this validator's signed handoff in
  the *bundled* `EndOfPublishV2` message.
- **Consume on joiner**: `JoinerBootstrapVerifier` — per-epoch
  task on true joiners that fetches the prior-epoch cert from
  current-committee peers and verifies it.

### Concerns

_(empty — to be filled as user raises them)_

### Author candidate concerns (raised by walkthrough, awaiting review)

> These are MY candidate flags from walking the code, not verdicts.
> Accept / reject / refine as you go through them. The `sent` atomic
> one (first item) is the one I'd flag highest-priority for your
> attention — looks like a real bug, not a debatable design call.

- **`HandoffSignatureSender::sent: AtomicBool` is the SAME bug
  pattern as the pre-`ee385e39c4` mpc_data_announcement_sender.**
  `crates/ika-core/src/epoch_tasks/handoff_signature_sender.rs:52`
  + `:271`. On line 268–271:
  ```rust
  self.consensus_adapter
      .submit_to_consensus(&[tx], &epoch_store)
      .await?;
  self.sent.store(true, Ordering::Release);
  ```
  `submit_to_consensus` returns `Ok` as soon as the transaction
  is handed to the background submit task — which can still fail
  to sequence (abandoned at epoch boundary, lost on crash, durable
  pending-tx persistence is commented out per `ee385e39c4`'s
  rationale). The one-shot `sent` flag then prevents any retry,
  so a dropped EOPV2 silently never lands.

  This is **the same bug** that was fixed in
  `mpc_data_announcement_sender.rs` by replacing the atomic with
  confirmation-based retry (`announcement_confirmed()` checks
  our entry in the per-epoch table). The fix wasn't propagated
  to the handoff sender. The blast radius is more limited
  because EOPV2's chain-side equivalent (the actual
  `system_inner.epoch` advancing) provides a hard guarantee
  that we'll eventually need to move past this — but a dropped
  EOPV2 means *this* validator's EndOfPublish vote is silently
  lost for the rest of the epoch.

  **Fix:** mirror the `mpc_data_announcement_sender` pattern.
  Replace `sent: AtomicBool` with a confirmation check — e.g.
  `epoch_store.has_local_end_of_publish_v2_recorded()` —
  re-checked each tick. Loop retries until our own message
  appears in consensus delivery (i.e., our submission was
  sequenced + recorded), then no-ops. The cached attestation
  reuses the same `(attestation, signature)` so consensus
  dedups on a stable key.

- **`HandoffSignatureSender::send` falls back to raw assembled
  committee when frozen set is empty (per `34f880b124`).** The
  rationale is non-blocking emission of the bundled EOPV2 vote —
  correct trade-off (stalling reconfig is worse than a
  non-aggregating handoff sig). But the silent fallback to
  `frozen_set.is_empty() ⇒ no filter` means: under a chronic
  "freeze not yet fired locally before EOP" situation, the
  handoff sigs from this validator will be deterministically
  different from peers whose freeze did fire, producing
  cross-`AttestationMismatch` rejections.

  This is operator-invisible today. The 10-epoch churn test
  comment (`joiner.rs:756–783`) acknowledges
  `AttestationMismatch` under churn is a known limitation, and
  the aggregate assertion `total_certs_seen > 0` is loose
  enough to not catch it.

  **Recommendation:** surface "EOPV2 emitted before local freeze"
  as a metric/warning. If this fires in production, the operator
  knows to investigate why their local freeze is lagging
  consensus. Without a metric, this is silent flapping.

- **`verify_certified_handoff_attestation` does O(committee_size)
  individual Ed25519 verifies per joiner bootstrap.** At
  `handoff_cert.rs:347–389`, the loop iterates `cert.signatures`
  and verifies each against its claimed signer's consensus
  pubkey. On a committee of ~100 this is ~100 × 75µs ≈ 7.5ms per
  cert. Acceptable in isolation, but every joiner bootstrap runs
  `verify_joiner_bootstrap_cert` which calls this. Combined with
  the F3-4 concern (BLS aggregation would be a single verify),
  the operational cost vs design simplicity trade-off is more
  visible here than in the announcement path.

- **Prior-committee consensus pubkey availability under high
  churn.** Per the `7a278375b4` commit:
  > the prior-committee signers' consensus pubkeys are sourced
  > from the current epoch's active-validator set (consensus
  > keys are fixed at registration, so continuing signers' keys
  > are present)

  This breaks for FULLY departed prior-committee signers — they
  may have signed the prior epoch's cert but are not in the
  current epoch's active set. `consensus_pubkey(departed_signer)`
  returns `None`, and `verify_certified_handoff_attestation`
  fails with `no consensus pubkey for handoff signer`.

  If the cert's signers are a quorum of the prior committee but
  a significant fraction of those signers have since departed,
  the cert can't verify on the joiner — not because the cert is
  bad, but because the joiner can't resolve the signers'
  pubkeys. The joiner's bootstrap returns `Rejected` for a
  *valid* cert.

  This is a real high-churn correctness issue. The fix paths:
  1. Query Sui historical state for departed validators'
     `StakingPool.validator_info`. Non-trivial — depends on Sui
     storage retention policy.
  2. Have current-committee peers serve the prior-committee
     pubkeys via Anemo alongside the cert (one extra field on
     the cert response, or a separate RPC). Most reliable.
  3. Persist prior committee's pubkeys in our own perpetual
     store so a continuing validator can serve them after the
     signer left.

  Option 2 is the cleanest. Worth a follow-up.

- **`JoinerBootstrapVerifier` outcome enforcement is fail-OPEN
  for both `Unavailable` and `Rejected`.** Per
  `joiner_bootstrap_verifier.rs:155–204`, neither outcome
  aborts the joiner. `Unavailable` is benign (warn-and-
  continue); `Rejected` is logged at `error!` but still
  continues. The commit message for `7a278375b4` explicitly
  says fail-closed enforcement is a deliberate follow-up.

  Until that follow-up lands, a joiner whose prior-committee
  view is being attacked (every reachable peer is serving
  certs for the wrong committee, indicating eclipse) joins the
  committee anyway. Cross-epoch trust is observably broken but
  not enforced.

  **Recommendation:** prioritize the fail-closed follow-up.
  The current `Rejected` path is the most security-relevant
  outcome and it's silently ignored.

- **Single-hop only verification by design.** Per
  `verify_joiner_bootstrap_cert` doc: "Anchoring trust to the
  prior committee is sufficient because that committee was
  reached through some earlier handoff chain that this joiner
  either already trusts (steady-state) or doesn't (initial
  sync — caller's job)." This is a clean separation, but it
  means initial-sync trust establishment is **out of scope**
  for this PR. A bootstrapping joiner needs an out-of-band way
  to trust the prior committee (e.g., genesis fingerprint, or
  syncing forward from an earlier committee). Today this is
  implicit; documenting it explicitly in the JoinerBootstrap
  module doc would help future operators.

- **`HandoffAggregator::insert_verified` replaces existing
  signatures.** Line 228–234: "Replaced an existing signature
  for the same signer — don't double-count their stake.
  (Replacement is tolerated for resilience: a flaky signer
  could re-submit a fresher signature.)" This means a
  byzantine signer can submit DIFFERENT signatures over time;
  the aggregator silently keeps the LAST one. If the cert
  certifies before the byzantine signer's last submit, the
  cert has the early sig; if after, the late one. Probably
  fine — the cert is one-shot post-certification — but a
  defensive `debug!` on replacement would be cheap diagnostics.

- **`HandoffAggregator` doesn't cap signature count.** If
  somehow more signatures than committee-size arrive (e.g.
  byzantine peers spamming distinct names that hit
  `committee.weight == 0` and get rejected — the `== 0`
  weight-check pre-filters), no unbounded growth here.
  Verified at `:222–227`. Good defense.

- **`build_handoff_attestation` rejects duplicate keys but
  `HandoffItemsBuilder` impls are responsible for their own
  disjointness.** If two builders produce overlapping
  `HandoffItemKey` ranges (e.g., both contribute
  `NetworkDkgOutput(key_id)`), `build_handoff_attestation`
  returns an error and the handoff for this epoch is wedged.
  No defense beyond "register builders carefully".

  **Fix:** the `HandoffItemKey` enum could be split into per-
  builder sub-enums (each builder owns a distinct top-level
  variant). Today there's no compile-time enforcement that
  builders don't overlap.

- **`hydrate_protocol_output_digests_from_chain` is called
  before `build_local_handoff_attestation`** at signing time.
  This is the fix for the original local-MPC-cache-race per
  `8b7dbc1704` ("Cache DKG/reconfig output digests from
  consensus-voted data"). Re-caching with the same canonical
  bytes is a no-op for the digest, so this is idempotent.
  Good.

  But: it's also called every time `send()` retries (which is
  every 1s after EOP). Idempotent so harmless, but a
  per-second `cache_protocol_output` call per network key is
  visible in metrics. If the snapshot is stable, this loop is
  doing wasted work. Minor.

- **`snapshot_ready_for_signing` requires ALL keys to be in
  `NetworkReconfigurationCompleted` state with non-empty
  reconfig output.** What if a key is in
  `NetworkDKGCompleted` (post-DKG but pre-first-reconfig)?
  Specifically: in epoch 1, before any reconfig has happened,
  is the state `NetworkDKGCompleted` or `NetworkReconfigurationCompleted`?

  If it's `NetworkDKGCompleted`, then in epoch 1
  `snapshot_ready_for_signing` returns `false` forever and we
  never sign a handoff cert for epoch 1. That breaks epoch-2
  joiner bootstrap (no cert for the anchor epoch). Worth a
  spot-check that epoch 1's chain state correctly resolves to
  `NetworkReconfigurationCompleted` by the time EOP fires.

- **The `intent_msg` BCS encoding is computed on every
  signature verify in the loop at `:352–356`.** Inside
  `verify_certified_handoff_attestation`, the BCS-encoded
  bytes are computed ONCE outside the loop. Good — verified.
  Same for `verify_handoff_signature` (per-message). The
  hot path is clean.

### Open questions raised during walkthrough

- **Persistence + replay safety:** how are pending handoff
  signatures persisted across restart? The
  `pending_handoff_signatures` buffer (from `2be3d94a99` #3 +
  `cec2fc67cd`) — does it survive restart, or rebuild from
  consensus replay? Worth one explicit verification step.
- **`HandoffAggregator.signatures` is `BTreeMap<AuthorityName, Ed25519Signature>`,
  which collects into `Vec` for the cert.** The
  `Ed25519Signature` `Clone` may be expensive. Optional
  micro-optimization: build the cert lazily on first
  `certified()` query.

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

After spot-checking the full 38 commits since the review was
first written (`9a8398a6bc..34f880b124`):

| # | Concern | Verdict | Resolving commit(s) |
|---|---|---|---|
| F2-1 | Blob-store sync by convention only | ✅ ADDRESSED | `be254d52f9` (write-through `BlobCache`) |
| F2-2 | APES Finalize site missing mirror | ✅ ADDRESSED | `be254d52f9` (read-through covers perpetual-only sites) |
| F2-3 | `peer_blob_fetcher` can't reach joiners | ✅ ADDRESSED | `41bc8ba05b` step 1 (fanout) + `73f4ab8048` (joiner pushes bytes) |
| F3-1 | Once-per-epoch is producer-only | ✅ ADDRESSED | `cec2fc67cd` + `aaf9e10cb2` + `ee385e39c4` (confirmation-based self-heal) |
| F3-2 | 2s heartbeat too aggressive | ✅ OBSOLETED | `5a241701d1` (`epoch_scaled_poll_interval`) + design now does real work per tick |
| F3-3 | Split into two consensus message kinds | ✅ ADDRESSED | `3c479841b9` — split + Ed25519 for relayed kind |
| F3-4 | Unify handoff sigs to BLS aggregation | ❌ NOT ADDRESSED | Project moved further away from BLS (`3c479841b9` chose Ed25519 for announcements too) |
| F3-5 | Joiner-relay availability race | ⚠️ PARTIAL | Relayer-side: ✅ via Option A (joiner retry — `73f4ab8048` + `cc455e2a02` + `ee385e39c4`). Receiver-side: ⚠️ still drops on missing provider, warn-only (`d02019c214`). Option B unimplemented. |
| F4-1 | Ready signal sent before V_{e+1} → joiners drop | ✅ ADDRESSED | `2a0f655c39` (ready-signal gate) + `fd3e0fd313` (chain-committee channel) + `5a241701d1` (end-to-end) + `69995f598f` (deadline observability). Cluster test `c309e75698` exists but `#[ignore]`'d for short-epoch timing. |

## What the post-walk commits caught that we missed

The 38 commits since the original walk independently found several
bugs we didn't surface. Worth knowing for the next session's pace:

### Caught in the first 14 commits (9a8398a6bc..751e431bae)

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

### Caught in the next 24 commits (751e431bae..34f880b124)

- **Three more F4-1 bugs surfaced by the cluster test**
  (`5a241701d1`). The decide-ready-to-finalize gate fixed the
  freeze-timing root, but the targeted simtest revealed: (1)
  joiner stripped from `validated_peers` by current-committee
  canonicalization; (2) joiner blob has no propagation path —
  current-committee peers can't fetch from joiner; (3) poll
  cadences too coarse for short test epochs. Each fix was
  necessary independently. The bug-density per test run is a
  reminder that "the design works on paper" survives the first
  real test run roughly 0% of the time.
- **Freeze deadlock between off-chain-assembled committee and
  joiner mpc_data** (`fd3e0fd313`). The first F4-1 fix
  (`2a0f655c39`) keyed the joiner-fanout watcher and the freeze
  gate off the *assembled* next-epoch committee, but assembly
  itself needs the joiner's mpc_data. Circular dependency, fixed
  by publishing the chain view of V_{e+1} on a separate channel
  before assembly. We didn't flag this because our F4-1 sketch
  didn't specify which committee to gate on — the chain/assembled
  distinction wasn't on our radar.
- **`peer_blob_fetcher` reading the wrong table value**
  (`cd42e9c015`). The fetcher read the announcement from a wrap
  that no longer existed after `3c479841b9`'s table simplification.
  A typed table change with no compile-time error because the
  outer access was structurally similar.
- **Joiner-bootstrap verifier wasn't bound to a specific prior
  epoch** (`155ed58d4d`). `verify_joiner_bootstrap_cert` checked
  sigs against the passed-in committee and the next-committee
  hash, but never asserted that the cert's epoch is the one the
  joiner believes it's anchoring to. A real cert for a different
  epoch would have been accepted with a matching committee. We
  missed this in our F7 prep notes (handoff-cert verify) — the
  fact that the epoch is signature-bound hid the missing
  primitive-level epoch assertion. Standard cross-epoch trust
  anchor pattern.
- **Handoff committee membership non-deterministic under churn**
  (`a480cf1d0d`). The handoff attestation committee was built
  from a set whose iteration order could vary across validators
  during churn, producing non-deterministic membership and thus
  non-aggregatable sigs.
- **EndOfPublishV2 vote withheld by handoff committee
  intersection** (`34f880b124`). Most-recent fix on the branch:
  the handoff-cert subsystem could withhold the EOP vote in a
  way that wedged the epoch boundary. Walked through in F8.
- **`cache_protocol_output` (Finalize site) durably stored but
  unservable to mid-epoch peers** — the F2-2 site, fixed
  structurally by `be254d52f9`. We did flag this one, but
  diagnosed it as "needs paired in-memory write" when the right
  fix was "make `get` read-through from perpetual on miss." Our
  fix would have worked; theirs is cleaner.
- **Empty network-key blob cached when off-chain overlay isn't
  ready** (`95a3f5c6fb`). Sui-syncer overlay path could cache an
  empty blob if the off-chain assembly hadn't yet completed —
  poisoning the cache for the rest of the epoch. We'll cover in
  F6.
- **Dead V1 HandoffSignature consensus path** (`51c35dbf22`) and
  **dead NetworkKeyDKGReadySignal plumbing** (`159c190fe0`). Two
  full subsystems that survived their replacement and would have
  shown up as dead-code surface to walk in F7/F4. Their removal
  reduces the surface to review by hundreds of lines.

These are exactly the kinds of bugs a feature-walkthrough at our
level of abstraction tends to miss — they require running the code
in your head against specific byzantine or restart scenarios, not
just reading the design. Next session: ask "what happens if
sender is byzantine?" / "what happens after a restart?" at every
piece. The 24-commit pass also adds: **"what happens during churn
when iteration order isn't deterministic?"** (per `a480cf1d0d`)
and **"what's the cross-epoch trust anchor — is it bound to a
specific epoch?"** (per `155ed58d4d`).

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

## Refactors since the original walk (affect F5+ scope)

The 24 commits since `751e431bae` reshaped several modules; the
remaining feature walks (F5–F13) operate on the new structure:

| Refactor | Commit | Impact |
|---|---|---|
| `BlobCache` introduced | `be254d52f9` | F2 closed; F6 sui-syncer paths now read through |
| Two-kind announcement split + BLS→Ed25519 | `3c479841b9` | F1/F3 wire-shape changed; `epoch` returned to body |
| Joiner fan-out + push-bytes | `73f4ab8048` + `5a490ef0f7` + `cc455e2a02` + `ee385e39c4` | New `JoinerAnnouncementSender` task; closes F3-5 relayer-side |
| Freeze gate via `decide_ready_to_finalize` | `2a0f655c39` + `fd3e0fd313` + `69995f598f` + `5a241701d1` | Closes F4-1; introduces `chain_next_epoch_committee` channel |
| Pubkey-provider updaters unified | `2f7e6537a7` | F5 walks one generic `PubkeyProviderUpdater<C>` |
| Handoff-cert subsystem extracted | `7ecfa690cb` + `155ed58d4d` + `a480cf1d0d` + `34f880b124` | F7 walks the new `handoff_cert.rs` module |
| Joiner-bootstrap consumer wired | `7a278375b4` + `fc9a7786d6` | F7 adds end-to-end consumer; new `JoinerBootstrapVerifier` |
| V1 HandoffSignature dropped | `51c35dbf22` | F7 has one path, not two |
| NetworkKeyDKGReadySignal dropped | `159c190fe0` | F4 simpler; per-key freeze surface gone entirely |
| Dead off-chain helpers dropped | `4ca60b699a` | F9 dead-code audit was already done |
| Doc accuracy sweep | `d02019c214` | F11 logging consistency improvements |
| Empty-blob caching guard | `95a3f5c6fb` | F6 sui-syncer overlay safety |

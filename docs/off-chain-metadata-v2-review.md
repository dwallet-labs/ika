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

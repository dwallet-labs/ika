# #1736 — root mechanism of the silently-dead / laggard validator, and the fix

> ARCHIVED RECORD — forensic review of the silently-dead / laggard validator
> (ika #1736), written 2026-06-28 against `feat/ocs-grpc-migration`, with its
> resolution block added 2026-07-25. The primary fix shipped as #1761 and the
> issue closed 2026-08-06. Current truth for the prepare-then-start barrier,
> certificate birth and network-key adoption is
> [`../../specs/handoff.md`](../../specs/handoff.md). Kept as history; not
> maintained.

Repo: `feat/ocs-grpc-migration`. Read-only forensic synthesis grounded in code
(every claim cites `file:line`). This consolidates a 5-stage pipeline trace and
re-verifies the load-bearing claims against the source, because two of the stages
reached *conflicting* roots and the conflict turns out to be resolvable.

The headline correction vs. the stage notes: the prepare-then-start barrier
(`wait_for_handoff_data_ready`, `ika-node/src/lib.rs:3210`) does **not** merely
check a presence slice and then start. It blocks **indefinitely** (no timeout,
`lib.rs:3192-3193`, `:3353-3356`) until BOTH (1) a verified `cur_epoch` handoff
cert is held AND (2) every reconfiguration output the cert certifies is held
locally with a matching digest (`lib.rs:3268-3270`). And on every 1s retry it
peer-fetches the missing certified outputs by cert digest
(`install_joiner_network_key_outputs`, `lib.rs:3300-3306`, `:3400`). This barrier
is the spine of the whole story and forces a single, coherent mechanism.

---

## 1. THE MECHANISM

### 1a. The one upstream root: a validator never holds epoch-N's *own* handoff cert, and the cert was never minted on a quorum of validators

The certified handoff attestation for epoch E is **not** a consensus-delivered
object. It is **locally assembled** on each validator from per-signer handoff
signatures that ARE consensus-delivered (each bundled into an `EndOfPublishV2`
tx, `handoff_signature_sender.rs:307`). On each `EndOfPublishV2` the consumer
runs `record_handoff_signature` then `process_end_of_publish_vote`
(`authority_per_epoch_store.rs:4414-4415`). The cert is persisted to the
**perpetual** `certified_handoff_attestations` DBMap
(`authority_perpetual_tables.rs:53`) **only** when this validator's own
in-memory `HandoffAggregator` crosses stake quorum — the `Certified` arm at
`authority_per_epoch_store.rs:2831`.

The decisive asymmetry (`apes.rs:4399-4414`): the **EOP vote** that drives epoch
close is counted **unconditionally**, even when the bundled handoff signature is
**rejected** as `AttestationMismatch`. The **handoff cert** needs a *quorum of
valid* signatures. So **epoch close is a strictly weaker condition than
handoff-cert formation.** A laggard emits its `EndOfPublishV2` only after
`snapshot_ready_for_signing()` (`handoff_signature_sender.rs:267`,
`:170-180`) — which requires THIS validator's own epoch-keyed reconfiguration
output digest to be present locally
(`get_network_reconfiguration_output_digests_for_epoch(self.epoch_id)`,
`:171`, `:175-179`). A validator that never cached its own epoch-N
reconfiguration output never emits V2 → contributes neither an EOP vote nor a
handoff signature, while the epoch still closes off the other validators' EOP
votes.

If **two** such validators (or enough cross-rejecting sigs) keep the count of
*valid* handoff signatures below `quorum_threshold()`, the cert is **born on no
validator**. The aggregator is in-memory and per-epoch, so once E closes there
is no way to re-drive its collection.

### 1b. How that produces the exact forensic signature (zero MPC activity for the whole epoch)

There are two distinct laggard end-states, and the trace lets us tell them apart
by which side of the barrier the validator sits on. Both ultimately come from
1a, but they look different in logs:

**State A — stuck at the barrier (never starts the N+1 MPC service).**
At the E→E+1 seam the barrier's `prepare_handoff_anchor` (`lib.rs:3004`) tries to
obtain the E cert: if absent locally it fetches+verifies from peers
(`lib.rs:3109-3146`). When the cert was born nowhere, every peer returns
`Ok(None)`, the verifier exhausts its `30 × 10s` budget and returns
`BootstrapOutcome::Unavailable` → `prepare_handoff_anchor` returns `None`
(`lib.rs:3172-3178`) → `ready` is false (`lib.rs:3268`) → the barrier loops
forever (`lib.rs:3353-3356`). `start_epoch_specific_validator_components`
(`lib.rs:2845`) is gated behind the barrier, so the **per-epoch MPC service never
starts.** This validator emits the barrier's every-10-retry WARN
(`lib.rs:3340-3350`, "still awaiting full verified handoff data"). This is the
*safe* failure — visibly stuck, never signs stale.

**State B — passed the barrier, but the per-iteration adoption loop adopts
nothing (the "silently-dead / low-volume" signature).** This is the validator
that holds the E cert (it self-formed it during E, or fetched it) but whose
overlay never carries the cert-matching reconfiguration bytes for the inherited
key. The service starts (`dwallet_mpc_service.rs:423`), waits past
`replay_waiter.wait_for_replay()` (`:425`), and runs
`run_service_loop_iteration` every `READ_INTERVAL_MS` (`:474`), calling
`adopt_cert_verified_keys` + `instantiate_adopted_network_keys` each tick
(`:501-508`). In `adopt_cert_verified_keys` (`mpc_manager.rs:730`):

- empty `network_dkg_public_output` → `continue` (`mpc_manager.rs:809-810`); or
- **cert present, pins a reconfiguration digest, but the overlay's
  reconfiguration output is empty** → `continue` (`mpc_manager.rs:864-888`); or
- digest mismatch with no already-adopted value → `continue`
  (`mpc_manager.rs:949-988`).

Each path skips inserting into `adopted_network_key_data`, so
`instantiate_adopted_network_keys` (`mpc_manager.rs:2193`) spawns nothing → no
"Instantiating agreed network key" line, zero `dwallet_mpc` output all epoch. The
syncer faithfully republishes the empty-blob key every 5s but never records it
complete (`sui_syncer.rs:983-1017`) and logs "No new network keys to fetch"
(`sui_syncer.rs:825`) once it has — exactly the forensic signature.

### 1c. Which state is #1736? Ranking, and what distinguishes them

The forensic signature in the issue is **State B** ("service runs at ~1/6 volume,
no `mpc_manager` lines, syncer loops 'No new network keys'"), NOT State A
(State A would not run the syncer/MPC loop at low volume — it would be parked in
the barrier emitting the prepare-then-start WARN, with consensus components not
started). So the precise #1736 mechanism is:

> **A validator holds (or fetches) the epoch-E handoff cert and passes the
> barrier, but its overlay never resolves the cert-matching reconfiguration
> bytes for the inherited key, so `adopt_cert_verified_keys` skips that key on
> every ~20ms tick for the whole epoch → zero MPC output.**

How can it pass the barrier (which fetches the certified reconfiguration outputs
by digest, `lib.rs:3300`) yet have an empty overlay at runtime? The barrier
caches the fetched bytes into `new_epoch_store` via
`install_joiner_network_key_outputs` (`lib.rs:3400`), and the runtime overlay
resolves bytes through the installed `EpochStoreBlobSource`
(`validator_metadata.rs` → `AuthorityPerEpochStore::network_reconfiguration_output_blob`
→ `lookup_protocol_output_blob`, `apes.rs:2598`). The genuine residual seams
where these can disagree:

1. **Blob-source epoch-install ordering.** The blob source is installed as a
   `Weak` to the **current-iteration** epoch store at the TOP of
   `monitor_reconfiguration` (`lib.rs:2595-2601`). During the barrier and the
   N+1 service start (END of the same iteration), the live blob source is still
   the **epoch-N** `Weak`; the N+1 source is installed only on the NEXT loop
   iteration (`lib.rs:2595` again). After `release_db_handles`
   (`lib.rs:2912`) the epoch-N store's per-epoch `tables()` is cleared, so
   cross-epoch byte resolution survives only through the **perpetual** mirror
   (`mpc_artifact_blobs` + non-epoch digest mirror) written by
   `cache_protocol_output` (`apes.rs:2480-2528`). NB: the code comment at
   `lib.rs:2820-2826` explicitly states the barrier needs no pre-install because
   readiness is decided off the cert + the local digest slice — but that reasons
   about the *barrier's* readiness check, not the *runtime overlay's* byte
   resolution, which is exactly the asymmetry.

2. **Presence-vs-resolvability asymmetry.** The barrier's condition-2 asserts
   digest PRESENCE in the epoch-keyed slice
   (`get_network_reconfiguration_output_digests_for_epoch(cur_epoch)`,
   `lib.rs:3266`; the slice is `apes.rs:695-731`, written at `:717`). The
   runtime overlay/adoption path resolves BYTES via `lookup_protocol_output_blob`
   (per-epoch table OR non-epoch perpetual mirror + `mpc_artifact_blobs`,
   `apes.rs:2598`). `install_joiner_network_key_outputs` and the producer path
   (`dwallet_mpc_service.rs:1946`, `cache_network_reconfiguration_output`) write
   BOTH the epoch-keyed slice and the mirror, so in the common case they agree;
   the residual is the window where condition-2 is satisfied (digest present) but
   the byte resolution the overlay uses isn't yet wired for the new epoch.

**Honesty note on closure.** Code alone does NOT fully close State B as a
guaranteed-reachable state in steady-state v4: `install_joiner_network_key_outputs`
writes via the same `cache_*` entry points the overlay reads, so for a validator
that *passed* the barrier the bytes should be resolvable. The most defensible
reading is that **#1736 is dominated by State A masquerading as State B in the
logs** (a validator whose cert was born nowhere is parked in the barrier; its
*previous* epoch's already-started syncer/service keep ticking at low volume on
the OLD epoch store until shutdown), OR a thin install-ordering window (seam 1)
where the first adoption ticks fire against the about-to-be-released epoch-N
blob source. Both reduce to the same upstream root (1a) and the same fix
surface; the fix below hardens **both** the cert-birth guarantee (State A) and
the barrier↔overlay resolvability coupling (State B), so it is correct
regardless of which sub-state dominates a given incident.

**Ranking of candidate roots:**

1. **(HIGH) Cert born nowhere because epoch close is decoupled from handoff-cert
   quorum** (`apes.rs:4399-4414`, `:3947-4008`; `handoff_signature_sender.rs:170-180`).
   This is the only mechanism that (a) is self-reinforcing across a *new* epoch,
   (b) is not caught by any recovery net, and (c) produces a validator that does
   zero MPC for a whole epoch. It is the upstream cause of State A and the
   precondition for the two-laggard quorum collapse.
2. **(MEDIUM) Barrier↔overlay byte-resolvability asymmetry + blob-source `Weak`
   install ordering** (`lib.rs:2595-2601`, `:2820-2826`, `:3266` vs `apes.rs:2598`).
   The cleanest explanation for a validator that PASSED the barrier yet idles.
   Narrower window; depends on the producer/joiner paths and the per-iteration
   re-install timing.
3. **(MEDIUM) One-shot 300s detached cert bootstrap that no-ops on `Unavailable`**
   (`lib.rs:2552-2554`; `joiner_bootstrap_verifier.rs:160-208`). A *secondary*
   amplifier: it is the catch-up fetch that gives up and never re-arms within the
   epoch. Note the barrier's `prepare_handoff_anchor` re-attempts indefinitely,
   so this detached task is not the gating path for *starting* the service, but
   it is the path that would otherwise heal a slow cert and it quits early.

What is **refuted** as the root (re-verified): cert *absence* by itself does NOT
wedge `adopt_cert_verified_keys` — with `cert == None` a reconfigured key with a
non-empty reconfiguration output adopts via the cert-less v3→v4 fallback
(`mpc_manager.rs:990-1006`, warned at `:1043-1050`) and an initial-DKG key adopts
its local DKG output (`:889-918`, the `if let Some(cert_dkg)` is skipped when the
digest map is empty). The skip-forever requires the cert to be **present**
(`:864-888`, `:919-988`). This is why the wedge needs the cert to *exist and pin
a digest the overlay can't satisfy* (State B), or the cert to be *un-fetchable so
the barrier never releases* (State A) — not merely "cert is None".

---

## 2. WHY THE RECOVERY NETS DON'T CATCH IT

There are four self-heal mechanisms; each fails for a precise, code-level reason.

**(a) The per-tick adoption retry** (`dwallet_mpc_service.rs:501-508`) re-runs
every ~20ms but is a pure function of `(overlay snapshot, cert)`. It has no
permanent early-out bug (a late cert flips `last_adoption_input.cert_was_present`
false→true and drives a fresh pass, `mpc_manager.rs:786-791`), so it self-heals
the moment the overlay carries resolvable bytes — but it has **no mechanism to
make the overlay resolvable**. It loops over the same empty overlay forever.

**(b) The quorum-replay net** `cache_network_key_output_from_quorum`
(`mpc_manager.rs:517`) is invoked **only** on the `Some(...)` arm of
`handle_consensus_round_outputs` (`mpc_manager.rs:451-456`), i.e. only AFTER the
reconfiguration output reaches quorum in consensus (`handle_output` →
`build_outputs_to_finalize` → `weighted_majority_vote`,
`mpc_manager.rs:2595-2620`; below `quorum_threshold()` it returns `None` via
`ThresholdNotReached`, `:2620`). It heals a **single** dead-compute laggard
(consensus output processing is independent of the local MPC compute service —
outputs are read from the per-epoch store, `dwallet_mpc_service.rs:842-1305`), and
it caches BOTH the DKG and reconfiguration blob plus the epoch-keyed
reconfiguration digest (`mpc_manager.rs:559-581`; `apes.rs:717`) that
`snapshot_ready_for_signing` gates V2 on. **But with two non-producers the
producing set drops below `quorum_threshold()` → no `Some` arm → the net is never
invoked for either laggard.** The net is a downstream consumer of a quorum the
two non-producers themselves prevent; strengthening the cache/replay path cannot
help because the cache is never written.

**(c) The prepare-then-start barrier's peer-fetch**
(`install_joiner_network_key_outputs`, `lib.rs:3300`, `:3400`) fetches a
certified reconfiguration output from peers by the cert's item digest and caches
it — this DOES heal a validator that holds the cert but missed the outputs. It
fails when the **cert itself does not exist on any peer** (born nowhere): then
`prepare_handoff_anchor` returns `None` and the barrier blocks forever (State A);
the peer-fetch is never even reached because it is gated on `cert.is_some()`
(`lib.rs:3294`).

**(d) The boundary cert bootstrap recovery net**
(`JoinerBootstrapVerifier`, `lib.rs:2474-2554`; `joiner_bootstrap_verifier.rs:160-208`)
fetches the cert from peers, but classifies "no peer has it" as
`BootstrapOutcome::Unavailable` and treats it as **benign propagation lag**: no
halt, no persist, no retry past the `30×10s` budget (`lib.rs:2552-2554`). It
assumes the cert exists on an honest peer and only needs propagating — false when
the cert was born nowhere. Secondary amplifier: the replay-mint and
buffered-quorum cert paths do **not** persist the cert (only the
`record_handoff_signature::Certified` arm at `apes.rs:2831` does; the replay path
at `apes.rs:2330,2355-2359` only sets a metric gauge, and the buffered-quorum
install at `apes.rs:2737-2743` routes through `install_expected_handoff_attestation`
which also does not persist directly), so a validator that crossed quorum via
replay/buffer holds the cert **in memory only** and serves `Ok(None)` after a
restart — shrinking the serve set and making `Unavailable` more likely.

---

## 3. THE FIX

> **RESOLUTION (added 2026-07-25): the primary fix below SHIPPED.** PR #1761
> ("fix(epoch): couple v4 epoch close to the handoff-cert quorum") merged
> 2026-06-24 — four days *before* this file was first committed — implementing
> exactly the mechanism proposed here. It is live in
> `authority_per_epoch_store.rs` as `handoff_signatures_meet_quorum` (:3447)
> and `decide_v4_epoch_close` (:3470), with dedicated unit tests. Read
> everything below as the analysis that motivated a landed change, not as
> outstanding work.
>
> **Scope caveat — this document and issue #1736 are not the same
> investigation.** #1736 is still OPEN, but its thread tracks a *different*
> mechanism: the stale-mpc_data double-fetch / VSS empty-key-map race
> (addressed piecemeal by #1735 and #1807, with an intermittent residual).
> PR #1761 was tagged against #1736 but the issue thread never references it.
> Don't read this file's "resolved" status as closing the issue, or the
> issue's open status as meaning this fix is pending.

Two layers. The **primary** fix removes the state where the cert is born nowhere
(the upstream root, kills State A and the two-laggard collapse). The
**secondary** fixes harden the barrier↔overlay coupling (kills State B's window)
and the recovery-net robustness. None weakens the cert-digest gate:
`adopt_cert_verified_keys` still re-validates every byte against the prior-epoch
handoff cert; a missing/unreadable cert still **skips** adoption, never bypasses
it (`mpc_manager.rs:742-783`).

### Primary — couple the v4 epoch close to handoff-cert quorum (defense in depth on the existing grace)

Touch-point: the v4 deferred-close path,
`authority_per_epoch_store.rs:3947-4008` (the EOP-vote-quorum + grace close), and
the freeze-decision helper it already uses (`apes.rs:4011-4019`).

Shape: gate the close not only on EOP-vote quorum + grace, but ALSO require that
this commit's handoff aggregator has reached `Certified` (the local cert exists),
OR that a separate, longer **handoff-cert grace** has elapsed. Because every
validator evaluates the **same consensus-ordered** handoff-sig set, the
"aggregator certified" condition is a deterministic function of the consensus
sequence at a given commit — the exact property the close already relies on. This
makes "epoch closes ⇒ a quorum of valid handoff sigs was sequenced ⇒ every
validator can assemble the cert from the same sequence."

Keep the EOP grace as a **liveness backstop** so a genuinely stuck handoff (two
permanently-dead validators) still closes — but in that case **escalate loudly**
(metric + alert), never close silently into a guaranteed-wedged next epoch.

Risk on the MPC critical path: this delays epoch close by the handoff-cert grace
when sigs are slow but otherwise healthy. Mitigate by setting the cert grace to a
small multiple of the EOP grace and keeping the EOP grace as the hard backstop;
the close stays a deterministic function of the consensus sequence so honest
validators cannot disagree on the close round (the very property the unconditional
EOP vote was designed to preserve, `apes.rs:4399-4408`).

### Secondary 1 — make the barrier's readiness check use the same byte-resolution path the overlay uses, and install the new-epoch blob source before the service starts

Touch-points: `lib.rs:2595-2601` (blob-source install), `lib.rs:3265-3270`
(barrier condition 2), `lib.rs:2842-2845` (service start).

Shape:
- Install the **epoch-N+1** `EpochStoreBlobSource` for `new_epoch_store` at the
  reconfigure seam (immediately before `start_epoch_specific_validator_components`,
  `lib.rs:2842`), not on the next `monitor_reconfiguration` iteration. The
  install is an idempotent `ArcSwap` set, so this is low risk and removes the
  window where the live blob source is the about-to-be-released epoch-N `Weak`.
- Strengthen barrier condition-2 to assert byte-RESOLVABILITY via the exact
  runtime path — `new_epoch_store.network_reconfiguration_output_blob(key_id)`
  returns `Some(bytes)` with `mpc_data_blob_hash(bytes) == cert_digest` — for
  every cert-certified reconfiguration key, not merely that the epoch-keyed digest
  slice contains the key (`lib.rs:3268`). This ADDS a resolvability check on top
  of the existing digest match; a read error / missing blob keeps the validator
  waiting, never bypasses the gate.

Risk: the barrier already blocks indefinitely; tightening condition-2 can only
make it wait *longer* in the pathological case, never start stale. Net safety
strictly improves.

### Secondary 2 — make the cert recovery net robust

Touch-points: `apes.rs:2330/2355` and `apes.rs:2737-2743` (persist on every mint
path), `joiner_bootstrap_verifier.rs:199-208` + `lib.rs:2552-2554` (reclassify
steady-state `Unavailable`).

Shape:
- Call `insert_certified_handoff_attestation` on EVERY path that mints the cert:
  from `install_expected_handoff_attestation` when `replay_certified_epoch.is_some()`
  (`apes.rs:2330/2355`) and after the buffered-quorum install
  (`apes.rs:2737-2743`). This maximizes the set of peers that can serve the cert,
  directly shrinking the `Unavailable` window.
- Reclassify a persistent `Unavailable` for a **steady-state v4** epoch (the prior
  epoch ran v4, so a cert MUST exist) from benign to a loud, metricized, alertable
  condition — distinct from the genuine v3→v4 boundary where no cert is expected
  (tell them apart by the prior epoch's protocol version). Optionally fail-closed
  (like `Rejected`) rather than limping into a guaranteed-wedged epoch.

### Is a targeted retry/escalation enough, or is the structural change needed?

The structural change (Primary) is the correct fix: a pure retry/escalation
cannot manufacture a cert that was never minted on a quorum. Secondary 2's
re-arm/persist widens the serve set but still depends on the cert existing
*somewhere*; only coupling the close to cert-quorum guarantees birth. Secondary 1
is independently worth doing (it is a small, safe, surgical hardening of the
barrier↔overlay seam and removes State B's window) but is not sufficient alone.

---

## 4. HOW TO VALIDATE (without observing the heisenbug race)

The race is logging-perturbed, so validate the **stuck path deterministically**,
not by reproducing the flake.

1. **Unit test the close↔cert-quorum coupling (Primary).** In
   `authority_per_epoch_store.rs` tests, drive `process_end_of_publish_vote` /
   the v4 deferred-close (`apes.rs:3947-4008`) with a hand-built consensus
   sequence in which EOP votes reach quorum but valid handoff signatures do NOT
   (inject `AttestationMismatch` rejects for ≥ N−quorum signers). Assert: with
   the fix, the epoch does NOT close until either the handoff aggregator
   certifies OR the cert-grace elapses (and in the latter case the escalation
   metric fires). This is fully deterministic — no MPC compute, no timing race.

2. **Unit test `all_cert_reconfiguration_outputs_held_locally` +
   resolvability (Secondary 1).** Tests already exist at `lib.rs:3605-3654`.
   Extend with a case where the epoch-keyed digest slice contains the key but
   `network_reconfiguration_output_blob` returns `None` (mirror not written):
   assert the strengthened condition-2 reports NOT ready (barrier keeps waiting),
   proving the presence-vs-resolvability gap is closed.

3. **Unit test cert persistence on the replay/buffered-quorum paths
   (Secondary 2).** Re-mint a cert via `install_expected_handoff_attestation`
   replay (`apes.rs:2330`) and via `quorum_attestation_in_buffer`
   (`apes.rs:2737`); assert `get_certified_handoff_attestation(epoch)` returns
   `Some` afterward (today it returns `None` for these paths).

4. **Cluster regression (existing).** Run
   `test_global_presigns_complete_across_epoch_switches`
   (`epoch_boundary_presign_traffic.rs`) — the dwallet-MPC-across-epoch path the
   wedge breaks. Pair with a **flake-rate measurement**: the issue reports ~1/3
   heavy-TS flake; run the heavy TS-integration epoch-boundary suite N≥30 times
   pre/post fix on CI and compare failure rates. The fix should drive the
   "Object does not exist" / "MPC output yet to reach quorum" wedge to ~0.

5. **Negative/security check.** Add a test that a present cert whose pinned
   reconfiguration digest does NOT match the overlay bytes is still SKIPPED by
   `adopt_cert_verified_keys` (`mpc_manager.rs:864-888,949-988`), and that a cert
   read ERROR skips the tick rather than blind-adopting (`mpc_manager.rs:742-783`)
   — proving the fix did not weaken the cert-digest gate.

---

## 5. CONFIDENCE & OPEN QUESTIONS

**Solid (HIGH, code-verified):**
- The cert is locally assembled and persisted only on the `Certified` arm
  (`apes.rs:2831`); replay/buffered-quorum mints do not persist
  (`apes.rs:2330,2355-2359,2737-2743`). Verified directly.
- Epoch close (EOP-vote quorum + grace) is strictly weaker than handoff-cert
  quorum; the EOP vote is counted even when the bundled handoff sig is rejected
  (`apes.rs:4399-4414`). Verified directly.
- `snapshot_ready_for_signing` requires THIS validator's own epoch-keyed
  reconfiguration output digest (`handoff_signature_sender.rs:170-180`). Verified.
- The quorum-replay net is gated on the `Some` arm and never fires below quorum
  (`mpc_manager.rs:451-456,2595-2620`). Verified.
- The barrier blocks indefinitely and peer-fetches certified outputs; with the
  cert born nowhere it never releases (`lib.rs:3004-3180,3210-3357`). Verified —
  this is the correction to the stage notes.
- Cert ABSENCE alone does not wedge `adopt_cert_verified_keys` (cert-less fallback
  adopts); the skip-forever needs a PRESENT cert + empty/mismatched overlay
  (`mpc_manager.rs:864-1006`). Verified.

**Less certain (MEDIUM), needs the maintainer's deployment knowledge:**
- **Which sub-state is the observed #1736?** The forensic signature reads as
  State B (service runs at low volume), but State A (parked in the barrier) is the
  more code-supported terminal state for "cert born nowhere." The likely
  resolution is that the low-volume ticking is the *prior* epoch's
  already-started syncer/service on the old store while the node is parked in the
  barrier for the next epoch. The maintainer's raw logs (does the dead laggard
  ever emit the `prepare-then-start: still awaiting full verified handoff data`
  WARN at `lib.rs:3340`?) would settle this immediately and is the single highest
  -value disambiguator. If yes → State A → Primary fix is decisive. If the
  laggard genuinely passed the barrier and still idles → State B → Secondary 1's
  resolvability window is implicated and needs the producer-path audit below.
- **Producer-path caching audit.** Confirm the own-MPC-output reconfiguration
  finalize (`dwallet_mpc_service.rs:1946`) and `install_joiner_network_key_outputs`
  (`lib.rs:3400`) BOTH go through `cache_network_reconfiguration_output`
  (`apes.rs:695`) so the epoch-keyed slice AND the perpetual mirror are written
  atomically — guaranteeing the barrier-check table and the overlay-read table can
  never disagree. If any path writes only one, that is the State-B seam.
- **Committee/stake arithmetic.** The two-laggard collapse assumes the producing
  set can drop below `quorum_threshold()`; the exact threshold is
  deployment-specific (`dwallet_mpc/mod.rs:165-171`), but the direction holds for
  any stake quorum.

**Open question for the maintainer:** the handoff-cert-grace value for the Primary
fix is a liveness/safety trade-off (longer = more robust cert birth, slower close
when sigs lag). Recommend deriving it from the same parameters as the existing EOP
grace and validating against the cluster suite's epoch cadence.

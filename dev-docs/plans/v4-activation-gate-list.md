Status: active (2026-07-12) — fixes in progress on branch `fix/v4-gate-list`; PR #1820 landed the first isolated batch.

# Protocol-v4 activation gate list

Every issue here ships **dark** in 1.2.0 (the paths are v4-gated) but protocol
v4 **activates automatically** ~one epoch after enough stake runs a
v4-advertising binary — validators advertise `SupportedProtocolVersions::SYSTEM_DEFAULT`
(= MIN..=MAX = v3..=v4), capabilities are tallied at every epoch close
(`choose_highest_protocol_version_and_move_contracts_upgrades_v1`, `authority.rs:571`),
and `SetNextConfigVersion(4)` is emitted once quorum+buffer stake supports it.
There is **no separate vote**. So this whole list must be sound before any
v4-advertising binary rolls out fleet-wide — or the 1.2.0 default advertisement
must be capped at v3 and lifted in the release that closes this list.

Source: the 1.2.0 release review's §3, re-verified at head `c7cfd03f4c` by a
14-item design pass + cross-check (2026-07-12).

## Landed

- **PR #1820** (`fix/v4-gate-list`): V5 (`refresh()` per-member skip), V9c
  (prior-committee snapshot-name keying), `read_bls_committee_lossy` for the
  bootstrap anchor, V7-partial (`get_committee` unwrap→propagate), SDK 0.5.0
  changeset + README rename fix. Cluster + integration suites dispatched.

## Open — two tracks

### Track A — handoff / barrier (consensus-critical; precedes any v4 rollout)

Ordering DAG (from the cross-check; each arrow = "must precede"):

1. **V7** committee legacy-decode (medium) — PREREQUISITE: the v3→v4 transition
   epoch can panic reading a 1.1.8 `committee_map` record before anything else
   runs. Legacy-fallback decode via a `LegacyCommittee` mirror + `From`
   (empty `consensus_keys`), a reopened `legacy_committee_map` DBMap view over
   the same cf, distinct decode-failure logging at `lib.rs:2313`. Standalone PR.
2. **V5 + V9c** — landed in #1820 (one PR, shared `fetch_previous_committee`).
3. **V2** ready-signal receive-time canonicalization (small) — precondition for
   V1's freeze determinism. Keep zero-weight joiner pairs in the persisted
   `validated_peers`; never filter against the wall-clock joiner-provider table.
4. **V1** freeze fail-stop + barrier call-sites (medium) — `prior_epoch_mpc_data_digests`
   must return `IkaResult` and propagate read errors (crash-replay), reserving
   the empty map for `Ok(None)`; add the `wait_for_handoff_data_ready` barrier to
   the joiner-promotion (`lib.rs:2865`) and startup (`lib.rs:1121`) consensus-start
   paths, not just the continuing-validator path. Depends on V2 and on the escape.
5. **wedge** barrier escape (medium) — must land WITH or BEFORE V1 (so V1's new
   call sites aren't new indefinite wedges) and before V4. Bounded barrier wait
   then chain-import of the certified reconfiguration output; fail-stop, never
   "start consensus without E-1 data". Owns the barrier's final shape.
6. **networkkeyid-minors** (small) — Minor 1 (memo invalidation on changed
   inputs) standalone; Minor 2 (unmapped-key never-ready) folds into the barrier
   rewrite (step 5).
7. **V3 + V9b** (one PR) — run snapshot-ready+build+install before the durable
   early-return in `handoff_signature_sender.rs:246`; batch-delete non-verifying
   `handoff_signatures` rows in the install replay. Independent of the freeze work.
8. **V4** pure close-gate tally (medium) — LAST: tally sequenced EndOfPublishV2
   bundles per attestation digest, RETIRE `handoff_signatures_meet_quorum` (don't
   coexist). Depends on wedge (escape), V3 (restart recovery). If multi-key-holes
   Part B ships (NOA attestation anchor), settle the `HandoffAttestation` schema here.

Barrier caveat (I1/I2 from the cross-check): V3's local re-install re-mints the
validator's OWN attestation; divergent-validator recovery is 100% the barrier
peer-fetch of the cert for the quorum digest D — confirm the barrier covers the
CONTINUING (not just joining) validator path.

### Track B — presign uniformity (node-side; parallel except the S3 coupling)

- **V9a** VSS-cache tri-state (small) — independent; `derive_vss_shamir_cache_for_key`
  `.ok()?` → `Result` with a `NotApplicable` (pre-V3 key) variant + one `error!`
  per real failure. Land anytime.
- **expiry-desync + multi-key-holes** (ONE PR — forced by C1/C2):
  - **DECISION REQUIRED (C1):** `next_internal_presign_sequence_number` is a
    single `u64` shared across all keys+algos, and #1819's `fast-schnorr-vss.md`
    spec *enshrines* that. multi-key-holes Part A would re-key it per
    `(key,curve,algo)` — MORE correct (closes the adoption-lag hole where
    `agreed_key_ids` is a wall-clock set) but it **rewrites** the #1819 invariant
    + the `mpc_manager.rs:1674` comment. Choose: (a) keep the shared counter and
    make `agreed_key_ids` consensus-uniform instead, or (b) adopt per-key counters
    and rewrite the spec. Do not ship both framings.
  - expiry-desync and multi-key-holes both re-key `internal_presign_batch_instantiated_at_round`
    — must be one PR or the second clobbers the first.
  - multi-key-holes Part B (NOA attestation anchor) is the only bridge to Track A
    (S3) — if included, gate on V4's `HandoffAttestation` schema.

## SDK 0.5.0 (rollout precondition, zero code coupling)

Publish before any v4-advertising binary reaches quorum stake: the published
`@ika.xyz/ika-wasm@0.2.1` cannot parse V3-tagged reconfiguration outputs.
Changeset landed in #1820; the version bump + `npm publish` are release-process
acts. README hash-validity row (DoubleSHA256/secp256r1) still needs verifying
against the TS+Rust tables (deferred — correctness question, not a rename).

## Not on this list (further out, separate flags)

NOA (N1–N3) and OCS (O1–O5) sit behind their own flags, not the v4 capability
vote. See the 1.2.0 release review §1.3–1.4.

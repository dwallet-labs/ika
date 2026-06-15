# Review — PR #1714: Fast Schnorr (VSS Schnorr) support

Point-in-time review (see `README.md` — this is a record, not maintained truth).

- **PR:** [#1714](https://github.com/dwallet-labs/ika/pull/1714) — `feat/ika-upgrade-test ← fast-schnorr`, +4,532/−915, 47 files.
- **Reviewed at:** head `248ed10350` ("Integrate fast-schnorr (VSS) into feat/ika-upgrade-test").
- **Method:** extra-high-recall multi-agent pass (5 correctness angles + cleanup + altitude, 3 adversarial verifiers, 1 gap sweep) over the checked-out head, plus the failing CI log and merge archaeology. Crypto math in `cryptography-private` is out of scope.
- **Verdict:** **Not mergeable as-is — CI is red** because a merge dropped test-side updates (B0 below). Once that's fixed, the remaining items are one operator-facing footgun on the off-chain-metadata path (C1) plus latent/determinism notes and hygiene. The VSS integration itself is well-defended.

Author context applied: VSS is not user-exposed yet (external VSS sign is `#[ignore]`d; v4 only runs *internal* NOA-VSS), and the v3→v4 upgrade-of-existing-keys path is explicitly out of scope. Findings are re-scoped accordingly.

---

## B0 — BUILD BLOCKER: merge dropped test-side API updates (CI red)

`Cargo Test Check` fails — `ika-core (lib test)` does not compile (4 errors). The history shows a take-theirs dev merge (`bf21544442`) + a follow-up that restored *two* dropped fixes (`78e08d5483`); these are the ones it missed. The pattern is test code stranded on the **old** API while production moved to the **new** one:

1. **`crates/ika-core/src/dwallet_mpc/integration_tests/network_dkg.rs:10` + `:541`** — imports/calls `instantiate_dwallet_mpc_network_encryption_key_public_data_from_public_output` (3-arg, `.await`ed). Production refactored this into `…_from_dkg_public_output` (6-arg, **sync**, `network_dkg.rs:881`) and `…_from_reconfiguration_public_output` (`reconfiguration` module), dispatched by `spawn_network_encryption_key_public_data_instantiation` (`network_dkg.rs:695`). The test builds a *reconfigured* key, so it must use the reconfiguration variant / dispatcher. (E0432 + the cascading E0282 at `:541`.)
2. **`crates/ika-core/src/validator_metadata.rs:2005` and `:2106`** — two test-helper `Committee::new(...)` calls pass 8 args; the fn now takes 9 (the new 7th `vss_hpke_public_keys_and_proofs: HashMap<…>`, `committee.rs:111-131`). Add an empty map as arg #7. (E0061 ×2.)

→ *Fix:* re-apply the PR's test-side adaptations (B0.1 to the new reconfiguration API; B0.2 add the `vss_hpke` empty map). **Also worth a deliberate pass for *silent* reverts** the merge may have introduced that still compile — the take-theirs resolution already proved lossy twice.

### B0 status — FIXED + silent-revert sweep done

B0 is fixed (network_dkg test → the `spawn_network_encryption_key_public_data_instantiation` dispatcher; both `Committee::new` calls take the `vss_hpke` empty map; one stale doc comment refreshed). Verified: `cargo check -p ika-core --all-targets`, `ika-node` + `ika-test-cluster` all-targets, and `cargo fmt --all --check` all clean; `test_network_key_reconfiguration` passes in release. Pushed to `fast-schnorr`.

The deliberate silent-revert sweep (three-way content diff of every conflicted file: branch-pre-merge `bf21544442^1` vs dev `bf21544442^2` vs head, since `git cherry` is blind here — take-theirs keeps branch commits *reachable* while discarding their *content*) found **no further correctness reverts**. Everything the merge dropped falls into:

- **Superseded by dev's newer design** — the off-chain-metadata / handoff-cert / joiner-bootstrap P2P redesign (`announcement_relay`, `peer_blob_fetcher`, `blob_store`, `mpc_data_announcement_sender`, `handoff_signature_sender`, `ika-node/src/lib.rs` wiring) and the determinism-safe freeze in `mpc_session.rs` (dev's commit-boundary `is_mpc_data_frozen()` read replaced the branch's local-timing `freeze_mpc_data_if_quorum()` at the gate — dev's is the correct, consensus-pure version).
- **Already in dev via separate PRs** — the post-v1.1.8 consensus-output stream gate (`853925ed6a`, "same fix landed on dev via #1728"), deterministic internal-presign session-ids (#1733), the notifier stale-gas/`tx-effects` gas-coin fixes (dev's `sui_executor` already carries them; the branch-only delta there was commented-out debug lines).
- **Cleanup / observability only** — leftover debug comments, dead `#[allow(dead_code)]` fields (`sui_connector/mod.rs`), and unused metric/accessor methods (`HandoffAggregator::signer_count`/`accumulated_stake`; the `joiner_bootstrap_outcomes_total` / `mpc_data_blob_fetch_total` counters).

Branch-unique *upgrade* logic (the PR's actual purpose) all survives in head: `GlobalPresignConfig` genesis parameterization, the global-presign-as-MPC-session queue, and the epoch-keyed reconfiguration-output digest lookup (`insert/get_network_reconfiguration_output_digest_for_epoch`, restored by `78e08d5483`).

One **minor, optional** observability residue (not a correctness revert): `handoff_prepare_duration_seconds` lost the branch's minute-scale histogram buckets, so on dev's default prometheus buckets (top out at 10s) every legitimately-slow barrier exit (cert fetch + blob convergence run minutes) collapses into `+Inf`. Restore the custom buckets only if that metric's distribution is wanted.

---

## v3→v4 primer (frames several findings)

Two independent version axes move at this upgrade:

- **Protocol version** (governance): activates via on-chain capability voting at an epoch boundary; flips `off_chain_validator_metadata`, `fast_schnorr_supported` ("internal NOA-VSS only", `lib.rs:27-29`), internal-presigns, noa-checkpoints (`lib.rs:731-732`).
- **Network-key version** (per key): VSS material (`VssShamirCachePerKey`) derives only from a **V3** key output (`network_dkg.rs:336-345`; pre-V3 → no cache). A pre-existing key is V2 until its first v4 reconfiguration.

So there is a one-epoch-per-key window after v4 activation ("protocol v4, key pre-V3"). A fresh v4 genesis never hits it; the author has scoped that window out.

---

## Correctness

### C1 — Strict bare-class-groups chain decode silently drops bundle-shape validators · MEDIUM (stands)
`crates/ika-types/src/sui/epoch_start_system.rs:198`, `crates/ika-core/src/sui_connector/sui_syncer.rs:678`
Replaces the shape-tolerant `decode_validator_encryption_keys` on chain reads with a strict `bcs::from_bytes::<ClassGroupsEncryptionKeyAndProof>` (no fallback); on failure the validator is silently omitted from `class_groups_public_keys_and_proofs` (load-bearing). The production CLI (`become-candidate` / `set-next-epoch-mpc-data`) writes the **5-field bundle by default** (bare only with `--legacy-class-groups-only`). An operator on the default path is silently dropped from the committee. This is the off-chain-metadata path (live under plain v4), independent of VSS or the upgrade window.
→ *Fix:* keep shape-tolerant decode on chain reads, or make bare the only writable on-chain shape (guard/flip the CLI default).

### C2 — AHE sign path unconditionally requires the VSS shamir cache · LOW (transition-only, free fix)
`crates/ika-core/src/dwallet_mpc/mpc_session/input.rs` (Sign ~356, NetworkOwnedAddressSign ~401, DWalletDKGAndSign ~141)
The sign arms call `network_keys.vss_shamir_cache(key_id)?` with no `is_vss()` gate; the AHE arms never use the value. For a pre-V3 key the cache is absent → `WaitingForNetworkKey` → ordinary signs are **rejected** (not parked) in the v3→v4 window. Cannot occur on fresh v4 genesis; out of the author's concern. But it couples AHE-sign liveness to VSS infra for no reason.
→ *Fix (recommended hygiene, non-blocking):* gate the fetch behind `is_vss()`.

### C3 — Centralized-party VSS sign is version-inconsistent (V2 vs V3) · LOW (dormant)
`crates/dwallet-mpc-centralized-party/src/lib.rs:~509`
Centralized VSS sign arms sit under `VersionedPresignOutput::V2`, but a global VSS presign is wrapped V2 while the validator side (`vss_public_presign_identity`) requires V3 → external VSS sign can't complete end-to-end. Confined to the `#[ignore]`d external path; will bite the moment VSS is ungated.
→ *Fix:* align the version tag, or add a `// TODO(vss-enable)` marker.

### C4 — Empty committee VSS map silently disables VSS · NIT (corrected down)
`crates/ika-types/src/committee.rs:408`, `presign.rs:437`
Initially flagged as "VSS may be non-functional" — **withdrawn**: `sui_syncer.rs:556-569` builds the committee with `bundles.vss_hpke` in the same `Committee::new` as `bundles.class_groups`, and the passing joiner test proves that overlay reaches the active `epoch_store.committee()`, so the map *is* populated. Residue: `verify_vss_hpke_keys_at_committee_construction`'s `Err(_) => HashMap::new()` collapses a systemic verify error into a silent VSS-disable with no metric/log.
→ *Fix:* warn/metric on the `Err` arm instead of silently emptying.

---

## Determinism & robustness

### D1 — `SUPPORTED_CURVES_TO_SIGNATURE_ALGORITHMS_TO_HASH_SCHEMES` reverted `BTreeMap`→`HashMap` · LOW (latent)
`crates/dwallet-mpc-types/src/mpc_protocol_configuration.rs`
Safe today (the consensus-critical session-id iteration moved to the deterministic `network_presign_pool_algorithms` Vec; remaining consumers single-node/dead), but the revert deleted the doc comment warning that ordering prevents divergent session-ids → epoch wedge. A future consumer iterating this map for consensus-visible order silently reintroduces the wedge.
→ *Fix:* restore `BTreeMap`, or re-document why ordering is no longer load-bearing.

### D2 — msim compute via `rayon::spawn_fifo` can abort the process · LOW (test-infra)
`crates/ika-core/src/dwallet_mpc/crytographic_computation/orchestrator.rs`
When `sim_node` is `None`, completion spawns on a captured `Handle` that re-resolves the current node on a rayon worker — the teardown-during-epoch-swap abort the deleted inline path avoided. Flaky simtest only.

### D3 — `unreachable!()` arms enforce a type-unsafe invariant · LOW (altitude)
`crates/ika-core/src/dwallet_mpc/crytographic_computation/protocol_cryptographic_data.rs` (`attempt_number`/`mpc_round_number`)
"VSS outer variant always carries a VSS advance request" is enforced only by construction-site discipline; a future refactor/mis-route turns a recoverable mismatch into a validator panic on a peer-driven session. Prefer a method on the advance-request enum.

---

## Cleanup & docs

- **H1** Committed `ika_protocol_config__test__version_3.snap.new` (stray insta pending file) + orphaned `…version_5.snap` (`MAX_PROTOCOL_VERSION = 4`, never exercised; it also omits `schnorr_presign_third_round_delay`). Remove both.
- **H2** Dead `is_empty(&BTreeSet<String>)` helper + `#[allow(unused)]` on `is_false` (used 12×) in `ika-protocol-config/src/lib.rs` — the spurious allow violates the repo's no-`#[allow]`-without-asking rule.
- **H3** Dead newly-added `ConsensusNetworkKeyData` (`messages_dwallet_mpc.rs:~182`), zero consumers.
- **H4** Leftover `// return Err(anyhow::anyhow!("2.1"));` debug lines in `dwallet-mpc-centralized-party/src/lib.rs` (~945/951).
- **H5** ~9 near-identical `build_<curve>_vss_*` builders + triplicated dispatch + triplicated VSS→AHE-sibling pool-sizing arms across 3 curves — N lockstep edit sites (drift risk). A generic-over-protocol helper / `ahe_sibling()` would collapse them.
- **H6** `is_vss()` doc (`dwallet_mpc.rs:225`) says VSS has no combined DKG-and-sign path, but `DWalletDKGAndSignVSS` is implemented — doc/code contradiction.
- **H7** `Schnorrkel`→`SchnorrkelSubstrate` rename drops `FromStr "Schnorrkel"` — log/CLI parses of the old name break (wire discriminant unaffected).

---

## Checked and cleared (reviewer confidence)

- Presign write/read key symmetry (`from_le_slice(session_identifier)` vs `presign.session_id` → same `CommitmentSizedNumber`).
- VSS HPKE keypair determinism (published public vs orchestrator secret sample the same domain-separated child RNG).
- Internal-presign pool ordering deterministic (`network_presign_pool_algorithms` Vec; cross-validator session-sequence counter).
- Off-chain VSS overlay populates `vss_hpke` alongside `class_groups` (so VSS works in the normal path — see C4).
- Generation-failure handling skips one session, not siblings.
- `VersionedPresignOutput::V3` decode handled at all sites; V2/V3 wrapping correctly gated on `is_vss()`.

---

## Recommendation

1. **Fix B0** (build is red) — re-apply the dropped test-side adaptations, and sweep for any *silent* reverts the take-theirs merge introduced.
2. Address **C1** (operator default footgun, independent of VSS) before broad rollout.
3. Take the free **C2** `is_vss()` gate and the **H1–H4** hygiene fixes.
4. Mark **C3** with a tracking comment so it isn't forgotten when VSS is enabled.
5. **D1**/**D3** and **H5–H7** are latent/nits.

# PR #1744 Definitive Review — OCS verified Sui reads over untrusted relay + peer-only validators

**Stacked with:** `#1736` catch_unwind slot-release fix (`fix/1736-compute-panic-slot-leak`, tip `27b71f891e`) and the Sui mainnet-v1.72.3→1.73.2 bump (`feat/sui-bump-1.73.2`, tip `bad8a49062`).

**Base:** `origin/dev` (`aa4e81242c`). **#1744 tip:** `feat/ocs-grpc-migration` (`90fa29419b`), +21428/−1052 across 67 files.

**Review scope:** the UNION of the three branches as if all merge. READ-ONLY; every finding below cites `file:line` and survived an adversarial verification pass. Confidence is HIGH on all confirmed items unless stated otherwise.

---

## 1. Executive Summary

The combined surface is **substantially sound and mergeable on correctness grounds**, but it does **not** fix the bug it is stacked to address. The OCS verified-read core (committee trust chain, BLS-verified summaries, version-monotonic high-water, shadow/absorb cache split, changeset-stream currency) is correctly constructed and fail-closed by default; the Sui-1.73.2 bump is **byte-for-byte BCS-compatible** on every persisted type (verified by diffing the two pinned sui-types revs), so it cannot trigger the N1 boot-halt; and the StakeAggregator quorum-after-eviction fix is sound and mirrors upstream.

**The single most important finding:** the `#1736` catch_unwind slot-release fix is **inert in production**. `Cargo.toml:42` sets `panic = 'abort'` under `[profile.release]`, and CLAUDE.md mandates release mode for all validator/CI/localnet builds. Under `panic = 'abort'` a panic in `compute()` runs the abort handler at the panic site **without unwinding**, so the `catch_unwind` at `orchestrator.rs:319` can never intercept it — the entire `Err(panic) → ComputationPanicked` recovery arm is dead code in the exact environment where `#1736` manifests. The fix is live only under `cargo test` / `cargo simtest` (unwind profiles).

**Is the #1736 wedge present and unfixed in this code? YES — present and unfixed.** See §2.

---

## 2. #1736 Status — HEADLINE

**The real `#1736` fix is MISSING. The catch_unwind change does not address it and is additionally inert in release.**

Established forensics (HIGH-confidence background, re-grounded against code here) locate the `#1736` root cause in **network-key non-adoption at the epoch boundary** — a laggard validator's per-epoch dwallet MPC service fails to adopt the new network key, produces zero MPC outputs, "MPC output yet to reach quorum" persists for ~40 sessions, the epoch never closes, and the SDK sees "Object does not exist". This is a **participation/liveness defect in the mpc_data adoption pipeline**, not an orchestrator slot leak and not output divergence.

**The stacked fix targets the wrong layer AND is inert:**
- `orchestrator.rs:319` wraps `compute()` in `catch_unwind(AssertUnwindSafe(...))`; on `Err` it synthesizes `DwalletMPCError::ComputationPanicked` (`orchestrator.rs:341`; variant at `ika-types/src/dwallet_mpc_error.rs:23`) to release the compute slot.
- `Cargo.toml:42` (`panic = 'abort'` under `[profile.release]`, `Cargo.toml:34`) means the abort handler fires at the panic site with no unwinding → `catch_unwind` cannot intercept → the recovery arm is unreachable in release. The process SIGABRTs instead.
- The fix's own justifying comment (`orchestrator.rs:308`, "no rayon panic_handler on the test node") is **factually wrong**: `runtime.rs:19` installs a `.panic_handler(...)` on the global rayon pool. (Moot under abort, but the stated rationale is incorrect.)
- Under abort there is **no within-epoch slot leak** to begin with — the leak the comment at `orchestrator.rs:298-315` describes is unwind-profile behavior; in release the process simply dies.

**Confirmed latent participation-shortfall mechanism that the PR carries but does NOT fix** (the genuine `#1736`-adjacent code smell): the network-key overlay watch is **not epoch-tagged**, asymmetric with the `uncompleted_requests` watch which carries `(Vec, EpochId)`:
- `crates/ika-core/src/lib.rs:45` — `network_keys_receiver` carries `Arc<HashMap<ObjectID, DWalletNetworkEncryptionKeyData>>` with **no EpochId**, vs `lib.rs:59` `uncompleted_requests_receiver` = `(Vec, EpochId)`.
- `mpc_manager.rs:1059` — `adopt_cert_verified_keys` inserts `data.clone()` with no `data.current_epoch` check, so stale epoch-(N−1) entries can enter `adopted_network_key_data`.

**Why this is NOT the wedge (verified, do not over-attribute):** adoption is **cert-digest gated**, not envelope-epoch gated — `adopt_cert_verified_keys` (`mpc_manager.rs:730`) matches overlay bytes against the prior epoch's handoff cert, so stale/wrong data is *rejected by the digest gate*. There are TWO independent epoch gates on the instantiate path (`mpc_manager.rs:2215` pre-spawn and `mpc_manager.rs:2062` post-instantiation, derived from the instantiated key's own epoch). Stale entries are overwritten by `key_id` on later ticks and instantiation is deferred — nothing wedges epoch advance. Adding an `EpochId` tag would change **no correctness property**; it is defense-in-depth / maintainability only.

**Fix direction for the real `#1736`:** the missing fix is in the **adoption/participation pipeline**, not the orchestrator. Investigate why a laggard performs *zero* dwallet_mpc activity at the boundary — i.e. the path from `fetch_network_key_data_with_off_chain_blobs` → overlay publish → `adopt_cert_verified_keys` → per-epoch service instantiation, focusing on a validator that never fetches/adopts the new key (mpc_data blob source + handoff-cert timing). The quorum-replay recovery net (`cache_network_key_output_from_quorum`, `mpc_manager.rs:456→517`, doc at `mpc_manager.rs:490-505`) heals a *single* missing DKG blob via consensus replay, so the residual is a **quorum-wide** adoption failure where no quorum output exists to replay. Revert or de-scope the catch_unwind change (it gives false confidence that `#1736` is fixed); it is harmless dead code in release but should not be mistaken for a fix.

---

## 3. Confirmed Issues (ranked by severity)

### HIGH

**[FIXES] `#1736` catch_unwind fix is inert in the release/CI binary (`panic = 'abort'`)**
`crates/ika-core/src/dwallet_mpc/crytographic_computation/orchestrator.rs:319` with `Cargo.toml:42`.
*Scenario:* a `compute()` panic in a release build runs the abort handler at the panic site with no unwinding; the `Err(panic) → ComputationPanicked` recovery arm is never reached; the whole process SIGABRTs. The fix is exercised only under `cargo test` / `cargo simtest`. It neither prevents the production failure mode nor addresses the documented `#1736` stall.
*Fix direction:* do not rely on this for `#1736`; pursue the real adoption-pipeline fix (§2). If panic-recovery in compute is genuinely wanted in production, it must be implemented at a layer that survives `panic = 'abort'` (e.g. isolating compute in a process/task whose death is observed and converted to a failure completion), not via `catch_unwind`.

### MEDIUM

**[EPOCH/COMMITTEE] Head-regression race between committee follower and ratchet (plain store clobbers a higher head)**
`crates/ika-core/src/sui_connector/committee_store.rs:288` (also `:136`, `:188`, `:204`).
*Scenario:* every head write is `self.head.store(epoch, Relaxed)` with **no `fetch_max`/`compare_exchange`** (grep-confirmed, none anywhere). Three independent tokio tasks share one `Arc<CommitteeStore>`: follower (`committee_follower.rs:93`), pusher (`push_worker.rs:215/266`), and the ratchet (`ocs_verifier.rs:202/216`). `ratchet_lock` (`ocs_verifier.rs:101`) serializes ratchets vs each other only. If the ratchet reads `head=E` (`committee_store.rs:343`), is preempted after BLS-verify+extract but before the store, the follower installs `E` then `E+1` (head→E+2), and the ratchet then stores `next.epoch=E+1` → head regresses E+2→E+1. The persisted head regresses too (`authority_perpetual_tables.rs:459`/`:439` do unconditional `insert_batch`), so it survives restart. Self-heal only via the ratchet forward-walk, which does a **network** `get_full_checkpoint(last_of_{E+1})` (does not consult the already-persisted summary) → if pruned upstream, `ProofChainBroken` (`ocs_verifier.rs:178`) wedges the chain (the finding-17 stall).
*Why medium, not higher:* the preempt window (between head read and store) is narrow, and a true wedge additionally needs the E+1 end-of-epoch checkpoint to be pruned before the next ratchet pass; the common non-pruned case self-heals.
*Test gap (real):* `concurrent_install_same_boundary_is_idempotent` (`committee_store.rs:536`) only tests the same boundary (benign); `follower_ahead_then_ratchet` (`:644`) is sequential. Neither exercises the staggered lower-value clobber.
*Fix direction:* make head advancement monotonic — replace the plain `store` with `fetch_max`, and gate the persisted-head write so it never regresses. Add a test for the staggered clobber.

**[FIXES] catch_unwind is moot under `panic = 'abort'` (cross-branch framing)**
`Cargo.toml:42` vs `orchestrator.rs:~310`; incorrect-justification comment at `orchestrator.rs:308` contradicted by `runtime.rs:19`.
*Same root as the HIGH item above*, recorded separately because its load-bearing point is the **false confidence** that `#1736` is fixed plus the factually-wrong comment. The dead code is otherwise harmless (no regression; abort behavior unchanged).

### LOW

**[OCS / peer-only] `SuiMirrorTransport::execute_transaction` returns relayed effects without verifying content (latent, unreachable today)**
`crates/ika-network/src/sui_state_mirror/client.rs:533`.
*Scenario:* the code verifies the echoed digest (`:524-529`) and that it is checkpoint-committed (`get_transaction_checkpoint`, `:532`), but decodes `resp.effects_bcs` straight into `TransactionEffects` (`:533`) and returns it **without binding the effects content/digest to the committed checkpoint** — a malicious relay could return forged success effects for a committed-but-aborted tx.
*Why dead today (verified 3 ways):* (1) `FallbackTransport::execute_transaction` (`fallback_transport.rs:132-136`) routes writes to the direct-gRPC fallback, never the mirror primary; (2) `setup.rs:294-303` wires the bare mirror only in true peer-only; (3) the actual writer is the notifier via `SuiClient<SuiBackend>` (`sui_executor.rs:970`), a separate direct client. The only live callers of the trait method are tests. The honest guard comment (`:507-514`) is adequate mitigation.
*Fix direction:* before any future peer-only submitter wires this path, bind the effects digest to the committed checkpoint contents.

**[PERSISTED-FORMAT/N1] `auto_reanchor_on_format_change=true` with no anchor wipes good-enough tables and halts with a more confusing error**
`crates/ika-core/src/sui_connector/setup.rs:318-338` (wipe with no anchor check); `setup.rs:198` (resolve fall-through); `committee_store.rs:151-158` (error); unenforced doc at `node.rs:445`.
*Scenario:* a `SerializationError` with the flag set calls `wipe_sui_committee_state_for_format_recovery()` with **no check that an anchor is configured**. After the wipe, `highest_sui_committee_epoch()` is `None`, `resolve_bootstrap_plan` falls through (`compiled_in_trusted_anchor` always returns `None` today — `node.rs:212-217` TODO) to `BootstrapPlan::Hydrated` → `bootstrap=None` → `CommitteeStore::open` errors "OCS verifier needs bootstrap material". A misconfigured operator who set the flag to escape a halt still halts, now with a less-obvious message. No incremental data loss (tables were already unbootable without re-anchor); requires deliberate misconfiguration.
*Fix direction:* enforce the documented precondition — refuse to wipe (or warn explicitly) unless an anchor is configured.

**[FIXES] `ComputationPanicked` Err is not a per-node retry; catch_unwind comment overstates "recover"**
`dwallet_mpc_service.rs:1698-1718`; `orchestrator.rs:195,224-233`.
*Scenario:* the Err arm does **not** retry. Internal presign / NOA-sign sessions log `should_never_happen` and drop; user sessions call `submit_failed_session` → `new_dwallet_mpc_output(rejected=true)` (a terminal on-chain rejection vote). `orchestrator.rs:195` inserts the id into `completed_cryptographic_computations` on Err too, and `try_spawn` (`:224-233`) returns true without respawning. So the comment's "the existing retry/quorum machinery can recover" is inaccurate at the per-node level. Not a correctness bug at the network level (one node's rejection is outvoted by the honest quorum), and reachable only under unwind (test/CI) builds. Comment-accuracy risk, leaning nit.

---

## 4. Risks & Needs-Human

There are **no NEEDS-HUMAN findings** — every examined item resolved to a verdict.

Decisions for the maintainer:

- **`#1736` remains open.** The headline action is to pursue the adoption-pipeline fix (§2) and decide whether to keep, revert, or re-scope the catch_unwind change so it is not mistaken for a fix. Correct the inaccurate comment at `orchestrator.rs:308`.
- **Head-monotonicity (medium).** The single actionable correctness hardening in this PR: make `committee_store` head advancement monotonic (`fetch_max`) and non-regressing on persist, with a staggered-clobber test. Recommended before relying on peer-only ratcheting under load.
- **Watch-list to monitor (documented, intentional, low/nit — no code change required, but note in operational docs):**
  - From-boot eclipse residual: `setup.rs:449` passes `None` for `freshness_bound`; `verified_reader.rs:881-883` no-ops freshness when `None`. Integrity-preserving, single-node self-eclipse, explicitly documented in `dev-docs/specs/ocs-verified-sui-reads.md` (~144-151). Mitigable via a multi-peer relay list (`node.rs:402 sui_state_mirror_peers`). `freshness_bound` is fully plumbed but unset in prod.
  - Currency dormant during warm-up (`verified_reader.rs:791-808`): safe `Unknown` fallback; documented in `ocs-changeset-stream-mirror-currency.md`.
  - Reader shadow-write can prune pusher-folded objects via inflated shared cache head (`verified_state_cache.rs:272`, `:261`, `:281`): operator-misconfig-gated (tiny `verified_cache_retention_checkpoints`), benign (cache miss falls through to per-read-verified path), never a persistence/trust violation.
  - Committee format-recovery off by default (`setup.rs:333`): deliberate fail-closed for the trust root, with an actionable error (`setup.rs:126-132`). Object cache self-recovers (`verified_state_cache.rs:143-152`); the asymmetry is intentional. **Add a runbook entry to the sui-version-bump checklist** for any future layout-changing bump.
  - Peer-only boot ratchet has no overall deadline (`lib.rs:586-609`): deliberate retry-forever; only determinate errors fail fast (`ocs_verifier.rs:82-84`). Optional polish: escalate `warn!`→`error!`/metric on a persistently stuck boot.
  - Changeset prune-gap stalls currency coverage (`mod.rs:258`): safe `Unknown`; missing observability metric only.

---

## 5. Cross-Branch Integration (#1744 + bump + catch_unwind)

If all three land together:

- **Bump does NOT trigger N1 boot-halt — verified, not assumed.** Diffing the two pinned sui-types revs (mainnet-v1.72.3 = `f271946`, mainnet-v1.73.2 = `1f6e1e6`): `committee.rs` byte-identical, `messages_checkpoint.rs` byte-identical (covers `CertifiedCheckpointSummary`), `crypto.rs`/`base_types.rs` identical. The only `message_envelope.rs` change is an unused import removal + an added `verify_committee_sigs_only` method — no struct-layout change. `Owner::Party` is an **additive trailing enum variant** (index 5; variants 0..=4 byte-identical, plain `Serialize`/`Deserialize`, no `#[serde]` tagging) → pre-bump cached objects decode identically. The persisted committee/summary types do not reference `sui_sdk_types`, so the sdk-types rev bump (`e494a36→5b41bc7`) is irrelevant to the trust chain. **No existing store is bricked; the fail-closed halt cannot fire from this bump.**
- **StakeAggregator quorum-after-eviction fix is sound** (`stake_aggregator.rs:~163-196`): survivors individually re-verified via `verify_secure`, `total_votes` decremented once per eviction, guarded by `committee.threshold::<STRENGTH>()`, rebuilt via `new_from_auth_sign_infos` (which re-checks epoch + quorum threshold). No off-by-one. Does not change `#1736`-relevant epoch behavior.
- **ConsensusProtocolConfig bump args** (`300,12` literals) are inert under `enable_v3=false`; protocol-config snapshots regenerated with grace-round fields v4-gated. No drift detected.
- **`#1736` remains unfixed across the integrated surface.** None of the three branches touch the adoption-pipeline root; the catch_unwind delta is `orchestrator.rs` + `dwallet_mpc_error.rs` only, inert in release.

**Integrated verdict:** the three branches compose cleanly. The only net-new correctness item worth addressing pre-merge is the head-monotonicity race (§3 medium). The `#1736` stall and the inert-fix false-confidence are the chief substantive concerns.

---

## 6. What Was Checked and Cleared

Examined and **refuted** (so coverage is on record):

- **`#1736` attributed to the epoch-untagged network-key overlay watch** — structural asymmetry is real (`lib.rs:45` vs `:59`) but the causal claim is false: adoption is cert-digest gated (`mpc_manager.rs:730`), the service is per-epoch, the watch is a documented "possibly-lagging non-consensus carrier" (`handoff_signature_sender.rs:186-225`), and a stale `Arc` only delays adoption one tick (ptr_eq early-out). Tagging would change no correctness property.
- **`#1736` empty-DKG-overlay skip causes the wedge** — refuted by the quorum-replay recovery net: `cache_network_key_output_from_quorum` (`mpc_manager.rs:456→517`, doc `:490-505`) reassembles the quorum-agreed DKG/reconfig output from checkpoint chunks and caches it durably (`mpc_artifact_blobs`), so a single lagging/dead validator self-heals once the output reaches quorum.
- **`verified_anchor_object` bypasses currency/freshness** — confirmed behavior but not a bug: cache holds only committee-verified, version-monotonic state; `record_high_water` blocks any backward move; skipping currency/freshness is the deliberate cure for the pusher-lag feedback loop. No rollback path.
- **`Owner::Party` additive variant triggers N1** — refuted; additive-at-end is BCS-backward-compatible (see §5).
- **StakeAggregator quorum-after-eviction is a bug/hole** — refuted; sound, mirrors upstream.
- **Sui-bump changes persisted committee/summary BCS layout** — refuted by direct cross-rev diff (see §5).

**Trust-model verdict:** the OCS verified-read trust model holds as designed. Reads are BLS-committee-verified with version-monotonic high-water and a fail-closed committee trust root; the relay cannot forge or roll back below what it has already served a process. The two residual non-guarantees (from-boot eclipse and warm-up currency dormancy) are integrity-preserving, single-node, explicitly documented design residuals, operationally closable via a multi-peer relay list and the (plumbed-but-unset) `freshness_bound`. The one latent write-path trust hole (`client.rs:533`) is unreachable in production today and honestly commented.

---

*Confidence: HIGH on all confirmed/refuted items; each cite was re-grounded against the working tree (`fix/1736-compute-panic-slot-leak`, HEAD `27b71f891e`) and the pinned sui-types revs. `panic='abort'` (Cargo.toml:42), the catch_unwind site (orchestrator.rs:319), and the plain non-monotonic head store (committee_store.rs:288, no fetch_max anywhere) were re-verified directly while writing this report.*

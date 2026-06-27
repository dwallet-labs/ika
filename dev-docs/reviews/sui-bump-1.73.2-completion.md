# Sui 1.72.3 → 1.73.2 bump — completion & adoption report

Branch: `feat/sui-bump-1.73.2`. Audience: senior eng (Omer). Scope: finish the
version bump (compile + correctness) and adopt the upstream changes that fit ika.
All file:line citations are against the working tree at
`/Users/omersadika/dev/fix_consensus/ika` as read for this report.

---

## 1. Executive summary

**The bump is essentially done and shallow, not deep.** Every compile-required
drift between 1.72.3 and 1.73.2 has already been applied in the live working tree
(`git diff HEAD` shows the bump touching only 10 files: workflows, `Cargo.toml`/
`Cargo.lock`, four source files, one Cargo manifest, one doc-comment). There is no
outstanding deep drift in the surfaces the user asked about:

- **Consensus**: the only real change is `ConsensusProtocolConfig::new` growing two
  trailing args (`leader_schedule_window_size`, `leader_schedule_update_interval`).
  ika's `to_consensus_protocol_config` already passes upstream's exact literals
  `300` / `12` (`crates/ika-core/src/consensus_manager/mod.rs:82-83`). Both values
  are inert while `enable_v3 = false` (hardcoded at `mod.rs:75`, matching upstream)
  — they only feed Mysticeti's v3 leader schedule, which is gated off. No
  protocol-config getter is needed; Sui itself hardcodes these. No mid-epoch
  consensus fork risk from this bump.
- **Protocol config**: the `ProtocolConfigAccessors` derive macro now expands to a
  `render<F>` method referencing `mysten_common::rpc_format`, so
  `ika-protocol-config` must depend on `mysten-common`. Already added
  (`crates/ika-protocol-config/Cargo.toml`, `mysten-common.workspace = true`). The
  generated method is dead in ika (no caller) but must type-check. No
  protocol-version bump, no on-chain format change from the bump itself.

**Remaining work is small and mechanical:**
1. Regenerate the 9 stale protocol-config snapshots (RED today, but from a
   **pre-existing #1721 field drift — NOT the bump**). Separate commit.
2. (Optional, recommended) Port the upstream `StakeAggregator` post-eviction quorum
   re-check — a real latent bug in ika's cert aggregation, independent of the bump
   but the natural moment to re-sync.

**Adoptable improvements: one** worth doing now (the StakeAggregator quorum
re-check). The render/rpc_format capability lands for free but has no surface to
wire into; the OCS proof primitives and canonical-bitmap hardening were examined
and ruled out (ika already covers those needs via `sui-light-client`, and ika's
decode path doesn't use the hardened serde entry point).

**Confidence: high** on the compile-completion plan (verified the edits are in the
tree and grounded against upstream diffs). **Medium / needs-human-judgment** on two
points flagged inline: (a) whether #1721 intended the two new grace-round fields to
apply retroactively to v1/v3 before you `insta accept`; (b) the N1 persisted-format
boot-halt watch-out (§5) — not triggered by anything found here, but the bump is the
class of change that can trigger it, so it's called out.

---

## 2. Bump-completion plan (ordered MUST checklist)

> Status note: items 1–6 are **already applied** in the working tree (confirmed by
> reading the files). They are listed so the plan is auditable and so a fresh
> checkout / rebase can re-verify each. Item 7 (snapshots) is the only **open**
> compile/gate item.

### 1. sui-sdk-types rev skew — root `Cargo.toml` pin `e494a36` → `5b41bc7`
- **File**: `Cargo.toml:315`.
- **Drift**: sui@v1.73.2 transitively pulls `sui-sdk-types` rev `5b41bc70` (0.3.1);
  ika previously pinned `e494a36` (0.3.0). Two coexisting crate versions →
  `grpc.rs:85`'s `sui_sdk_types::ValidatorAggregatedSignature::try_from(proto_sig)`
  resolves to ika's 0.3.0 type while the `TryFrom`/`From` impls live over 0.3.1 →
  cross-crate type-identity mismatch (E0277/E0308).
- **Fix (applied)**: `sui-sdk-types = { git = "...sui-rust-sdk.git", rev =
  "5b41bc701525f1b94f1fe63008d4841bc6fb1065" }`. Collapses the tree to one
  `sui-sdk-types` (confirm: `Cargo.lock` has a single `sui-sdk-types`).
- **No source edit at the consumer**: `crypto/validator.rs` is byte-identical
  0.3.0→0.3.1 (empty diff), so `grpc.rs:82-88` compiles as-is. Do **not** touch
  `grpc.rs` — it's on the OCS verified-read path (`decode_certified_summary` →
  `CertifiedCheckpointSummary` feeding committee/checkpoint verification).
- **Verify**: `cargo tree -p sui-sdk-types` shows one rev; `cargo check -p
  ika-sui-client`.

### 2. `ConsensusProtocolConfig::new` 10→12 args — pass `300, 12`
- **File**: `crates/ika-core/src/consensus_manager/mod.rs:56-85` (the two new args
  at `:82-83`).
- **Drift**: upstream `consensus/config/src/consensus_protocol_config.rs` added
  `leader_schedule_window_size:u32` and `leader_schedule_update_interval:u32` after
  `enable_v3`. `consensus-config` is the **pinned Sui crate**, so ika's call site
  must match. 10 args → E0061.
- **Fix (applied)**: after the `false` (enable_v3) line, append `300,` then `12,`,
  mirroring Sui's own caller (`sui-core/src/consensus_manager/mod.rs`
  `to_consensus_protocol_config`), which passes the literals, not protocol-config
  getters. Doc comment at `mod.rs:76-81` documents why these are inert constants.
- **Correctness**: both values are read only by `LeaderScheduleV3`, instantiated only
  when `enable_v3()` is true; ika hardcodes `enable_v3 = false`, so they never reach
  ika's forked consensus handler. No getter, no version gate needed (Sui doesn't gate
  them either).
- **Verify**: `cargo check -p ika-core`.

### 3. `ProtocolConfigAccessors` derive → `mysten-common` dependency
- **File**: `crates/ika-protocol-config/Cargo.toml` (`mysten-common.workspace =
  true`); derive site `crates/ika-protocol-config/src/lib.rs:234`.
- **Drift**: the 1.73.2 macro emits `pub fn render<F>` whose body references
  `::mysten_common::rpc_format::{Format, Meter, MeterError, ToFormat}` for every
  accessor field. Without the dep → E0433 unresolved path.
- **Fix (applied)**: add `mysten-common.workspace = true`; root pin at the same
  `mainnet-v1.73.2` tag as the macro (the pins must stay co-versioned). ika's
  accessor fields are all `Option<u64>` plus one `Option<u32>` (`consensus_gc_depth`),
  all covered by `ToFormat` impls; `version`/`feature_flags` are non-Option and the
  macro skips them. Method is dead in ika but must type-check.
- **Verify**: `cargo check -p ika-protocol-config`.

### 4. `CertifiedTransactionEffects` family removed — local re-alias
- **File**: `crates/ika-types/src/quorum_driver_types.rs:26-28` (alias),
  used at `:134` and `:185-186`.
- **Drift**: sui `effects/mod.rs` deleted `CertifiedTransactionEffects`,
  `VerifiedCertifiedTransactionEffects`, and their inherent `verify` /
  `verify_authority_signatures` impl.
- **Fix (applied)**: re-alias both over the still-present generics
  `TransactionEffectsEnvelope<S>` / `VerifiedTransactionEffectsEnvelope<S>` with
  `AuthorityStrongQuorumSignInfo`. ika never called the removed methods (verified:
  the only methods used are `into_data_and_sig()`, still on `Envelope`, and
  `cert.epoch`, a field on `AuthorityStrongQuorumSignInfo`). This whole cluster is
  self-contained fork residue with no external consumers — the re-alias is the
  complete fix.
- **Verify**: `cargo check -p ika-types`.

### 5. `ika-upgrade-test` client type `SuiClient<SuiSdkClient>` → `IkaClient<SuiBackend>`
- **File**: `crates/ika-upgrade-test/src/cluster.rs:56` (field), `:477` (accessor),
  imports `:23-24`.
- **Drift**: NOT a bump drift — an **OCS SuiBackend-migration leftover** surfaced by
  the `--all-targets` typecheck once the bump compiled far enough. `IkaClient::new`
  returns `SuiConnectorClient = SuiClient<SuiBackend>`
  (`crates/ika-sui-client/src/lib.rs:111`), so the field's old `SuiClient<SuiSdkClient>`
  annotation is E0308.
- **Fix (applied)**: import `ika_sui_client::SuiBackend`, drop the stale
  `sui_sdk::SuiClient as SuiSdkClient`, annotate both as `IkaClient<SuiBackend>`.
  Confirmed in tree (no `SuiSdkClient` remains in the crate).
- **Verify**: `cargo check -p ika-upgrade-test --all-targets`.

### 6. `consensus_output_api` doc-comment version string
- **File**: `crates/ika-core/src/consensus_types/consensus_output_api.rs:42`.
- **Drift**: cosmetic — comment said reputation scores were removed in
  `mainnet-v1.72.3`; updated to `mainnet-v1.73.2`. No behavior change (the
  `reputation_score_sorted_desc` no-op was already correct). Listed for completeness.

### 7. (OPEN) Protocol-config snapshots are stale — regenerate all 9
- **Files**: `crates/ika-protocol-config/src/snapshots/*.snap` (9 files); source of
  truth `crates/ika-protocol-config/src/lib.rs` (the two fields set unconditionally
  to `Some(50)` in the base/min constructor).
- **Status**: `cargo test -p ika-protocol-config` is **RED**: `snapshot_tests`
  panics on `version_3`, adding `+end_of_publish_grace_rounds: 50` and
  `+mpc_data_freeze_grace_rounds: 50`. Verified: `grep grace_rounds` over the 9
  committed `.snap` returns **0** — every snapshot is stale, not just v3. An
  untracked `..version_3.snap.new` is present.
- **Cause**: **pre-existing, independent of the bump.** Both fields were introduced
  by commit `8cb46d8803` ("Off-chain validator metadata + EndOfPublishV2 (#1721)"),
  set unconditionally in the base constructor; the golden files were never
  regenerated. Nothing in 1.73.2 touches these ika-local fields.
- **Fix**: `cargo insta test -p ika-protocol-config --accept` (or `cargo insta
  accept`) in a **separate commit**. Do **NOT** bump a protocol version for this.
- **Human-judgment gate**: the test header warns "never update snapshots from this
  test, only add new versions." That warning is about semantic edits to a *shipped*
  version. Here the fields are base constants added to *all* versions in #1721 — but
  **confirm #1721 intended them to apply retroactively to v1/v3** (rather than be
  version-gated) before you `insta accept`. If they were meant to be gated, the fix
  is in `lib.rs`, not the snapshots.
- **Verify**: `cargo test -p ika-protocol-config` (the CLAUDE.md gate for this crate).

### Final verification (run, do NOT pipe through `tail` — you need the full error list)

```
cargo check --workspace --all-targets
```

Separate gates (run before merge, not covered by `cargo check`):
- **Protocol-config snapshots**: `cargo test -p ika-protocol-config` (item 7).
- **msim / simtest**: `MSIM_DISABLE_WATCHDOG=1 cargo simtest --package
  ika-test-cluster -- test_swarm_reaches_epoch_2` — the consensus arg change is
  inert under `enable_v3=false`, but a simtest run is the cheapest proof that the
  forked consensus handler still drives epoch advancement under the new pin.
- **Sui-version consistency**: `scripts/check-sui-version-consistency.sh` — the bump
  must update the ~90 tag pins, the excluded wasm workspace locks, the sui-binary
  downloads in the TS CI workflows, CLAUDE.md, and every dev's local `sui` binary
  (a mismatched localnet binary completes DKG but silently stalls reconfiguration).
  `git diff HEAD` already shows the two TS workflows + CLAUDE.md updated; run the
  script to confirm nothing was missed.

---

## 3. Good changes to adopt ("changes that fit") — SHOULD, ranked

> Keep these SEPARATE from §2. None is required to compile; each is a deliberate
> re-sync with upstream. Ranked by value/effort.

### 3.1 Port the StakeAggregator post-eviction quorum re-check  — HIGH value / LOW effort
- **What sui 1.73.2 does**: in `StakeAggregator::insert`, when the aggregated
  signature fails to verify and bad signers are evicted individually, upstream now
  re-checks whether the *surviving* signers still meet quorum:
  `if self.total_votes >= self.committee.threshold::<STRENGTH>() { ...
  new_from_auth_sign_infos(...) → QuorumReached } else { NotEnoughVotes }`, plus a
  regression test.
- **Where ika diverges**: `crates/ika-core/src/stake_aggregator.rs:180-183` —
  after eviction (the loop at `:163-178` removes bad signers from `self.data` and
  decrements `self.total_votes`), ika **unconditionally** returns
  `InsertResult::NotEnoughVotes { bad_votes, bad_authorities }`, with no
  post-eviction quorum re-check. This is the old upstream bug, still present.
- **Why it fits ika**: ika mirrors this file from Sui; the buggy method is on a real
  path — `StakeAggregator<AuthoritySignInfo,_>::insert` is driven via
  `MultiStakeAggregator::insert` from both dwallet checkpoint cert aggregation
  (`dwallet_checkpoints/mod.rs`) and system checkpoint cert aggregation
  (`system_checkpoints/mod.rs`). Today the lost-quorum case falls through to
  `check_for_split_brain()` and costs the cert until the next signature insert; under
  adversarial timing (one validator repeatedly submitting a bad sig) it can stall a
  checkpoint cert. The helpers needed already exist in ika:
  `new_from_auth_sign_infos` (`stake_aggregator.rs:139`, used on the happy path) and
  `threshold::<STRENGTH>()` (`:116`).
- **Risk**: LOW. Pure local/off-chain cert aggregation, deterministic given the same
  input signatures; no on-chain or serialization change; `InsertResult` enum
  unchanged. Does not touch the OCS verified-reads layer, the forked consensus
  handler, or protocol versioning.
- **Diff sketch** (`stake_aggregator.rs:180-183`):
  ```rust
  // replace the unconditional NotEnoughVotes:
  if self.total_votes >= self.committee.threshold::<STRENGTH>() {
      match AuthorityQuorumSignInfo::<STRENGTH>::new_from_auth_sign_infos(
          self.data.values().cloned().collect(),
          self.committee(),
      ) {
          Ok(aggregated) => InsertResult::QuorumReached(aggregated),
          Err(error) => InsertResult::Failed { error },
      }
  } else {
      InsertResult::NotEnoughVotes { bad_votes, bad_authorities }
  }
  ```
- **Caveat**: the upstream **regression test** needs adaptation, not a verbatim
  copy: ika has no `is_quorum_reached` helper, and ika's test-committee constructor
  is `new_simple_test_committee_of_size` (`committee.rs:337`), not
  `new_simple_test_committee_with_normalized_voting_power`. The production block above
  ports verbatim; the test does not.

### 3.2 `render<F>` / rpc_format precision-safe accessor path — FREE capability, NO action
- **What it is**: the `ProtocolConfigAccessors` derive now generates a `render<F:
  Format>` method over `mysten_common::rpc_format` (used by Sui for precision-safe
  RPC serialization of protocol config). Because ika derives the macro
  (`ika-protocol-config/src/lib.rs:234`), ika's `ProtocolConfig` gains `render::<F>()`
  automatically at zero cost.
- **Why no action**: there is nothing to wire it into. ika has **zero** callers of
  `render`/`ToFormat`/`rpc_format`. ika's only `get_protocol_config`
  (`ika-sdk/src/apis.rs`) is a passthrough to the Sui fullnode returning Sui's
  `ProtocolConfigResponse` for the L1 chain — it does **not** serialize ika's forked
  `ProtocolConfig`. Adopting `render` would mean building a net-new gRPC/JSON
  endpoint over ika's protocol config — net-new feature work, larger than the bump,
  gated on a product decision. Recorded as an informational capability, not a task.

---

## 4. ika ↔ Sui gaps worth noting (follow-ups, NOT part of this bump)

- **Leader-schedule version-gating (forward watch, not actionable now)**: the two
  consensus literals `300`/`12` and `enable_v3=false` are inline constants mirroring
  upstream. Sui does **not** expose these via `sui_protocol_config::ProtocolConfig`
  at 1.73.2 (grep confirms no `leader_schedule_*` / `enable_v3` getter), so there is
  nothing to mirror yet. The convention is already documented at
  `consensus_manager/mod.rs:66-81`: when Sui promotes any of these into the protocol
  config, add a **version-gated** ika getter and source it here — do **not** flip the
  constants, since an un-gated change forks consensus mid-epoch. Wire all three
  through together when that day comes.

- **OCS proof primitives in sui-sdk-types `unstable`** — examined, **no gap**. ika's
  verified-reads layer is built on `sui-light-client` (pinned `mainnet-v1.73.2`),
  used across 7+ files (`verified_reader.rs`, `verified_state_cache.rs`,
  `ocs_currency.rs`, `committee_store.rs`, `ocs_verifier.rs`, network
  `proof_provider.rs`). That dependency's proof modules are a superset of the
  sdk-types `unstable` reimpl, which ika doesn't even compile (no `unstable` feature
  enabled). No need, no value.

- **sui-sdk-types 0.3.1 canonical-bitmap hardening** — examined, **does not apply**.
  The trailing-bytes hardening is in the *private* serde `Deserialize` path; ika's
  decode goes through the *public* `Bitmap::deserialize_from` (via the proto
  `TryFrom`), which in 0.3.1 was simplified to a thin `RoaringBitmap::deserialize_from`
  with no extra check. ika gains nothing here and references only
  `ValidatorAggregatedSignature`, never `MultisigAggregatedSignature`/`legacy_bitmap`.

- **No CONSIDER items** survived verification — the only judgment call that remains is
  the snapshot-retroactivity question in §2 item 7, which is a bump-gate, not a
  follow-up.

---

## 5. Risks & watch-outs

1. **Consensus behavior — none from this bump.** The leader-schedule args
   (`300`/`12`) and `enable_v3=false` are inert: they feed only `LeaderScheduleV3`,
   which is never instantiated while v3 is off. ika is byte-aligned with Sui's live
   wiring. The only latent risk is a future *silent* fork if `enable_v3` is flipped
   without a version-gated getter — already documented in-code, out of scope here.

2. **Protocol-config snapshot / format.** The bump does **not** change ika's
   protocol-config format or bump a protocol version. The RED snapshots are a
   **pre-existing #1721 drift**, not a bump regression — but they leave the
   `ika-protocol-config` CLAUDE.md gate red until regenerated (§2 item 7). Human
   gate: confirm #1721 intended the two grace-round fields to apply to v1/v3
   retroactively before `insta accept`; otherwise the fix belongs in `lib.rs`.

3. **N1 persisted-format boot-halt (cross-reference, watch — not observed here).**
   This bump is the *class* of change (a Sui crate version move) that can shift a BCS
   layout under ika's OCS perpetual cache and brick the cache-open path on boot —
   the "persisted-format fragility (HIGH, Sui-bump bricks boot)" finding from the
   OCS deep-review. Nothing in the verified drift set touches a persisted OCS type:
   `ValidatorAggregatedSignature` (validator.rs) is byte-identical across the rev,
   the removed `CertifiedTransactionEffects` aliases are unused fork residue, and the
   protocol-config `render` method is non-persisted. So **no boot-halt is expected**
   from these specific changes — but the only honest proof is a **cluster/localnet
   boot against an existing perpetual cache** (an `ika-test-cluster` run that opens a
   pre-bump store), not a `cargo check`. Treat that as a required pre-merge gate, not
   an optional one. Cross-ref the OCS deep-review memory note for the failure
   signature.

4. **Crypto-pinning / `cargo update` hazard.** This repo pins crypto crates and the
   `sui-sdk-types` rev deliberately. A bare `cargo update` will destroy that pinning
   (and re-introduce the rev skew this bump just fixed). Use **targeted** updates
   only (`cargo update -p <crate> --precise <ver>`); never a blanket update. The
   `Cargo.lock` churn in this bump (611 lines) is expected from the tag move — review
   that it collapses to a single `sui-sdk-types` and does not silently advance a
   crypto crate.

5. **Multi-place version pinning.** Per CLAUDE.md, the Sui tag lives in ~90 root
   `Cargo.toml` pins, the excluded wasm workspace locks, the TS CI sui-binary
   downloads, CLAUDE.md, and every dev's local `sui` binary. `git diff HEAD` shows
   the workflows + CLAUDE.md updated; run `scripts/check-sui-version-consistency.sh`
   as the authoritative check, and make sure local `sui` binaries are re-installed
   before any localnet run (a stale binary completes DKG but silently stalls
   reconfiguration).

---

### Confidence ledger
- **High**: §2 items 1–6 (read the edits in the tree; grounded against upstream
  diffs), §3.1 bug location and port mechanics, §4 rejections.
- **Medium / human-judgment**: §2 item 7 snapshot-retroactivity decision; §5.3
  boot-halt — believed clear but only a cache-open cluster run proves it.
- **Open**: snapshot regeneration (mechanical) and the StakeAggregator port
  (optional but recommended) are the only code actions left.

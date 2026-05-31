# PR #1721 — Review Action Plan

Combined from: `docs/off-chain-metadata-v2-review.md` (feature walkthrough),
the GitHub PR #1721 review (`ycscaly` — naming), `PR-1721-review.md` (Cursor),
and `pr_1721_code_review.md`. Decisions agreed with the user.

Branch `feat/off-chain-metadata-v2`. Both Cursor reviews are already
merge-ready/Approve — everything below is polish/follow-up, not a blocker.

---

## ✅ Will do — in order

| # | Item | Why | Notes | Status |
|---|------|-----|-------|--------|
| 1 | **Naming: `class_groups` → `mpc_data` / `ValidatorMpcData`** on the assembly path | The bundle is class-groups **+ per-curve PVSS keys + proofs** since #1707; the name lies. `ValidatorMpcData` is already the convention elsewhere. | Source-only (BCS is positional → no wire-shape impact). Sites: `install_mpc_data_source` (`sui_connector/mod.rs:181`), `OffChainCommitteeClassGroupsSource` trait, assembly-path sites. Follow-up sites (out of diff): `MPCDataV1.class_groups_public_key_and_proof` field + `VersionedMPCData::class_groups_public_key_and_proof()` accessor. **Do NOT** rename `Committee.class_groups_public_keys_and_proofs` (genuinely class-groups, beside `*_pvss_*`). | ✅ `<naming>` |
| 2 | **Fix stale "consensus-voted" comments** in `mpc_manager` / `dwallet_mpc_service` | Comments describe the vote path that was removed in the unification. Misleads the next reader. | Trivial; my own debt. | ✅ `<comments>` |
| 3 | **EOP: reject the EOP vote when the bundled handoff sig *verifiably* fails** | Makes the `EndOfPublishV2` bundle atomic ("observed together" ⇒ "processed together"). Safe now that `AttestationMismatch` ≈ 0. | **Nuance:** only when the sig *verifies-and-fails* (`AttestationMismatch`). While the sig is *buffered* (expected attestation not installed yet, can't verify), still count the vote — else epoch advance stalls. | ☐ |
| 4 | **Fail-closed bootstrap on `Rejected`** | `Rejected` = every reachable peer served a wrong cert = possible eclipse / wrong prior-committee view. Halt loudly instead of limping. | The unification already half-does this (no cert ⇒ no key ⇒ can't really operate); this adds the explicit halt + actionable alert. | ☐ |
| 5 | **F6: escalate when off-chain assembly never converges** | Exactly the "assembly incomplete" we kept hitting — today it spins forever at `warn!` with no `error!`/metric. | Surface `EverythingExcluded` / permanent-incompleteness as `error!` + metric; keep transient (waiting-for-P2P) as `warn!`. | ☐ |
| 6 | **F7: resolve departed prior-committee signers' pubkeys** | Under churn, a *valid* cert is `Rejected` on a joiner because it can't resolve the keys of signers who left after E-1. | **First** check whether ika's chain retains the prior committee + consensus pubkeys (→ simple chain read, done). Only if Sui has pruned them: persist locally (we were in E-1, we hold them) and/or serve alongside the cert. | ☐ |
| 7 | **F5: epoch-consistency check in `refresh()`** | 2-line belt-and-suspenders: stops a lagging prev-epoch pubkey updater from installing the *next* committee's keys onto the live store. | `if system_inner.epoch != self.epoch_id { return Ok(()); }`. | ☐ |
| 8 | **F3-5: receiver-side relay buffer** | Closes the consensus-delivery race the joiner-retry can't: a validator whose `JoinerPubkeyProvider` lagged drops the relayed joiner announcement, and consensus dedup means it never re-sees it. Under load the window widens and a dropped joiner can diverge the next-committee assembly. | Buffer (bounded size + TTL) joiner announcements with a currently-absent/lagging provider; re-evaluate on provider install. | ☐ |

---

## ❌ Won't do

| Item | Why |
|------|-----|
| **BLS aggregate handoff cert** (docs F3-4) | Big rewrite of a working, well-tested Ed25519 path for a size/speed win that isn't hurting us. Risk > reward. |
| **F4-1 deadline excludes slow joiners** | By design — the liveness backstop so one dead joiner can't wedge the epoch. Already logged. Correct trade-off. |

---

## ⏭️ Follow-up (after this plan)

| Item | Why deferred |
|------|--------------|
| **F5/F6 nits** — refresh loop spins forever on dropped epoch store; `from_iter` silent overwrite on duplicate `AuthorityName`; base64 dedup cleanup; no RPC backoff; `CommitteeMembership` type for the chain channel; incomplete empty-blob entry publish | Each trivial + low-impact; batch later. |
| **Churn green on CI** | Behaviors verified by 5 targeted tests (incl. `test_user_sessions_across_multiple_epochs`, a multi-reconfig mini-churn under load); CI just captures the full 10-cycle stress run this box can't sustain. |
| **Restart-replay integration test** | Replay re-verify logic is already in + unit-tested; a dedicated integration test is nice-to-have. |
| **Final review together — part by part** | On the *last* version of the PR, walk the whole thing with the user section by section as a final pass (replaces the F9–F13 solo walkthrough). **Last item.** |

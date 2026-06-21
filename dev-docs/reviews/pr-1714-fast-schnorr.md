# Review — PR #1714: Fast Schnorr (VSS) support

Point-in-time review (see `README.md` — this is a record, not maintained truth).

- **PR:** [#1714](https://github.com/dwallet-labs/ika/pull/1714) — Fast Schnorr (VSS)
  signing plus its validator-key transport and the cross-binary upgrade-test harness.
- **Reviewed at:** head `96ffae7dfa` ("Merge dev into fast-schnorr (keep ours)").
- **Date:** 2026-06-16.
- **Method:** multi-agent cross-diff of the branch against `dev` and against the
  now-closed clean reimplementation `fast-schnorr-vss`, each finding independently
  re-verified, plus a full heavy-suite run dispatched on this head.
- **Verdict:** **functionally sound** — the off-chain genesis path is empirically
  green — but the branch must be brought onto `dev` with a real merge rather than the
  current take-ours merge, and a handful of low-severity items remain. Details below.

## Verdict detail

The feature works. All three heavy suites pass on this head: the TypeScript
integration suite — which was 0/9 with on-chain abort code 22
(`validate_network_encryption_key_supports_curve`) on the pre-[#1753] bare-genesis
defect — now passes, which is direct evidence that the genesis network-key DKG
completes. The earlier worry that the off-chain PVSS delivery path would not converge
for the genesis (first-epoch) committee is refuted by that run.

The one structural concern is the merge shape (finding 1): the head is a take-ours
merge whose tree equals the branch side, so landing it on `dev` would revert `dev`
wherever the two differ. Most of that delta is the deliberate architecture in
finding 2; the merge must be done so that only the intended changes land.

## Findings

1. **The head is a take-ours merge — it reverts `dev` where the branch differs.**
   · HIGH (process) · merge commit `96ffae7dfa`
   The merge tree is byte-identical to its first parent and records `dev` only as a
   second parent, so the forge reports it conflict-free while merging it would drop
   every `dev` change the branch does not already carry (61 files differ). Most of
   that delta is the deliberate design in finding 2, but the branch should be brought
   onto `dev` with a genuine merge — resolving each conflicting file on its merits —
   so no unrelated `dev` fix is silently undone.
   RESOLUTION: open — redo as a real `dev` merge (or audit the full 61-file delta and
   confirm every reverted hunk is intended) before landing.

2. **Genesis publishes the bare key shape on-chain; per-curve PVSS travels off-chain.**
   · was BLOCKER → RESOLVED (empirically) · `validator_initialization_config.rs`,
   `sui_client.rs`, `ika-types/.../committee.rs`, `ika-types/.../epoch_start_system.rs`,
   `sui_connector/sui_syncer.rs`
   The branch (via [#1756]) replaces `dev`'s per-protocol-version on-chain bundle
   ([#1753]) with an always-bare on-chain shape, drops the shape-tolerant chain
   decoder, and delivers each member's per-curve PVSS through a new current-epoch
   off-chain channel into the MPC manager. This was flagged as an unproven
   genesis-liveness risk; the heavy-suite run on this head (TypeScript + cluster +
   integration, all green) shows the path converges at genesis.
   RESOLUTION: validated by CI on `96ffae7dfa`. Record the chosen design in
   `specs/cross-binary-upgrade.md` so the divergence from `dev`'s on-chain approach is
   intentional and documented rather than read later as an accidental revert.

3. **Workspace crypto pin diverges from `dev`.** · MEDIUM (dependency) → being fixed
   · `Cargo.toml`
   The branch pinned `cryptography-private` at `4fe410fe` while `dev` is at `de3cddd`.
   RESOLUTION: [#1759] (into this branch) moves the pin to `32a27aa`, keeps the
   `parallel` feature, and refreshes the excluded wasm lock. Builds green, no source
   changes.

4. **The AHE sign path fetches the VSS Shamir cache with no version gate.**
   · LOW (transition-only) · `dwallet_mpc/mpc_session/input.rs` (the Sign,
   NetworkOwnedAddressSign, and DWalletDKGAndSign arms)
   The cache fetch is unconditional, so for a pre-v3 key during the v3→v4 window an
   ordinary (non-VSS) sign is rejected rather than served. It cannot occur on a fresh
   v4 genesis, but it couples ordinary-sign liveness to VSS infrastructure for no
   reason.
   RESOLUTION: open — gate the fetch behind the is-VSS check.

5. **A systemic VSS-key verification error collapses to a silent VSS-disable.**
   · LOW · `ika-types/.../committee.rs` (the verify-at-construction path)
   The error arm returns an empty map, so a real verification failure becomes "VSS
   quietly off" with no log line or metric.
   RESOLUTION: open — log/metric on the error arm instead of emptying the map.

6. **The centralized-party VSS sign carries an inconsistent version tag.**
   · LOW (dormant) · `dwallet-mpc-centralized-party/src/lib.rs`
   The external VSS sign path's version tag does not match the validator side, so an
   external VSS sign cannot complete end to end. Confined to the currently-ignored
   external path; it will surface the moment VSS is ungated.
   RESOLUTION: open — align the version tag, or add a tracking note where VSS is
   gated on.

7. **Hygiene.** · NIT
   A `#[allow(unused)]` in `ika-protocol-config/src/lib.rs` (the repo forbids
   `#[allow]` without sign-off); a dead newly-added type in `messages_dwallet_mpc.rs`
   with no consumers; leftover commented-out debug lines in the centralized-party
   crate; and the dropped doc-comment warning on the
   curve→algorithm→hash-scheme map when it reverted from an ordered to an unordered
   map (safe today because the consensus-visible iteration moved elsewhere, but the
   warning that kept a future consumer from reintroducing a divergent-session-id wedge
   is gone).
   RESOLUTION: open — low priority; fold the recurring ones into
   `learnings/pitfalls.md` if they recur.

## Tidy-ups landed separately

[#1759] (into `fast-schnorr`) carries the crypto-pin bump (finding 3), unifies the
`upgrade-test` workflow with `dev`'s four-scenario version while keeping the
branch's worthwhile additions, and relocates the test-validation methodology into
`playbooks/test-testing.md` behind a thin skill.

[#1714]: https://github.com/dwallet-labs/ika/pull/1714
[#1753]: https://github.com/dwallet-labs/ika/pull/1753
[#1756]: https://github.com/dwallet-labs/ika/pull/1756
[#1759]: https://github.com/dwallet-labs/ika/pull/1759

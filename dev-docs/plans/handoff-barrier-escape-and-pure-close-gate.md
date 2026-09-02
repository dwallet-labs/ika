# Handoff barrier escape + sequence-pure epoch-close gate (future work)

> **2026-08-20: the central safety premise no longer holds at HEAD and must
> be re-derived before this is built.** The cert-less-entry argument below
> rests on `all_cert_reconfiguration_outputs_held_locally` gating ONLY
> reconfiguration outputs, with DKG outputs passing unconditionally. That
> function is now `all_cert_network_key_outputs_held_locally` and gates both
> (`crates/ika-node/src/lib.rs:3603-3620`); `specs/handoff.md` describes the
> current behavior correctly. The rest of the plan is unreviewed against
> that change. Nothing else here has been edited.

Status: deferred — designed and cross-checked 2026-07-12, deliberately NOT
built before the 1.2.0 release. The centerpiece (the barrier's cert-less
chain fallback) relaxes the prepare-then-start barrier's block-forever
safety gate, and that risk-acceptance call needs its own review cycle,
separate from the release. Nothing here blocks 1.2.0: the shipped v4 fix
set (PRs #1820–#1827) is self-contained, and the residual risks below are
liveness (wedge) risks, not share-safety risks.

Grounding: all line anchors below were verified against `main` at
`c7cfd03f4c`. Re-verify them before building — this plan records intent
and sequencing, not a frozen diff.

## Background (read first)

- `dev-docs/specs/handoff.md` — the attestation / certificate / barrier
  contract. The prepare-then-start barrier
  (`wait_for_handoff_data_ready`, `crates/ika-node/src/lib.rs:3187`)
  blocks epoch entry until the prior epoch's handoff certificate AND
  every certified network-key reconfiguration output are held locally.
- The epoch close under v4 defers past the EndOfPublish quorum by a
  grace window; `handoff_signatures_meet_quorum`
  (`authority_per_epoch_store.rs:3122`) is consulted at the close.

Two facts confirmed at head that shape everything below:

1. **The barrier already recovers a continuing validator.**
   `prepare_handoff_anchor` (lib.rs:2988) runs on the
   continuing-validator reconfigure path, peer-fetches + verifies the
   cert when absent, and fetches missing certified outputs by digest.
   So a validator whose own attestation diverged from the quorum's can
   still obtain the quorum's cert from peers — recovery from divergence
   is the barrier's peer-fetch, NOT a local attestation re-build
   (`handoff_signature_sender` re-derives the validator's OWN
   attestation, which is exactly the divergent one).
2. **The barrier has no escape when no cert exists anywhere.** If no
   stake quorum ever signed one attestation digest (validators built
   divergent attestations), no cert is ever minted for the epoch, and
   the barrier blocks forever (lib.rs:3357: "No timeout — block
   indefinitely"). The wedged validator never enters the next epoch and
   never publishes its mpc_data — it is silently lost to the committee
   until operator intervention. This is the residual liveness wedge
   tracked in issue #1736.

## Item 1 — barrier cert-less chain fallback (the escape)

**Problem.** Fact 2 above. Today the no-cert epoch is a rare residual;
item 3 (lockstep close) would make cert-less entry routine, so this
escape is a hard prerequisite for item 3 and should land first.

**Why the fallback is safe (chain-equivalence).** The barrier's only
share-safety gate is "hold the committee-agreed reconfiguration output
for the epoch being entered" — `all_cert_reconfiguration_outputs_held_locally`
(lib.rs:3572) gates ONLY `NetworkReconfigurationOutput` items; DKG
output and validator mpc_data items pass unconditionally (mpc_data
feeds the NEXT reconfiguration's committee assembly, not this epoch's
signing). The chain holds those exact bytes:
`respond_dwallet_network_encryption_key_reconfiguration`
(`coordinator_inner.move`) pushes the reconfiguration `public_output` bytes
into `reconfiguration_public_outputs[next_epoch]` as part of a
quorum-certified dwallet-checkpoint system-session completion. Those
bytes are byte-identical to what the cert would certify — the cert
digest is `mpc_data_blob_hash` (Blake2b256) of the same bytes. They are
already readable via `get_network_encryption_key_with_full_data_by_epoch`
(`ika-sui-client/src/lib.rs:1262`). What the cert adds beyond the bytes
— the successor-committee pubkey-set binding and the permanent history
anchor for later joiners — protects against neither stale shares nor
cross-committee replay (the chain read is rooted in the config-pinned
coordinator object, and the successor committee is defined by the same
chain advance). Conclusion: cert-less entry backed by the on-chain
reconfiguration output is stale-share-EQUIVALENT, not degraded.

**Design sketch.**

1. Thread the run-loop `sui_client` into `wait_for_handoff_data_ready`
   (in scope at the reconfigure call site, lib.rs:2816).
2. Keep the off-chain-cert fast path exactly as today (faster, P2P,
   defense-in-depth, and it mints the history anchor future joiners
   need).
3. Add a bounded local threshold (a `const`, ~120s / 120 retries — NOT
   protocol config: the barrier is a wall-clock local gate, never
   consensus-consumed, so a local constant keeps it off the
   sequenced-stream discipline). Below the threshold, behave
   identically to today.
4. Past the threshold with the cert still unobtainable: import each
   still-missing key's reconfiguration output from
   `reconfiguration_public_outputs[next_epoch]`, verify
   `mpc_data_blob_hash(bytes)` against the local digest slice keying,
   cache it, and enter cert-less. Log loudly (this is the degraded
   mode; in steady-state v4 it indicates the epoch closed without a
   cert quorum).
5. The barrier must still block for a key whose reconfiguration never
   completed on chain — the fallback substitutes the SOURCE of the
   agreed bytes, never the requirement to hold them.

**The two implementation traps (where the real risk is):**

- **Epoch keying.** The imported blob must be cached under the
  reconfiguration SESSION's epoch (the epoch being handed off from),
  not the wall-clock next epoch — the same off-by-one that produced the
  `AttestationMismatch` wedge fixed earlier (handoff.md, "epoch-keyed
  perpetual slice"). Lock with a unit test against a chain stub
  (extend the tests near `all_cert_reconfiguration_outputs_held_locally_cases`,
  lib.rs:3631).
- **Consistency with the sibling degraded path.**
  ~~`adopt_cert_verified_keys`' absent-cert chain adoption
  (`mpc_manager.rs`, the v3→v4-boundary branch) and this fallback are
  the SAME degraded mode; both must back cert-less entry with the
  identical on-chain copy, or the barrier admits bytes the adoption
  pass then rejects.~~ [Update, issue #1751: the absent-cert chain
  adoption of a reconfigured key is now a REJECTION — the adoption pass
  admits cert-less entries only for DKG-only keys. Any barrier fallback
  designed here must match that: cert-less entry may not install a
  reconfigured key's bytes at all.]

**Spec deltas (same PR):** handoff.md step 2 (barrier) gains the
two-tier rule; invariant 5 is amended from "verified epoch-E handoff
artifacts" to "epoch-E reconfiguration outputs, from the cert-verified
peer blobs OR the quorum-certified on-chain copy when no cert was
minted"; note the shared-degraded-mode alignment with
`adopt_cert_verified_keys`.

**Tests:** the epoch-keying unit test above, plus a cluster test that
drives an epoch boundary where NO cert is minted (fault-inject:
suppress handoff-signature emission on enough validators that no
attestation digest reaches quorum) and asserts every validator enters
the next epoch via the fallback and signing works — validated per
`dev-docs/playbooks/test-testing.md` (prove the log evidence appears).

## Item 2 — barrier on ALL consensus-start paths

> **DONE.** The barrier now runs on the fullnode→validator promotion and
> process-startup paths as well as the reconfigure seam; `specs/handoff.md`
> describes the shipped behavior (the three paths, the generalized inputs,
> the genesis and unmapped-key carve-outs). It landed WITHOUT item 1, so the
> ordering note at the end of this item stands as an accepted risk rather
> than a satisfied prerequisite: the indefinite block now applies to a
> restarting or joining validator too. Items 1 and 3 remain deferred, item 1
> still subject to the re-derivation the banner at the top of this file
> demands.

**Problem.** `wait_for_handoff_data_ready` runs only on the
continuing-validator reconfigure path (lib.rs:2816). Two consensus-start
paths skip it:

- **Fullnode→validator promotion** (lib.rs:2865): a promoted node
  starts MPC without blocking on the prior epoch's handoff data.
- **Cold startup** (lib.rs:1121): a validator restarting into an epoch
  whose prior cert it does not hold starts consensus without it.

Both can enter an epoch without the agreed reconfiguration outputs —
the exact stale-share condition the barrier exists to prevent.

**Design sketch.** (a) Promotion: call the barrier before
`construct_validator_components`, inside the is-validator branch — the
fullnode's prior-epoch store carries the committee and peer ids that
`prepare_handoff_anchor` needs; no new plumbing. (b) Startup: gate a
validator whose local `get_certified_handoff_attestation(epoch - 1)` is
absent behind the same barrier before components construct; the
prior-epoch committee resolves from chain state (this is the joiner
bootstrap's existing resolution path). Both call sites reuse the
barrier's protocol-flag self-gate, so the v3→v4 boundary (prior epoch
ran v3, no cert exists, flag off in the prior store) passes through
without a crash-loop.

**Ordering constraint.** These are two NEW indefinite-block exposures if
they land before item 1's escape. Land WITH or AFTER item 1.

The freeze-side half of this work — fail-stop on a prior-cert READ
error at the mpc_data freeze instead of freezing a shrunken set — was
NOT deferred; it shipped in PR #1827.

## Item 3 — sequence-pure epoch-close gate

**Problem.** The v4 deferred close consults
`handoff_signatures_meet_quorum` (authority_per_epoch_store.rs:3122),
which sums a locally-verified signature table — NOT a pure function of
the sequenced consensus stream (the call site comment admits this). Two
validators can disagree on whether the gate holds at the same commit
and close the epoch at different points. PR #1824 hardened the interim
gate (dropping stale rows); this item replaces it.

**Design sketch.** Tally EndOfPublish-bundled handoff signatures
directly from the consensus-ordered stream, keyed by
`blake2b256(bcs(&HandoffAttestation))` — count stake per attestation
digest as messages are sequenced, and close when one digest's stake
reaches quorum (or the grace expires). Every validator computes the
identical tally at the identical commit — lockstep close. RETIRE
`handoff_signatures_meet_quorum` in the same change; two gates summing
different tables at the same commit is a second divergence surface.

**Consequences that force the ordering below:**

- Lockstep close means a validator whose OWN attestation diverged
  closes without holding a cert for the quorum digest — cert-less entry
  becomes routine, so item 1's escape and the barrier peer-fetch (fact
  1) are prerequisites, not nice-to-haves.
- Anything that changes the `HandoffAttestation` schema (e.g. the
  proposed network-owned-address anchor item) changes the tally key.
  Settle the schema BEFORE keying the tally on the digest, or the
  tally silently splits across schema variants.

**Spec deltas:** handoff.md's deferred-close section currently
describes only the grace deferral; it must gain the cert-quorum close
rule and the backstop behavior.

## Sequencing (dependency order)

1. Item 1 (escape) — standalone, reviewable on its own safety argument.
2. Item 2 (call sites) — with or after item 1.
3. Item 3 (pure close gate) — last; depends on both, plus the
   attestation-schema decision.

Each item is one PR; each changes consensus-adjacent behavior, so each
takes the full cluster suite on CI before merge (CLAUDE.md testing
rules), and items 1 and 3 need fault-injection validation per
`dev-docs/playbooks/test-testing.md`.

## Why deferred (the decision to revisit)

The escape converts "block forever until a cert exists" into "after a
bounded wait, enter on the chain's quorum-certified copy of the same
bytes". The chain-equivalence argument above says this preserves the
no-stale-shares guarantee; the residual risk is concentrated in the two
implementation traps (epoch keying, degraded-mode consistency), not the
concept. It was deferred from the 1.2.0 release because a deliberate
relaxation of the epoch-entry safety gate on a funds-handling signing
network warrants its own focused review, and the release did not need
it: without item 3, divergent-attestation epochs remain rare, and the
existing barrier peer-fetch covers every case where a cert exists
somewhere.

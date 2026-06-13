# Plan: carry-forward of stable mpc_data to fix the freeze wedge (#1742)

Status: proposed (2026-06-13). Regression harness: PR #1741
(`test_validator_restart_mid_end_of_publish_grace`), currently red on
exactly this wedge.

## The bug

Under v4 off-chain validator metadata, a committee member that enters an
epoch late (restart recovery near the boundary, or any slowness) can miss
that epoch's mpc_data announcement deadline. The freeze then finalizes a
frozen set that omits the member, while the chain's next-epoch committee
still seats it. `ReconfigurationParty::generate_public_input`
(`crates/ika-core/src/dwallet_mpc/crytographic_computation/mpc_computations/reconfiguration.rs:94`)
requires full bundle coverage of the seated committee, so every validator
deterministically rejects the reconfiguration session. The frozen set is
immutable for the epoch, so the rejection repeats forever and the epoch
never closes. The same wedge hits any `excluded_set` member, not only the
missed-freeze case — `new_next_committee` is never filtered by exclusion.

## Verified findings (why the obvious fixes are wrong)

- **Reducing the upcoming committee's `voting_rights` to the frozen set —
  rejected.** The architecture deliberately keeps the FULL chain
  membership in `voting_rights` and filters only the class-groups maps;
  narrowing membership made honest handoff certs unverifiable by the
  joiners they certify (`crates/ika-core/src/handoff_cert.rs:52-66`).
  Party IDs are positional into `voting_rights`, so reducing membership
  also shifts them and breaks the current→upcoming party map.
- **Resharing to the frozen subset (M of N) and leaving all N seated —
  rejected (unsafe signing).** The network key never persists its own
  access structure (`crates/dwallet-mpc-types/src/dwallet_mpc.rs:100`),
  and share decryption uses the chain committee's access structure, not
  the key's: `decrypt_and_store_secret_key_shares` is called with
  `self.access_structure`
  (`crates/ika-core/src/dwallet_mpc/mpc_manager.rs:2043`), built once per
  epoch from the full committee
  (`generate_access_structure_from_committee`,
  `crates/ika-core/src/dwallet_mpc/mpc_manager.rs:342`). A subset reshare
  would decrypt/sample against the wrong (N-party) structure. The
  architecture couples chain-committee ≡ share-holders; decoupling is a
  large, security-critical change, deferred.
- **The chain does not evict dead validators.** Next-committee selection
  is top-N by stake; peer reports only slash rewards, never remove from
  the committee; there is no uptime/timeout eviction. So "wait for the
  chain to drop a dead member" is not a mechanism.
- **mpc_data is stable across epochs — the enabling fact.**
  `derive_mpc_data_blob(seed: &RootSeed)`
  (`crates/ika-core/src/validator_metadata.rs:292`) is a pure function of
  the validator's root seed: no epoch parameter. A continuing validator
  re-derives byte-identical bytes every epoch. The only way it changes is
  a root-seed rotation = a new validator identity (new authority key).
- **The last-known data is durably available.**
  - Bytes: `mpc_artifact_blobs` is a perpetual `DBMap<[u8;32], Vec<u8>>`
    (`crates/ika-core/src/authority/authority_perpetual_tables.rs:36`)
    with no prune/remove anywhere, hydrated into the in-memory cache at
    boot (`crates/ika-node/src/lib.rs:978`).
  - Digest per validator: the prior epoch's handoff cert carries
    `ValidatorMpcData { validator } -> digest`
    (`crates/ika-types/src/handoff.rs:40,62`), read via
    `get_certified_handoff_attestation`
    (`crates/ika-core/src/authority/authority_perpetual_tables.rs:313`),
    kept forever, and guaranteed local before the next epoch by the
    prepare-then-start barrier (handoff spec, invariant 5).

## The fix: carry forward stable mpc_data at the freeze

When the freeze finalizes the frozen `validator -> blob_hash` set for
epoch E, any committee member that lacks a fresh quorum-attested digest
this epoch but is present in epoch E-1's handoff cert is frozen **at its
E-1 cert digest**. Only members with NO prior-cert entry — first-time
joiners — and no fresh attestation are left unfrozen (excluded). This is
exactly "reuse the last-handoff mpc_data for anyone already on record;
only exclude joiners."

### Why the freeze, not the assembly

The frozen set is pinned into the handoff attestation
(`ValidatorMpcData{validator}` items) AND drives the reconfiguration
input. Carry-forward must land in the frozen set itself so the
attestation, the off-chain assembly, and the reconfiguration all see the
same membership. Supplementing only at assembly would make the assembled
committee disagree with the attested frozen set → cross-validator
divergence.

### Why it is safe and complete

- **Exact, not approximate.** The carried bytes are byte-identical to
  what the member would have announced (root-seed-deterministic), so the
  reconfiguration encrypts the member's new share to the same stable PVSS
  key it can later decrypt — whenever it recovers, even epochs later.
- **Deterministic.** The E-1 cert and the blob bytes are consensus-
  anchored and perpetual; every validator carries forward the identical
  digest.
- **Trust preserved.** A carried digest was quorum-attested when it was
  first frozen (it is in a certificate a stake-quorum signed); carrying
  it forward does not weaken the freeze's attestation model.
- **Restores the v3 property.** Under v3 this data was read from chain —
  always available. The v4 off-chain move regressed "always available" to
  "available only if announced this epoch"; carry-forward restores it.
- **No residual wedge.** Because a carried digest itself lands in epoch
  E's cert, coverage CHAINS: a validator frozen even once is covered in
  every subsequent epoch, whether up or down. A permanently-down-but-
  staked validator therefore never wedges reconfiguration. The only
  excludable members are never-frozen first-time joiners — which is the
  announcements spec's stated intent.

The reconfiguration guard (`reconfiguration.rs:94`) STAYS — it is the
correct safety net and should simply never fire in steady state once the
freeze stops producing gaps.

## Implementation steps

1. **Prior-cert digest lookup.** Add a read helper (epoch store /
   perpetual tables) that returns `validator -> mpc_data digest` from
   epoch E-1's `CertifiedHandoffAttestation` (filter `items` for
   `HandoffItemKey::ValidatorMpcData`). Confirm the freeze handler can
   reach perpetual tables at the commit boundary (handoff processing
   already reads/writes them there).
2. **Supplement the freeze.** In the freeze decision
   (`crates/ika-core/src/authority/authority_per_epoch_store.rs`,
   `compute_freeze_partition` / `freeze_mpc_data_if_first`): after the
   attested partition is computed, for every current/next committee member
   not covered by a fresh attested digest, fall back to its prior-cert
   digest if one exists; otherwise leave it for the joiner-exclusion path.
   Keep the decision a pure function of consensus state + perpetual cert.
3. **No change at assembly/handoff/reconfiguration** — they read the
   frozen set, which now has full coverage. Verify
   `compute_effective_reconfig_input_set` (frozen ∩ (V_e ∪ V_{e+1})) and
   `decide_assembly_inputs` resolve all members.
4. **Spec.** Update `dev-docs/specs/validator-mpc-data-announcements.md`
   (see delta below) in the same PR.

## Spec delta (validator-mpc-data-announcements.md)

Add under "Ready signals and the freeze" / "Frozen set semantics":

> **Carry-forward (stable mpc_data).** A validator's mpc_data blob is a
> pure function of its root seed (`derive_mpc_data_blob`), so a continuing
> validator's blob is byte-identical every epoch. At the freeze, a
> committee member that has not been freshly attested this epoch but is
> present in the prior epoch's handoff cert is frozen at its prior-cert
> digest (bytes resolved from perpetual `mpc_artifact_blobs`). Only
> members with no prior-cert entry — first-time joiners — can be excluded
> for failing to announce. This restores the v3 "always available"
> property for any validator ever frozen, and because a carried digest
> re-enters the current epoch's cert, coverage chains across epochs.

## Tests

- **Regression:** PR #1741 `test_validator_restart_mid_end_of_publish_grace`
  goes green (validator X, a continuing member, is carried forward
  instead of excluded; the reconfiguration gets full coverage).
- **Unit:** a `decide`/freeze-level test — member silent this epoch but
  present in the prior cert → frozen at the prior digest; a joiner with
  no prior cert entry and no announcement → excluded.
- Run the cluster suite on CI (epoch-boundary / reconfiguration change).

## Open details to settle during implementation

- A member that announced a malformed blob this epoch (attested-but-
  excluded) while it has a valid prior-cert digest: recommend carry
  forward the known-good prior digest (its true blob is deterministic;
  bad bytes are byzantine/transient).
- Carry-forward looks at E-1 only (not deeper). A member excluded in E-1
  has no E-1 entry and must re-announce in E to rejoin — the intended
  self-heal path.
- Genesis / epoch-0 has no prior cert; all members announce fresh —
  unaffected.

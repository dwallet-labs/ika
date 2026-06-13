# Cross-epoch handoff (attestation, certificate, barrier)

Status: active under protocol v4 (`off_chain_validator_metadata_enabled`).
The handoff replaces the removed consensus vote on network-key outputs:
it is the cross-epoch agreement on exactly which off-chain artifacts the
next epoch inherits.

## The attestation

`HandoffAttestation { epoch, next_committee_pubkey_set_hash, items }`:

- `epoch` — the epoch the outgoing committee hands off FROM.
- `next_committee_pubkey_set_hash` — Blake2b256 of the next committee's
  BLS pubkey set; binds the attestation to the specific committee
  receiving the handoff (an attestation cannot be replayed against a
  different successor committee).
- `items` — `(HandoffItemKey, digest)` pairs, sorted strictly ascending
  by key:
  - `NetworkDkgOutput { key_id }` — stable across the encryption key's
    lifetime (the DKG output is a one-time deterministic computation).
  - `NetworkReconfigurationOutput { key_id }` — this epoch's
    reconfiguration output. Its digest MUST come from the epoch-keyed
    perpetual slice (`network_reconfiguration_output_digest_by_epoch_and_key`,
    keyed by the reconfiguration SESSION's epoch, not the wall-clock
    epoch a validator happened to finalize in) — otherwise a
    late-finalized output crossing the epoch boundary lands under
    different epochs on different validators and peers cross-reject as
    `AttestationMismatch`, wedging EndOfPublish. A validator that has
    not recorded the epoch's output simply omits the item and is
    excluded from it by design (the computing validators are a quorum).
  - `ValidatorMpcData { validator }` — pins the exact mpc_data version
    consumed by this epoch's MPC sessions (the frozen set; see the
    announcements spec).
- The attestation is built once per epoch when the validator's local
  view is complete (snapshot-ready), and it must be DETERMINISTIC
  across validators: every digest source above is consensus-anchored.

## Signing and EndOfPublish V2

- Signatures use the validator's **consensus Ed25519 key** — never the
  BLS authority key (authority keys are reserved for Sui Move-side
  artifacts).
- `EndOfPublishV2 { authority, handoff_signature }` bundles the
  validator's `HandoffSignatureMessage` into its EndOfPublish vote in
  ONE consensus message, so the two cannot be reordered relative to
  each other. The consumer splits them:
  1. The EndOfPublish vote is counted UNCONDITIONALLY and exactly like
     V1 — whether a peer's bundled attestation matches local state MUST
     NOT affect the vote tally (vote counting has to be deterministic
     across validators; only the signature half is subject to local
     verification).
  2. The signature half is routed to the handoff aggregator. A
     signature that cannot be verified yet (consensus pubkey provider
     not installed, expected attestation not yet built) is BUFFERED,
     not dropped; buffered signatures are re-verified when the
     missing dependency installs.
- **Deferred close (v4 only)**: after the EndOfPublish stake quorum is
  reached, the epoch close is deferred `end_of_publish_grace_rounds`
  (protocol config, default 50) consensus leader rounds past the
  persisted quorum anchor (`end_of_publish_quorum_round`) so more
  EndOfPublish votes and handoff signatures can land before the final
  checkpoint. Under v3 the close stays inline at the quorum-crossing
  message — the deferral MUST NOT change v3 behavior (mixed-binary
  committees on a v3 network must produce byte-identical close
  sequences). The close itself is restart-idempotent via a persisted
  `epoch_close_emitted` marker.

## Certificate

`CertifiedHandoffAttestation { attestation, signatures }`:

- Aggregated independently by every validator from consensus-ordered
  signature messages; the certificate exists once signatures reaching a
  stake quorum agree on one attestation. A quorum present entirely in
  the buffer (signatures that arrived before the local expected
  attestation) also forms a certificate on drain.
- Persisted in the PERPETUAL store keyed by epoch
  (`insert_certified_handoff_attestation`) and kept forever — handoff
  certs are never pruned; they are the only cross-epoch trust anchor a
  later joiner can verify history against.
- Exactly one certificate per epoch is expected. Verification of a
  certificate for epoch E checks: epoch binding, every signature
  against the SIGNING committee (epoch E's committee — for a
  bootstrapping joiner that is the PRIOR committee), quorum stake, and
  `next_committee_pubkey_set_hash` against the entering committee.
  Consensus pubkeys are fixed at registration; members that have since
  left the active set are resolved from chain (their staking pool
  object persists) so churn cannot wrongly reject a valid certificate.

## Consuming the certificate

1. **Joiner bootstrap (epoch start)**: a validator that does not hold
   the prior epoch's certificate fetches it from current-committee
   peers (`JoinerBootstrapVerifier`), verifies as above, persists it,
   and installs the network-key outputs it certifies. Outcomes:
   - `Verified` — persist + install.
   - `Rejected` (peers served certificates but NONE verified) — a
     genuine trust-anchor mismatch or eclipse: **fail closed, halt the
     node**. A single bad peer cannot cause this (every peer is tried).
   - `Unavailable` (no peer served one) — benign propagation lag;
     retry.
   A validator that already holds the certificate re-verifies it before
   it anchors anything (a persisted certificate is NEVER trusted
   blindly — defense against local DB tampering/corruption), then
   re-installs certified outputs (idempotent: locally-present digests
   skip the fetch).
2. **Prepare-then-start barrier (reconfiguration seam)**: before
   entering epoch E+1, the validator blocks until the FULL verified
   handoff data for epoch E is local: the certificate (fetched and
   verified via the same verifier, anchored once per barrier entry) and
   every certified network-key output blob. Holding the certificate
   does NOT imply holding the outputs (a lagging validator can adopt
   the certificate from a buffered signature quorum without ever
   computing the outputs), so the barrier installs missing outputs by
   digest. This is what prevents stale-share `InvalidParameters`
   signing failures after the boundary.
3. **Network-key adoption (steady state)**: each epoch, locally-held
   network-key outputs are adopted into the instantiation set only if
   their digests match the prior epoch's certificate
   (`adopt_cert_verified_keys`): a reconfigured key must match BOTH its
   stable DKG digest and its epoch-specific reconfiguration digest. A
   certificate READ ERROR skips adoption for the tick (retry) — it must
   not be conflated with the genuinely-absent-certificate case, which
   exists only at the v3→v4 boundary and falls back to the chain copy.
   Chain reads here are deprecated: v4 keeps chain writes for
   compatibility, but the certificate-gated off-chain copy is the only
   sanctioned read path.

   Two adoption guards keep the installed parameter set identical
   across the committee (a validator that installs anything else
   honestly computes byte-divergent MPC outputs and is convicted
   malicious by the output-quorum byte-equality tally — silently
   reducing the committee's fault tolerance):
   - An overlay entry whose reconfiguration output is (transiently)
     EMPTY must not be adopted through the initial-DKG branch while
     the certificate pins a reconfiguration digest for the key:
     DKG-derived parameters are a set the committee never agreed to
     run this epoch. Skip and retry; the overlay re-merges every sync
     tick and the barrier installs the pinned blob by digest.
   - Adopted data whose `current_epoch` metadata differs from the
     manager's epoch is rejected BEFORE the (expensive, ~10s)
     instantiation spawns — a stale chain snapshot at the boundary
     otherwise burns the instantiation and blocks the same key's
     correct data behind the in-flight entry, widening the
     epoch-entry key gap during which sessions park.

## Key invariants

1. One handoff per epoch, attested at EndOfPublish, verified against
   the signing (prior) committee only, kept forever.
2. EndOfPublish vote counting is independent of attestation
   verification — a malformed or mismatched bundled attestation can
   never block epoch advance by suppressing votes.
3. Every attestation digest source is consensus-anchored (epoch-keyed
   reconfiguration slice, frozen mpc-data set), so honest validators
   sign byte-identical attestations.
4. Fail closed on contradiction (`Rejected`, persisted-cert
   re-verification failure); fail open with retry on absence
   (`Unavailable`, read errors).
5. The barrier guarantee: no validator participates in epoch E+1
   sessions without locally holding the verified epoch-E handoff
   artifacts.

Code anchors: `crates/ika-types/src/handoff.rs` (types),
`crates/ika-core/src/handoff_cert.rs` (aggregation + verification),
`crates/ika-core/src/authority/authority_per_epoch_store.rs`
(EndOfPublish V2 processing, deferred close, epoch-keyed digest slice),
`crates/ika-core/src/epoch_tasks/handoff_signature_sender.rs`,
`crates/ika-core/src/epoch_tasks/joiner_bootstrap_verifier.rs`,
`crates/ika-node/src/lib.rs` (bootstrap at epoch start +
prepare-then-start barrier), `crates/ika-core/src/dwallet_mpc/mpc_manager.rs`
(`adopt_cert_verified_keys`).

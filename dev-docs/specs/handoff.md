# Cross-epoch handoff (attestation, certificate, barrier)

Status: active — unconditional since `MIN_PROTOCOL_VERSION = 5`. The
feature flag that used to gate it is gone from the code; the pre-v4
chain-sourced mode no longer exists in the binary.
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
  - `NetworkDkgOutput { key_id }` — the canonical network DKG output.
    Stable across epochs WITHIN a representation, with exactly one
    consensus-deterministic transition over the key's lifetime: a
    mainnet-v1.1.8-origin key's on-chain DKG anchor is V1 (the raw
    `class_groups::dkg::PublicOutput`) and its reconfiguration outputs are
    V2; the canonical DKG output migrates ONCE to the full V3
    `decentralized_party::dkg::PublicOutput` at the first v4 reshare
    (when the cert-pinned reconfiguration output first becomes V3, every
    validator reconstructs the full V3 output and flips its perpetual
    digest mirror — see `dev-docs/plans/network-dkg-anchor-v2-to-v3-migration.md`).
    The flip is epoch-uniform because it is driven by the cert-pinned
    reconfiguration output, identical committee-wide. A natively-v4 key
    is V3 from the start and never migrates.
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
    announcements spec). Divergence guard: if the ready-signal quorum
    round is anchored for the epoch but the local frozen table is empty
    (freeze not yet fired, or a crash window lost it), the items builder
    DEFERS (errors → the sender retries) instead of emitting an
    attestation missing every `ValidatorMpcData` item — a missing
    signature aggregates as nothing, while a divergent one pollutes the
    aggregation bucket. A quorum-less epoch legitimately emits none,
    uniformly with peers.
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
     missing dependency installs. On a RESTART the missing dependency
     (the expected attestation) is re-installed by the signature
     sender's own build path re-running each service iteration — NOT
     only by a fresh snapshot-ready transition — so buffered-quorum
     adoption is not the sole recovery path.
- **Restart recovery of the aggregator.** The expected-attestation
  install runs on the sender's service iteration even after this
  validator's own EndOfPublish vote is durably recorded — until the
  aggregator is built, at which point a steady-state early-out (vote
  recorded AND aggregator installed) stops the per-tick pass (the
  hydrate+build it runs re-hashes and rewrites full key blobs, so it
  must not run once per second until teardown). So a restart after our
  own EndOfPublishV2 was sequenced rebuilds the in-memory aggregator
  ONCE by replaying the persisted `handoff_signatures` rows and
  re-mints+persists the certificate. Buffered-quorum adoption alone is
  NOT the recovery mechanism — it sees only signatures that arrive after
  the restart. SCOPE: this replay recovers a NON-divergent validator
  (the rebuilt attestation matches what the persisted rows endorse). A
  validator whose rebuilt attestation DIVERGES from the rows re-verifies
  none of them and mints nothing — its recovery is the barrier
  peer-fetch of the quorum's certificate, never local replay.
- **`handoff_signatures` table invariant.** The table holds ONLY rows
  that verify against the currently-installed expected attestation. A
  re-install that changes the attestation (e.g. a fresh hydration
  changed the items) drops the superseded rows from BOTH the aggregator
  and the table, in one atomic batch-delete — because the deferred-close
  quorum gate (`handoff_signatures_meet_quorum`) sums the TABLE, not the
  aggregator. The table therefore plays two roles: a restart-durable
  source for aggregator rebuild, and the close-gate quorum input; the
  second role is what makes stale-row hygiene load-bearing. (If the
  close gate migrates to a sequence-pure tally, that second role is
  retired.) TRADEOFF (deliberate): the delete is destructive under
  divergence — a validator that adopted the quorum's attestation via
  buffered signatures and then installed a divergent local build deletes
  the quorum's rows, flips its own close gate true → false, and closes
  via the grace backstop instead of the quorum commit. The persisted
  certificate is NOT deleted, and the sender's steady-state early-out
  bounds the clobber to a single recovery pass. The non-destructive
  alternative (rows keyed by attestation digest, gate counts matching
  rows) is heavier schema surgery on a gate the planned sequence-pure
  close-gate rework retires — see
  `dev-docs/plans/handoff-barrier-escape-and-pure-close-gate.md`.
- **Deferred close**: after the EndOfPublish stake quorum is
  reached, the epoch close is deferred `end_of_publish_grace_rounds`
  (protocol config, default 50) consensus leader rounds past the
  persisted quorum anchor (`end_of_publish_quorum_round`) so more
  EndOfPublish votes and handoff signatures can land before the final
  checkpoint. (Historically v4-gated — under v3 the close stayed inline
  at the quorum-crossing message; that inline branch is dead code since
  `MIN_PROTOCOL_VERSION = 5`.) The close itself is restart-idempotent
  via a persisted `epoch_close_emitted` marker.

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
  Two properties of the chain-read prior committee
  (`fetch_previous_committee`) are load-bearing here:
  - **Snapshot-name keying.** The consensus-key map is keyed by each
    member's PRIOR-epoch snapshot name (resolved by validator id from
    the frozen `previous_committee`), never by the member's current
    on-chain protocol pubkey — a member that rotated its protocol key
    at the boundary signed under the old name, and current-name keying
    would silently drop its stake from the cert quorum.
  - **Lossy membership read (and its sharp edge).** A prior-committee
    member whose frozen snapshot `protocol_pubkey` bytes fail to parse
    is SKIPPED rather than panicking the reader — but the skip is not
    graceful degradation: the member is absent from `voting_rights`,
    and verification hard-rejects any certificate carrying a weight-0
    signer's signature. Since such a member's own node keeps signing,
    its signature is in every aggregated cert, so every served cert
    fails and bootstrap surfaces `Rejected`. The reader logs the
    dropped ids so that outcome is attributable to the corrupt record
    (near-unreachable trigger: the bytes are validated at
    registration; the pre-lossy behavior was a panic crash-loop).

## Consuming the certificate

1. **Joiner bootstrap (epoch start)**: a validator that does not hold
   the prior epoch's certificate fetches it from current-committee
   peers (`JoinerBootstrapVerifier`), verifies as above, persists it,
   and installs the network-key outputs it certifies. Outcomes:
   - `Verified` — persist + install.
   - `Rejected` (peers served certificates but NONE verified) — a
     genuine trust-anchor mismatch or eclipse: **fail closed** — the
     node must never anchor on an unverified cert. A single bad peer
     cannot cause this (every peer is tried). Enforcement today: the
     epoch-start bootstrap task logs `Rejected` at error and installs
     nothing (it does NOT hard-halt the process; a refuse-participation
     policy layers above it), and the prepare-then-start barrier simply
     never becomes ready without a verified anchor — the node blocks
     out of MPC participation. The one place that DOES halt the node is
     the barrier's re-verification failure of a locally-PERSISTED cert
     (local DB tampering/corruption — see step 2).
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
   every certified network-key output blob — reconfiguration outputs
   AND the canonical DKG outputs. Holding the certificate
   does NOT imply holding the outputs (a lagging validator can adopt
   the certificate from a buffered signature quorum without ever
   computing the outputs), so the barrier installs missing outputs by
   digest. This is what prevents stale-share `InvalidParameters`
   signing failures after the boundary. The DKG items are part of the
   readiness predicate deliberately: a local mirror whose digest
   contradicts the certificate (the hydration-clobber shape below) can
   only be repaired here — the installer fetches the cert-pinned bytes
   from peers and re-caches them, and it only runs while the gate reads
   not-ready. When the gate skipped DKG items, a poisoned mirror passed
   the barrier instantly every epoch and stayed wedged permanently. The
   DKG digests are read from the NEW epoch store (empty per-epoch table
   → perpetual mirror), never the outgoing store, whose per-epoch table
   is exactly what the end-of-epoch hydration may have poisoned.
3. **Network-key adoption (steady state)**: each epoch, locally-held
   network-key outputs are adopted into the instantiation set only if
   their digests match the prior epoch's certificate
   (`adopt_cert_verified_keys`): a reconfigured key must match BOTH its
   DKG digest and its epoch-specific reconfiguration digest. The DKG
   digest migrates once (V1|V2 -> V3, above): at that single boundary an
   ALREADY-ADOPTED key whose overlay DKG digest has moved past the prior
   epoch's (pre-V3) certificate is the expected defer — it keeps its adopted
   value rather than being dropped, exactly as a moved reconfiguration
   output is tolerated; only an UNADOPTED key contradicting the
   certificate is the security-relevant anomaly (the output-quorum
   byte-equality tally remains the guard against a divergent output). A
   certificate READ ERROR skips adoption for the tick (retry) — it must
   not be conflated with a genuinely-absent certificate, which is an
   answer: a reconfigured key with no prior certificate is REJECTED
   (its output has no quorum anchor — a certificate is built durably
   every off-chain epoch, so absence alongside a reconfigured overlay
   entry is anomalous), while a DKG-only key (genesis, fresh key)
   adopts its deterministic local DKG output. Chain blob reads are
   gone from this path: v4 keeps chain writes for compatibility, and
   the certificate-gated off-chain copy is the sanctioned steady-state
   read path — the one exception is the un-instantiated
   restart-recovery read (third guard below). (Until issue #1751 the
   v3→v4 rolling upgrade bridged keys whose DKG or last
   reconfiguration ran under v3 by importing their blobs from chain
   and adopting them cert-less; that scaffolding is removed — a
   network with keys DKG'd under v3 can no longer upgrade into v4+.)

   Three adoption guards keep the installed parameter set identical
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
   - Stranded-key recovery — two trigger shapes, one mechanism. First
     (joiner / cold start): an overlay entry with NO blobs at all for a
     key DKG'd in a PRIOR epoch, on a validator that holds nothing for
     it. The producer cache can never fill (this validator never
     computed the key's outputs) and the cert-pinned blob install
     (barrier) covers only continuing validators today, so adoption
     flags the key for the syncer's chain-sourced read instead of
     skipping it forever. (Until issue #1751 removed the migration
     chain-read fallback, that fallback covered this shape implicitly;
     the `v125_churn` scenario's mirrored joiner caught the regression.)
     A key DKG'd THIS epoch is excluded — the healthy fresh-key
     bootstrap window. Second (mid-epoch restart, issue #1852). Once this
     epoch's reconfiguration completes, the off-chain copy of a key's
     reconfiguration output is the just-produced NEXT-committee output;
     adoption's produced-this-epoch guard correctly skips it (a running
     validator already holds this epoch's parameters and is only
     pre-staging the boundary flip), but for a validator holding
     nothing — restarted or freshly booted after that completion — the
     skip would strand the key un-instantiated all epoch, parking every
     session on it. When the guard skips a key the validator holds
     NOTHING for (not instantiated, no instantiation in flight, nothing
     adopted — the in-flight/adopted checks keep the healthy
     first-instantiation window out of the set), adoption flags it in a
     shared stranded-key set, and the sync task chain-reads exactly the
     flagged keys: a full read instead of the synthesize-empty fast
     path, serving the CHAIN's canonical current-epoch reconfiguration
     output (never overlaid by the off-chain copy) so adoption and
     instantiation proceed; a confirmed instantiation un-flags the key.
     The DKG blob still prefers the canonical off-chain mirror — the
     digest the certificate pins — because the chain's pre-V3 anchor
     would fail the DKG-digest gate and, via the handoff hydration
     path, file a divergent DKG digest for this epoch's attestation.
     The set is empty in every healthy flow — non-validators never run
     adoption at all — so the v4 no-steady-state-chain-read invariant
     holds exactly (asserted by the
     `off_chain_metadata_v4_does_not_read_blobs_from_chain` cluster
     test), and both paths install the identical canonical output for
     the epoch (no fork surface). KNOWN RESIDUAL: a mid-epoch
     restart during the single V2→V3 canonical-migration epoch is NOT
     recovered — the prior cert pins the V2 DKG digest while the
     restarted validator's mirror already flipped to V3 (the V2 bytes
     no longer exist locally), so adoption warns and skips until the
     next epoch's cert pins V3. Fail-closed, bounded to that one
     epoch, identical to pre-recovery behavior; epoch close is
     unaffected (the validator still votes EndOfPublish).
   - Current-epoch validator MPC keys (mid-epoch restart, issue #1879).
     The manager's current-epoch key bundle
     (`validator_mpc_keys_by_party_id` — consumed by the within-epoch
     network DKG and by every VSS presign/sign public input) is sourced
     from the prior cert's `ValidatorMpcData` items ∩ current committee,
     assembled against the perpetual blob store
     (`try_ingest_current_epoch_keys_from_prior_handoff_cert`). The
     cert set IS the committee-agreed value of this epoch's bundle: it
     pins the prior epoch's frozen set, which is what the boundary-window
     delivery hands every continuing validator, and blobs are
     content-addressed, so the rebuild is byte-identical — and unlike
     the boundary window's process-local watch channel it survives a
     mid-epoch restart. With a cert present the freeze-gated channel
     delivery is NEVER consulted: post-freeze it carries the CURRENT
     epoch's frozen set, a possible strict superset of the boundary set
     (a late-attested joiner), and ingesting that superset would
     byte-diverge this validator's VSS presign inputs from the
     committee's. The channel remains the source only for the
     chain-true no-cert epochs (genesis, the first off-chain-enabled
     epoch), where the epoch's own freeze is the only agreed set. A
     cert READ ERROR retries without falling back to the channel; a
     missing cert-pinned blob defers ingestion (retry as propagation
     converges), never downgrades to the channel bundle. The deferral
     has an active repair (issue #1881): each per-epoch peer-blob
     fetcher pass also fetches the prior cert's `ValidatorMpcData`
     blobs missing locally from committee peers (any holder is
     authoritative — content-addressed, verified against the
     quorum-signed cert digest) into the perpetual store, so a store
     that never held a long-dark carried-forward member's blob heals
     instead of deferring forever; the missing count is exported as
     `ika_dwallet_mpc_prior_cert_blobs_missing`.
   - The hydration-clobber variant (issue #1852, never-instantiated
     shape) and its three defenses. Post-restart, until the per-epoch
     blob source installs, the sync task's full chain read publishes an
     overlay whose DKG blob is the chain's ORIGINAL pre-V3 anchor; with
     no later refetch trigger that overlay used to sit in the watch
     channel all epoch, and the end-of-epoch hydration pass cached it —
     overwriting the DURABLE perpetual canonical mirror. Every later
     epoch then failed the DKG-digest gate above before reaching the
     produced-this-epoch guard (so the stranded-key recovery never
     fired), permanently: the barrier read ready without checking DKG
     items, so its installer never repaired the mirror. Defenses, each
     independently sufficient for its layer: (1) hydration is
     fill-absence only — it never overwrites an existing per-key DKG
     digest (the instantiation mirror and the cert-anchored barrier
     install are strictly more authoritative than the overlay
     snapshot); (2) the sync task clears its per-key fetch memo
     whenever the blob-source identity changes, so a source-less
     chain-read overlay is re-merged within a tick of the install
     instead of persisting; (3) the barrier verifies and repairs DKG
     items (see the barrier section) — the only layer that heals an
     already-poisoned mirror.

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
   (`Unavailable`, read errors). The freeze is a cert CONSUMER too:
   `prior_epoch_mpc_data_digests` (carry-forward source) reads the prior
   cert's `ValidatorMpcData` items, and a READ ERROR there PROPAGATES —
   the commit fails and replays on restart — rather than degrading to an
   empty (shrunken) carry-forward map that would diverge this validator's
   frozen set from its peers'. An empty map is returned only for the
   chain-true no-cert epoch (genesis; historically also the v3→v4
   boundary epochs). CAVEAT: the committee-uniformity of that empty-map case rests
   on invariant 5 holding on EVERY consensus-start path; today the
   barrier is wired only into the continuing-validator reconfigure path
   (joiner-promotion and cold startup are pending — see
   `dev-docs/plans/handoff-barrier-escape-and-pure-close-gate.md`), so
   a joiner racing its bootstrap fetch can still freeze absent-cert.
   The read-error flavor of the fork is closed; the absent-cert flavor
   closes with the barrier wiring.
5. The barrier guarantee: no validator participates in epoch E+1
   sessions without locally holding the verified epoch-E handoff
   artifacts. Currently enforced on the continuing-validator
   reconfigure path; extending it to the fullnode→validator promotion
   and cold-startup consensus-start paths is planned work (see the
   plan referenced in invariant 4).

Code anchors: `crates/ika-types/src/handoff.rs` (types),
`crates/ika-core/src/handoff_cert.rs` (aggregation + verification),
`crates/ika-core/src/authority/authority_per_epoch_store.rs`
(EndOfPublish V2 processing, deferred close, epoch-keyed digest slice),
`crates/ika-core/src/epoch_tasks/handoff_signature_sender.rs`,
`crates/ika-core/src/epoch_tasks/joiner_bootstrap_verifier.rs`,
`crates/ika-node/src/lib.rs` (bootstrap at epoch start +
prepare-then-start barrier), `crates/ika-core/src/dwallet_mpc/mpc_manager.rs`
(`adopt_cert_verified_keys`).

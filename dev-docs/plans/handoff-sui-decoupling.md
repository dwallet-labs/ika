# Plan: decoupling the cross-epoch handoff from Sui

Status: proposed — design only, not started (2026-06-15). No stage is
greenlit for implementation; this records the coupling map, the staged
options, and the one architectural decision the effort hinges on.

Read the handoff spec first (`../specs/handoff.md`): this plan assumes
its model (per-epoch attestation, EndOfPublish V2, certificate, joiner
bootstrap, prepare-then-start barrier).

## Why

The handoff certificate is the off-chain replacement for the removed
on-chain consensus vote on network-key outputs. The cryptographic core
(`crates/ika-core/src/handoff_cert.rs`, `crates/ika-types/src/handoff.rs`)
is already Sui-clean — it is pure signing, aggregation, and verification
over an attestation. The coupling to Sui lives entirely in the *wiring*
around that core: identity of the artifacts, the trust root for signers,
the network-key state feed, and the emission trigger. The goal is to
move the validator-side handoff path off chain reads so the MPC/protocol
layer stops depending on Sui object polling for steady-state operation.

## Coupling map (where Sui actually enters)

The crypto core leaks Sui through exactly one type; everything else is
in the surrounding tasks.

| Layer | Where | What Sui supplies | Hardness |
|---|---|---|---|
| Artifact identity | `handoff.rs:33,36` — `HandoffItemKey::{NetworkDkgOutput,NetworkReconfigurationOutput}{ key_id: ObjectID }` | A network key's identity is its Sui object id | Type-only, but wire-frozen |
| Trust root (signers) | `sui_connector/pubkey_provider_updater.rs:82` `fetch_previous_committee_consensus_pubkeys`, `:128` `fetch_previous_committee` | *Who* the signing committee is and their Ed25519 consensus keys, via `get_system_inner` + `get_validators_info_by_ids` → `StakingPool.validator_info` | Fundamental |
| State / liveness | `sui_connector/sui_syncer.rs:716` `sync_dwallet_network_keys` (5s poll → `network_keys_receiver`) | Which keys are reconfiguration-complete; the DKG output bytes used to hydrate digests at signing | Medium |
| Emission trigger | EndOfPublish gate (`all_network_encryption_keys_reconfiguration_completed`, read from the coordinator object) | When the handoff is emitted | Medium |
| v3→v4 migration | `sui_syncer.rs:818-877` | Full output blobs for keys whose DKG/last reconfiguration ran under v3 | Temporary, self-removing |

What is already Sui-free: the certificate fetch on joiner bootstrap is
P2P, not a chain read (`epoch_tasks/joiner_bootstrap_verifier.rs`); and
steady-state key adoption reads the cert from the local perpetual store,
not chain (`dwallet_mpc/mpc_manager.rs:730` `adopt_cert_verified_keys`).

## The decision this effort hinges on: the trust root

The handoff cert proves *"a stake-quorum of committee E signed this
attestation."* It does **not** establish *who committee E is or what
their signing keys are* — that fact is read from Sui, for both paths:

- True joiner: `fetch_previous_committee` + `fetch_previous_committee_consensus_pubkeys`.
- Continuing validator: `committee_store` ← the reconfiguration handler
  ← `epoch_start_state` ← chain.

The current design endorses this on purpose. The handoff verifies
against the prior committee *one hop only*, and the spec states the prior
committee's trust root is Sui, not an earlier cert — chaining certs back
to genesis was deliberately rejected as needless complexity.

So "decouple the handoff from Sui" forces a choice:

- **Keep Sui as the committee-identity oracle.** Then the trust root
  stays on chain by design, and only the state/liveness/identity layers
  are removable. This is the bounded, lower-risk reading.
- **Make the cert chain self-anchoring.** Each epoch's attestation would
  have to carry the *next* committee's Ed25519 consensus pubkeys (today
  it commits only to the next committee's BLS membership *hash* —
  `handoff_cert.rs:82` `hash_next_committee_pubkey_set`), so epoch E's
  cert is verifiable from data carried in E-1's cert, walked back to a
  trusted genesis committee. This **reverses the one-hop decision** and
  eventually implies removing network-key/committee state from Move.

Everything below the trust root can be done without that reversal.

## Staged options

Presented in priority order. The content-derived identity is the primary
work; the network-key-poll change is largely a migration artifact; the
self-anchoring trust root is conditional on a bigger ambition.

### Primary — content-derived network-key identity

Make `NetworkKeyId([u8; 32]) = Blake2b256(versioned_network_dkg_output)`
*the* identity of a network key everywhere above the Sui connector,
replacing `HandoffItemKey`'s `key_id: ObjectID`. It is curve-agnostic,
self-verifying (anyone recomputes it from the DKG output they hold), and
invariant across reconfiguration — the DKG public output is the one-time
stable value; reconfiguration changes shares, not it — and it is
byte-identical across the committee, so every validator derives the same
id.

Two things to design, not hand-wave:

1. **The pre-DKG gap.** Before DKG completes there is no output to hash,
   so the id does not exist yet. Use a separate `NetworkKeyRequestId`
   for the request phase, content-derived from the triggering event (the
   way `SessionIdentifier` at `messages_dwallet_mpc.rs` is keccak256 of a
   Merlin transcript). Bind request→key when DKG completes. Do not try to
   span both phases with one id.
2. **Blast radius + the Move/SDK constraint.** ObjectID is the key for
   `HandoffItemKey`, `network_reconfiguration_output_digest_by_epoch_and_key:
   DBMap<(EpochId, ObjectID), _>`, `network_keys_receiver:
   HashMap<ObjectID, _>`, and `adopt_cert_verified_keys`. SDK clients and
   Move still index keys by ObjectID, and Move is out of scope. So the
   shape is: `NetworkKeyId` is the protocol-internal identity everywhere
   above the Sui connector; ObjectID survives only as the chain handle,
   translated at the connector boundary (one `ObjectID ↔ NetworkKeyId`
   map maintained where chain I/O happens).

Changing `HandoffItemKey` is a **breaking attestation wire change** — the
BCS variant tags are pinned by `handoff.rs` tests precisely because
reordering/altering them forks the committee — so it needs a coordinated
network-wide upgrade.

### Minor — replace the network-key chain poll with a tracker

The 5s `get_dwallet_mpc_network_keys` poll (`sui_syncer.rs:777`) feeds
`network_keys_receiver`, consumed by `handoff_signature_sender.rs:153`
`snapshot_ready_for_signing` and `:192`
`hydrate_protocol_output_digests_from_chain`. A network-key state tracker
could replace it, fed by (1) the handoff cert as the epoch-boundary
snapshot, (2) Sui *events* for mid-epoch transitions (request /
completion / rejection events already exist on the coordinator), (3)
local MPC outputs for own completions.

Why this is minor, not a real decoupling: a key's `state` (e.g.
`NetworkReconfigurationCompleted`) is structurally a chain/consensus fact
— reconfiguration is requested by a Move event and completed by writing
back to Move; "all keys reconfiguration-complete" is shared state, not
locally derivable. So the tracker converts *polling → event
subscription* but still consumes Sui events; it does not remove Sui.

Note the two chain reads in `sync_dwallet_network_keys` have different
lifetimes: the **full blob read** (`sui_syncer.rs:819`/`:852`, the
`key_blobs_already_cached` / `dkg_in_handoff` branch) is already
v3→v4-migration-only and becomes dead once every key has reconfigured
under v4; the **lightweight metadata/state poll** above runs in
steady-state v4 too. The genuinely-removable-without-Move chain read is
therefore essentially just the migration blob read — which is what makes
this stage low ROI. It does, as a side effect, fix the fullnode-freshness
liveness coupling (see findings).

#### v3→v4 migration-scaffolding cleanup checklist

The migration blob read does NOT delete itself — it becomes a dead branch
that must be removed by hand once the trigger condition holds. The set is
five coupled `TODO(v3->v4 migration)` markers (greppable:
`grep -rn "TODO(v3->v4 migration)" crates`). Remove together — the
mpc_manager guards explicitly depend on the syncer chain-import being
gone.

- **Trigger:** every network key is in the off-chain handoff plane (the
  syncer never takes the `key_blobs_already_cached`-false fallback for any
  key). Worth making observable (log/metric when the last pre-v4 key
  migrates) rather than relying on memory.
- `sui_syncer.rs:819` + `:852` — delete the `key_blobs_already_cached`
  blob-read branch; collapse `chain_fetched` to the unconditional
  `off_chain_on` synthesize-empty fast path (anchor removal).
- `mpc_manager.rs:966` — tighten cert-less adoption of a *reconfigured*
  key to reject rather than blindly adopt from chain.
- `mpc_manager.rs:973` — remove the transiently-empty-overlay downgrade
  guard.
- `mpc_manager.rs:2081` — remove the `off_chain_validator_metadata_enabled()`
  gate on DKG mirroring (always mirror).
- **NOT in scope** (permanent guards, not migration scaffolding, untagged):
  `dwallet_mpc_service.rs:941` (internal-presign history-replay guard) and
  `reconfiguration.rs:79` (fail-loud partial-map check in the v3-callable
  reconfig path).

Tracking issue:
[dwallet-labs/ika#1751](https://github.com/dwallet-labs/ika/issues/1751).

### Conditional — self-anchoring trust root

Only if the second decision branch above is chosen (full Sui
independence). Today the attestation carries only
`next_committee_pubkey_set_hash` (`handoff_cert.rs:82`) — a binding to
the next committee, not the material to verify *its* cert. This stage has
epoch E's cert carry the full next-committee descriptor (each member's
BLS AuthorityName + stake + Ed25519 consensus pubkey + the
quorum/validity thresholds), so verification chains inductively from a
trusted genesis committee forward, each cert authenticated by the keys
the previous cert delivered. No RPC read of committee identity.

This **reverses the one-hop decision**: one hop works *because* it leans
on chain as the anchor; removing the chain anchor means needing the whole
cert chain (or a trusted recent checkpoint) to walk.

Critical caveat on value: this changes committee *authentication*
(trustless verification via the cert chain), NOT committee *selection* —
Sui still elects the committee (top-N by stake, staking pools,
registration are all Move). And ika already trusts Sui for consensus
ordering (Mysticeti routes the MPC messages and checkpoints). If you
already trust Sui to order your messages, trustless committee
verification is a small marginal trust gain. It pays off only as part of
making ika eventually not depend on Sui at all; as incremental hardening
on a Sui-ordered network it is high cost for low marginal gain.

## Secondary review findings (independent of decoupling)

- **One-sided epoch guard in joiner bootstrap.**
  `fetch_previous_committee` guards `on_chain_epoch == expected_prior_epoch + 1`
  (`pubkey_provider_updater.rs:138`), but
  `fetch_previous_committee_consensus_pubkeys` (`:82`) does a *separate*
  `get_system_inner()` with no epoch guard. If the chain advances an
  epoch between the two reads, a joiner could pair committee-E membership
  with committee-(E+1) consensus keys. Low probability; fix by reading
  one `system_inner` snapshot and deriving both from it.
- **Signing liveness bounded by fullnode freshness.**
  `snapshot_ready_for_signing` treats an empty/stale
  `network_keys_receiver` as not-ready, so a lagging fullnode defers
  handoff signing. The network-key tracker (minor stage) removes this
  dependency as a side effect.

## Recommendation

If/when this is greenlit: the **content-derived identity** stage is the
work that matters — it is the real decoupling and the foundation for
anything later. The **network-key-poll** stage is mostly a migration
artifact (the removable chain read already self-removes), so it is low
ROI as standalone decoupling; do it only if its side-effect liveness fix
or the tracker is wanted for its own sake. The **self-anchoring trust
root** should not start without an explicit decision to pursue full Sui
independence and to reverse the endorsed one-hop design. The two
secondary findings are worth fixing independently of any of this.

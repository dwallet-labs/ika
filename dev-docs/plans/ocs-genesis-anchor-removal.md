# OCS: replace the trusted anchor with a genesis-rooted committee chain (plan)

**Status:** implemented — see "Implementation outcome" below for the
deliberate deviations from this plan's removal list.
**Depends on:** the OCS verified-Sui-reads subsystem
([`../specs/ocs-verified-sui-reads.md`](../specs/ocs-verified-sui-reads.md)).

## Implementation outcome

Shipped as planned: the `sui_genesis` config and verified blob loader
(`crates/ika-sui-client/src/genesis.rs`), the `SuiCheckpointArchive`
verified fallback with per-chain public defaults, the genesis-rooted
`resolve_bootstrap_plan`, and the deletion of the operator-pinned anchor
(`sui_trusted_anchor`, `compiled_in_trusted_anchor()`,
`verify_anchor_summary()`, `CommitteeBootstrap::EndOfEpoch`).

Deliberate deviations from the "removed" list below — all three config
fields were **kept**:

- `sui_unsafe_genesis_committee` stays: swarm/test tooling that boots
  against an externally started Sui localnet can only obtain
  `committee[0]` over RPC (`fetch_genesis_committee`); a genesis blob
  cannot be reconstructed over RPC. `sui_genesis` takes priority
  whenever both are configured, and the unsafe path logs a loud
  not-for-production warning.
- `allow_unverified_committee_fallback` stays: the premise "the Remote
  Store makes every EOP checkpoint available" does not hold on the
  default config — the default archive is the public HTTPS store
  (~30-day retention; full history needs the requester-pays buckets),
  and Devnet/Custom get no default archive at all. A gap that both the
  fullnode and the archive miss still needs the opt-in degraded path.
  Default remains `false` (fail closed with `ProofChainBroken`).
- `auto_reanchor_on_format_change` stays, re-rooted: it wipes persisted
  committee state that no longer deserializes (a Sui bump changing the
  on-disk BCS layout) and re-bootstraps from the genesis blob — the
  genesis-rooted successor of "re-anchor", needed because perpetual
  committee state always wins over the configured genesis seed.

Also deviating: the mainnet/testnet genesis blobs are **not** embedded
in the release; `sui_genesis` is a path-only config today.

## What this changes, in one sentence

Today an OCS node trusts an operator-pinned **end-of-epoch checkpoint digest**
(a weak-subjectivity "anchor") as the root of its Sui-committee chain; this PR
replaces that root with the **Sui genesis blob**, verified against a 32-byte
compiled-in chain identifier, and bootstraps the committee chain genesis→latest
by BLS-verifying every end-of-epoch (EOP) checkpoint — exactly how Sui's own
light client works.

## Why

The anchor is a **weak-subjectivity** trust root: each operator must obtain a
recent trusted EOP digest out-of-band and pin it, and the compiled-in default
(`compiled_in_trusted_anchor()` in `crates/ika-config/src/node.rs`) is a `None`
stub. The pinned digest also only proves the chain *above* the anchor.

Re-rooting at genesis is strictly stronger and simpler:

| | Anchor (today) | Genesis-rooted (this PR) |
|---|---|---|
| Trust root | Recent EOP digest, obtained out-of-band per operator | **Genesis checkpoint** — the same root every Sui full node uses |
| Smallest thing that must be authentic | A digest the operator sources themselves | A **32-byte chain identifier compiled into the binary** (already present, see below) |
| Forgery resistance | Chain above the anchor only | **Full chain from genesis** — no committee can be forged |
| Pruning handling | Needs an unverified-committee fallback when a full node prunes an EOP checkpoint | **Removed** — EOP checkpoints are sourced from a store that retains them |
| Operator UX | Pin a digest; compiled-in default is a stub | Embed the genesis blob in the release; zero operator input on public chains |

It also **closes the deferred chain-identifier trust gap** (below) for free.

## The trust root: chain identifier → genesis blob → committee[0]

`ChainIdentifier` *is* the genesis checkpoint digest
(`crates/ika-types/src/digests.rs:146`: "Representation of a network's
identifier by the genesis checkpoint's digest"), and ika **already hardcodes**
the mainnet/testnet values (`digests.rs:225-249`). Today
`get_chain_identifier()` is fetched over RPC and string-compared to those
constants (`crates/ika-core/src/sui_connector/mod.rs:307-329`) — i.e. the chain
identity is **trusted as the full node claims it**, with no cryptographic check.

This PR turns that into the root of trust:

1. Load the embedded `genesis.blob` (Sui's `Genesis` type), recompute the
   **genesis checkpoint summary digest**.
2. Assert it **equals the compiled-in `ChainIdentifier` constant** for the
   configured chain. (Verify everything — the genesis blob itself is not trusted
   blindly; it is checked against the 32-byte constant.)
3. Only then extract `committee[0]` from the genesis system state.

So the entire trust root reduces to a 32-byte constant in the binary, and the
genesis blob is *verified against it* — no out-of-band digest, no weak
subjectivity.

## The committee chain (unchanged machinery, new first link)

ika **already** uses Sui's `extract_new_committee_info()` and a `+1`-per-step
BLS-verified ratchet (`CommitteeStore::install_next_from_verified_summary` in
`crates/ika-core/src/sui_connector/committee_store.rs`): for each epoch `E`,
fetch the EOP checkpoint of `E`, BLS-verify it against `committee[E]`, assert the
extracted committee's epoch is `E+1`, install it. This is identical to
`sui-light-client::check_and_sync_checkpoints`.

**The ratchet does not change.** What changes is the *first link*: instead of
seeding the head from a digest-verified anchor mid-chain, we seed `committee[0]`
from genesis and ratchet from there. The live-update machinery
(`CommitteeFollower` summary stream, the direct-node `IkaCheckpointPusher`) is
untouched and keeps the chain current after backfill reaches the live epoch.

**"Verify everything, trust nothing" — including the enumeration.** The EOP
checkpoints are enumerated by an `epochs.json` (a list of EOP sequence numbers).
This list is an **untrusted hint**: a malicious source can omit, reorder, or
duplicate entries, but the `next.epoch == head+1` monotonicity assert +
contiguity + per-EOP BLS verify catch it. Worst case is a *stall* (missing
tail), never adoption of a false committee.

## Sourcing EOP checkpoints: relay primary, Sui Remote Store as verified fallback

Every byte below is BLS-verified against the committee chain regardless of where
it came from, so the source is purely an availability concern.

**Primary**
- **Direct node** (`sui-state-direct`): its own Sui full node over gRPC; it
  retains EOP checkpoints in `sui_end_of_epoch_*` and serves them to peers via
  `RetainedFullnodeTransport`
  (`crates/ika-core/src/sui_connector/retained_transport.rs`).
- **Peer-only / mirrored node**: the relay — a direct node's
  `RetainedFullnodeTransport`. **`RetainedFullnodeTransport` is kept**, because
  it is what lets an air-gapped peer-only validator (no outbound internet, only
  the p2p mesh) obtain its committee chain.

**Fallback — Sui Remote Store (two tiers; see the format note below)**

| Need | Source |
|---|---|
| Recent checkpoints (≤ 30 days) | `https://checkpoints.{mainnet,testnet}.sui.io` (free HTTPS; **30-day retention only**) |
| Full genesis→latest EOP chain (cold bootstrap) | the **requester-pays** buckets `gs://mysten-{mainnet,testnet}-checkpoints-use4` (or the S3 mirror), or a self-hosted Remote Store |

Note the correction to a common misconception: the public **HTTPS** endpoints
retain only the most recent **30 days**, not all EOP checkpoints since genesis.
Full history (including every EOP checkpoint) lives in the requester-pays GCS
buckets. A cold genesis bootstrap that cannot use the relay must therefore reach
the full-history bucket; for most nodes the relay + a non-pruned local full node
covers it.

**Format (verified against the pinned Sui `mainnet-v1.73.2`).** The store layout
the light-client reader expects is `{seq}.binpb.zst` (zstd-compressed protobuf
`Checkpoint`) plus a root `epochs.json`
(`crates/sui-storage/src/object_store/util.rs`: `fetch_checkpoint` reads
`{seq}.binpb.zst`; `end_of_epoch_data` reads `epochs.json`). A Sui full node's
`data-ingestion-dir` writes the **same** `{seq}.binpb.zst`
(`sui-core/.../checkpoint_executor/data_ingestion_handler.rs:store_checkpoint_locally`)
— it just doesn't emit `epochs.json`. (Older docs mention a legacy `{seq}.chk`
BCS format from a deprecated pipeline; the pinned version does not use it. **A
Phase-0 spike confirms the byte format empirically before we build on it.**)

## Localnet

Localnet has no public archive, but needs none:

1. ika's test cluster **already** enables a local checkpoint store —
   `crates/ika-cluster-test/src/cluster.rs` passes `.with_data_ingestion_dir(...)`
   to the in-process Sui, so the local node already writes `{seq}.binpb.zst`.
2. The only missing piece is `epochs.json`. Generate it from the live full node
   by enumerating `last_checkpoint_of_epoch(0..current)` — an **existing**
   transport method (`crates/ika-sui-client/src/transport.rs`) — and writing the
   JSON into the ingestion dir.
3. Point the OCS archive reader at `file://<ingestion-dir>`. This exercises the
   **exact production reader path** (zstd + protobuf decode), not a mock.

Default localnet bootstrap reads EOP from the live local full node over the
existing gRPC transport (a short localnet never prunes); the `file://` store is
used by at least one integration test so the archive reader path has real
coverage.

Required deps are already in the workspace: `object_store` v0.13 (aws/gcp/azure/
http), `sui-storage`, `prost`, `zstd`; `ika-archival` already uses
`sui_storage::object_store`.

## What's removed / rewired / kept / added

**Removed**
- `SuiConnectorConfig.sui_trusted_anchor` + `compiled_in_trusted_anchor()`
  (`ika-config/src/node.rs`)
- `verify_anchor_summary()` digest gate (`sui_connector/setup.rs`) and the
  `CommitteeBootstrap::EndOfEpoch` digest path (`committee_store.rs`)
- the unverified-committee fallback in the ratchet and its
  `allow_unverified_committee_fallback` flag — the Remote Store makes every EOP
  checkpoint available, so the degraded-trust path is dead
- any `auto_reanchor_on_format_change` re-anchoring logic (no anchor to re-anchor)
- the validator `has_anchor` boot gate (`ika-node/src/lib.rs`) → genesis presence

**Rewired**
- `resolve_bootstrap_plan()` (`setup.rs`): perpetual-state-wins → else **genesis
  + backfill** (drop the anchor / unsafe-genesis branches)
- `has_anchor` 4-way OR (`ika-node/src/lib.rs`) → `has_genesis`
- chain-identifier check (`sui_connector/mod.rs:307-329`): RPC string-compare →
  recompute genesis digest and assert == compiled-in `ChainIdentifier`
- EOP-summary retention (`verified_state_cache.rs` `eop_retention_floor`): floor
  at **genesis** (keep all EOP summaries since genesis — ~one small summary per
  epoch, a few MB at mainnet scale)

**Kept**
- `extract_new_committee_info`, `install_next_from_verified_summary`, the ratchet
  loop, `CommitteeFollower`, `IkaCheckpointPusher`, **`RetainedFullnodeTransport`**
  (relay-served EOP for air-gapped peers)

**Added**
- `sui_genesis` config (a `genesis-file-location` path mirroring Sui's `genesis:`),
  with mainnet/testnet genesis **embedded in the release** and a path override for
  private nets
- a `SuiCheckpointArchive` source over `object_store` (enumerate `epochs.json`,
  fetch `{seq}.binpb.zst`), with per-chain default fallback URLs/buckets
- a genesis→latest **EOP backfill** routine driving the existing
  `install_next_from_verified_summary`; **block-but-resumable** (boot waits for the
  chain to reach the live epoch; a restart resumes from the persisted head)
- a localnet `epochs.json` generator (enumerate `last_checkpoint_of_epoch`)

## Phased implementation

0. **Format spike** — run the test cluster, confirm the ingestion dir contains
   `{seq}.binpb.zst` and that `sui-storage`'s reader decodes it; confirm the
   genesis blob's recomputed digest equals the compiled-in `ChainIdentifier`.
   This validates the two load-bearing assumptions before any code is built on
   them.
1. **Genesis config + loader** — `sui_genesis` field; load `committee[0]`; verify
   the genesis digest against the compiled-in chain identifier. Unit-tested
   against a real `genesis.blob` fixture.
2. **Archive client** — `SuiCheckpointArchive` (enumerate + fetch + decode) over
   `object_store`; per-chain default URLs/buckets. Unit-tested against a local
   filesystem store fixture.
3. **Backfill** — genesis→latest over `install_next_from_verified_summary`;
   resumable from the persisted head.
4. **Bootstrap switchover** — rewire `resolve_bootstrap_plan` + `has_anchor`→
   `has_genesis` + the chain-id check; delete the anchor paths. The load-bearing
   commit.
5. **Recent fallback** — wire the archive behind the read path for pruned /
   ≤30-day checkpoints.
6. **Localnet** — genesis blob from the swarm's local Sui; `epochs.json`
   generator; `file://` store wired into the test harness.
7. **Cleanup + docs** — delete dead anchor config/code; update
   `../specs/ocs-verified-sui-reads.md` (Bootstrap/Ratchet, Residuals — drop
   weak-subjectivity and the `compiled_in_trusted_anchor` residual) and the
   `node.rs` config docs.
8. **Tests** — woven throughout (see below).

## Security analysis

- **Trusting `epochs.json` for enumeration is safe** — omission/reorder/dup is
  caught by epoch monotonicity + contiguity + per-EOP BLS verify; worst case a
  stall, never a forged chain.
- **Genesis authenticity = a 32-byte compiled-in constant** — the genesis blob is
  verified against the hardcoded `ChainIdentifier`; an attacker who swaps the blob
  is caught at digest comparison.
- **Liveness / DoS** — genesis→current is longer than anchor→current (one BLS
  verify + a small download per epoch). One-time and persisted; backfill must be
  bounded, parallelized, and resumable so a fresh mainnet boot is minutes, not a
  wedge. (Flag for review.)
- **External dependency** — archive bootstrap needs the node to reach the store
  (or a mirror). Air-gapped peer-only nodes keep the relay-served EOP path
  (`RetainedFullnodeTransport`), so this PR does not regress the air-gapped case.

## Testing

- **Unit**: genesis.blob → `committee[0]` + chain-id digest check; archive
  enumerate/decode against a `file://` fixture; chain verify genesis→N over a
  synthetic committee sequence.
- **Adversarial unit (test-testing)**: inject a forged `next_epoch_committee` and
  a skipped EOP into the archive fixture; assert the BLS / epoch-monotonicity
  checks **reject** (evidence in logs), then revert. This is the real proof the
  re-rooting is sound — see [`../playbooks/test-testing.md`](../playbooks/test-testing.md).
- **Localnet integration**: boot a peer-only validator with **no anchor**, only
  `sui_genesis` + a local EOP source; cross several epochs; assert it ratchets
  `committee[0] → committee[N]` from genesis. Adapt the existing
  `crates/ika-test-cluster/tests/ocs_verifier.rs` suite (remove anchor seeding).
- **Archive-path coverage**: one integration test points the reader at a
  `file://` ingestion store so the production zstd+proto reader path runs on
  localnet.

## Decisions (locked) and open items

**Locked**
- Branch off `dev` (#1744 is merged).
- Trust artifact: the **full Sui `genesis.blob`**, embedded for mainnet/testnet,
  path-override for private nets — verified against the compiled-in chain
  identifier.
- Backfill is **block-but-resumable**.
- **Keep `RetainedFullnodeTransport`**; the Sui Remote Store is a **verified
  fallback**, not the primary source.

**Open**
- Backfill performance bound (parallelism, resume granularity) — settle during
  Phase 3 against a real mainnet-scale epoch count.
- Whether direct nodes still need to *retain* EOP once the full-history bucket
  exists, or can re-fetch on demand — a follow-up simplification, explicitly out
  of scope here (it would trade the air-gapped guarantee for less code).

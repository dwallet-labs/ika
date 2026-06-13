# OCS verified Sui reads (object-checkpoint-state)

Status: active for nodes that opt in with a Sui trust anchor (the
"new-style" `sui-data-source` config). The opt-in is a NODE choice, not
an ika protocol version: transport selection keys off config SHAPE so a
protocol flag can never halt running validators en masse at an upgrade
boundary. Requires the upstream Sui chain to run protocol **v122+** with
`include_checkpoint_artifacts_digest_in_summary` — without the artifacts
digest in the checkpoint summary there is nothing to prove against, and
startup refuses (`probe_artifacts_digest`). Nodes without an anchor stay
on the legacy JSON-RPC read path.

## Problem

A validator needs Sui state (the dWallet coordinator, the system
object, validator-set and session-event bags) to run MPC. Reading it by
trusting a fullnode's word means trusting whoever serves the read. OCS
lets a node read Sui state through an **untrusted** relay (a peer, or a
fullnode) and verify every byte against the Sui committee's own
signature — so the relayer can withhold or delay data, but can never
forge it. This unlocks **peer-only validators**: nodes with no direct
Sui uplink that read everything over the p2p relay.

## Trust chain

A verified read returns a `VerifiedObject { object, source_checkpoint_seq }`
only after a three-link proof. The relay supplies `(object, summary,
OCSInclusionProof, claimed_head)`; nothing in that tuple is trusted
until it passes:

1. **Committee BLS** — the `CertifiedCheckpointSummary` is verified
   against the Sui committee for *its own* `epoch()` (aggregate
   signature over the intent-scoped summary, plus epoch-binding). The
   committee comes from the local `CommitteeStore`; `verify_summary` is
   the single chokepoint, so reader, push handler, and snapshot verifier
   cannot drift apart. Missing committee → retriable; bad signature →
   terminal.
2. **Artifacts-digest binding** — the proof's `tree_root` is believed
   only because `from_artifact_digests(vec![tree_root])` reproduces the
   `checkpoint_artifacts_digest` the committee signed. A fabricated tree
   with a matching object fails here.
3. **Merkle inclusion** — `object.compute_object_reference()`
   `(ObjectID, version, ObjectDigest)` is proven to be a leaf under
   `tree_root`. Because `ObjectDigest` hashes the whole `ObjectInner`
   (data, **owner**, type, contents), the proof binds the FULL object,
   not just id+version.

The **reader owns the target**: it always builds `ProofTarget` from the
object it holds, so the relay can never point a valid proof at a
different object than the one returned. For batch and bag reads each
distinct checkpoint is BLS-verified once and reused, but every entry
still gets its own inclusion check.

## Node roles and transports

Role is `NodeMode::detect_from_config` (Validator = has `consensus_config`;
Notifier = has `notifier_client_key_pair`; Fullnode = neither) and is
orthogonal to whether OCS is on. Transport is chosen by config shape:

- **Direct validator** — `SuiDataSource::SuiStateDirect { url, serve_mirror }`:
  all Sui I/O over direct gRPC; with `serve_mirror` (default true) it
  also runs the `SuiStateMirror` server, becoming a verified-state
  source for the cluster.
- **Mirrored validator (with fallback)** — `SuiStateMirrored { fallback_grpc_url: Some(url) }`:
  verified reads relayed over p2p; the fallback gRPC is used only for
  the methods that cannot be relayed (tx submission, `get_transaction`)
  and as the bootstrap uplink.
- **Peer-only validator** — `SuiStateMirrored { fallback_grpc_url: None }`:
  no Sui uplink at all; every read, including committee/epoch bootstrap,
  flows over the verified relay. This is the *sole* identifier of the
  peer-only role.
- **Notifier / fullnode** — read gRPC at one endpoint; notifiers are the
  only nodes that submit transactions and always use a direct uplink.

**Config-shape gate** (evaluated at startup, `ika-node` boot):

| `sui-data-source` | `sui-rpc-url` | result |
|---|---|---|
| absent | absent | error: no Sui endpoint |
| absent | present | old-style: validators → legacy JSON-RPC; notifier/fullnode → gRPC at `sui-rpc-url` |
| present | present | new-style wins; info log to drop `sui-rpc-url` |
| present | — | new-style: gRPC + OCS; a **validator** additionally requires a trust anchor |

`has_anchor` is a 4-way OR: persisted committees OR `sui_trusted_anchor`
OR `sui_unsafe_genesis_committee` OR `compiled_in_trusted_anchor(chain)`
(the last returns `None` for every chain today). A new-style validator
without any anchor is rejected — on the gRPC path it has no MPC event
source (no JSON-RPC `query_events`; the verified `BagEventPump` needs
the anchor). `SuiDataSource` must carry `rename_all_fields = "kebab-case"`
so `fallback-grpc-url` is not silently dropped (a dropped field flips a
mirrored validator into peer-only).

## Bootstrap and the committee ratchet

The trust root is a single operator-pinned **end-of-epoch checkpoint
digest** (`sui_trusted_anchor`), or an unsafe genesis committee on
private nets. At boot the fetched anchor summary's recomputed digest
must equal the pinned digest byte-for-byte and be end-of-epoch; from it
the node installs `committee[E+1]` (the anchor epoch's own committee is
never installed — trust flows from the pinned digest, not from holding
`committee[E]`).

**Perpetual state always wins**: once any committee is persisted, the
configured anchor/genesis is ignored on every later boot. Re-anchoring
requires manually clearing the OCS committee tables.

The ratchet advances the trusted head strictly **+1 per step** up to the
relay-claimed current epoch. For each step it fetches the end-of-epoch
checkpoint of epoch `head`, BLS-verifies it against `committee[head]`,
requires `end_of_epoch_data`, and installs the embedded `committee[head+1]`
— the next committee is read out of the *verified* summary, never from a
side fetch. The store is keyed by each committee's own `.epoch`, so the
relay never chooses the install key. Only one ratchet runs at a time
(concurrent callers coalesce).

If the end-of-epoch checkpoint has been pruned upstream (`NotFound`), the
behavior forks on `allow_unverified_committee_fallback` (default
**false**): false → terminal `ProofChainBroken` (operator must re-anchor
nearer the head and clear tables); true → a degraded direct
`get_committee(head+1)` fetch, gated by an explicit `epoch == head + 1`
check (`FallbackEpochMismatch` otherwise), logged security-critical.

## Freshness and rollback protection

The relay's claimed head is never trusted directly. Every response folds
`claimed_head` into a process-monotonic `observed_upstream_head`
(`fetch_max`); freshness is always measured against that monotone value,
so a relay cannot under-report its head to make a stale proof look
fresh. Per **well-known** object (coordinator, system, versioned inner
children) a version high-water rejects any read below the highest
version already accepted (`StaleVersion`); bag-entry dynamic-field
children are deliberately excluded (short-lived ids). High-water is
recorded only *after* the inclusion proof passes, so an unproven object
can never poison it.

The absolute checkpoint-distance bound (`StaleCheckpoint`) is wired but
**dormant** in production (`freshness_bound = None`). The active
anti-rollback guarantees today are version monotonicity and the
cache-first staleness tripwire.

**Eclipse residual (known non-guarantee):** the monotone defenses are
relative, not absolute. A fresh node whose only relay is malicious can
be pinned to an internally-consistent OLD-but-validly-proven snapshot
indefinitely: `observed_upstream_head` and the high-water both start
empty, so the stale-but-real view sets the floor rather than tripping a
guard. The relay still cannot forge state or roll back below what it has
already served this process. Closing this requires an enabled freshness
bound and/or multiple independent relays.

## Bag walks and the event pump

The MPC engine's event source on the gRPC path is the `BagEventPump`,
which walks the coordinator's `session_events` bags (≈20 Hz). A bag's
children are dynamic-field objects; the relay enumerates them with an
**untrusted** `list_dynamic_fields` index and serves each child with its
own inclusion proof.

An inclusion proof alone only attests that an object existed on-chain —
**not** that it is a child of the requested bag. Each entry is therefore
bound to its bag after the proof: a genuine bag child is owned by the
bag's UID (`Owner::ObjectOwner(bag_id)`), and that owner is inside the
proof-bound `ObjectDigest`, so the reader rejects any entry whose owner
is not the requested bag (`ReaderError::BagMembership`). Without this an
untrusted relay could return a validly-proven dynamic field of a
*different* bag (e.g. replayed session events from another coordinator).

Bag entries get no freshness bound and no high-water (an event can sit
in a bag across many checkpoints). The remaining defenses against a relay
dropping entries are layered:

- **Omission detector** (warn-only, count-only): compares the listed
  count against the authenticated `Bag.size` read from the OCS-verified
  parent state. It fires `bag_omission_suspected` on `listed < expected`
  but never halts — `Bag.size` legitimately drifts mid-walk, so only
  *persistent* suspicion is actionable. It is count-only (cannot tell
  *which* entries are missing) and is disabled on direct nodes (where the
  bag is trusted-local but `Bag.size` lags cache-first).
- **Downstream session-id dedup**: the MPC engine keys sessions by
  `SessionIdentifier`, skips already-completed sessions via the
  perpetual store, and treats re-delivery of an in-flight session as a
  no-op. This makes the pump's emit-full-snapshot-every-tick behavior,
  and any spurious/replayed entry that slips past the count check,
  harmless.

## Relay protocol

The relay exposes verified-read RPCs (`VerifiedObject`,
`BatchVerifiedObjects`, `VerifiedBagPage`), committee-ratchet plumbing
(checkpoint summary/full/by-digest, `LastCheckpointOfEpoch`,
`GetTransactionCheckpoint`, `get_current_epoch`, `get_reference_gas_price`),
and `SubmitTransaction`. `get_committee`, `get_transaction`,
`execute_transaction`, and `list_owned_gas_coins` **cannot** be relayed
(non-Deserializable returns) and must error on the relay surface so
callers fall through to a direct gRPC fallback.

The client (`SuiMirrorPeers::try_peers`) is the failover engine: it
rotates the peer list round-robin but every pass visits all peers,
returns the first success, and demotes failing peers to the back.
Crucially, each per-peer request carries a **30s timeout** — anemo sets
no default outbound timeout and QUIC keep-alives keep an idle-but-hung
peer "connected", so without it one peer that accepts the stream and
never replies would hang every read forever and starve failover. A
timeout counts as a peer failure, not a `NotFound`.

`NotFound` is returned only when at least one peer was reached AND every
reached peer returned `NotFound` — any non-`NotFound` error or any
timeout downgrades the verdict to a network failure. The committee
ratchet keys its "data really doesn't exist → consider fallback"
decision on exactly this distinction, so the rule must hold.

Peer-only submit (`execute_transaction` over the relay) verifies the
relay echoed the transaction's deterministic digest and that it is
committed under a BLS-signed checkpoint, but does **not** verify the
effects bytes. This is acceptable only because no live caller reaches it
(writes are notifier-gated, and notifiers run direct gRPC).

## The push/cache fast path (optimization)

Direct validators run a checkpoint pusher that builds inclusion proofs
for Ika-modified objects and fans them to peers; receivers verify every
pushed entry against their own `CommitteeStore` before caching, and
direct nodes serve verified reads cache-first (with the staleness
tripwire above falling through to the network when the cache lags).
**Pushed/cached state is never trusted on the basis of the push** — the
cache only ever holds committee-verified state, which is why a cache hit
may skip re-running the proof.

Known reachability gap at HEAD: the push handler and snapshot provider
are installed only on direct `serve_mirror` nodes, but the doc-comments
name *mirrored* nodes as the intended receivers; mirrored nodes build no
handler and read with `cache_first = false`. So pushes are accepted only
by other direct nodes (which already self-populate), and the push /
gap-recovery path is effectively dead for its stated consumer.

## Key invariants

1. A returned `VerifiedObject` is committee-BLS-attested at the byte
   level: id, version, owner, type, and contents are all proven for
   `source_checkpoint_seq`. No field of the object ref is left unproven,
   and the reader — not the relay — owns the proof target.
2. The trusted head epoch is monotone and advances strictly +1; on the
   verified path `committee[head+1]` is only ever derived from a
   BLS-verified end-of-epoch summary signed by `committee[head]`. The
   store is keyed by each committee's own epoch.
3. Trust is rooted in a single operator-pinned end-of-epoch digest;
   persisted committee state always overrides a reconfigured anchor.
4. Freshness is measured against a process-monotonic observed head,
   never the relay's per-response claim; per-object version high-water is
   monotone and recorded only after proof success.
5. A bag-page entry must be owned by the requested bag
   (`Owner::ObjectOwner(bag_id)`); the inclusion proof alone does not
   establish bag membership. Omission/replay past that are backstopped by
   the count-only detector and downstream session-id dedup, not by the
   proof.
6. The relay is fully untrusted; only proofs are trusted. Un-relayable
   methods must error (never silently return data), and `NotFound` is
   produced only when every reached peer agreed.
7. Transport selection is a function of config shape, never of chain
   state — OCS opt-in is a node-level trust-anchor choice, not a
   protocol feature.
8. Cached/pushed state is committee-verified before it enters the cache;
   the cache never holds unverified state.

## Residuals and known gaps

- **Eclipse on a fresh node** (above): a lone malicious relay can pin a
  cold-started node to a stale-but-real snapshot; mitigations
  (freshness bound, multiple relays) are not active on the per-read
  path today.
- **`compiled_in_trusted_anchor`** returns `None` for all chains; when
  release tooling fills it, every old-style config on that chain would
  gain `has_anchor` and trip the anchor-without-data-source guard —
  the compiled-in contribution should be gated on `sui-data-source`
  being present.
- **Peer-only initial ratchet retries forever** on permanent errors
  (a misconfigured anchor that cannot chain to the current epoch),
  blocking boot with only warn-level logs and no deadline.
- The verified ratchet path relies on the structural uniqueness of an
  epoch's end-of-epoch checkpoint for `next.epoch == head + 1`; the
  explicit assertion exists only on the unverified fallback path.

Code anchors: `crates/ika-core/src/sui_connector/` — `verified_reader.rs`
(verification, freshness/high-water, bag-membership binding),
`committee_store.rs` (committee trust + ratchet install),
`ocs_verifier.rs` (ratchet loop + fallback), `setup.rs` (bootstrap plan,
anchor digest gate, stack wiring), `bag_event_pump.rs` (event pump +
omission detector), `push_worker.rs` / `push_handler.rs` /
`verified_state_cache.rs` (push/cache fast path);
`crates/ika-network/src/sui_state_mirror/` (relay client/server) and
`proof_provider.rs` (serving side); `crates/ika-node/src/lib.rs`
(role/transport gate, peer-only boot); `crates/ika-config/src/node.rs`
(`SuiConnectorConfig`, `SuiDataSource`, anchor fields); proof primitives
in the pinned `sui-light-client` (`proof/base.rs`, `proof/ocs.rs`).

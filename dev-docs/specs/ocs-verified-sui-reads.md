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
   the single chokepoint, so the reader and the direct-side checkpoint
   folder cannot drift apart. Missing committee → retriable; bad signature
   → terminal.
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

## Object-graph binding (every read rooted in a pinned object)

The trust chain proves a *single* object — but the relay still chooses WHICH object
to serve. Safety therefore also requires that every object a node reads is reachable
from one of the two **config-pinned** roots (`IkaNetworkConfig.objects.{ika_system_object_id,
ika_dwallet_coordinator_object_id}`) by a chain of *bound* hops. Each hop is one of:

- **(a) DERIVED** — the child id is computed locally from the parent id
  (`derive_dynamic_field_id` / a versioned child id / an ObjectField `Wrapper<K>` id).
  The relay can't substitute because the reader chose the id.
- **(b) OWNER-BOUND** — the child is proven, then its proof-bound `Owner` is checked
  `== parent id` (or the derived wrapper id), else `ReaderError::DynamicFieldMembership`.
- **(c) UNBOUND** — the child id is taken from an untrusted `list_dynamic_fields` and
  read without deriving or owner-checking it: a relay chooses the id → substitution risk.

```
       PINNED ROOTS (config, trusted)
       ika_system_object_id              ika_dwallet_coordinator_object_id
             │ (a) derived (versioned child id)     │ (a) derived
             ▼                                       ▼
       SystemInner                              DWalletCoordinatorInner
        │  │  │                                      │ (a) inline
        │  │  │ (a) inline                           ▼
        │  │  └─ active / next / previous committee  session_events bags
        │  │      → epoch committee + QUORUM bound        │ (b) owner-bound
        │  │                                              ▼
        │  └─ validators: ObjectTable               session-event children ✓
        │        │ (b) owner-bound
        │        ▼
        │     StakingPools ✓
        │
        └─ pending_active_set: ExtendedField
                 │ (b) owner-bound  (child Owner == wrapper UID; ocs-binding-1)
                 ▼
              PendingActiveSet ✓
```

Every hop is now (a) or (b): the versioned `*Inner` children are **derived**; the
active/next/previous committees and the quorum are **inline** in the proven `SystemInner`
bytes; and the validator `StakingPool`s, the `session_events` entries, AND the
`pending_active_set` `ExtendedField` value are **owner-bound**. The last was the one gap
(`get_extended_field_value_bcs` listed the wrapper's single field and read `.first()`
without an owner-check) — closed by `ocs-binding-1` via the shared
`transport::dynamic_field_child_owned_by` (the same primitive `verified_dynamic_fields_page` uses):
the proof-bound child `Owner` must equal the wrapper id.

**Type-correctness follows from id-binding.** The inclusion proof binds the object's
Move type (it is inside the proof-bound `ObjectDigest`), so a correctly-bound id yields a
correctly-typed object — the consumer does not *separately* assert the type
(`bcs::from_bytes` is structural); only the event path re-checks the `StructTag` against
the pinned ika package. With every hop now bound, a same-layout wrong object can't be
substituted at a relay-chosen id either; that residual was closed by the same
owner-binding, not by a separate type assert.

## Node roles and transports

How the roles connect to Sui and to each other:

```
                     SUI  (L1)
          Sui validators ──▶ checkpoints (BLS-signed)
                     │
                     │  a Sui FULL NODE follows the chain / serves RPC
                     ▼
             ┌──────────────────┐       submit txns        ┌──────────────────┐
             │   SUI FULL NODE   │ ◀──── (ika checkpoints ─ │   NOTIFIER        │
             │   (gRPC / RPC)    │        write-back)       │   (direct uplink) │
             └────────▲──────────┘                          └──────────────────┘
                      │
         gRPC reads ──┤  direct Sui uplink
        (Sui state)   │  (DIRECT + mirrored-with-fallback only)
                      ▼
             ┌──────────────────────────┐
             │  DIRECT validator         │ ──────┐
             │  • reads Sui over gRPC    │       │  SuiStateMirror relay
             │  • serves SuiStateMirror  │       │  (verified Sui state
             └─────────────┬─────────────┘       │   + changeset stream)
                           │                       ▼
                           │             ┌──────────────────────────┐
                           │             │  PEER-ONLY validator      │
                           │             │  • NO Sui uplink          │
                           │             │  • every read via relay   │
                           │             └─────────────┬─────────────┘
                           │                           │
                           └───────────────────────────┘
                     anemo p2p mesh — ALL validators:
                     consensus (Mysticeti) · MPC · trusted-peer discovery
                     (the SuiStateMirror relay rides this mesh)
```

The asymmetry is the point: a **direct** validator reaches Sui two ways — its own
gRPC uplink to a full node, and the p2p mesh — while a **peer-only** validator
reaches Sui *only* through the relay, with every byte verified against the Sui
committee signature (the trust chain above). A **mirrored-with-fallback** validator
is a peer-only reader that additionally keeps a gRPC fallback (used only for the few
reads it does not relay, and as the bootstrap uplink). The notifier always has a
direct uplink — it is the only node that submits transactions back to Sui.

```
        ══▶ PUSH  (source streams / submits, no per-item request)
        ──▶ PULL  (consumer requests each item, on demand)

  SUI full node  ══▶  direct validator   checkpoint-summary subscription  (committee chain)
  SUI full node  ──▶  direct validator   point object reads (get_object)
  notifier       ══▶  SUI full node      submit ika checkpoints (write-back)

  direct (relay) ──▶  peer-only          verified object / bag reads
  direct (relay) ──▶  peer-only          ChangesetPage currency stream (polled)

  validator     ◀══▶  validator          consensus (Mysticeti) + MPC  (mesh broadcast)
```

Read it as: the **committee chain** rides a push (a Sui subscription, on uplinked
nodes); **all verified state** a peer-only node depends on — objects, bags, and the
currency changesets — is pulled over the relay; consensus/MPC are pushed across the
mesh; and the notifier pushes write-back to Sui.

**Push vs pull on these links:**

- **Push** (the source streams / submits without a per-item request):
  - *Sui → direct validator* — the committee follower **subscribes** to Sui's
    checkpoint-*summary* stream (`subscribe_checkpoint_summaries`); Sui streams each new
    summary, keeping the committee chain current without polling.
  - *Notifier → Sui* — the notifier **submits** (pushes) ika checkpoints back to Sui.
  - *Validator ↔ validator* — consensus blocks (Mysticeti) and MPC messages are
    **broadcast** across the p2p mesh.
- **Pull** (the consumer requests, on demand) — **the entire relay is pull**:
  - *Peer-only → relay* — every verified read is request/response
    (`verified_object` / `batch_verified_objects` / `verified_dynamic_fields_page`). There is **no
    push of verified state**: a direct node's pusher folds into its *own* cache only (the
    earlier push-gossip subsystem was removed).
  - *Changeset currency stream* — **polled** in contiguous pages
    (`ChangesetPageRequest { from_seq, limit }`), never a held-open stream; the
    session-event bag pump likewise lists pages on a tick.
  - *Direct validator → Sui* — point object reads over gRPC (`get_object`).

So the committee chain rides a **push** (a Sui subscription on uplinked nodes), while all
verified state — objects, bags, and the currency changesets a peer-only node depends on —
is **pulled** over the relay.

Role is `NodeMode::detect_from_config` (Validator = has `consensus_config`;
Notifier = has `notifier_client_key_pair`; Fullnode = neither) and is
orthogonal to whether OCS is on. Transport is chosen by config shape:

- **Direct validator** — `SuiDataSource::SuiStateDirect { url, serve_mirror }`:
  all Sui I/O over direct gRPC; with `serve_mirror` (default true) it
  also runs the `SuiStateMirror` server, becoming a verified-state
  source for the cluster.
- **Mirrored validator (with fallback)** — `SuiStateMirrored { fallback_grpc_url: Some(url) }`:
  verified reads relayed over p2p; the fallback gRPC is used only for
  the reads it does not relay (`get_transaction`, `get_committee`,
  `list_owned_gas_coins`) and as the bootstrap uplink.
- **Peer-only validator** — `SuiStateMirrored { fallback_grpc_url: None }`:
  no Sui uplink at all; every read, including committee/epoch bootstrap,
  flows over the verified relay. This is the *sole* identifier of the
  peer-only role. A fresh peer-only node can't dial out to reach the relay,
  so existing validators *dial it inbound* off the on-chain `pending_active_set`
  — see [`trusted-peer-discovery.md`](trusted-peer-discovery.md).
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
anti-rollback guarantees today are version monotonicity, the cache-first
staleness tripwire, and — on mirrored/peer-only nodes — the
**changeset-stream currency gate** (below) — except the two singleton
anchors (`System` / `DWalletCoordinator` inner), which are deliberately
served *through* a tripped tripwire on direct nodes (see *The cache fast
path*) and so rely on version monotonicity alone.

**Changeset-stream currency gate (LIVE on mirrored/peer-only nodes).** An
inclusion proof attests an object at its last-modifying checkpoint M, not
that M is still the latest version. Each mirrored/peer-only node therefore
*pulls* a committee-signed **changeset stream** (paged `ChangesetPage`,
`from_seq`+`limit`) and folds it into a per-id lifecycle index keyed by
last-modifying checkpoint, with enforced contiguity (`+1` advance +
`previous_digest` chaining + id-set gap recovery) so a relay cannot silently
skip a checkpoint where an object changed. It rests on an id-binding
non-inclusion primitive (verify neither neighbor leaf of the proof matches
the target id, so absence cannot be forged for a present object). Every
verified read — `verified_object`, `batch_verified_objects`,
`verified_dynamic_fields_page` — then consults the index as a fourth, read-**blocking**
gate: a read whose anchor predates the object's latest folded modification,
or whose object is `Deleted`/`Wrapped` in the folded range, is rejected
`ReaderError::NotCurrent` (metered `not_current`) even though the proof is
validly signed. `Unknown` anchors (outside the folded/retain window) fall
back to the per-read monotone defenses. The index is bounded by a retain
window (`CHANGESET_RETAIN_WINDOW`, larger than one epoch). Direct nodes do
not run it — their own folder is already a complete in-order fold.

**Eclipse residual (known non-guarantee, NARROWED by the currency gate):**
the monotone defenses are relative, not absolute. A fresh node whose only
relay is malicious can be pinned to an internally-consistent
OLD-but-validly-proven snapshot: `observed_upstream_head` and the high-water
both start empty, so the stale-but-real view sets the floor rather than
tripping a guard. The currency gate raises the bar — a relay must now also
withhold the changeset stream consistently, and contiguity makes a silent
gap detectable — but a relay that withholds the *whole* stream can still
stall a node at a consistent point. The relay still cannot forge state or
roll back below what it has already served this process. Fully closing the
residual requires an enabled freshness bound and/or multiple independent
relays.

## Verified dynamic-field enumeration (`verified_dynamic_fields_page`)

`verified_dynamic_fields_page` is the relay's **generic verified
enumeration** of a parent object's dynamic-field children. Given a parent
`UID` it lists the children via an **untrusted** `list_dynamic_fields`
index and serves each child with its own inclusion proof, paginated
(`parent_id`, `page_size`, `page_token`). It is **not bag-specific** — at
the Sui level a `Bag`, `Table`, `ObjectTable`, `ObjectBag`, and raw
dynamic / dynamic-object fields are *all the same thing*: dynamic fields
hanging off a `UID`. So this one RPC covers every dynamic-field-backed
collection. The verified transport routes the gRPC backend's
`list_dynamic_fields` through it, so every table/bag walk a peer-only node
makes is committee-verified. The response also carries the field **key**
(name type + BCS value) per entry, which the reader needs to bind
dynamic-object-field values (below).

Its primary consumer is the `BagEventPump`, the MPC engine's event source
on the gRPC path, which walks the coordinator's `session_events` bags
(≈20 Hz) — but the RPC itself is collection-agnostic.

An inclusion proof alone only attests that an object existed on-chain —
**not** that it is a child of the requested collection. Each entry is
therefore bound to its collection after the proof, using the entry's
proof-bound owner (the owner is inside the proof-bound `ObjectDigest`).
The binding depends on the collection kind:

- A plain **Bag/Table** (also a raw dynamic field) stores the value inline
  in a `Field<K, V>` owned by the collection UID, so a genuine child's
  owner is `Owner::ObjectOwner(parent_id)`.
- An **ObjectTable/ObjectBag** (also a raw dynamic *object* field) stores
  the value as a separate object pointed to by a `Field<Wrapper<K>, ID>`;
  `list_dynamic_fields` resolves to that wrapped value object, which is
  owned by the `Field` wrapper, not the collection. The genuine child's
  owner is therefore the wrapper id,
  `derive_dynamic_field_id(parent_id, 0x2::dynamic_object_field::Wrapper<K>,
  bcs(key))`. The relay carries the entry's key (name type + BCS value,
  from `list_dynamic_fields`) on the verified dynamic-fields-page response; the reader
  re-derives the wrapper id and matches it against the proven owner. The
  gRPC field visitor reports the *unwrapped* inner key type, so the reader
  re-wraps in `Wrapper<K>` before deriving (the BCS value is identical — a
  single-field `Wrapper` encodes as its inner value).

The reader rejects any entry whose proven owner matches neither
(`ReaderError::DynamicFieldMembership`). The derivation is collision-resistant
against the committee-proven owner, so a relay cannot forge a key that
derives to a foreign object's owner. Without this binding an untrusted
relay could return a validly-proven dynamic field of a *different*
collection (e.g. replayed session events from another coordinator, or a
foreign network-encryption-key object).

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
`BatchVerifiedObjects`, `VerifiedDynamicFieldsPage`), the `ChangesetPage` currency
stream (paged `from_seq`+`limit`; see *Freshness and rollback protection*),
and committee-ratchet plumbing (checkpoint summary/full/by-digest,
`LastCheckpointOfEpoch`, `get_current_epoch`). It serves **reads only** — there is no
`SubmitTransaction`: writes are notifier-gated and the notifier always uses a
direct uplink, so no node submits through the relay (a submit-via-relay surface
would only be an unverified-effects + amplification hazard). Every served read
RPC carries an inflight cap so a byzantine peer can't flood a serving node, and
symmetrically the *consumer* re-bounds each paged/batched response against what
it asked for — `verified_dynamic_fields_page` rejects a page longer than the
requested `page_size` (capped at a hard ceiling), `BatchVerifiedObjects` requires
`results.len() == ids.len()`, and the changeset pump rejects a page longer than
its `limit` — before allocating or verifying, since a byzantine *server* can
ignore its own clamp.
`get_committee` and `get_transaction` are part of the read transport but **not**
relayed: they error on the relay surface so callers fall through to a direct
gRPC fallback. `get_transaction` is *un*-relayable for a hard reason (its
`ExecutedTransaction` return isn't Deserializable); `get_committee` is a routing
choice (the committee comes from the ratchet/anchor).

Two capability sets are deliberately **off the relay-able `SuiTransport` trait
entirely**, so a relay/peer transport doesn't even pretend to offer them:
- **Writing** (`SuiWriter`: `execute_transaction`, `get_reference_gas_price`,
  `list_owned_gas_coins`) — building and submitting transactions. Notifier-gated
  to a direct uplink; a read-only mirrored/peer node has no writer at all.
- **`get_transaction_checkpoint`** — `tx → checkpoint` lookup whose sole user is
  the *direct* proof builder, so it's an inherent `SuiGrpcClient` method.

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

## The cache fast path (sui-state-direct only)

Direct and peer-only nodes run the SAME cryptography but reach it differently — the
verification asymmetry:

```
  DIRECT validator                          PEER-ONLY validator
  ────────────────                          ───────────────────
  fold once (own gRPC) → verify → cache     (no fold, no cache-first)
  cache HIT  → serve, NO re-verify  ◄── asymmetry ──►  EVERY read → verify
  cache MISS / stale → fetch + verify        (committee BLS + Merkle + currency)
  trust root: own gRPC uplink               trust root: committee signature
  ── both: committee ratchet BLS-verified; per-object high-water on every read ──
```

Direct validators run a checkpoint folder (`IkaCheckpointPusher`) that
folds every Ika-modified object of every checkpoint, in order, into a
local verified state cache — building each object's inclusion proof from
the checkpoint's `ModifiedObjectTree`. Direct nodes then serve verified
reads **cache-first** (with the staleness tripwire above falling through
to the network when the cache lags). Because the folder reads from the
node's own authoritative Sui access and folds in order, a cache hit is
the object's current state up to the poll lag, and may skip re-running
the proof.

The two **singleton anchors** — the `System` and `DWalletCoordinator`
inner objects (and their versioned-child inners) — are served from the
folded cache **even when the staleness tripwire trips**.
`verified_anchor_object` prefers the cached snapshot but **bounds its
staleness**: it forces a verified network re-read on a genuine cache
miss *and* at most once per `ANCHOR_REFRESH_INTERVAL` (2 s), serving
cache in between; the per-object version high-water still rejects a
rollback. This bypasses the tripwire so these hot-path anchors don't
reach back on *every* 120 ms tick: under heavy load the pusher's
processed head lags the live head past the tripwire bound, and a
per-tick reach-back (each anchor read is the outer wrapper plus its
versioned-child inner — several fullnode round-trips) slows the pusher
further and latches the tripwire, a self-reinforcing loop that collapses
dwallet throughput. **The TTL bound is essential, not merely an
optimization knob:** a rare singleton like the `System` inner is updated
only at epoch boundaries, so if the pusher *skips* its update (the
defining checkpoint pruned before the lagging pusher folds it; the
singleton is never modified again that epoch to re-fold it) the stale
snapshot would be served *indefinitely* and wedge the epoch — the gate
that drives epoch advance reads the mid-epoch committee through this
anchor (#1736). The 2 s interval keeps the refresh well below the
per-tick rate that latches the loop while bounding staleness to ~2 s.
Ordinary (non-anchor) reads still fall through to the network when the
tripwire trips. Cache-served anchors are counted
`ika_ocs_cache_read_total{outcome="anchor"}`.

The cache is authoritatively populated *only* by the node's own folder —
it does not ingest peer state. Mirrored and peer-only validators have no
such folder; they read with `cache_first = false`, pulling each object
over the relay and re-verifying it per read.

> The committee-attested **currency mechanism** a cached mirror read would
> need is now built and live on the per-read *pull* path (the
> changeset-stream currency gate, under *Freshness and rollback protection*).
> What remains future is the cache-*first* optimization itself — letting
> mirrored/peer-only nodes serve a read from a local fold instead of
> re-pulling every read — see
> [`../plans/ocs-changeset-stream-mirror-currency.md`](../plans/ocs-changeset-stream-mirror-currency.md).

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
5. A bag-page entry must be bound to the requested collection by its
   proof-bound owner: `Owner::ObjectOwner(bag_id)` for a plain Bag/Table,
   or the entry's derived `Field<Wrapper<K>, ID>` wrapper id for an
   ObjectTable/ObjectBag. The inclusion proof alone does not establish
   membership. Omission/replay past that are backstopped by the count-only
   detector and downstream session-id dedup, not by the proof.
6. The relay is fully untrusted; only proofs are trusted. Un-relayable
   methods must error (never silently return data), and `NotFound` is
   produced only when every reached peer agreed.
7. Transport selection is a function of config shape, never of chain
   state — OCS opt-in is a node-level trust-anchor choice, not a
   protocol feature.
8. Cached state is committee-verified before it enters the cache; the
   cache never holds unverified state, and on a direct node it is folded
   only from the node's own authoritative Sui access, never from peers.
9. On mirrored/peer-only nodes a verified read additionally passes a
   committee-attested **currency** gate: an authentic-but-superseded object
   is rejected — a read anchored before the object's latest folded
   modification (or after its deletion/wrapping) returns `NotCurrent`. The
   backing changeset fold is contiguity-enforced, so a skipped modification
   is detectable, not silently dropped.

## Residuals and known gaps

- **Eclipse on a fresh node** (above): a lone malicious relay can pin a
  cold-started node to a stale-but-real snapshot. The changeset-stream
  currency gate (now live on the per-read path) narrows this — the relay
  must withhold the whole stream consistently, and contiguity makes a silent
  gap detectable — but does not fully close it; the absolute mitigations
  (an enabled freshness bound, multiple independent relays) are still not
  active today.
- **`compiled_in_trusted_anchor`** returns `None` for all chains; when
  release tooling fills it, every old-style config on that chain would
  gain `has_anchor` and trip the anchor-without-data-source guard —
  the compiled-in contribution should be gated on `sui-data-source`
  being present.
- The verified ratchet path relies on the structural uniqueness of an
  epoch's end-of-epoch checkpoint for `next.epoch == head + 1`; the
  explicit assertion exists only on the unverified fallback path.

Code anchors: `crates/ika-core/src/sui_connector/` — `verified_reader.rs`
(verification, freshness/high-water, bag-membership binding),
`committee_store.rs` (committee trust + ratchet install),
`ocs_verifier.rs` (ratchet loop + fallback), `setup.rs` (bootstrap plan,
anchor digest gate, stack wiring), `bag_event_pump.rs` (event pump +
omission detector), `push_worker.rs` / `verified_state_cache.rs`
(direct-side checkpoint folder + cache fast path);
`crates/ika-network/src/sui_state_mirror/` (relay client/server) and
`proof_provider.rs` (serving side); `crates/ika-node/src/lib.rs`
(role/transport gate, peer-only boot); `crates/ika-config/src/node.rs`
(`SuiConnectorConfig`, `SuiDataSource`, anchor fields); proof primitives
in the pinned `sui-light-client` (`proof/base.rs`, `proof/ocs.rs`).

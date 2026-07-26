# OCS verified Sui reads (object-checkpoint-state)

Status: active for nodes that opt in with the "new-style" `sui-data-source`
config and a Sui committee trust root (a `sui_genesis` blob — the
genesis-rooted trust root that replaced the old operator-pinned end-of-epoch
anchor). The opt-in is a NODE choice, not an ika protocol version: transport
selection keys off config SHAPE so a protocol flag can never halt running
validators en masse at an upgrade boundary. Requires the upstream Sui chain
to run protocol **v122+** with `include_checkpoint_artifacts_digest_in_summary`
— without the artifacts digest in the checkpoint summary there is nothing to
prove against, and startup refuses (`probe_artifacts_digest`). Nodes without a
trust root stay on the legacy JSON-RPC read path.

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
- **Notifier / fullnode** — on a new-style config, read gRPC at one endpoint;
  notifiers are the only nodes that submit transactions and always use a
  direct uplink.

**Config-shape gate** (evaluated at startup, `ika-node` boot):

| `sui-data-source` | `sui-rpc-url` | result |
|---|---|---|
| absent | absent | error: no Sui endpoint |
| absent | present | old-style: legacy JSON-RPC for **every role** — the transport this exact config selected on 1.1.8. A binary upgrade must not flip a node's transport under an unchanged config (a `sui-rpc-url` endpoint need not serve Sui gRPC; a notifier failing softly on gRPC stalls epoch advance network-wide). Moving to gRPC is an explicit migration: add `sui-data-source` |
| present | present | new-style wins; info log to drop `sui-rpc-url` |
| present | — | new-style: gRPC + OCS; a **validator** additionally requires a Sui committee trust root |

`has_anchor` (the gRPC/OCS opt-in) is: persisted committees OR a configured
`sui_genesis` blob. A new-style
validator without any of these is rejected — on the gRPC path it has no MPC
event source (no JSON-RPC `query_events`; the verified `BagEventPump` needs
the committee chain). `SuiDataSource` must carry `rename_all_fields =
"kebab-case"` so `fallback-grpc-url` is not silently dropped (a dropped field
flips a mirrored validator into peer-only).

## Bootstrap and the committee ratchet

The trust root is the **Sui genesis blob** (`sui_genesis`). At boot the node
loads it, recomputes the genesis checkpoint digest, and asserts it equals the
binary's **compiled-in chain identifier** for the configured chain
(`ika_sui_client::genesis::compiled_in_chain_identifier`, `genesis.rs:300` —
the chain identifier *is* the genesis checkpoint digest). **That constant must
come from `sui_types::digests::{MAINNET,TESTNET}_CHAIN_IDENTIFIER_BASE58`, not
from the identically-named getters in `ika_types::digests`** — ika's decode to
the ika SYSTEM OBJECT IDs, so verifying against them can never succeed for any
legitimate blob. That was a real bug (#1875): it made this whole path
unbootable on both public chains until it was fixed, and a regression test now
pins the two as unequal. On a public chain a
swapped/forged blob fails this check; on `Custom`/`Devnet` localnets there is
no compiled-in identifier, so the blob's own digest is the root (the
swarm/operator supplies a trusted blob). `committee[0]` is extracted from the
verified genesis and the ratchet walks forward from there. So the trust root
shrinks to a **32-byte compiled-in constant** — no weak-subjectivity anchor,
no out-of-band digest. Localnet/test harnesses that boot against an
externally started Sui localnet reconstruct the genesis blob from the chain's
genesis checkpoint over gRPC (`ika_sui_client::genesis::fetch_genesis_blob`),
write it to disk, and point `sui_genesis` at it — same config path as
production, with the trust placed in the queried endpoint (fine on a chain
you just started yourself).

**Perpetual state always wins**: once any committee is persisted, the
configured genesis seed is ignored on every later boot. Re-bootstrapping
requires manually clearing the OCS committee tables — with one exception:
when the persisted committee state fails to *deserialize* on boot (a Sui
version upgrade changed the on-disk BCS layout) and a `sui_genesis` blob is
configured, the node wipes the committee tables and re-bootstraps from
genesis automatically (worst case a full genesis→now re-ratchet; the public
checkpoint stores retain every end-of-epoch checkpoint since epoch 0).
Without a configured genesis the same condition is a loud, actionable boot
error, never a silent wipe.

**The persisted anchor is the cross-restart verification root.** Every
successful ratchet/follower/pusher install persists the verified transition
summary and advances `sui_committee_head` in the perpetual tables
(`sui_committee_summaries`, `sui_committees`, `sui_committee_head`), and boot
resumes verification from that head — a validator that has ever been synced
never needs historical Sui epochs again. The anchor is
machine/identity-independent (plain rows keyed by Sui epoch, nothing derived
from the host or the validator identity), so a snapshot-restored or mirrored
DB is exactly as bootable as the original. It fails **closed**: an
unresolvable head fails `CommitteeStore::open` fast, and a tampered/hand-
edited summary or committee makes every genuine summary fail terminal BLS
verification (`BadSignature`) — a forged root can stall the node, never make
it accept forged state.

The ratchet advances the trusted head strictly **+1 per step** up to the
relay-claimed current epoch. For each step it fetches the end-of-epoch
checkpoint of epoch `head`, BLS-verifies it against `committee[head]`,
requires `end_of_epoch_data`, and installs the embedded `committee[head+1]`
— the next committee is read out of the *verified* summary, never from a
side fetch. The store is keyed by each committee's own `.epoch`, so the
relay never chooses the install key. Only one ratchet runs at a time
(concurrent callers coalesce).

A pruned epoch boundary — the source answers `NotFound` for either the
**epoch record** (`last_checkpoint_of_epoch(head)`, "Epoch N not found": a
pruned fullnode, or `sui-state-direct` which serves current state + a change
stream only) or the end-of-epoch **checkpoint** itself — routes to one shared
fallback chain. The gRPC client maps the epoch-record "not found" status to
`TransportError::NotFound` for exactly this reason: it used to collapse into
a retryable `Network` error, which made a boot against a history-less source
spin forever in a 30-second retry loop with no health signal (the 2026-07
testnet incident: three validators restarted on `sui_state_direct` and their
entire MPC stacks sat dead behind `MissingCommittee` retries). The chain:
the ratchet first tries the resolved **Sui checkpoint archive** — an explicit
`sui_checkpoint_archive` config wins verbatim; with none configured, mainnet
and testnet default to the network's public checkpoint store
(`https://checkpoints.{mainnet,testnet}.sui.io`, which retains the complete
end-of-epoch history; no default is guessed for devnet/custom — see
`resolve_sui_checkpoint_archive` in `ika-config`, applied only where the
verified connector stack is built, so legacy JSON-RPC configs are untouched).
The ratchet fetches the end-of-epoch checkpoint from the
object store (`epochs.json` + `{seq}.binpb.zst` — when the epoch record was
pruned, the sequence comes from the archive's own enumeration) and
BLS-verifies it the same way — a *verified* fallback (a forged archive
summary fails closed; the `epochs.json` enumeration is an untrusted hint, so
omission/reorder can stall but never forge). If no archive resolved (or it
also lacks the checkpoint), the ratchet fails closed with the terminal
`ProofChainBroken` — there is **no** unverified committee fetch anywhere in
the ratchet; the proof chain is BLS-verified end to end or it stops.

### Anchor staleness bound and boot posture

**Maximum anchor staleness the source must bridge**: the forward walk needs,
for every epoch from the persisted anchor to the current one, the epoch
record *and* the full end-of-epoch checkpoint. So the bridgeable staleness is
exactly the source's retention window for those two artifacts — unbounded on
a full-retention fullnode; the fullnode's pruning window on a pruned one; on
the p2p relay, the serving direct node's retained end-of-epoch store (kept
back to its own bootstrap anchor, pruned with the verified-cache retention);
and unbounded when a checkpoint archive resolved (the verified archive
bridges any gap; on mainnet/testnet one resolves by default — the public
checkpoint store). Beyond the window the outcome is **defined and
loud**: terminal, non-retryable `ProofChainBroken` whose message names the
remediation (boot once against a full-retention Sui RPC so the anchor
catches up, or configure an archive retaining the epoch) — never a silent
retry loop.

**Boot posture (all roles: direct, mirrored-with-fallback, peer-only)**: the
initial ratchet failing with a **non-retryable** error fails node startup
with that remediation in the error — at boot the node holds no in-flight
duties, and a supervisor-visible crash loop beats a zombie whose MPC stack is
invisibly dead. Retryable (transport) failures only warn; the periodic
ratchet retries. An anchor-less cold start on a history-less source (fresh
DB, genesis-only anchor) is therefore a defined loud startup failure, not an
emergent hang. **Mid-run** the node is never torn down: a determinate
periodic-ratchet failure escalates to an `error!` log and sets
`ika_ocs_ratchet_stalled` to 1 (with `ika_ocs_ratchet_failures_total{reason}`
counting attempts; only `reason="transport"` is retryable) — set at the
ratchet chokepoint itself, cleared on the next success — so a wedged ratchet
is directly alertable instead of presenting only as absent downstream
series.

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
  parent state. It fires `bag_omission_suspected_total` on `listed < expected`
  but never halts — `Bag.size` legitimately drifts mid-walk, so only
  *persistent* suspicion is actionable. It is count-only (cannot tell
  *which* entries are missing) and is disabled on direct nodes (where the
  bag is trusted-local but `Bag.size` lags cache-first).
- **Pruned-defining-checkpoint resolution (direct nodes only)**: the
  page builder needs each entry's defining checkpoint to construct its
  inclusion proof, and once the fullnode prunes that checkpoint the
  proof can never be built again — a skip there is permanent, not
  transient (this silently hid `session_events` entries of sessions
  re-pulled across epoch boundaries and pinned epoch closes). The
  provider therefore reports the ids it listed but could not prove
  (`skipped_entry_ids`), and the reader resolves each through
  `verified_object` — its own proof verification, currency check, and
  committee-verified cache fallback included. Being live-listed proves
  the entry still exists on-chain, so resolution cannot resurrect a
  completed session's entry. Trusted listings only: on a mirrored node
  a relay's skipped ids carry no membership binding (no proof), so they
  stay omitted and the count-based policing covers them. Residual: if
  the local cache also lacks the entry (e.g. the node was down when it
  was folded and the upstream has pruned it), the reader warns per walk
  until the session completes network-wide and the entry leaves the
  bag.
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

The client (`SuiMirrorPeers::try_peers`) is the failover engine: every
pass visits all peers, returns the first success, and demotes failing
peers to the back.
Crucially, each per-peer request carries a **30s timeout** — anemo sets
no default outbound timeout and QUIC keep-alives keep an idle-but-hung
peer "connected", so without it one peer that accepts the stream and
never replies would hang every read forever and starve failover. A
timeout counts as a peer failure, not a `NotFound`.

The peer set comes in two modes, selected by whether
`sui-state-mirror-peers` is configured:

- **Pinned** (non-empty list): the operator's explicit override, logged
  at WARN on startup so a list left behind in a config isn't missed.
  Only the configured peer ids are used; configured peers that aren't
  currently connected are skipped within a pass. Passes rotate their
  start round-robin: the fleet shares one operator-written list, so
  without rotation every node would hammer `peers[0]`. An entry is
  either a bare hex peer id — selecting the peer among connections the
  p2p layer establishes by other means (seeds, fixed peers, committee
  discovery) — or a `{peer-id, address}` pair, which is additionally
  registered as a high-affinity anemo known peer (the seed-peer
  mechanism) so the connection is dialed and maintained even when
  nothing else would reach it.
- **Automatic** (empty list, the preferred default): every operation
  snapshots the peers *currently connected* through Ika's discovery
  system — never a boot-time capture, since peers connect, disconnect,
  and change across epoch transitions. A preference order is kept on
  top of the live set (demoted peers stay at the back while connected;
  newly-connected peers append behind proven ones), so failover memory
  survives across passes. Automatic passes do **not** rotate — rotation
  would cycle the pass start through the demoted tail (non-serving
  committee peers, or a stalling one costing the full 30s timeout),
  taxing a 1/n share of every read and neutralizing demotion. Each
  pass starts at the preference-order head; fleet load still spreads
  because each node's order is emergent, not a shared list.

Automatic mode routinely reaches peers that don't serve `SuiStateMirror`
at all (discovery connects every committee peer, mirrored/peer-only
ones included). Such a peer fails fast with anemo's **route-miss**
`NotFound` — distinguishable from the service's own data-absence
`NotFound` because the service always attaches a status message (the
`status-message` header on the wire) and the router fallback never
does. A route miss is treated like a not-connected peer: demoted and
skipped *without counting as reached*, so non-serving peers can neither
manufacture an all-peers-`NotFound` verdict nor destroy one produced by
genuinely-serving peers.

`NotFound` is returned only when at least one peer was reached AND every
reached peer returned a data-absence `NotFound` — any non-`NotFound`
error, any timeout, or an all-route-miss pass downgrades the verdict to
a network failure. The committee ratchet keys its "data really doesn't
exist → consider fallback" decision on exactly this distinction, so the
rule must hold.

At startup, a sui-state-mirrored node waits (bounded, 60s) for a usable
relay peer before building the OCS stack — in pinned mode until a
configured peer is connected, in automatic mode until a connected peer
answers a cheap `get_chain_identifier` probe (`find_serving_mirror_peer`;
mere connectivity is not enough, see above). To make automatic
discovery converge before that wait, the node publishes the initial
committee trusted-peer set to discovery as soon as the p2p network is
up, *before* the wait/stack build (a mirrored-with-fallback node has
already read the committee over its fallback uplink; a peer-only node
has nothing to publish yet and relies on p2p seeds plus the inbound
dials of the trusted-peer refresh loop).

## The cache fast path (sui-state-direct only)

Direct and peer-only nodes run the SAME cryptography but reach it differently — the
verification asymmetry:

```
  DIRECT validator                          PEER-ONLY validator
  ────────────────                          ───────────────────
  fold once → committee-verify → cache      (no fold, no cache-first)
  cache HIT  → serve, NO re-verify  ◄── asymmetry ──►  EVERY read → verify
  cache MISS / stale → fetch + verify        (committee BLS + Merkle + currency)
  trust root: committee (verified at fold)   trust root: committee (verified per read)
  ── both: committee ratchet BLS-verified; per-object high-water on every read ──
```

The asymmetry is *when* the committee proof runs, not *whether* it does:
a direct node verifies once at fold time and reuses that result on cache
hits; a peer-only node verifies on every read. Neither trusts a fullnode's
word — the trust root on both sides is the Sui committee.

Direct validators run a checkpoint folder (`IkaCheckpointPusher`) that
folds every Ika-modified object of every checkpoint, in order, into a
local verified state cache — building each object's inclusion proof from
the checkpoint's `ModifiedObjectTree`. Before anything is folded, the
folder verifies the checkpoint against its committee (`verify_before_fold`
→ the shared `verify_summary` chokepoint for the committee BLS, then the
`checkpoint_artifacts_digest` binding when objects are being folded), so a
compromised or buggy *own* fullnode cannot seed the cache with forged
state. A verify failure is refused, not cached: the error propagates and
the fold cursor stays put, so a transient missing committee self-heals on
the next poll while a bad signature halts the fold loudly
(`security_critical`). Because the cache is therefore committee-attested
and folded in order, a cache hit is the object's current state up to the
poll lag, and safely skips re-running the proof.

**Fetch-failure semantics (pending-gap repair).** The folder polls at
250 ms because the fullnode's checkpoint-pruning watermark can trail its
executed head by as little as a couple of seconds: at a slower cadence
the newest checkpoints of every pruner tick are pruned before the folder
fetches them, and any checkpoint the folder never folds is a PERMANENT
cache gap (an Ika object whose only mutation rode it — e.g. a
`session_events` bag entry — never enters the cache; observed pinning
epoch closes when the entry belonged to a session re-pulled across an
epoch boundary). A full-checkpoint fetch failure must therefore neither
stall the scan (one unfetchable checkpoint would freeze the whole cache
behind it) nor be skipped silently (the historical behavior, and the
root cause above). Instead the scan continues and the failed seq becomes
a **pending gap**, retried at the top of every tick and folded LATE when
it materializes — out-of-order folding is safe because the cache is
monotonic-by-version and its fold head is monotone-max, so a late fold
can only fill gaps, never regress state. A gap that outlives a generous
retry deadline is dropped with a loud warn (genuinely pruned upstream);
gaps inside a far-behind fast-forward's sacrificed span go with it.
Gaps are in-memory only — after a restart the on-chain
uncompleted-session re-pull is the backstop.

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
only at epoch boundaries, so if the pusher *misses* its update (the
defining checkpoint pruned before the lagging pusher folds it; the
singleton is never modified again that epoch to re-fold it) the stale
snapshot would be served *indefinitely* and wedge the epoch — the gate
that drives epoch advance reads the mid-epoch committee through this
anchor (#1736). The pending-gap repair above makes such a miss unlikely
(the folder retries an unfetchable checkpoint instead of skipping it),
but the TTL bound stays as defense-in-depth for the drop-after-deadline
and restart cases. The 2 s interval keeps the refresh well below the
per-tick rate that latches the loop while bounding staleness to ~2 s.
Ordinary (non-anchor) reads still fall through to the network when the
tripwire trips. Cache-served anchors are counted
`ika_ocs_cache_read_total{outcome="anchor"}`.

The cache is authoritatively populated *only* by the node's own folder —
it does not ingest peer state. Mirrored and peer-only validators have no
such folder; they read with `cache_first = false`, so **non-anchor** reads
pull each object over the relay and re-verify it per read.

The **singleton anchors are the exception**, mirroring the direct
`verified_anchor_object` fast path above. A mirrored/peer-only node
shadow-populates its cache with every verified read, and
`verified_anchor_object` serves that shadow-cached anchor when — and only
when — the committee-signed **changeset-stream currency gate** (under
*Freshness and rollback protection*) returns `Current` for the cached
version, i.e. positively attests it is still the id's latest. The **same
`ANCHOR_REFRESH_INTERVAL` (2 s) TTL** the direct path uses is the hard
staleness bound: it forces a verified network re-read every interval, so a
*stalled* changeset stream — which would freeze the verdict at `Current`
and otherwise serve the anchor stale forever — cannot wedge the epoch
(#1736). `Unknown`/`Stale`/`NotLive` verdicts, and every non-anchor read,
stay on the per-read-verified relay path. `currency == Current` is thus
*necessary but not sufficient*: it only attests freshness up to the
changeset index's contiguous head, which may lag the relay head, so the
TTL re-read is what caps that gap. Mirror cache-served anchors are counted
`ika_ocs_cache_read_total{outcome="mirror_anchor"}`.

This is the direct/mirror **currency symmetry**: a direct node's
cache-first rests on its complete, contiguous local fold; a mirror's rests
on the changeset index's version+digest currency signal *plus* the TTL
bound — two attestations of the same "still current" property. Extending
the cache-first serve beyond the singleton anchors to *all* slowly-changing
mirror reads remains future work — see
[`../plans/ocs-changeset-stream-mirror-currency.md`](../plans/ocs-changeset-stream-mirror-currency.md).

## Retained state: surviving a restart and a pruning fullnode

Two independent durability mechanisms keep a direct node useful after a
restart and keep a mirrored peer's ratchet advancing after the direct
node's own Sui fullnode has pruned. Both live in
`AuthorityPerpetualTables`.

### The verified cache is durable, and so is its head

`verified_object_cache` (`ObjectID → VerifiedSnapshot { object, proof,
summary, source seq }`) is written through on every checkpoint the pusher
folds. A restart rehydrates the cache from RocksDB instead of re-fetching
from a fullnode that may since have pruned the proving checkpoint.

`verified_object_cache_head` — the highest checkpoint sequence the cache
reflects — is persisted **and restored alongside it**. That is not
bookkeeping: the staleness tripwire compares the cache against the head, so
a rehydrated cache restored *without* its head reads as stale and the fast
path silently disables itself. Restore both or neither.

The parent→children index is **rebuilt from the objects' owners on load**,
not persisted — it is derived state, so persisting it would create a second
thing to keep consistent.

### A direct node serves the ratchet from its own retained store

`RetainedFullnodeTransport` (`sui_connector/retained_transport.rs`) is a
`SuiTransport` decorator a sui-state-direct node places in front of its
mirror server's gRPC transport. It answers exactly the two committee-ratchet
primitives from local state — `last_checkpoint_of_epoch` and the
end-of-epoch `get_full_checkpoint` — and delegates **every** other method
straight through.

The data comes from the pusher's **eager capture**: as it streams past an
end-of-epoch checkpoint it persists it (`persist_end_of_epoch` →
`sui_end_of_epoch_seqs`, `sui_end_of_epoch_checkpoints`), including
checkpoints recovered by gap repair. One entry per Sui epoch, so the table
is sparse despite each value being a full `CheckpointData`; it is pruned
with the verified-cache retention floor.

Why it exists: a mirrored peer bootstrapping or catching up must walk the
committee ratchet, which needs each epoch's end-of-epoch checkpoint. Sui
fullnodes prune those. Without retention the mirrored peer's ratchet stalls
at the first pruned boundary — and the direct node's fullnode is exactly the
thing OCS is trying to stop being a dependency on.

**This is a serving optimization, not a trust change.** The mirrored peer
re-verifies the committee-signed summary it gets back, exactly as it would
from any relay. A direct node that serves a wrong or forged checkpoint here
is caught by the same verification that catches a byzantine relay — see
[Relay protocol](#relay-protocol). Nothing about the trust chain changes
because the bytes came from a peer's disk rather than its fullnode.

## Key invariants

1. A returned `VerifiedObject` is committee-BLS-attested at the byte
   level: id, version, owner, type, and contents are all proven for
   `source_checkpoint_seq`. No field of the object ref is left unproven,
   and the reader — not the relay — owns the proof target.
2. The trusted head epoch is monotone and advances strictly +1; on the
   verified path `committee[head+1]` is only ever derived from a
   BLS-verified end-of-epoch summary signed by `committee[head]`. The
   store is keyed by each committee's own epoch.
3. Trust is rooted in the compiled-in chain identifier (the verified genesis
   blob) on first boot, and thereafter in the persisted, machine-independent
   committee anchor in the perpetual tables; persisted committee state always
   overrides a configured genesis seed, and a corrupted/tampered anchor fails
   closed (verification failure and a stall — never silent acceptance).
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
   The direct-side folder enforces this at fold time
   (`verify_before_fold`): the committee BLS on the summary plus the
   artifacts-digest binding run before `absorb_entries`, so a direct
   node's own fullnode is not in its trust boundary — serving forged state
   is refused, not cached.
9. On mirrored/peer-only nodes a verified read additionally passes a
   committee-attested **currency** gate: an authentic-but-superseded object
   is rejected — a read anchored before the object's latest folded
   modification (or after its deletion/wrapping) returns `NotCurrent`. The
   backing changeset fold is contiguity-enforced, so a skipped modification
   is detectable, not silently dropped.

## Residuals and known gaps

- **Eclipse on a fresh node** (above): a lone malicious relay can pin a
  cold-started node to a stale-but-real snapshot. The committee chain itself
  is now genesis-rooted and unforgeable (each end-of-epoch checkpoint is
  BLS-verified back to the genesis blob), so a relay can only stall the head,
  never forge a committee. The changeset-stream currency gate narrows the
  head-staleness window — the relay must withhold the whole stream
  consistently, and contiguity makes a silent gap detectable — but does not
  fully close it; the absolute mitigations (an enabled freshness bound,
  multiple independent relays) are still not active today.
- **Embedded mainnet/testnet genesis blob**: the trust root is the Sui
  genesis blob verified against the compiled-in chain identifier. Until the
  release embeds the per-chain `genesis.blob` (an `include_bytes!` seam),
  operators supply a `sui_genesis` path. The chain-identifier verification
  (recomputed genesis digest == compiled-in constant) is now live, closing
  the former trusted-as-claimed `get_chain_identifier` gap.
- The verified ratchet path relies on the structural uniqueness of an
  epoch's end-of-epoch checkpoint for `next.epoch == head + 1`; this is now
  asserted explicitly on the verified install path
  (`install_next_from_verified_summary`), not only on the unverified
  fallback.
- **Byzantine relay tax in automatic peer discovery** (liveness-only): with
  no pinned list, any connected committee peer can mount a `SuiStateMirror`
  service and *stall* (accept, never reply), costing the 30s per-request
  timeout whenever a pass reaches it, and — because a timeout counts as
  `Unreachable` — persistently downgrading a genuine all-peers-`NotFound`
  verdict to `Network`, deferring the ratchet's archive fallback. In pinned
  mode the attacker had to be on the operator's list; automatic mode widens
  that to the connected set. Demotion plus head-anchored (non-rotating)
  passes confine the steady-state cost to passes where every peer ahead of
  the staller failed; all bytes remain committee-verified, so this is delay
  and withholding — the relay's already-documented privilege — never
  forgery.

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

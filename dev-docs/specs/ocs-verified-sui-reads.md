# OCS verified Sui reads (object-checkpoint-state)

Status: active for nodes configured with `sui-data-source`
and a Sui committee trust root (a `sui_genesis` blob — the
genesis-rooted trust root that replaced the old operator-pinned end-of-epoch
anchor). The opt-in is a NODE choice, not an ika protocol version: transport
selection is a node choice, so a protocol flag can never halt running
validators en masse at an upgrade boundary. Requires the upstream Sui chain
to run protocol **v122+** with `include_checkpoint_artifacts_digest_in_summary`
— without the artifacts digest in the checkpoint summary there is nothing to
prove against, and startup refuses (`probe_artifacts_digest`). Validators
without a trust root are rejected at startup.

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
                 │ (b) owner-bound  (child Owner == wrapper UID)
                 ▼
              PendingActiveSet ✓
```

Every hop is now (a) or (b): the versioned `*Inner` children are **derived**; the
active/next/previous committees and the quorum are **inline** in the proven `SystemInner`
bytes; and the validator `StakingPool`s, the `session_events` entries, AND the
`pending_active_set` `ExtendedField` value are **owner-bound**. The last was the one gap
(`get_extended_field_value_bcs` listed the wrapper's single field and read `.first()`
without an owner-check) — closed via the shared
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
  the two reads it does not relay (`get_transaction`, `get_committee`)
  and as the bootstrap uplink. `list_owned_gas_coins` is not among them —
  it lives on `SuiWriter`, not `SuiTransport`, and a mirrored node has no
  writer.
  Every gRPC call on the direct and fallback paths passes a **node-wide
  shared rate-limit gate** (`SuiGrpcClient::with_gate`, wired in
  `sui_connector/setup.rs`). When Sui rate-limits the node, the whole node
  backs off together rather than each caller discovering the limit
  independently. Nothing about the verification story changes — but a
  backoff is a shared stall, so a read that looks slow may be waiting on
  the gate rather than on the endpoint.
- **Peer-only validator** — `SuiStateMirrored { fallback_grpc_url: None }`:
  no Sui uplink at all; every read, including committee/epoch bootstrap,
  flows over the verified relay. This is the *sole* identifier of the
  peer-only role. A fresh peer-only node can't dial out to reach the relay,
  so existing validators *dial it inbound* off the on-chain `pending_active_set`
  — see [`trusted-peer-discovery.md`](trusted-peer-discovery.md).
- **Notifier / fullnode** — read gRPC at one endpoint;
  notifiers are the only nodes that submit transactions and always use a
  direct uplink.

**Configuration gate** (evaluated at `ika-node` startup):

- `sui-data-source` is required for every role.
- `sui-state-direct` supplies a direct Sui gRPC endpoint.
- `sui-state-mirrored` may carry `fallback-grpc-url`; omitting the fallback is
  valid only for a peer-only validator.
- A validator additionally requires a Sui committee trust root.
- A notifier requires a direct writer uplink and cannot use peer-only mode.

`has_anchor` is: persisted committees OR a configured `sui_genesis` blob. A
validator without any of these is rejected because the verified
`BagEventPump` needs the committee chain. `SuiDataSource` must carry `rename_all_fields =
"kebab-case"` so `fallback-grpc-url` is not silently dropped (a dropped field
flips a mirrored validator into peer-only).

### Authenticated gRPC endpoints

Both direct sources and mirrored sources with a fallback can attach arbitrary
ASCII gRPC metadata to every request sent to their configured endpoint. This is
the provider-neutral authentication surface: bearer authentication is an
`authorization` header whose complete value is `Bearer …`; provider-specific
schemes use names such as `x-api-key` or `x-auth-header`. There are no separate
bearer- or provider-specific config branches.

```yaml
sui-data-source:
  kind: sui-state-direct
  url: https://provider.example.com:443
  headers:
    authorization:
      from-file: /run/secrets/sui-grpc-authorization
    x-client-name:
      literal: ika-validator
```

A mirrored validator places the same `headers` map next to
`fallback-grpc-url`; the headers apply only to that direct fallback, never to
the Ika p2p relay. Configuring headers on a peer-only source (no fallback URL)
is rejected at startup because there is no endpoint to receive them.

Each header value has exactly one source:

- `from-file`: recommended for credentials mounted by Kubernetes, Docker, or
  systemd. The file is read once at startup. One terminal LF or CRLF is removed
  to accommodate ordinary secret files; all other bytes are preserved and
  validated. Rotation therefore requires a node restart.
- `from-env`: reads the complete value from the named environment variable at
  startup. A missing, non-UTF-8, or empty value fails startup.
- `literal`: embeds the value in YAML and is intended only for non-secret
  metadata.

Header names and values are validated before the client connects. Every value
is marked sensitive in tonic metadata, and config debug output redacts literal
values. Errors may name the header and its environment variable or file path,
but never include the resolved value or file contents. The same metadata covers
unary calls, checkpoint subscriptions, and notifier transaction submission
because it is installed on the shared upstream Sui RPC client.

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
`resolve_sui_checkpoint_archive` in `ika-config`).
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
fresh. That fold is **bounded but not weakened**: a claim passes the same
token-bucket rate bound the folder applies (`WatermarkGuard`, under
*Reading the head*) before it may raise the floor, because the fold is
irreversible and an inflated claim otherwise pins the floor above the
real chain head forever — making every genuinely-current cached object
read stale and forcing permanent fall-through to network reads, and
failing every read outright once the absolute freshness bound is enabled
(ika #2041). The bucket here is anchored to the verified cache's fold
head, not to the relay's first claim — see the *Seeding* note under
*Reading the head*, and the cold-node residual it states. The monotone
semantics are untouched: a refused claim leaves the floor exactly where
it was, and refusing an unexplained *increase* cannot help an
under-reporting relay, which can already just claim a low head (that is
the eclipse residual below, not a new hole). Deliberately
**not** done here: making the comparison windowed or decaying. The
all-time max IS the anti-under-report guarantee — a floor that ages back
down is a floor a relay can wait out and then under-report through.
Per **well-known** object (coordinator, system, versioned inner
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
  parent state. It fires `ika_ocs_bag_omission_suspected_total` on
  `listed < expected` but never halts — `Bag.size` legitimately drifts
  mid-walk, so only *persistent* suspicion is actionable (a sustained
  streak does escalate the log from warn to error). It is count-only (cannot tell
  *which* entries are missing) and is disabled on direct nodes (where the
  bag is trusted-local but `Bag.size` lags cache-first).
- **Pruned-defining-checkpoint resolution**: the
  page builder needs each entry's defining checkpoint to construct its
  inclusion proof, and once the fullnode prunes that checkpoint the
  proof can never be built again — a skip there is permanent, not
  transient (this silently hid `session_events` entries of sessions
  re-pulled across epoch boundaries and pinned epoch closes). The direct
  proof provider shares the durable verified-state snapshot cache populated
  by the checkpoint pusher. If rebuilding a proof returns `NotFound`, it may
  reuse a cached `(object, proof, summary)` only after fetching the current
  object from Sui and requiring its complete object reference (id, version,
  digest) to equal the cached object reference. That makes a stale snapshot
  unusable while allowing both the local direct reader and remote mirrored
  readers to receive a proof after the source checkpoint is pruned. Hits are
  counted by `ika_ocs_proof_snapshot_cache_hits_total`.

  A malicious or lagging Sui source can replay an older, once-current object
  reference and thereby make an exact cached snapshot appear current. This
  grants no capability beyond withholding: control of that source already lets
  it freeze the validator on an old view by withholding newer state. The cached
  object remains bound to a committee-certified inclusion proof, so the source
  cannot fabricate state, and the consumer's version high-water still rejects
  a rollback below any version the process has already accepted.

  If no exact cached snapshot exists, the provider reports the ids it listed
  but could not prove (`skipped_entry_ids`). A direct reader can still resolve
  each through its trusted listing plus `verified_object` cache fallback.
  Being live-listed by its own Sui source proves the entry still exists, so
  resolution cannot resurrect a completed session's entry. On a mirrored node
  a relay's remaining skipped ids carry no membership binding (no proof), so
  they stay omitted and the count-based policing covers them. Residual: if the
  direct cache lacks the current version (for example, the node was down when
  it was folded and the upstream pruned it), the entry remains unavailable
  until a source capable of proving that version is used.
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

**Reading the head (pruning-immune watermark).** Everything below starts
from "what is the latest checkpoint sequence" — the folder's per-tick
scan bound, the folder's first-start cursor, the `SuiClient` describe
probe on every node-start path, and the `claimed_latest_checkpoint_seq`
a direct node stamps on each verified-read response. None of them need
the summary, only the NUMBER, and taking it from a summary fetch reads
through the fullnode's availability window (`lowest_available..=latest`).
A fullnode pruning AT head can empty that window and then answers
`NotFound` for its OWN latest — persistently, while the window stays
empty. Every one of those call sites is fatal-on-error, so that state
froze the folder cursor, failed node boot, and failed every verified-read
response this node served.

The height therefore comes from `GetServiceInfo.checkpoint_height`, the
store's own watermark, read WITHOUT the availability check
(`SuiTransport::get_latest_checkpoint_sequence`). This does not weaken
the trust chain: the head sequence was never a trust input. It bounds a
scan, and every checkpoint the scan reaches is still committee-verified
at fold time (`verify_before_fold` / `verify_archive_checkpoint`); the
`claimed_latest_checkpoint_seq` it stamps is untrusted by construction —
the reader folds it through `fetch_max` and never treats it as an
attested head. The watermark is deliberately unauthenticated, which is
exactly what the surrounding invariant ("the relay's claimed head is
never trusted directly") already assumes. Wrapper transports forward the
probe explicitly so a direct primary keeps it; the mirror relay exposes
no watermark RPC, so behind a relayed stack the probe degrades to the
window-bound fetch.

**Bounding the watermark's irreversible consumers.** Being untrusted is
not the same as being harmless. Several consumers fold the height into
state that cannot come back down — the folder's cursor in the perpetual
tables (a restart resumes it), the cache's monotone processed head, the
reader's freshness floor — so a single inflated sample (a buggy
fullnode, a desynced load-balancer backend, an endpoint pointed at the
wrong network, a corrupted response) used to latch permanently: the
folder fast-forwarded past the real head, persisted that cursor, dropped
the sacrificed span's pending gaps, and pinned the reader's staleness
tripwire "healthy" while nothing folded (ika #2041). Content trust was
never affected — everything folded still passes `verify_before_fold` —
but an availability hint must not feed irreversible state. Two bounds,
both in `watermark_guard.rs` / `push_worker.rs`:

1. **Rate bound (`WatermarkGuard`, applied by the folder's probe and by
   the reader's freshness fold).** A *token bucket over admitted
   advance*, not a per-sample delta limit: allowance accrues at `10/s`
   up to a `15_000` ceiling (about an hour of real production at Sui's
   ~4 checkpoints/s) and is **spent by every accepted increase**. The
   exact guarantee: advance admitted over any window of length `T` is at
   most `15_000 + 10·T` checkpoints — one burst, plus the sustained rate
   — whatever step size the upstream chooses. (So the *average* over a
   short window can exceed 10/s: at exactly one burst-length window it
   is ~20/s, converging on 10/s as the window grows.) A per-sample limit
   would
   bound nothing over time — an upstream reporting "previous + just
   under the limit" every 250 ms tick is admitted forever and walks the
   head arbitrarily far, one legal step at a time; that is the shape the
   bucket exists to refuse. Real production spends 4 of the 10
   checkpoints/s accruing, so the bucket sits at its ceiling in steady
   state and the remaining ~6/s is what a drained bucket recovers at.
   The bucket compares observations **within this process, never against
   persisted state**: a node starting against a mature chain, or
   resuming after downtime with a cursor millions of checkpoints behind,
   passes trivially — catch-up distance is never what is metered. A
   retreating watermark is admitted, costs nothing, and does not lower
   the head (so a retreat cannot refund spent allowance). A refused
   sample is skipped loudly, moves nothing, and is counted
   `ika_ocs_watermark_implausible_total{consumer}`; the folder's tick is
   retried 250 ms later.

   **Seeding.** An unseeded bucket takes its head from the first
   observation — sound for the folder, whose watermark comes from the
   node's own configured fullnode over its own transport. It is NOT
   sound for the reader on a mirrored/peer-only node, where the claim
   comes from a relay that is untrusted by design and would otherwise
   pick the floor outright. The reader therefore anchors the bucket to
   the verified cache's **fold head** before every claim
   (`note_verified_floor`), which only advances to checkpoints carrying
   a committee quorum signature and so cannot be inflated by a relay.
   Because the anchor is re-applied on every call it also tracks local
   progress for free, and a claim at or below it never spends allowance.
2. **Two-sided agreement before the fast-forward.** The far-behind
   fast-forward is the single-shot, persisted, span-sacrificing
   consumer, so it acts only on a target **two consecutive ticks agree
   on**: the first far-behind tick proposes and changes nothing (no
   cursor write, no gap drop, no processed-head advance), and the next
   tick executes only if its own watermark is within `250` checkpoints
   of the proposal **in either direction** — then jumping to the
   **lower** of the two. Both halves are load-bearing. A one-sided "at
   least as high" test leaves the confirming sample itself unbounded
   above the proposal, so an inflated confirmer — or an alternating load
   balancer whose high backend lands in the confirming slot — would
   execute an inflated jump; taking the lower sample means neither
   position can raise the target. The band is a minute of real
   production: consecutive ticks are 250 ms apart and even a tick
   delayed by every bounded retry budget in the gap-repair loop (tens of
   seconds) stays well inside it, so two samples further apart are not
   one head seen twice. A source flapping outside the band never
   fast-forwards and stays visibly stalled (`ika_ocs_pusher_stalled`),
   which is the correct outcome — an unexplained sample must not
   sacrifice a span. The proposal is taken at the top of every tick,
   *before* the probe and the rate bound, so a tick that errored or was
   refused disarms it: confirmation can only come from the immediately
   preceding tick. Cost is one poll interval on a genuinely far-behind
   folder and no extra RPC. Agreement is by repeated observation rather
   than by fetching the target checkpoint: an unfetchable target does
   not distinguish an inflated watermark from an upstream prune — the
   very condition that makes the fast-forward necessary — so a
   fetchability gate would turn a pruned-at-head window into a scan of
   thousands of failing fetches and as many pending gaps.

`ika_ocs_pusher_stalled` is computed from the raw sample *before* the
rate bound decides, so a run of refused ticks reads as the stall it is.
The gauge is neither monotone nor persisted, so a bad sample cannot
latch it.

Residuals, stated exactly:

- **Cold reader, no local anchor.** A peer-only/mirrored node whose
  verified cache is still empty has nothing to anchor to, so its first
  relay claim seeds the reader's floor. This is the eclipse residual
  above (a lone malicious relay pinning a fresh node), narrowed — the
  relay can no longer inflate a *warm* node's floor — not closed.
  Chain-identifier verification does **not** cover this: it pins the
  node's own configured Sui endpoint to the right network, and says
  nothing about what a peer claims its head is.
- **Folder's first observation.** The folder's own first probe seeds its
  bucket, so a fullnode already reporting a wrong height at boot is
  taken at its word. The endpoint is the operator's own, and a
  wrong-*network* endpoint is caught by the chain-identifier
  verification on the trust path; a same-network endpoint reporting a
  wrong height is not.
- **Sustained adversarial ramp (the bound's shape, not a bug in it).**
  The rate bound caps *how fast* the head may be walked, not *whether*
  it can be. A source that is adversarial rather than merely buggy — one
  that emits a self-consistent monotone ramp instead of a single wrong
  number — can hold the folder's head, its persisted cursor and (from a
  relay) the reader's floor ahead of reality indefinitely, at up to the
  bound's spare rate over real production (~6/s here). Nothing downstream
  caps it: consecutive ramp samples sit ~2.5 apart, well inside the
  fast-forward's 250-checkpoint agreement band, and the reader's
  verified-floor anchor only ever *raises* the head, never trims it back
  toward locally-verified reality.

  **Signature, once the margin passes ~2,400 checkpoints** (the
  600 s gap-retry deadline × ~4/s production): every checkpoint the scan
  reaches is still in the future, so every seq becomes a pending gap and
  every gap expires before it can materialize. The verified cache stops
  advancing entirely while `ika_ocs_pusher_stalled` reads **0** (the
  cursor is *ahead* of the head, so there is no lag to report) and
  `ika_ocs_watermark_implausible_total` stays **0** (every sample was
  inside the bound). The one live signal is
  `ika_ocs_pusher_gap_dropped_total` climbing steadily at roughly the
  chain's checkpoint rate — a permanent-loss counter that should
  otherwise be flat, and which already carries an alert. A steadily
  climbing drop rate with the cursor ahead of the chain head is a ramp;
  a one-off jump ahead with a flat drop counter is the single-sample
  poisoning this bound does close. Recovery is the same cursor-row clear
  as a poisoned cursor, plus replacing the endpoint — a source that can
  do this is outside #2041's fault classes (buggy fullnode, desynced
  backend, wrong-network endpoint, corrupted response), all of which
  produce inconsistent or one-shot values that the bound refuses.
- **Long host pauses.** `Instant` excludes suspended time, so a host
  paused longer than the burst covers (~an hour of production) resumes
  with a genuine head beyond the bucket and refuses it until the bucket
  refills — bounded, self-healing at ~6/s net, and cleared immediately
  by a restart, since the bucket is in-process state. The refusal shows
  as `ika_ocs_watermark_implausible_total` climbing with
  `ika_ocs_pusher_cursor_seq` **behind** the chain head, which is the
  opposite signature to a poisoned cursor (below).

**Symptom and recovery of a poisoned cursor.** Should a cursor still end
up ahead of the chain (an older binary, or a fault outside these
bounds), the signature is deceptive: `ika_ocs_pusher_stalled` reads
**0** — a cursor ahead of the head has no lag to report — and
`ika_ocs_pusher_cursor_seq` keeps up with, or exceeds, the
chain head, while `ika_ocs_pusher_pushed_total` is flat, the verified
cache never advances, and sessions stall behind objects that never enter
it. The tripwire cannot see it either: it compares the *observed
upstream head* against the *processed head*, and a poisoned processed
head makes that difference zero forever. The discriminator is
`ika_ocs_pusher_cursor_seq` against the chain's real latest checkpoint
(any fullnode's `GetServiceInfo.checkpoint_height`). Recovery is to
clear the persisted cursor so the folder re-initializes from the
watermark on the next start: with the node stopped, delete the single
row of the `sui_pusher_last_seq` column family in the perpetual tables
(the same column `reset_direct_cache_for_format_recovery` clears
alongside `verified_object_cache_head`). Trust is unaffected — every
re-folded checkpoint is re-verified — and the objects whose only
mutation rode the skipped span are repaired by their next mutation or by
a consumer's network fallback.

**Fetch-failure semantics (pending-gap repair).** The folder polls at
250 ms because the fullnode's checkpoint-pruning watermark can trail its
executed head by as little as a couple of seconds: at a slower cadence
the newest checkpoints of every pruner tick are pruned before the folder
fetches them, and any checkpoint the folder never folds is a PERMANENT
cache gap (an Ika object whose only mutation rode it — e.g. a
`session_events` bag entry — never enters the cache; observed pinning
epoch closes when the entry belonged to a session re-pulled across an
epoch boundary, and again in issue #2018 where the lost entry was a live
DKG request that sat inside the epoch's locked close set). A
full-checkpoint fetch failure must therefore neither
stall the scan (one unfetchable checkpoint would freeze the whole cache
behind it) nor be skipped silently (the historical behavior, and the
root cause above). Instead the scan continues and the failed seq becomes
a **pending gap**, retried at the top of every tick and folded LATE when
it materializes — out-of-order folding is safe because the cache is
monotonic-by-version and its fold head is monotone-max, so a late fold
can only fill gaps, never regress state. A gap the fullnode keeps
refusing past a short grace (5 s) is fetched from the resolved
**checkpoint archive** instead (the same object store the ratchet falls
back to; the public stores retain *ordinary* checkpoints ~30 days, and a
localnet points this at the Sui fullnode's `--data-ingestion-dir` via
`ika start --sui-checkpoint-archive-url file://…`). Fullnode retries
of pending gaps are capped per tick as well, for the same reason and
newly load-bearing: now that a pruned-at-head window is traversed rather
than aborting the tick, every unfetchable checkpoint in it becomes a
pending gap — thousands, at mainnet rates, by the retry deadline — and
retrying all of them serially each 250 ms tick against the fullnode that
is already failing to serve them is precisely the self-amplification the
archive cap avoids. Gaps retry oldest-first, so the ones nearest their
deadline keep priority. Archive fetches are
paced per gap, capped per tick, and bounded by a per-fetch timeout (the
object-store client otherwise retries internally for up to 60 s, and an
unbounded stall here would hold the scan cursor back while the fullnode
prunes more — the fallback amplifying the loss it prevents). An
archive-served checkpoint must pass verification STRICTLY beyond what
the fullnode fold path applies before it may clear a gap — because the
archive is the lower-trust source (a third-party HTTP store by default
on public chains) and the fold path verifies nothing for a checkpoint
with no Ika-typed outputs, a blob that folds vacuously would clear the
gap silently and suppress the dropped-gap alarm: (1) the blob's
committee-signed `sequence_number` must equal the requested seq (file
naming is untrusted), (2) committee BLS on the summary, and (3) the
artifacts-digest binding over the blob's ENTIRE object set — both
unconditionally, so an emptied or mislabeled object set produces a tree
root the committee never signed and is refused
(`verify_archive_checkpoint` in `push_worker.rs`). The archive is thus
an availability source, never a trust source; repairs are counted by
`ika_ocs_pusher_gap_archive_repairs_total`. Only a gap that BOTH sources
fail to serve until the generous retry deadline is dropped, with a loud
warn and `ika_ocs_pusher_gap_dropped_total` (alert on any increase — each
drop is a potential wedged epoch); gaps inside a far-behind
fast-forward's sacrificed span go with it (counted in the same metric).
The end-of-epoch retained store is written only after the fold's
committee verification passes (`fold_checkpoint` verifies before
`persist_end_of_epoch`), so no source — fullnode or archive — can
overwrite a genuine retained entry with an unverified blob.
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
10. **A verified read of either singleton anchor asserts that the chain's
    object is typed by the package this binary compiled in for that role**
    (`System` → `ika_system_package_id`, `DWalletCoordinator` →
    `ika_dwallet_2pc_mpc_package_id`). Mismatch is `IdentityMismatch`, counted
    as `ika_ocs_identity_mismatch_total{anchor}`, and is **terminal**: the node
    refuses to run rather than retrying, because no amount of retrying changes
    a constant baked into the build. (The counter names the cause on the last
    scrape before exit; a node down for this reason otherwise presents only as
    absent series.)

    **This asserts the object's TYPE, which is a different address from the
    current executable package — both are live at once.** The object's type is
    its ORIGINAL defining package and never moves; the `package_id` FIELD names
    the latest upgrade and is read at runtime, which is why no constant here
    tracks contract upgrades. Testnet shows both packages already upgraded and
    the types still on the originals (checked 2026-07-25):

    | anchor | type (asserted) | `package_id` field (executable) |
    |---|---|---|
    | `System` | `0xae71e386…` | `0xde05f49e…` |
    | `DWalletCoordinator` | `0xf02f5960…` (dwallet **v1**) | `0x6573a6c1…` (**v2**) |

    **An upgraded package holds a MIX of type addresses, so "the package id" is
    not one value.** Sui records type identity per datatype in the package's
    `TypeOrigin` table (`{module_name, datatype_name, package}`): a type
    carried forward from the previous version keeps the ORIGINAL address, while
    a type **first defined in the upgrade** carries the UPGRADE address. Both
    networks show the same split (checked 2026-07-25):

    | package | types at original | types at upgrade |
    |---|---|---|
    | dwallet | 79 | **7** |
    | ika_system | 36 | **0** |

    The seven dwallet upgrade-defined types include four **events**
    (`DWalletDKGRequestEvent`, `CompletedDWalletDKGEvent`,
    `RejectedDWalletDKGEvent`, `SignDuringDKGRequestEvent`).
    `UserSecretKeyShareEventType` is not a fifth: despite the name it is an
    enum used as a FIELD of `DWalletDKGRequestEvent`, never emitted. That is why
    `ika_dwallet_2pc_mpc_package_id_v2` exists and why event filtering accepts
    both addresses — it is **load-bearing**, not defensive: without it those DKG
    events are dropped.

    Two consequences:

    - **This invariant is unaffected.** It asserts the type of the two
      singleton ANCHOR objects, and those were created by the original
      packages — their types sit in the original's `TypeOrigin` entries, and
      `System::try_migrate` mutates the object in place (`&mut System`) rather
      than recreating it, so an existing object's type can never move. Verified
      directly on both networks. It must therefore expect ONLY the original:
      accepting the upgrade id as well would admit exactly the #1908 defect
      (a constant set to the upgrade id) that this check exists to catch.
    - **`ika_system` needs no `_v2`, and adding one would be dead weight.**
      Nothing consumes system events by package address: the only
      event-address filter in the node is `sui_event_into_session_request`,
      which matches the DWALLET package (both ids) and the sessions-manager
      module. System state is read from the system OBJECT via verified reads,
      not from address-filtered events. `ika_system_package_id`'s only other
      consumer is the pusher's cache-fold relevance set, where an unmatched
      object degrades to a cache miss and a verified network read — never a
      wrong answer. An unused `_v2` constant would just be one more value that
      can drift, which is the #1908 hazard itself.
    - **The dwallet filter is where the constant hazard actually recurs.** It
      enumerates `{ika_dwallet_2pc_mpc_package_id, …_v2}`, and four of the
      seven v2-defined types are events — so the next dwallet upgrade that
      defines a new event type silently loses those sessions until someone
      remembers to add a `_v3`. This filter is live in `bag_event_pump`. The durable fix is to
      derive the accepted set from the package's `TypeOrigin` table at runtime
      rather than enumerating constants.

    This is a stable equality check, not something to bump on contract
    upgrades: a Sui type tag carries the **defining** package forever, so the
    system object stays `{original}::system::System` across every upgrade.
    The expectation therefore comes from `compiled_in_ika_identity` (the
    ORIGINAL package) and never from the config's `ika_system_package_id`,
    which on a localnet may legitimately name a later upgrade. It is `None`
    on Devnet/Custom, where ids are generated per genesis and there is
    nothing to assert against.

    Why it exists: #1908 shipped the system package's **v2 upgrade id** as the
    compiled-in identity — a value matching zero live event type tags — and
    because that PR removed the config escape hatch on public chains, the only
    remedy was another release. The symptom was a fleet silently deaf to
    system events. A unit test can pin what a human once verified; it cannot
    catch the next drift between compiled identity and chain reality. This
    turns that class of failure into a node that refuses to start with both
    values in the error. See #1913.

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
- **The proof chain does not authenticate a struct's SHAPE, only its
  bytes.** `DWalletCoordinatorInnerV1` and `DWalletNetworkEncryptionKey`
  are plain `#[derive(Serialize, Deserialize)]` structs with no version
  tag. A Move field-add WITHIN the same version therefore mis-decodes
  while passing every gate above — committee BLS, artifacts digest,
  Merkle inclusion, id-binding, currency — because every one of those
  proves the bytes are the chain's, and none proves the reader's struct
  still matches them. Contrast `VersionedMPCData`, a tagged enum that
  fails closed on an unknown variant. Treat "it verified" as a statement
  about provenance, never about well-formedness, and give any new leaf
  type read through this path a version tag.
- **`OBJECT_DIGEST_CANCELLED` is bucketed as `Modified -> Current`** in
  the changeset fold. A cancelled transaction's object entry is not a
  real modification, so folding it as one attributes a currency claim to
  a state the chain never adopted. This is an open soundness question
  against live code, not a known exploit — it is recorded here because
  the analysis that found it lives in a plan that may not survive, and
  nothing in the code names the case.
- **The children index and the binding check disagree on who a child's
  parent is.** The persisted-cache rebuild keys the index off
  `Owner::ObjectOwner(addr)` unconditionally, while the binding check
  accepts either the collection UID or the derived `Field<Wrapper<K>,ID>`
  id. For an `ObjectBag`/`ObjectTable` child the two resolve differently.
  Harmless only because `children_of` has no production caller today —
  every reference is inside `mod tests`. Whoever wires the first real
  caller has to reconcile them first.
- **The end-of-publish retention floor is not coupled to a lagging
  peer.** `eop_retention_floor()` clamps to the direct node's OWN oldest
  persisted committee summary; nothing couples it to any peer's ratchet
  position. A checkpoint-archive fallback narrows the consequence on
  mainnet and testnet, but `resolve_sui_checkpoint_archive` returns
  `None` for `Devnet | Custom`, so on a localnet a far-behind peer-only
  node can still wedge.

## Operational signals

Every consumer-side verification failure increments
`ika_ocs_proof_verify_failures_total{kind,reason}` with fixed call-kind and
reason enums. A stale-but-valid object version additionally increments
`ika_ocs_high_water_violations_total`. A successful proof-verified read on the
peer-only relay path updates `ika_ocs_last_successful_relay_timestamp_seconds`;
the gauge starts at zero on process start and cache/direct reads do not update
it. `ika_ocs_watermark_implausible_total{consumer}` counts latest-checkpoint
watermark samples refused by the rate bound (`folder` = the checkpoint folder's
scan bound and persisted cursor, `reader` = the freshness floor); steady state
is zero, and any increase means an upstream is claiming advance faster than
checkpoint production can explain — or that this process was paused longer than
the bound's burst covers, which a restart clears. Refusals leave the folder's
cursor *behind* the chain head, the opposite signature to a poisoned cursor. These metrics contain no object
id, checkpoint digest, peer identity, raw error, or proof material.

Code anchors: `crates/ika-core/src/sui_connector/` — `verified_reader.rs`
(verification, freshness/high-water, bag-membership binding),
`committee_store.rs` (committee trust + ratchet install),
`ocs_verifier.rs` (ratchet loop + fallback), `setup.rs` (bootstrap plan,
anchor digest gate, stack wiring), `bag_event_pump.rs` (event pump +
omission detector), `push_worker.rs` / `verified_state_cache.rs`
(direct-side checkpoint folder + cache fast path);
`crates/ika-network/src/sui_state_mirror/` (relay client/server) and
its sibling `crates/ika-network/src/proof_provider.rs` (shared by the
relay server and the sui-state-direct local consumer);
`crates/ika-node/src/lib.rs`
(role/transport gate, peer-only boot); `crates/ika-config/src/node.rs`
(`SuiConnectorConfig`, `SuiDataSource`, anchor fields); proof primitives
in the pinned `sui-light-client` (`proof/base.rs`, `proof/ocs.rs`).

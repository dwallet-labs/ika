# OCS read-path binding & verification (security-model review)

**Status:** active — one hardening item open (`ocs-binding-1`, the `pending_active_set`
owner-binding); the rest is a record of *current* behavior worth keeping.
**Date:** 2026-06-26. **Branch:** feat/ocs-grpc-migration (#1744).

Four reviewer questions on the OCS verified-read trust model, answered against the
code (every claim cites `file:line`). The one actionable gap is tracked as
`ocs-binding-1` in [`../reviews/ocs-1744-pre-merge-review.md`](../reviews/ocs-1744-pre-merge-review.md).

---

## Q1 — Does a direct validator also verify the proof, like a peer-only validator?

**Committee chain: yes, identically.** Both roles ratchet `committee[E]→[E+1]` by
BLS-verifying each end-of-epoch checkpoint (`ocs_verifier.rs:141-245`,
`committee_store.rs:365-400`) — no shortcut on either.

**Object reads: same crypto, different trust root.**
- **Peer-only** re-verifies *every* read off the relay (committee BLS + Merkle
  inclusion + currency + high-water) because the relay is untrusted
  (`setup.rs:436-455`, `cache_first = false`).
- **Direct** builds + verifies the proof **once** at fold time from its *own* gRPC
  uplink, caches the post-verification snapshot `{object, proof, summary, seq}`, and
  on a cache hit serves it **without re-verifying** (`verified_reader.rs:193-236`,
  `360-425`). On a cache miss or when the staleness tripwire fires (cache lags >100
  checkpoints) it re-fetches and re-verifies.

A direct validator's ultimate trust root is **its own gRPC uplink**; a peer-only
validator's is the **committee signature**. Both enforce per-object high-water
monotonicity on every read. No design/code gap here.

```
  committee chain        DIRECT: BLS-verify (ratchet)  ═  PEER-ONLY: BLS-verify (ratchet)
  object read (hit)      DIRECT: serve cached snapshot  →  PEER-ONLY: (no cache-first)
  object read (miss)     DIRECT: fetch own gRPC + verify →  PEER-ONLY: fetch relay + verify EVERY read
  trust root             DIRECT: own uplink             ≠  PEER-ONLY: committee signature
```

## Q2 — Is all data cached per checkpoint? ika-only? verifiable per checkpoint?

- **ika-only: yes.** The folder ingests an object only if *any address in its Move
  type tree* matches one of the 5 pinned ika package ids (`push_worker.rs:303-313,
  388-414`). Non-ika objects ika depends on (gas, dependencies) are **not** folded.
- **Not a per-checkpoint history.** The cache is keyed **per object-id**
  (`HashMap<ObjectID, VerifiedSnapshot>`, `verified_state_cache.rs:69-100`), holding
  the *latest* version, monotonic-by-version. The retain window bounds it.
- **"Verify all per checkpoint" is not the model.** Each cached object is
  committee-attested against *its own last-modifying checkpoint*, not one current
  checkpoint. A non-ika object read live is proven at the checkpoint it last changed
  (e.g. T-1000), and *rollback* protection then rests on high-water / freshness /
  currency, not on a per-checkpoint inclusion of everything.

## Q3 — Do we verify the Sui package / type of ika data?

**No — not at the verified-read surface.** The proof attests **(id, version, owner,
content digest)** only; the Move **type/package is not in the proof target** and is
**not asserted by `verified_reader`**. Proven bytes are
`bcs::from_bytes::<ExpectedType>()` — a *structural* decode; a different package with
an identical field layout would decode. Type/package is checked **only** at the
event-parsing boundary (`sui_event_into_request.rs:31-51`: `StructTag.address ==
pinned ika package` + module), not on `verified_system_inner` /
`verified_dwallet_coordinator_inner` / `verified_object`.

```
  PINNED ika package ids (IkaNetworkConfig)
        │  expected, but NOT consulted on the read path
        ▼
  PROVEN OBJECT ──► proof binds:  id ✓   version ✓   owner ✓   content-digest ✓
                                  TYPE / PACKAGE  ✗  (not in the proof target)
        │
        ├─ verified_system_inner()        → bcs::from_bytes::<SystemInnerV1>  ✗ no type assert
        ├─ verified_dwallet_coordinator() → bcs::from_bytes::<…Inner>          ✗ no type assert
        ├─ verified_bag_page()            → owner-bound ✓, type not asserted
        └─ [consumer] sui_event_into_request → ✓ asserts StructTag == pinned ika pkg + module
```

Mostly safe today because the trust-critical roots are read by a **pinned/derived id**
(Q4) — you can't be handed a wrong-typed object there without breaking the proof. The
exposure is real only where the **id itself is relay-chosen**, i.e. Q4's gap. The
architecture leaves type-checking to the consumer instead of enforcing it at the
proven-read surface.

## Q4 — Is every object relationship bound back to the pinned root?

**6 of 7 hops bound; 1 UNBOUND** (the `pending_active_set` read added with the
discovery feature). Roots = `IkaNetworkConfig.objects.{ika_system_object_id,
ika_dwallet_coordinator_object_id}` (config-pinned, trusted).

```
        PINNED ROOTS (config, trusted)
        system_object_id          coordinator_object_id
              │ (a) DERIVED              │ (a) DERIVED   (versioned child id, transport.rs:49-53)
              ▼                          ▼
        SystemInnerV1                DWalletCoordinatorInner
              │                          │ (a) inline
   ┌──────────┼─────────────┐           ▼
   │ (a)inline│ (a)inline    │      sessions_manager
   ▼          ▼              ▼           │ (b) OWNER-BOUND (verified_reader.rs:543-565)
 active   next/prev      validators      ▼
 committee committee     ObjectTable  session-event children ✓
 (bound by transitivity)  │ (b) OWNER-BOUND
              │           ▼ StakingPools ✓
              ▼
   pending_active_set (ExtendedField)
              │  (c) UNBOUND  ☠   (lib.rs:1093-1121, grpc_backend.rs:223-235)
              ▼
   list_dynamic_fields → .first() → read entry.object_id
   NO derive, NO owner-check against the wrapper id

  (a) DERIVED — child id computed locally from the parent → relay can't substitute
  (b) OWNER-BOUND — child proven, then proof-bound Owner checked == parent/derived id
  (c) UNBOUND — child id taken from an untrusted list, read without binding ☠
```

- **(a) Derived / inline:** roots→inner (versioned child id derived locally), and the
  three committees are **inline** in the proven `SystemInnerV1` bytes — so the actual
  epoch committee and quorum are fully bound.
- **(b) Owner-bound:** validator `StakingPool`s and `session_events` children — each
  proven child's `Owner` is checked `== bag_id` (or the derived wrapper id), else
  `BagMembership`.
- **(c) Unbound — `pending_active_set`:** `get_extended_field_value_bcs` lists the
  wrapper's single dynamic field and reads `.first().object_id` with **no derive and
  no owner-check**. A relay chooses which child id you read.

**Severity: real binding gap, LOW impact** (not "critical"):
- `pending_active_set` feeds **discovery only** (`known_peers`, merge-only), never
  consensus/committee/quorum — those come from the inline, bound committees.
- Resolved peers pass through `validator_info.verify()` + self-exclusion, so a relay
  **cannot inject an attacker-controlled peer** (it can't forge a `StakingPool`
  signature or a p2p address for a key it doesn't hold).
- Worst case: a malicious relay omits/staffs the staging set → it can *delay/deny a
  peer-only joiner's discovery* (availability), or show a stale joiner list. No
  trust/quorum break.

---

## Plan / actions

- [ ] **`ocs-binding-1` (HOP-4):** bind the `pending_active_set` ExtendedField child —
      after listing+reading the child, assert its proof-bound `Owner` is the wrapper id
      (`entry.owner == pending_active_set_id`), converting hop (c) → (b) and matching
      invariant #5. (We *list* rather than *derive* because the `Key()` child-id
      derivation produced a wrong id earlier; the owner-check is the right binding
      regardless.) Tracked in the review.
- [ ] **(consider) Q3 type assertion:** enforce a Move type/package assert at the
      verified-read surface (an optional `expected_type` on
      `verified_object`/`verified_*_inner`), or document the consumer obligation —
      today only the event path checks it. Lower priority; the pinned/derived ids cover
      the trust-critical roots.

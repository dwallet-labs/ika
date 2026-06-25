# Continuous trusted-peer discovery (active + next + previous committee + pending_active_set)

**Status:** design locked, `ika-types` mirror landed; rest in progress.
**Branch:** feat/ocs-grpc-migration (#1744).

## Why
A fresh peer-only (`SuiStateMirrored`, fallback=None) validator boots passively —
`wait_for_specific_peers` (ika-node lib.rs) returns once anemo `network.peer(id)` is
`Some` for one of its `sui_state_mirror_peers`, which an **inbound** dial satisfies. So
the bootstrap is: existing **direct** validators (always have a Sui uplink) keep
`pending_active_set` in their `known_peers` and **dial** the registered-but-not-yet-active
joiner. This replaces the static `seed_peers` workaround in the upgrade-test harness, and
fixes the same gap for real mainnet joiners. The fetch rides the node's existing
`SuiConnector` (direct gRPC on a direct node; the OCS verified relay on peer-only) — no
parallel reader, no fallback uplink.

Blueprint below produced + verified against the code by a mapping workflow.

---

# Implementation Plan: Continuous Trusted-Peer Feed

## 0. Verified facts (ground truth, checked against HEAD)

- **Channel**: `let (trusted_peer_change_tx, trusted_peer_change_rx) = watch::channel(Default::default());` at `ika-node/src/lib.rs:416`. `trusted_peer_change_tx` is a node field (set during construction, available on `Arc<Self>`).
- **Discovery handler is MERGE-only** — `discovery/mod.rs:268-276` iterates `new_peers` and only calls `known_peers().insert(...)`; never removes (TODO at `:266`). It coalesces via the watch channel and **early-outs entirely when `config.fixed_peers.is_some()`** (`:152`). → A continuous additive union push **coexists** safely with the existing startup (`:992`) and reconfig (`:2770`) pushes. No REPLACE semantics exist anywhere; **one task cannot "own"/prune the set**, but for the bootstrap goal (additive) that is exactly right. Leave the two existing `send_trusted_peer_change` calls in place (startup seed before first tick; reconfig is subsumed-but-harmless).
- **PeerInfo mapping** (`epoch_start_system.rs:252-276`): `peer_id = PeerId(network_pubkey.0.to_bytes())`, `address = p2p_address.to_anemo_address().into_iter().collect()`, `affinity = High`, plus the empty-address `warn!` guard. Self-exclusion is by `authority_name() != excluding_self`.
- **Resolver**: `SuiClient::get_validators_info_by_ids(Vec<ObjectID>) -> Vec<StakingPool>` (`lib.rs:575`), routed through `self.inner` (transport-agnostic: direct gRPC on a direct node, OCS verified relay on peer-only — no caller branching). Per pool, use `pool.validator_info.verify() -> Result<VerifiedValidatorInfo, u64>` (`staking.rs:53`, **non-panicking**; carries `network_pubkey` + `p2p_address` + `protocol_pubkey`). Do NOT use `verified_validator_info()` (panics).
- **Three committees** are inline on `system_inner.validator_set.{active_committee, next_epoch_committee: Option, previous_committee}` (`system_inner_v1.rs:37-39`); members carry only `validator_id`. Extraction pattern already exists at `pubkey_provider_updater.rs:52-69`.
- **`pending_active_set` is NOT readable today** — it is `ExtendedField { id: ObjectID }` (`system_inner_v1.rs:40`, `mod.rs:274`), a dynamic-field handle. The `SuiClientInner` trait (`lib.rs:955-1014`) has **no generic single-object read** method to reuse → net-new client code required (see §4, the one real blocker/fork).
- **Move layouts to mirror**: `extended_field.move:16` `Key()` (empty struct → empty BCS name bytes; phantom-`T` `ExtendedField<T>` is `{ id: UID }`). `pending_active_set.move:25-52`: `PendingActiveSetEntry { validator_id: ID, staked_amount: u64 }`, `PendingActiveSet { min_validator_count, max_validator_count, min_validator_joining_stake, max_validator_change_count, validators: vector<PendingActiveSetEntry>, total_stake, validator_changes: VecSet<ID> }`.
- **DF read primitives**: `derive_dynamic_field_id` (sui_types), `move_object_contents` (`transport.rs:85`), gRPC `transport.get_object(id)` (`grpc_backend.rs:85`), JSON-RPC `read_api().get_object_with_options(id, bcs_lossless())` (`lib.rs:1383-1395`). `pending_active_set` is a plain `df::add` field (NOT a dynamic *object* field) → use bare `derive_dynamic_field_id`, **not** `derive_object_field_wrapper_id`.
- **Upgrade-test harness**: `validator_seed_peers` and the `mirror.1`/`seed_peers` plumbing live in `crates/ika-upgrade-test/src/cluster.rs` (NOT ika-test-cluster). `sui_state_mirror_peers` is independent and must be kept.

---

## 1. Files to add / modify

### A. `ika-types/src/sui/pending_active_set.rs` (NEW)
Rust mirror of the Move struct so BCS-decode works:
```rust
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct PendingActiveSetEntry { pub validator_id: ObjectID, pub staked_amount: u64 }

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct PendingActiveSet {
    pub min_validator_count: u64,
    pub max_validator_count: u64,
    pub min_validator_joining_stake: u64,
    pub max_validator_change_count: u64,
    pub validators: Vec<PendingActiveSetEntry>,
    pub total_stake: u64,
    pub validator_changes: VecSet<ObjectID>,   // sui_types::collection_types::VecSet
}
```
`ID` in Move is `ObjectID` in Rust (32 bytes, identical BCS). Register `pub mod pending_active_set;` in `ika-types/src/sui/mod.rs`.

### B. `ika-sui-client/src/lib.rs` — new resolver method on `SuiClient` + new trait method
1. **New `SuiClientInner` trait method** (add near `get_validators`, `:976`):
   ```rust
   /// Read the `PendingActiveSet` value stored as the single `Key()`
   /// dynamic field under the ExtendedField wrapper `extended_field_id`.
   async fn get_pending_active_set(&self, extended_field_id: ObjectID)
       -> Result<Vec<u8>, Self::Error>;   // returns BCS of Field<Key, PendingActiveSet>
   ```
2. **New `SuiClient` method** that does the derive + decode, returning ids:
   ```rust
   pub async fn get_pending_active_set_ids(&self, ef: ExtendedField)
       -> Result<Vec<ObjectID>, IkaError> {
       let bytes = self.inner.get_pending_active_set(ef.id).await.map_err(..)?;
       // Field<Key, PendingActiveSet> — Key is empty, BCS-skippable; decode value.
       let field = bcs::from_bytes::<Field<(), PendingActiveSet>>(&bytes)?; // () == empty Key()
       Ok(field.value.validators.into_iter().map(|e| e.validator_id).collect())
   }
   ```
   (`Key()` BCS-encodes to zero bytes; a Rust unit `()` matches. Verify with a unit test round-tripping `Field<(), PendingActiveSet>` against on-chain bytes — if the wrapper layout disagrees, decode the raw `Field` header then the trailing value.)

### C. `ika-sui-client/src/grpc_backend.rs` — gRPC impl of `get_pending_active_set`
```rust
async fn get_pending_active_set(&self, ef_id: ObjectID) -> Result<Vec<u8>, GrpcSuiClientError> {
    let child = derive_dynamic_field_id(ef_id, &key_type_tag(), &[] /* empty Key() */)
        .map_err(GrpcSuiClientError::decode)?;
    self.object_bcs(child).await   // get_object + move_object_contents, already at :85
}
```
`key_type_tag()` = `TypeTag::Struct(StructTag { address: ika_common_pkg, module: "extended_field", name: "Key", type_params: [] })`. The package id is reachable via the backend's configured `ika_common_package_id` (same source the existing reads use). On the peer-only path `object_bcs`→`transport.get_object` lands on `VerifiedSuiTransport::get_object` (committee-verified) — no special casing.

### D. `ika-sui-client/src/lib.rs` JSON-RPC backend impl of `get_pending_active_set`
Mirror `get_system_inner` (`:1375-1395`): `derive_dynamic_field_id(ef_id, key_tag, &[])` → `read_api().get_object_with_options(child, bcs_lossless())` → `try_into_move().bcs_bytes`.

### E. `ika-core/src/sui_connector/trusted_peer_updater.rs` (NEW) — the continuous task
Template: `pubkey_provider_updater.rs:255-364` (loop + refresh + throttled-warn).

### F. `ika-node/src/lib.rs` — spawn the task
Insert in the `spawn_monitored_task!` block at `:1220-1235`.

### G. `ika-upgrade-test/src/cluster.rs` + `process.rs` — delete `validator_seed_peers` (§5).

---

## 2. Task structure (`trusted_peer_updater.rs`)

```rust
pub async fn refresh_trusted_peers_loop<C: SuiClientInner>(
    sui_client: Arc<SuiClient<C>>,
    sender: watch::Sender<TrustedPeerChangeEvent>,
    self_authority: AuthorityName,           // config.protocol_public_key()
    mut shutdown: broadcast::Receiver<Option<RunWithRange>>,
) {
    const REFRESH: Duration = Duration::from_secs(3);  // real-time; NOT epoch-scaled
    let mut cache: HashMap<ObjectID, Option<PeerInfo>> = HashMap::new(); // None = self/unresolvable-skip
    let mut last_sent: BTreeMap<PeerId, PeerInfo> = BTreeMap::new();
    loop {
        tokio::select! {
            _ = shutdown.recv() => break,
            _ = tokio::time::sleep(REFRESH) => {}
        }
        match refresh_once(&sui_client, self_authority, &mut cache).await {
            Ok(union) => {
                if union != last_sent {                       // diff: send only on change
                    let new_peers = union.values().cloned().collect();
                    if sender.send(TrustedPeerChangeEvent { new_peers }).is_err() { break; }
                    last_sent = union;                        // keep last good set
                }
            }
            Err(e) => { /* throttled warn!; keep last_sent untouched */ }
        }
    }
}
```

`refresh_once`:
1. `let (_, SystemInner::V1(si)) = sui_client.get_system_inner().await?;` — single anchor read; all three committees are inline.
2. Build `BTreeSet<ObjectID>` union of: `active_committee.members`, `next_epoch_committee` (Option → empty), `previous_committee.members`, and `get_pending_active_set_ids(si.validator_set.pending_active_set).await?`. **`pending_active_set` is the load-bearing set** — it is the only one containing a fresh joiner before it reaches `next_epoch_committee`; without it the bootstrap WHY fails.
3. **Resolve with the stable cache**: partition union ids into cached vs uncached. `get_validators_info_by_ids(uncached_ids)` for the misses only (steady state ≈ 0 misses → the poll is mostly a `SystemInner` read + DF read). Per resolved pool: `verify()` → if `Err`, `warn!` + cache `None` (skip); else build `PeerInfo` via the shared mapper (§ self-exclusion below); cache it keyed by `validator_id`.
4. **Cache invalidation**: validator network metadata only changes at epoch boundary (`next_epoch_*` rotation). Track `si.epoch()`; on epoch change, `cache.clear()` so rotated addresses are re-resolved. (Cheap and correct; avoids a stale p2p address surviving a key rotation.)
5. Return `BTreeMap<PeerId, PeerInfo>` for the union (deterministic, dedups by peer_id across the four overlapping sets).

**Extract a shared mapper** to avoid duplicating the `epoch_start_system.rs:256-273` block: add a free `fn verified_info_to_peer_info(&VerifiedValidatorInfo) -> PeerInfo` (preserving the empty-address `warn!`), and refactor `get_validator_as_p2p_peers` to call it. One definition, two callers.

---

## 3. Reading via SuiConnector (peer-only over OCS relay)

The task takes the node's existing `Arc<SuiConnectorClient>` (`sui_client` in scope at `lib.rs:1202`), whose `self.inner` is `SuiBackend` dispatching to direct gRPC or the OCS verified relay transparently. **No branching in the task.** All four reads decompose into `get_object`/`list_dynamic_fields`/`batch_get_objects`, each served by `VerifiedSuiTransport` (committee-checked) on peer-only:
- `get_system_inner`, `get_validators_info_by_ids` — already relay-safe (existing reuse precedent: `pubkey_provider_updater`, `sui_syncer`).
- New `get_pending_active_set` → one `get_object(child_id)` with a **locally-derived** `child_id` (pure `derive_dynamic_field_id`, no network) → `VerifiedSuiTransport::get_object` → `verified_object`. The ExtendedField wrapper UID + its `Key()` child are long-lived (persist across epochs) → satisfies the verified reader's high-water-mark version constraint (not a short-lived session bag child). **Freshness caveat (not feasibility)**: on peer-only the pending set reflects the latest *verified* version the relay has proven — monotonic, can lag chain tip by relay checkpoint latency; acceptable for ~3s bootstrap-dial.

---

## 4. Self-exclusion, error handling, MERGE vs REPLACE

- **Self-exclusion**: compare `(&verified.protocol_pubkey).into(): AuthorityName` against the task's `self_authority = config.protocol_public_key()`. Cache `None` for self so it's skipped every tick without re-resolving. (Matches `get_validator_as_p2p_peers`'s `authority_name() != excluding_self`.)
- **Unresolvable / withdrawn / malformed validator**: per-id, never abort the refresh. Use `verify()` (Result), not `verified_validator_info()` (panics). On `verify()` `Err`, missing pool, or empty `to_anemo_address()` → `warn!` + skip that id (cache `None`), push the rest. (Contrast `get_epoch_start_system`, which hard-errors `InvalidCommittee` — must NOT inherit.)
- **Transient read failure** (`get_system_inner`/`get_validators`/`get_pending_active_set` returns `Err`): throttled `warn!`, **do not** touch `last_sent` — keep last good set, retry next tick. The watch channel already holds the last value for the consumer; not sending leaves known_peers intact.
- **MERGE vs REPLACE**: handler is **MERGE-only** → the task is purely additive and composes with the existing startup/reconfig pushes. No fold-in of the reconfig active-set push is required; leave `:992` and `:2770` as-is. The task re-adds the active set every 3s anyway.
- **`fixed_peers` nodes**: handler early-outs at `:152`, so the task is a harmless no-op there (correct — that's the static-seed path being deleted).

---

## 5. Spawn point (`ika-node/src/lib.rs:1220-1235`)

Add alongside the existing `monitor_joiner_announcements` / `monitor_reconfiguration` spawns (do NOT reuse `sui_client_clone`, which is moved into `monitor_reconfiguration` at `:1227`):
```rust
let tp_sui_client = sui_client.clone();
let tp_sender = node.trusted_peer_change_tx.clone();          // node field
let tp_self = config.protocol_public_key();                   // == authority_name (:413)
let tp_shutdown = node.shutdown_channel_tx.subscribe();       // node field (:1193)
spawn_monitored_task!(async move {
    ika_core::sui_connector::trusted_peer_updater::refresh_trusted_peers_loop(
        tp_sui_client, tp_sender, tp_self, tp_shutdown,
    ).await;
});
```
Confirm `trusted_peer_change_tx` is exposed on the node struct (it is a field; clone the sender — `watch::Sender` is `Clone`). All of `sui_client`, `config`, `node` are in scope here.

---

## 6. Upgrade-test change: delete `validator_seed_peers`, KEEP `sui_state_mirror_peers`

Once the feed runs, an existing DIRECT validator's known_peers includes `pending_active_set` → it DIALS the registered-but-not-yet-committee joiner. The joiner's `wait_for_specific_peers` (`lib.rs:1434`) is satisfied by that INBOUND connection. So the static seed is no longer needed; the relay-peer config still is.

In `crates/ika-upgrade-test/src/cluster.rs`:
- **Delete** the `validator_seed_peers: Vec<SeedPeer>` field (`:75`), its init (`:293`,`:410`), the `.push(SeedPeer{...})` (`:719-722`), and `fn active_validator_seed_peers` (`:746-753`).
- **`add_joiner_validator_mirrored` (`:575-588`)**: drop `let seed_peers = self.active_validator_seed_peers();`; pass only mirror peers. Change `add_joiner_validator_inner`'s `mirror` param from `Option<(Vec<String>, Vec<SeedPeer>)>` to `Option<Vec<String>>` (mirror peers only).
- **`add_joiner_validator_inner` (`:678-684`)**: keep the `SuiStateMirrored { fallback_grpc_url: None }` + `.with_sui_state_mirror_peers(mirror_peers)` builder calls unchanged.
- **`:695-701`**: delete the `if let Some((_, seed_peers)) = &mirror { node_config.p2p_config.seed_peers = seed_peers.clone(); }` block entirely — this is the static workaround being removed.
- Keep `validator_peer_ids` and `peer_ids_of` (`:717`,`:729`) — `sui_state_mirror_peers` is built from them.
- `process.rs` (`:35`, `rewrite_config_to_mirrored`) is untouched — it only sets `sui_state_mirror_peers`, never seed_peers.

**Verification of the deletion**: run the upgrade-test peer-only-joiner scenario (`add_joiner_validator_mirrored`) and confirm the joiner boots (its `wait_for_specific_peers` returns from an inbound dial) and reaches the next epoch, with NO `p2p_config.seed_peers` set. Per the repo's test-testing rule: also confirm the negative — temporarily stub `get_pending_active_set_ids` to return empty and verify the joiner now FAILS to be dialed (proving the pending-set feed, not residual seeds, is what dials it), then revert.

---

## Blockers / design forks (flag before building)

1. **`pending_active_set` read is the one real net-new piece** (§1B-D, §4): new Rust types + a new `SuiClientInner` trait method + two backend impls. Everything else is a copy of existing patterns. This is load-bearing — the bootstrap dial depends specifically on the pending set (active/next/previous never contain a fresh joiner during the registration window). **Confirm the `Field<(), PendingActiveSet>` BCS layout with an on-chain round-trip test before relying on it** — the empty-`Key()` name encoding is the fragile assumption.
2. **No REPLACE / no eviction** (verified): departed peers are never pruned (handler TODO `:266`). Fine for the additive bootstrap goal; if pruning is ever wanted it's a separate change to the discovery handler, out of scope here.
3. **3s cadence vs RPC cost**: above the 2s floor flagged in `validator_metadata.rs`; with the `validator_id→PeerInfo` cache, steady state is ~1 `get_system_inner` + 1 DF `get_object` per tick (no `get_validators`, no mpc_data read). Acceptable. Confirm the relay backend tolerates this poll rate per peer-only node.

# Continuous trusted-peer discovery (peer-only joiner bootstrap)

How a freshly-registered **peer-only** validator gets dialed and boots with
no static seed peers and no direct Sui uplink. Landed on
`feat/ocs-grpc-migration` (#1744); supersedes the `validator_seed_peers`
upgrade-test workaround.

## The problem

A peer-only validator (`SuiStateMirrored { fallback_grpc_url: None }`) reads all
Sui state over the OCS verified relay — but at boot it has no committee on disk
and no uplink, so it cannot dial anyone. Its only path onto the p2p network is an
**inbound** dial: `wait_for_mirror_peers` (`ika-node/src/lib.rs`) returns once a
usable relay peer is connected — with a pinned `sui_state_mirror_peers` override,
anemo `network.peer(id).is_some()` for one of the configured ids; without one
(automatic discovery), once a connected peer answers a cheap SuiStateMirror probe
— and an inbound connection satisfies either. So *something already on the
network must dial the joiner first*. A just-registered joiner is in the on-chain
`pending_active_set` but not yet in any committee, so the existing
startup/reconfig peer pushes (which feed only the active committee) never mention
it.

## The mechanism

Every validator runs `refresh_trusted_peers_loop`
(`ika-core/src/sui_connector/trusted_peer_updater.rs`), spawned at node startup.
Every **3 s** (`REFRESH_INTERVAL` — wall-clock, NOT epoch-scaled) it:

1. Reads `get_system_inner()` once and unions the validator-ids from four sources
   (dedup by `ObjectID`):
   - `active_committee` — current quorum.
   - `previous_committee` — still needed for cross-epoch signature aggregation.
   - `next_epoch_committee` (`Option`) — joiners that will activate at the boundary.
   - `pending_active_set` — **load-bearing**: the only set a fresh joiner appears in
     during the registration window, before it reaches `next_epoch_committee`.
2. Resolves ids to `StakingPool`s (`get_validators_info_by_ids`), `verify()`s each
   (non-panicking; skip + warn on failure), and maps each to a `PeerInfo`
   (`peer_id = PeerId(network_pubkey.0.to_bytes())`, `affinity = High`,
   `address = p2p_address.to_anemo_address()`), excluding self.
3. Sends a `TrustedPeerChangeEvent { new_peers }` over the watch channel **only when
   the resolved set differs** from the last one sent.

The discovery service (`ika-network/src/discovery/mod.rs`) **merges** the event into
anemo `known_peers` (insert-only; it never prunes). A direct validator therefore
dials the registered-but-not-yet-active joiner within ~3 s; that inbound dial
satisfies the joiner's `wait_for_mirror_peers` gate and it boots. (In automatic
discovery mode the gate additionally needs the dialing peer to answer a
SuiStateMirror probe, so a joiner dialed first by a *mirrored* validator keeps
waiting until a serving — sui-state-direct — validator's dial arrives.)

The read rides the node's own `SuiConnectorClient` (`self.inner` dispatches to direct
gRPC on a direct node, the OCS verified relay on a peer-only node), so there is no
parallel reader and no special-casing per topology.

## Invariants

- **Merge-only.** The discovery handler never removes peers (TODO at
  `discovery/mod.rs:266`); the loop is purely additive and coexists with the
  startup and reconfiguration pushes. Departed peers age out via anemo's own window,
  not this loop.
- **Self-excluded.** A node never dials itself: filter by
  `(&verified.protocol_pubkey).into() == self_authority`.
- **Degrade, don't abort.** A `pending_active_set` read failure logs a (throttled)
  warn and proceeds with the committee peers only — it must not drop the whole set.
  Likewise a single unresolvable/withdrawn validator is skipped, not fatal.
- **Keep the last good set.** A transient read error leaves `last_sent` untouched; the
  watch channel still holds the last value, so `known_peers` is unaffected.

## Reading `pending_active_set` — the BCS framing

`pending_active_set` is an `ExtendedField<PendingActiveSet>` — a dynamic-field handle,
not an inline value. `get_pending_active_set_ids` (`ika-sui-client/src/lib.rs`) reads
it by **listing** the wrapper's single dynamic field (not by deriving the child id),
then decodes the child `Field<Key, PendingActiveSet>` object.

The trap: the child's bytes are `id: UID` (32) ++ `name: Key` ++ `value`, and on-chain
`ika_common::extended_field::Key` serializes to **one byte**, not zero (an "empty" Move
struct still carries a `bool` dummy field → `0x00`). So the value lives behind a
**33-byte** header — decode `Field<u8, PendingActiveSet>`, not `Field<(), _>`. The
decoder (`decode_pending_active_set`) tries `Field<u8, _>` → `Field<(), _>` → bare
value for robustness, and a unit test pins the framing against captured on-chain bytes
(`pending_active_set_tests::decodes_field_wrapped_pending_active_set_from_chain_bytes`).
See the general rule in [`../learnings/pitfalls.md`](../learnings/pitfalls.md)
("empty Move structs are one BCS byte, not zero").

## Accepted residuals

- **No eviction.** Departed validators are never pruned from `known_peers`; harmless
  for the additive bootstrap goal, but pruning would be a separate discovery-handler
  change.
- **Relay freshness.** On a peer-only node the pending set reflects the latest
  *verified* version the relay has proven — monotonic, can lag chain tip by relay
  checkpoint latency; acceptable for a ~3 s bootstrap dial.

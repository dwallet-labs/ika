# #1952 — root mechanism of the mid-epoch-restart MPC spectator, and the fix

Forensic synthesis grounded in the live wedged fleet (6/6 dWallet Labs
validators, epoch 363 mainnet / 366 testnet, `v1.2.6 74a44ed06deb`) and the
source at that commit. This CORRECTS the issue's root-cause dossier: the
mandated final reproduction step — reproduce
`SuiClientInner::get_network_encryption_keys` returning an empty map per
transport — came back **negative**, and the actual mechanism is one layer
further down, in the internal-presign ordinal stream.

## 1. What the reproduction disproved

The dossier's chain ended at "the transport/OCS layer returns a
silently-empty key-registry map." Measured against the live coordinator
(`0x5ea59bce…`, registry table `0xd0e04ada…`, size 1):

- The exact v1.2.6 read path (`GrpcSuiClient::get_network_encryption_keys` →
  `for_each_dynamic_child` → `SuiGrpcClient::list_dynamic_fields` →
  `sui.rpc.v2.StateService/ListDynamicFields`) returns the key, state
  `NetworkReconfigurationCompleted`. JSON-RPC agrees. The `sui-rpc` proto pin
  (`5b41bc7`) is identical v1.2.5↔v1.2.6 and field-number-identical to the
  fullnode's reflected schema.
- On the wedged pods: `ika_network_key_overlay_incomplete = 0` — and the
  syncer memoizes a key in `last_fetched_network_keys` ONLY on a complete
  merge (`sui_syncer.rs`, the `overlay_incomplete` branch), so the observed
  5s `"No new network keys to fetch"` stream is the *healthy* post-memoization
  shape, not an empty-read symptom.
- `network_key_loaded_epoch = <current epoch>` is only settable through
  `adopt_cert_verified_keys` → `instantiate_adopted_network_keys` →
  `update_network_key` (there is no persisted-state bypass), so adoption ran
  and the overlay was non-empty. Two dossier inferences were invalid:
  a *successful* adoption pass logs nothing at any level (the success arm is
  a bare map insert), and "zero adopt logs" therefore does not imply
  "adoption never ran."

## 2. The actual mechanism: an ordinal pursuit curve with zero closing speed

`next_internal_presign_sequence_number` (`mpc_manager.rs`) — the per-pool
counter that internal-presign `SessionIdentifier`s are derived from — is
in-memory. Every validator mints the SAME deterministic ordinal stream, which
is what lets the sessions reach quorum without any on-chain event. A
mid-epoch restart resets one validator's stream to 1 while the committee's
live window is (13h into a 24h epoch) tens of thousands of ordinals ahead:

1. The post-restart consensus replay reconstructs the epoch's completed
   internal-presign sessions as **terminal** entries in the session map
   (`session_origin: reconstructed_from_consensus`).
2. Every ordinal the restarted top-up loop mints is already terminal → the
   silent "already resolved without us" early-return in
   `try_activate_internal_presign_request`. No session is created; nothing
   ever activates; `ready_to_advance` is never sampled (it samples per
   *Active* session).
3. The `instantiated != completed` batch guard reopens only when the
   **pool-aggregated** `completed_internal_presign_sessions` counter advances
   — which peers' *live* completions do (saturating, keyed per pool, not per
   session). So the dead-mint rate tracks the live window's advance rate
   exactly: constant offset, zero closing speed, for the rest of the epoch.

Live signature (mainnet-1, ~3h wedged): 2,604/2,604 session-map additions
`active: false` (reconstruction); 1,737 "Topping up internal presign pools"
lines minting +1/+2 at the peer-completion ingest rate; `active = 0`;
`completed = 39,350`; zero warns/errors in the retained log. Event-driven
sessions (user Sign, NOA) still activate — their path checks
`key_public_data_exists`, which is true — so ONLY registry-driven
instantiation dies. Self-heal at the epoch boundary is structural: ordinals,
counters, pools, and slot markers are all per-epoch and reset fleet-wide
together.

Window changes that shaped (not caused) the incident: #1934's
slot-idempotent fills (`filled_presign_pool_slots`) correctly stopped
replayed fills from double-counting, which converted the pre-existing
post-restart collision from "inflated pool, quiet no-op" into "mints dead
ordinals, silently discards its own colliding refills"; #1922/#1916
downgraded every symptom log on the path; #1895 removed the syncer's
boot-window chain-read fallback (lengthening the key-adoption detour after
restart — the key still recovered via the stranded-key machinery).

## 3. Why every gate was green

`v125_rollout` performs exactly this restart — but its epochs are minutes
long and none of its gates assert per-validator top-up participation. Peers
absorb the sessions, `run_workload` passes on the event-driven path, and the
near-by boundary resets the ordinals before anything can notice. The missing
ingredient is **restart-to-boundary distance × a per-validator liveness
assertion on registry-driven instantiation**.

## 4. The fix

- **Seed** (`max_filled_presign_pool_slot`, `authority_per_epoch_store.rs`;
  consumed in `instantiate_internal_presign_session`): a pool's counter is
  lazily seeded on first touch from the persisted
  `filled_presign_pool_slots` high-water + 1. The markers are written on
  every fill and re-confirmed by replay, so the seed lands at-or-behind the
  replay frontier. No new table; write-discipline unchanged. Determinism:
  identifiers stay content-derived, and `high_water + 1` is exactly where
  the non-restarted majority's counters already are — this also heals the
  previously-documented "very late install is permanently ordinal-offset"
  mode.
- **Fast-forward**: the mint path skips ordinals whose sessions are already
  terminal (bounded, 512/mint, `internal_presign_ordinal_fast_forward_exhausted`
  invariant marker past the budget) and rejoins an in-flight
  `WaitingForSessionRequest` reconstruction in place (peers' buffered
  messages preserved). Only live mints count against the batch guard.
- **Silence-proofing**: `network_key_registry_read_empty` (registry read
  empty while the coordinator reports keys — the dossier's hypothesized
  state, previously legal-empty at every layer) and
  `stranded_network_key_missing_from_registry_read` (audited recovery pinned)
  in the syncer.
- **Recovery widening**: `adopt_cert_verified_keys` no longer memoizes an
  empty overlay (the syncer republishes only on a fetching pass, so an
  empty first Arc would latch `Arc::ptr_eq` for the epoch).
- **Gate**: `crates/ika-upgrade-test/tests/restart_spectator.rs` — restart
  one validator mid-epoch, far from the boundary, with production pool
  sizing, and require the restarted validator itself to log the seed and the
  one-shot "resumed live instantiation" marker within the epoch.

## 5. Diagnostics that would have caught this in minutes

- `ika_dwallet_mpc_session_state_count{state="active"} == 0` while
  `state="completed"` grows → spectator; check
  `sessions_reconstructed_total` for the reconstruction-only shape.
- `ready_to_advance_result_total` having NO series at all (vs `not_ready`
  samples) means zero sessions ever activated — different failure class from
  "sessions stuck not-ready".
- "Topping up internal presign pools" present while `active = 0` →
  ordinal-stream offset (pre-fix) — now the seed/fast-forward log lines and
  the `internal_presign_ordinal_fast_forward_exhausted` marker name it
  directly.

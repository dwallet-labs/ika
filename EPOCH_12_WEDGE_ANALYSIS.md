# Epoch Transition Wedge: Network-Key Consensus-Voting Path

This document describes a class of epoch-transition wedge that exists on `dev`
but not on `main`, traced from a reproduction on
`fix/sessions-manager-completion-equality`.

## Symptom

After a series of SDK integration tests against a localnet, the chain stops
advancing at epoch 12. The end-of-publish gate check stays in this state
indefinitely:

```
sync_dwallet_end_of_publish gate check
  epoch=12 ready=false locked=true
  all_epoch_sessions_finished=false
  user_completed=3 user_cap=4
  all_immediate_sessions_completed=false
  system_started=13 system_completed=12
  next_epoch_committee_exists=true
  all_network_encryption_keys_reconfiguration_completed=false
  all_noa_checkpoints_finalized=true
  calc_votes_none=true
```

A `DWalletEncryptionKeyReconfigurationRequest` event was emitted on chain at
the start of epoch 12 (the `system.started_sessions_count` ticked from 12 to
13). The validators never run the corresponding MPC session, so
`system.completed_sessions_count` never catches up, and the chain cannot
process `request_advance_epoch`.

## Timeline of the wedge

Reconstructed from `debug_output.txt`:

| Time                  | Event                                                                                                                                  |
| --------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| 13:07:38.740          | `process_request_advance_epoch()` runs. Epoch advances 11 → 12 on chain.                                                               |
| 13:07:39.446          | Old DWalletMPCService receives exit signal.                                                                                            |
| 13:08:09.282          | `process_mid_epoch()` runs and emits the reconfig event on chain.                                                                      |
| 13:08:14.618 – .631   | sui_executor `run_epoch epoch=12` starts on each validator.                                                                            |
| 13:08:14.658 – .696   | New `DWalletMPCService` spawned on each validator.                                                                                     |
| 13:08:14.664 – .700   | Each validator's `sui_syncer` reports `Observed 1 new events from Sui network module=sessions_manager` (the reconfig event).           |
| 13:08:24              | `try_receiving_next_active_committee: received committee committee_epoch=13 expected=13 matched=true`, `pending_for_next_active_committee=0`. |
| 13:08:14 – (forever)  | **No `Instantiating agreed network key from consensus-voted data` log appears for epoch 12.** Every prior epoch (0 – 11) had this log fire 4× within 2 – 5 s of spawn. |
| Every 30 s thereafter | `retrieved missed events from Sui successfully number_of_system_missed_events=1`. The recovery path keeps re-delivering the same event, which keeps getting re-queued and never advanced. |

The validators have the next active committee for epoch 13. The reconfig event
is being delivered (both via the broadcast push at 13:08:14 and via the
30 s recovery pull). But the request is being silently queued in
`requests_pending_for_network_key` because the validators have not loaded the
public data for the network encryption key yet — and they never will, because
they are waiting on a consensus-voted instantiation that does not happen this
epoch.

## Why the request is stuck

The request flow in `mpc_session.rs::handle_mpc_request` (dev):

```rust
if request.requires_network_key_data
    && let Some(network_encryption_key_id) =
        request.protocol_data.network_encryption_key_id()
    && !self.network_keys.key_public_data_exists(&network_encryption_key_id)
{
    // queue in requests_pending_for_network_key
    return None;
}

if request.requires_next_active_committee && self.next_active_committee.is_none() {
    // queue in requests_pending_for_next_active_committee
    return None;
}
```

A reconfig event has `requires_network_key_data: true` **and**
`requires_next_active_committee: true`. The network-key check is first, so the
event lands in `requests_pending_for_network_key[key_id]`.

The drain of that queue is gated on `newly_instantiated_network_key_ids`, which
is populated by `instantiate_agreed_keys_from_voted_data`. That function
returns a non-empty list only when `agreed_network_key_data` contains a key the
validator does not yet have locally. `agreed_network_key_data` is populated by
`handle_network_key_data_messages` once an authorized subset of validators has
broadcast a matching `ConsensusNetworkKeyData` transaction through consensus.

If that consensus agreement never lands (no message, no quorum, the round
carrying it is lost, etc.), `agreed_network_key_data` stays empty,
`instantiate_agreed_keys_from_voted_data` returns `[]`, the drain never runs,
the queue never empties, and the wedge persists.

## Why this happens on dev but not main

This is the architectural difference. On `main`,
`mpc_session.rs::handle_mpc_request_batch` calls `maybe_update_network_keys`
directly, pulling the public data **from the Sui watch channel** every
iteration:

```rust
// main
let newly_updated_network_keys_ids = self.maybe_update_network_keys().await;
```

There is no consensus-vote indirection. As soon as `sync_dwallet_network_keys`
publishes new key data on the Sui watch channel, the next iteration of
`handle_mpc_request_batch` instantiates the key locally and drains
`requests_pending_for_network_key`. A new epoch always re-fetches the data
(`sync_dwallet_network_keys` filters by `current_epoch > last_fetched_epoch`).
There is no dependency on consensus rounds for this path to make progress.

On `dev`, `maybe_update_network_keys` was removed from
`handle_mpc_request_batch` and replaced with the consensus-voted pipeline. The
commits that introduced this:

- **`649c514798` "Status Voting (#1627)"** — added `agreed_network_key_data`,
  `handle_network_key_data_messages`, the `sent_network_key_ids` filter on the
  send side, and the dependency on consensus quorum.
- **`2c0f727433` "Fix NOA checkpoint issues, split consensus messages
  (#1672)"** — split the consensus-output messages into typed DBMaps including
  `network_key_data_messages: DBMap<Round, Vec<ConsensusNetworkKeyData>>`, and
  reorganized `dwallet_mpc_service.rs` so that `instantiate_agreed_keys_from_voted_data`
  is the only path that produces `newly_instantiated_network_key_ids`.

The intent is sound — having validators agree on the exact key data they will
use is more robust than each validator pulling independently from Sui. But the
change introduces a new failure mode: any time the
`ConsensusTransaction::NetworkKeyData` round does not land cleanly at the
start of a new epoch, `requests_pending_for_network_key` becomes a dead queue
for the rest of that epoch.

On `main`, this failure mode simply does not exist, because there is no
consensus dependency on the network-key path.

## Suspected proximate trigger for epoch 12 specifically

Eleven prior epochs handled this transition cleanly. Epoch 12 wedged. The most
likely proximate trigger, from inspection of `debug_output.txt`:

- A ~35-second tokio thread stall observed at 13:08:14, coinciding exactly
  with the epoch 12 spawn. The stall ends with the new service already past
  its first iterations, so the window where `send_status_update_to_consensus`
  would normally fire its `NetworkKeyData` submission may have been missed.
- The 35 s stall is consistent with the SDK integration suite hitting the
  node with many concurrent requests right around the epoch boundary.

Worth verifying with focused logging:

1. After epoch 12 spawn, did each validator actually submit a
   `ConsensusTransaction::NetworkKeyData`? `send_status_update_to_consensus`
   returns early if `last_read_consensus_round` is `None`, and the
   `new_key_data` filter requires `state != AwaitingNetworkDKG`. Either could
   silently produce an empty submission.
2. If the transaction was submitted, did consensus deliver it back? Check the
   `network_key_data_messages` DBMap and `next_network_key_data` reads.
3. If consensus delivered it, did `handle_network_key_data_messages` collect
   an authorized subset of votes?

## Fix options

Two reasonable directions:

1. **Restore main's behavior for this path.** Re-introduce
   `maybe_update_network_keys` in `handle_mpc_request_batch` as a fallback.
   Keep the consensus-voted path as the primary, but if the watch channel has
   the data and consensus hasn't agreed yet, instantiate locally. This is a
   minimal-risk change that preserves dev's design intent while removing the
   single-point-of-failure.

2. **Make the consensus-voted path self-healing.** Retry the
   `NetworkKeyData` submission whenever the validator is in an epoch and
   has `requests_pending_for_network_key.len() > 0` but no agreed data yet.
   Today the submission only fires once per service lifetime (gated on
   `sent_network_key_ids`).

The second option is more architecturally consistent with the dev direction.
The first is faster to ship and closes the hole now.

## Reproduction notes

- Branch: `fix/sessions-manager-completion-equality`
- Localnet: `sui --force-regenesis` + ika validator stack, see
  `CLAUDE.md` "Local network preflight"
- Load: `sdk/typescript` integration test suite run sequentially with
  `bash scripts/run-integration-tests-sequential.sh --timeout 300`
- The wedge reliably appears within 10 – 15 epochs under this load.

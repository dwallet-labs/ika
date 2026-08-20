# Checkpoint-writer stall observability (single-notifier design)

How certified checkpoints reach Sui, why a stalled writer blocks the epoch
close network-wide, and the signals that make that stall loud and correctly
attributed (issue #1892: three writer outages in one week; the two epoch-close
stalls were near-silent in-protocol and lost their first debugging phase to
misattribution). Actors: the notifier's `sui_executor`, every validator's
`sui_syncer` EndOfPublish gate, and `ika-network` state sync.

## The write path and why it gates the epoch close

MPC session completions only reach the chain inside certified dwallet
checkpoints, submitted by the single notifier via
`process_checkpoint_message_by_quorum`. The close gate
(`all_epoch_sessions_finished` in `sui_syncer`, mirroring Move's
`advance_epoch` assertion) compares the coordinator's on-chain
`completed_sessions_count` with the frozen lock target — chain state only.
The epoch-switch calls (`process_mid_epoch`, pricing, the session lock,
`request_advance_epoch`) are likewise notifier-submitted.

This is a DELIBERATE single-writer design: exactly one node
(`notifier_client_key_pair` set, Notifier mode) publishes transactions.
Validators never submit — they only observe. A stalled notifier therefore
blocks EndOfPublish on every validator until the notifier is fixed or
restarted; recovery is operational, and the signals below exist to make the
outage minutes-to-detect instead of silent. (Redundancy directions that keep
a single writer identity — e.g. SIP-58 address-balance gas making
byte-identical submissions from replicated notifier processes safe — are
future work, deliberately out of scope here.)

## The two stall shapes and their signals

### 1. Sync-side stall: the writer has NOTHING to submit

The notifier receives certified checkpoints via p2p state sync. If its sync
wedges (the 2026-07 incidents: synced pinned at 0 while peers advertised
21k+), no submission is ever attempted, so the pre-existing
1h-of-failed-submissions error can never fire — from the binary's own
telemetry a fully-stalled writer looked identical to an idle one.

Signal (in `ika-network` state sync, both checkpoint streams): if same-chain
peers advertise checkpoints ahead of our VERIFIED watermark and that
watermark makes no progress for 120s, the node errors (rate-limited to 1/min,
"dwallet-checkpoint sync is STALLED" / "system-checkpoint sync is
STALLED" — the stream name is part of the string, so grep for the
`-checkpoint sync is STALLED` suffix to catch both) and exports
`ika_dwallet_checkpoint_sync_stall_seconds` /
`ika_system_checkpoint_sync_stall_seconds` (0 = healthy). The
`highest_known_*` gauges are refreshed every 5s from peer heights (not only
when a sync job runs, which is exactly what stops happening during this
stall). The tracker deliberately watches the VERIFIED watermark: the pull
path bumps it per fetched checkpoint, while the synced watermark is fed only
by the consensus output path and never advances on notifiers/fullnodes —
tracking synced would report a permanent false stall on exactly the node
this signal protects.

### 2. Submission-side stall, seen from the validators

Validators can distinguish "MPC hasn't completed the sessions" from
"completions are certified locally but absent from chain state" — the two
read identically through `user_sessions_lag` alone.

Signal (in `sync_dwallet_end_of_publish`): validators export
`ika_sui_connector_chain_dwallet_checkpoint_writer_lag` (highest
locally-certified dwallet checkpoint − the coordinator's
`last_processed_checkpoint_sequence_number`) and the EndOfPublish
blocked-reason gauge has a `checkpoint_writer_lag` label — set when sessions
are unfinished on chain AND certified checkpoints sit unlanded. It lights up
alongside `user_sessions_lag` and names the writer directly; the gate-stuck
WARN carries the same field. Sustained positive writer lag while the close is
blocked means: go fix the notifier, not the MPC pipeline. (Negative gauge
values mean the local certified store trails the chain — local sync lag, a
different problem. On a VALIDATOR, a negative value that never recovers is
its aggregator sitting below the epoch floor; see
[`checkpoint-sync-floor.md`](checkpoint-sync-floor.md), which is where that
resolves itself.)

## Key invariants

1. A wedged writer becomes visible within minutes from BOTH sides: its own
   sync-stall self-report, and every validator's writer-lag attribution — in
   particular in the sparse-traffic case where nothing reaches the
   submission path.
2. The signals are observability-only: no new transaction submitter exists;
   chain effects are identical with or without them.
3. `checkpoint_writer_lag` never blocks or fires EndOfPublish; it only
   annotates why the existing gate is unsatisfied.

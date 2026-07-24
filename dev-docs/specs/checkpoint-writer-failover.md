# Checkpoint-writer roles and failover (primary notifier, fallback writers, stall observability)

How certified checkpoints and epoch-switch calls reach Sui, why the
writer used to be a network-halting single point of failure (issue
#1892: three writer outages in one week, two of which stalled testnet's
epoch close until a human restarted the notifier), and the rules the
failover follows. Actors: the primary notifier's and any fallback
writer's `sui_executor`, every validator's `sui_syncer` EndOfPublish
gate, and `ika-network` state sync.

## The write path and why it gates the epoch close

MPC session completions only reach the chain inside certified dwallet
checkpoints, submitted by a *writer* via
`process_checkpoint_message_by_quorum`. The close gate
(`all_epoch_sessions_finished` in `sui_syncer`, mirroring Move's
`advance_epoch` assertion) compares the coordinator's on-chain
`completed_sessions_count` with the frozen lock target — chain state
only. The epoch-switch calls (`process_mid_epoch`, pricing, the session
lock, `request_advance_epoch`) are likewise writer-submitted. A stalled
writer therefore blocks EndOfPublish on every validator, indefinitely;
no MPC-side health compensates.

## Writer roles

A node's writer role is fixed by config, mutually exclusive:

- **Primary notifier** — `notifier_client_key_pair` set (Notifier-mode
  node). Acts on every submittable step immediately. Unchanged
  behavior, including the crash-after-one-hour-of-failed-submissions
  policy (the panic is the loudest available signal; the supervisor
  restarts the process).
- **Fallback writer** — `fallback_notifier_client_key_pair` set
  (validator or fullnode; rejected on the notifier itself — a fallback
  must survive the primary's outage, so it lives on another node). Runs
  the identical submission machinery but holds every step behind the
  `FallbackGate`.
- Everyone else — no keys, no submission (unchanged).

Funding: each fallback key's derived address is operator-funded with
SUI and MUST differ from the primary's address (two writers driving one
gas object would equivocate). A fallback node must have a direct Sui
uplink; `select_sui_transport` rejects a peer-only (`sui-state-mirrored`
without `fallback-grpc-url`) node carrying a fallback key, same rule as
for the notifier.

## Decision rules (`FallbackGate`, `sui_executor.rs`)

1. **Act only on observed primary staleness.** A fallback performs a
   step only after that step has been *continuously actionable* for
   `fallback_notifier_activation_delay_secs` (default 300s). Actionable
   is the same chain-derived predicate the primary uses (checkpoint N is
   in the local store and the on-chain cursor still wants N; a switch
   step's guard holds). A healthy primary clears steps in seconds, so
   the delay never elapses.
2. **Instance keying.** The timer is keyed per step, and per instance
   for checkpoints (the sequence number): when the primary lands
   checkpoint N and N+1 becomes pending, the delay restarts. A slow but
   live primary never trips the fallback.
3. **Disarm when not pending.** A step that stops being actionable
   (primary acted, or nothing certified yet) clears its timer.
4. **Duplicate submissions are safe, so racing is the mechanism.** All
   writer transactions are sequence-/state-checked in Move
   (checkpoint cursor equality, epoch-switch guards); when both writers
   submit, the loser's transaction aborts with no effect beyond its own
   gas. First-wins needs no coordination.
5. **A fallback never panics on submission failure.** After its (short,
   120s) retry window it logs an error and re-derives pending work from
   fresh chain state next tick. Rationale: a lost race against a
   recovering primary is indistinguishable from persistent failure at
   the submission site, and the primary's panic policy would crash a
   healthy validator over a benign race. The primary's hour-then-panic
   policy is unchanged.
6. **Per-epoch state.** The gate's timers live and die with
   `run_epoch`, like the epoch-switch memos; nothing survives an epoch
   boundary.

## Observability (the two incidents were near-silent in-protocol)

- **Writer-side sync-stall self-report** (`ika-network` state sync):
  if same-chain peers advertise checkpoints ahead of our synced
  watermark and the watermark makes no progress for 120s, the node
  errors (rate-limited to 1/min) and exports
  `ika_dwallet_checkpoint_sync_stall_seconds` /
  `ika_system_checkpoint_sync_stall_seconds` (0 = healthy). This covers
  the incident shape where the writer had *nothing to submit* (synced
  pinned at 0 while known grew to 21k), which the
  submission-failure log can never catch.
- **Close-gate writer attribution** (`sui_syncer`): validators export
  `ika_sui_connector_chain_dwallet_checkpoint_writer_lag` (local
  certified head − on-chain cursor) and the EndOfPublish blocked-reason
  gauge gained the `checkpoint_writer_lag` label — set when sessions
  are unfinished on chain *and* certified checkpoints sit unlanded, so
  operators see the writer named instead of diagnosing through
  `user_sessions_lag`.
- **Takeover visibility**: a fallback's actions increment
  `ika_sui_connector_fallback_writer_actions_total` (0 on a healthy
  network — alert on any increase) and log a
  "fallback writer taking over" warning per step.

## Key invariants

1. With a healthy primary, a fallback writer submits nothing (the
   activation delay strictly exceeds steady-state primary latency).
2. With the primary stalled or dead, every submittable step is
   performed at most one activation delay + retry late — the epoch
   close completes without human intervention.
3. No writer-role configuration can crash a validator via the writer
   path (fallbacks never panic on submission failure).
4. Writer failover changes WHO submits, never WHAT: checkpoint bytes
   and their quorum signatures come from the same certified stores, so
   chain effects are identical whichever writer lands them.
5. The primary and fallback addresses are distinct (enforced
   operationally; same-node dual-role is rejected at config
   validation).

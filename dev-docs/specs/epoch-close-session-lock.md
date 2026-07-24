# Epoch-close session lock (target freeze, completion gating, EndOfPublish predicate)

How an epoch decides which user sessions belong to it, why completing
the wrong set wedges the epoch permanently, and the rules every
completion path must follow. Actors: the Sui coordinator contract
(`sessions_manager.move`), the notifier validator's `sui_executor`,
every validator's `DWalletMPCService`/`DWalletMPCManager`, and the
`sui_syncer` EndOfPublish gate.

## The lock target

User-session sequence numbers are assigned on-chain at request time
(`sessions_manager.move::initiate_session`); validators cannot disagree
on a session's number. The coordinator maintains
`last_user_initiated_session_to_complete_in_current_epoch` (the "lock
target"): on every user-session initiation and completion it ratchets to
`min(completed_sessions_count + max_active_sessions_buffer, latest
initiated)`, monotone non-decreasing within an epoch.

At epoch end the notifier calls `request_lock_epoch_sessions`, freezing
the target. From then on the epoch's user-session set is fixed: a
session with sequence number at or below the frozen target MUST complete
in this epoch; one above it MUST NOT — it re-enters next epoch via the
on-chain `session_events` bag and the uncompleted-events re-pull.

Validators learn the target by polling the coordinator object through
their fullnode (no event), so each validator's local view is a delayed
sample of a monotone sequence: local view ≤ frozen target, always.
Skew delays *when* a validator acts on a session, never *whether*.

## The close predicate is a strict equality

`all_current_epoch_sessions_completed` requires
`completed_sessions_count == frozen target` (plus system sessions
started == completed, every network key reconfigured, and the lock
flag set). The Rust EndOfPublish gate (`sui_syncer`) mirrors the same
equality from chain state, so no per-validator divergence on the
predicate is possible — it is chain-global.

The equality cuts both ways:

- **Undershoot** (`completed < target`): a locked-set session that can
  never complete blocks the close — by design, until it completes.
- **Overshoot** (`completed > target`): completing any session beyond
  the frozen target wedges the epoch **permanently and unhealably** —
  the counter never decreases, and Move's `advance_epoch` asserts the
  predicate forever. `complete_user_session` itself performs no lock
  check; nothing on-chain prevents overshoot. Prevention is entirely
  the validators' responsibility, per the rules below.

## Decision rule: gate consensus submission, never checkpoint content

Checkpoint contents must be a deterministic function of the consensus
sequence; the local lock view is wall-clock fullnode state. Gating at
checkpoint build would therefore fork checkpoints. The sound choke
point is what each validator independently submits to consensus —
per-validator divergence there is tolerated, and quorum provides the
safety argument:

> A validator votes for / reports a user session only when its local
> lock view covers the session's sequence number. The chain target is
> monotone within the epoch and frozen at lock, so any quorum that
> agrees on the session implies an honest validator observed the target
> covering it — hence the frozen target covers it, and completing it
> cannot overshoot.

Every user-session completion path applies the rule
(`seq <= last_session_to_complete_in_current_epoch`, local view):

- **MPC computation** (`perform_cryptographic_computation`): user
  sessions only advance when covered. System, internal-presign, and
  network-owned-address sessions always advance (system sessions have
  their own started == completed predicate; the others never complete
  user sessions on-chain).
- **Global presign votes** (`get_unsent_presign_requests`): a request
  beyond the local view is not voted for. Once agreed (quorum-safe per
  the argument above), serving from the internal pool needs no further
  lock check. Held requests retry every round as the view advances and
  re-enter next epoch otherwise.
- **Admission rejections** (`submit_rejections_covered_by_lock_target`):
  a quorum'd Rejected response counts as completed on-chain, so
  rejections of beyond-target user sessions are buffered
  (`pending_rejected_sessions`) and retried each service iteration.
  System/internal rejections are not lock-gated.
- **Computation-failure rejections** need no gate: the computation only
  ran because the local view covered the session.

Anyone adding a new path that produces an on-chain user-session
completion (success or rejection) must gate its consensus submission on
the local lock target. Gating anywhere else is either unsound
(checkpoint build — forks) or insufficient (serving time — the vote
already committed the network).

## Batch processing must never abandon sibling results

`handle_computation_results_and_submit_to_consensus` consumes a batch
of completed computation results. A result for a session that went
non-active while its computation was in flight (it completed via the
peers' output quorum — routine under load) is skipped per-item, never
by aborting the batch: dropping sibling results silently withholds
round messages, starving those sessions below the message threshold on
every validator that hits the same race, which manifests as an
undershoot wedge (internal presign pool never refills, locked-set
global presigns unservable).

## Key invariants

1. A user session completes on-chain in epoch N iff its sequence number
   is at or below epoch N's frozen lock target.
2. `completed_sessions_count` never exceeds the frozen target
   (overshoot is unrecoverable; enforced by submission gating).
3. Validators' lock views are monotone samples bounded by the chain
   value; agreement on any user-session output/vote implies the frozen
   target covers it.
4. Every locked-set session eventually completes: lock-view convergence
   is bounded by fullnode poll lag, votes/rejections retry per
   iteration, and the internal presign pool refills via always-advancing
   internal sessions.
5. One stale computation result never suppresses another session's
   round message or output report.

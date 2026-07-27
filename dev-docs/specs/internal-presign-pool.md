# The internal presign pool and its replay contract

How the internal presign pool is filled and drained, and the rule that keeps
a validator that restarted mid-epoch serving the same presigns as the peers
that did not (issue #1928). Actors: the internal-presign top-up loop and
output handler in `DWalletMPCManager`, the global-presign and NOA-demand
drains in `DWalletMPCService`, and the pool tables in
`AuthorityEpochTables`.

## What the pool is

Per (signature algorithm, network encryption key) FIFO of precomputed
presigns, held in per-epoch RocksDB tables (`internal_presign_pool_*`, keyed
`(network_encryption_key_id, session_sequence_number)`, value
`(SessionIdentifier, Vec<(blending_index, presign_bytes)>)`), plus a
denormalized count per pool in `internal_presign_pool_sizes`.

**Fill.** `instantiate_internal_presign_sessions` starts a batch of internal
presign MPC sessions whenever a pool is below its configured minimum (or
below its maximum while the network is idle). When such a session's output
reaches quorum in the consensus stream, `record_internal_presign_output`
writes its presigns into the pool slot named by that session's per-pool
sequence number.

**Drain.** Two consumers, both driven by consensus-sequenced requests:

- global presign requests — `DWalletMPCService` serves each request from the
  pool head and puts the presign bytes into a `RespondDWalletPresign`
  checkpoint message;
- NOA sign demands — each demand is assigned a presign, recorded in
  `noa_assigned_presigns` and read back at sign-session instantiation.

The pool is drained lowest-sequence-number-first, and within a slot in
blending-index order.

## The determinism requirement

The pool is network-uniform: every validator fills slot *n* of a pool from
the same quorum-agreed output, and drains in the same consensus-delivered
request order. So every validator binds the same presign to the same request,
and the checkpoint messages built from those presigns are byte-identical
across the committee. A validator that binds a different presign to a request
than its peers signs a checkpoint nobody else signs — an honest validator
producing a divergent computation, the false-malicious class.

## Fills complete out of sequence order

A top-up batch starts *s* sessions at once. They finish in consensus order,
not sequence order, so slot *n+1* is routinely filled before slot *n*. This is
normal and network-uniform (every validator sees the same completion order),
and the drain still takes the lowest sequence number present. It matters only
because it is what makes replay unsafe — see below.

## The replay contract

**`DWalletMPCService` replays every consensus round of the epoch after a
restart.** Its round cursor (`last_read_consensus_round`) is in-memory and
starts unset, so a restarted validator re-reads the whole per-epoch round
stream — re-absorbing every internal presign output and re-draining every
global presign request and NOA demand.

**The pool is NOT reset for that replay.** It is durable per-epoch state, so
the replay runs against a pool holding whatever survived the crash. That
breaks the naive assumption that re-executing the same rounds reproduces the
same decisions:

- a slot filled late in the epoch, still holding presigns at crash time, is
  visible to drains replayed at rounds *before* its own fill round. When its
  sequence number is lower than the head at that round — routine, given
  out-of-order fills — the replayed drain takes it, and the request is bound
  to a different presign than the original run bound;
- a fill absorbed twice double-counts `internal_presign_pool_sizes`. The
  count feeds the top-up decision, so an inflated count reads as a full pool,
  suppresses top-ups, and starves the pool while its own gauge reports it
  healthy;
- a fill absorbed twice also resurrects presigns that were already served,
  which can hand one presign to a second on-chain presign id.

**Therefore both directions must be idempotent, and each must record its
idempotency marker in the same committed batch as the state it guards:**

| operation | idempotency key | marker table |
|---|---|---|
| fill (`insert_presigns`) | `(signature algorithm, network key id, session sequence number)` — the slot | `filled_presign_pool_slots` |
| global presign serve (`serve_global_presign`) | request's session sequence number | `served_global_presigns` |
| NOA demand assign (`assign_noa_presign`) | demand id digest | `noa_assigned_presigns` |

A repeated fill is a no-op. A repeated serve or assign returns the presign it
returned the first time, without touching the pool. Replay is then a no-op on
the pool by construction, and the restarted validator's checkpoint messages
match its peers' regardless of where it crashed.

The batching is load-bearing in both directions: a pool mutation that landed
without its marker is re-applied on the next replay, and a marker that landed
without its mutation loses the presigns (fill) or serves a presign the pool
never gave up (drain).

`pop_presign` is the bare, self-committing pop. It is correct only for
callers whose work is never replayed from the round stream — in practice,
tests. Production drains go through the recorded variants above.

## What this does not fix

The per-pool *session ordinal* counters (`instantiated_internal_presign_sessions`
/ the next-sequence-number counters) are in-memory and rebuilt by replay, and
a validator whose first top-up of a pool lands more than one batch lifecycle
behind its peers starts that pool's ordinal stream offset and never converges
(issue #1830). That is a separate defect with a separate heal
(fast-forwarding the ordinal from the completed sequence numbers observed in
consensus outputs); pool-slot and serve idempotency does not address it.

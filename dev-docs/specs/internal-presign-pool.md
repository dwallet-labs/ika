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

## Which pool a demand draws from

A pool is keyed by `(signature algorithm, network encryption key)`, so
draining a demand starts by choosing an algorithm. That choice comes from
the demand's IDENTITY (`NOAPresignDemandId::expected_signature_algorithm`),
never from the announcement that carried it.

The reason is the dedup key. Presign-demand announcements are deduplicated
on the demand-id digest ALONE — deliberately, so several validators
announcing the same demand collapse into one consensus transaction — and the
consequence is that the first announcement sequenced for a demand would
supply any payload field the drain reads, for the whole network, while every
honest duplicate is dropped behind it. A committee member could then pick the
pool for any demand whose id it can predict, and demand ids are derivable
from public data.

Deriving is what removes that, and it is stronger than validating the
announced value:

- **Rejecting a mismatch is unsafe.** The honest announcements were already
  deduplicated away, so no correct one can follow: the demand stays
  unassigned, its sign never happens, and the epoch cannot finalize its NOA
  checkpoints. A substitution bug would have been traded for a stall.
- **Carrying no second copy is stronger than comparing two.** Both demand
  arms commit to their algorithm — the checkpoint arm through `kind_name`
  (whose mapping to the counterparty chain's algorithm is pinned by test),
  the attestation arm by carrying it in the identity — so an announcer
  naming a different algorithm produces a DIFFERENT identity, a demand no
  honest consumer looks up, rather than a competing answer for this one.
  Neither the consensus message nor the internal sign request carries an
  algorithm beside the id, so the pool drained and the session instantiated
  cannot disagree.

`network_encryption_key_id` is NOT covered by this reasoning and remains
announcer-supplied behind the same dedup key: it is frozen at announce time
on purpose, so the assignment does not depend on the announce-time and
instantiate-time key resolutions agreeing. Closing that half is issue #2019;
the shape it wants is park-rather-than-reject, pending the question of
whether honest validators can transiently hold different adopted key sets.

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
| drain (`assign_presign_for_demand`) | the `PresignDemand` identity — see below | per demand kind, below |

Draining is ONE entry point, `assign_presign_for_demand`, taking the demand a
presign is being assigned to. The demand's identity IS the idempotency key,
and it selects the marker table:

| `PresignDemand` | idempotency key | marker table |
|---|---|---|
| `GlobalRequest { session_sequence_number }` | the request's session sequence number | `served_global_presigns` |
| `Noa { demand_id }` | `NOAPresignDemandId::digest()` | `noa_assigned_presigns` |

There is deliberately no way to drain the pool without naming a demand: a
consumer that could pop bare would have to know this hazard to avoid it,
and the next consumer's author is exactly who the type is protecting. (The
`Noa` arm carries the identity type rather than a bare digest for the same
reason — any other 32-byte value would type-check while keying the
assignment wrong.)

A repeated fill is a no-op. A repeated drain returns the presign it returned
the first time, without touching the pool. Replay is then a no-op on the pool
by construction, and the restarted validator's checkpoint messages match its
peers' regardless of where it crashed.

The batching is load-bearing in both directions: a pool mutation that landed
without its marker is re-applied on the next replay, and a marker that landed
without its mutation loses the presigns (fill) or serves a presign the pool
never gave up (drain).

The pool has no bare pop on any replayed path. `pop_presign_for_testing`
exists only so tests can inspect pool contents directly, and is
`#[cfg(test)]`-gated. (`assign_presign` — the user-facing pool-to-assigned-pool
move — does still pop unconditionally, but it has no consumer; a future one
must gain a demand identity before its stream can be replayed safely.)

## Ordinal-stream convergence

Slot and serve idempotency say nothing about *which* ordinals a validator
mints. That is the second, independent property the pool needs, and it has its
own failure mode (issues #1952, #1830).

**The ordinal stream.** Each pool's fill sessions are numbered by an in-memory
per-`(network key, curve, signature algorithm)` counter, and an internal
presign `SessionIdentifier` is derived from that ordinal. Nothing on chain
announces a fill session, so the committee agrees on one only because every
validator mints the same ordinal stream. The counter is in-memory and
re-derived per process, while the stream belongs to the epoch.

**The failure mode.** A validator that joins a pool's stream late — mid-epoch
restart, a very late key install, an epoch entered late, an empty or
state-synced store — starts minting ordinals the committee finished long ago.
Those mints can never produce live work: peers early-return on an
already-resolved identifier. Worse, the offset does not close on its own — the
in-flight batch guard reopens on the *pool-aggregated* completion counter,
which peers' live completions advance, so the dead-mint rate tracks the live
window's advance rate exactly. Constant offset, zero closing speed, for the
rest of the epoch. The validator is a spectator on that pool while every
event-driven path (user sign, NOA) still looks healthy. If more than f stake
is in that state at once — a rolling restart mid-epoch — the pool starves below
the MPC threshold, global presigns become unservable, and the epoch cannot
close.

**Three convergence sources, in order of local dependence:**

| source | where | needs |
|---|---|---|
| persisted fill high-water (`filled_presign_pool_slots`) | seed, on a pool's first mint this process | this validator's epoch store to hold the epoch's fills |
| completed ordinals observed in consensus outputs | seed, and a fast-forward on every completed output | nothing local — the output stream itself |
| terminal sessions in the session map | mint path, bounded per mint | this validator's session map, and a top-up actually firing |

The first and third normally agree with the stream — a fill is written by
every validator that processes the output, so a validator that has processed
the epoch's rounds holds both — and between them they converge the ordinary
mid-epoch restart. What they do not give is a rule with no precondition: both
act only at a pool's FIRST mint (the seed is read once) or only while a top-up
is firing, and both read state this validator may not have.

Every completed internal-presign output carries its `session_sequence_number`,
so the committee's completion frontier is consensus-anchored data every
validator holds regardless of what it instantiated, what its store persisted,
or whether it was in the pool when the ordinal was minted. The rule: on a
completed output for a pool whose next ordinal is at-or-below that sequence
number, jump the counter to one past it. It applies to a live counter, needs no
mint of its own, lands in one step instead of one ordinal per walk, and holds
when the durable proxies do not (a slot write that failed, a store that never
held the epoch's fills, a seed read that errored).

Safe by construction: the rule reads only consensus-agreed data, it moves a
counter only FORWARD and only to one past an ordinal the committee has already
completed (never past what peers have minted), and a validator already at the
frontier is untouched. Ordinals skipped this way are ordinals whose sessions
are already resolved — minting them could not have contributed anything.

**Observability.** The divergence is invisible from outside the process
otherwise — the counters are in-memory, and the symptom is "one pool gets no
advances from this validator" while everything else is healthy. Two metrics
name it directly:

- `ika_dwallet_mpc_internal_presign_ordinal_lag{curve, signature_algorithm,
  key_role}` — ordinals between this validator's next mint and the committee's
  completed frontier. A pool is minted before it completes, so a participating
  validator reads 0; sustained positive means the stream is not converging.
  Published by the top-up loop from the state at the top of a round, so a
  round that heals still publishes the divergence it started with.
- `ika_dwallet_mpc_internal_presign_ordinals_fast_forwarded_total{…}` — ordinals
  skipped to rejoin the frontier. The gauge reads 0 again once a jump lands, so
  this is what shows the condition occurred: one large jump is a validator
  rejoining a pool mid-epoch; a sustained dribble is a validator not minting
  for that pool at all and being dragged along by its peers' completions.

The seed and resume log lines (`seeded internal-presign ordinal stream…`,
`internal presign top-up resumed live instantiation…`) are the per-validator
gates the mid-epoch-restart upgrade scenario asserts on.

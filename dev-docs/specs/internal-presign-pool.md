# The internal presign pool and its replay contract

How the internal presign pool is filled and drained, and the rule that keeps
a validator that restarted mid-epoch serving the same presigns as the peers
that did not (issue #1928). Actors: the internal-presign top-up loop and
output handler in `DWalletMPCManager`, the global-presign and
network-owned-address (NOA) demand drains in `DWalletMPCService`, and the
pool tables in `AuthorityEpochTables`.

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
  `noa_presign_demand_resolutions` and read back at sign-session
  instantiation. A demand that stays unassigned for the park bound is recorded
  in the same table as dropped.

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
draining a demand starts by naming both. Neither comes from the announcement
that carried the demand: the announcement carries the demand IDENTITY and
nothing else the drain reads.

The reason is the dedup key. Presign-demand announcements are deduplicated
on the demand-id digest ALONE — deliberately, so several validators
announcing the same demand collapse into one consensus transaction — and the
consequence is that the first announcement sequenced for a demand would
supply any payload field the drain reads, for the whole network, while every
honest duplicate is dropped behind it. A committee member could then pick the
pool for any demand whose id it can predict, and demand ids are derivable
from public data. Rejecting a mismatch would not help: the honest
announcements were already deduplicated away, so no correct one can follow,
and the demand would stay unassigned for the epoch — a substitution bug
traded for a stall. Deriving both inputs is what removes the problem, and it
is stronger than validating an announced value: there is no second copy to
disagree with.

**The algorithm** comes from the demand identity
(`NOAPresignDemandId::expected_signature_algorithm`). Both demand arms commit
to it — the checkpoint arm through `kind_name` (whose mapping to the
counterparty chain's algorithm is pinned by test), the attestation arm by
carrying it in the identity — so an announcer naming a different algorithm
produces a DIFFERENT identity, a demand no honest consumer looks up, rather
than a competing answer for this one. Neither the consensus message nor the
internal sign request carries an algorithm beside the id, so the pool drained
and the session instantiated cannot disagree.

**The network encryption key** is the epoch's network-owned-address (NOA)
signing key, which every validator derives for itself from the prior epoch's
handoff certificate
(`DWalletMPCManager::network_owned_address_signing_key_resolution`; the rule
is stated in [`handoff.md`](handoff.md), "The network-owned-address signing
key"): among the keys the certificate names, the one with the largest
`dkg_at_epoch`, ties broken by the smaller `NetworkKeyId`. The certificate is
the one input every validator holds identically for the whole epoch —
quorum-signed, local before the epoch's components start (the
prepare-then-start barrier), never modified afterwards — so the answer is one
value per epoch, and a validator that has derived it agrees with every other
validator that has. The derivation is all-or-nothing: the certificate names
keys by `NetworkKeyId` while the pool is keyed by Sui `ObjectID`, and
`dkg_at_epoch` lives on the chain metadata the network-key syncer publishes;
a validator that cannot yet translate, or has no metadata for, ANY certified
key answers "no key yet" rather than choosing among the keys it can see.
Choosing among a subset is exactly the per-validator divergence the
derivation exists to remove. The answer is cached once it resolves (every
input only ever gains entries), and it is recorded with the assignment, so
the sign session later instantiates under the key its presign was drawn
from.

The previous rule — the oldest key in the validator's locally ADOPTED set,
carried in the announcement — let honest validators name different keys
while their adoption lagged at different rates, and let a dishonest announcer
name a key nobody holds (issue #2019, which is closed by construction rather
than by measurement: nothing is announced, and the derived key does not read
the adopted set at all). The adopted-set rule survives only behind
`noa_checkpoints` OFF, where it decides which pool receives the NOA pool
parameters on the live protocol version; changing it there would move the
internal-presign sequence numbers under a mixed-binary committee, and no
demand can be announced with the flag off in any case. With the flag on, the
top-up loop applies the NOA parameters to the derived key and mints nothing
at all while the derivation is still pending, so a key's pool role cannot
flip mid-epoch on one validator but not another; an epoch with no
certificate treats every key as a non-NOA key for the whole epoch.

## A demand with no key or no pool: park, with a bound

Two things stop a validator from assigning a consensus-delivered demand: it
has not derived the epoch's signing key yet, or that key's pool for the
demand's algorithm is empty. In both cases the demand **parks**: it stays in
the queue in consensus-delivery order and is retried on every following
round. It is **not** rejected — there is nothing to reject it against, and
an honest duplicate announcement could never follow (the dedup key again).

WHEN a validator can derive the key is the one per-validator input on this
path. The certificate is local from the start on every path that starts a
validator's epoch components, and the chain metadata is the syncer's
process-wide overlay, so a continuing validator derives the key on its first
attempt. A restarting or joining validator waits for the overlay's first
publish (one syncer tick) and, for a key outside the compiled-in deployed
constants, for the `NetworkKeyId -> ObjectID` translation to register at
instantiation or through the background derivation — seconds to minutes. A
demand delivered inside that window parks here while a peer that derived
earlier assigns it at delivery.

That park is not uniform in time: the parked demand is assigned when this
validator resolves, from the pool as it stands at THAT round, while the peer
drew from the pool at the delivery round. A fill landing between the two
rounds changes which presign is at the head only if it carries a LOWER
sequence number than the head the peer drew — possible, because fills
complete out of sequence order (below), but only while a batch is completing
inside a validator's own derivation window at epoch start, when the
per-epoch pool has just begun to fill. The top-up loop reads the same
derivation and mints nothing on a validator whose key is still pending, so
such a validator is not feeding the pool during its own window. This is the
residual of the certificate rule; it is narrower than the announced-key
design it replaces, where a validator that had not adopted the announced key
parked on the same per-validator moment AND the key itself could differ.

### Why the park needs a bound anyway

The bound is a liveness backstop, not a security control. There is no
announced key left for a byzantine member to point at nothing; what remains
is a validator that never derives the key this epoch — an epoch with no
prior certificate (genesis, or the first epoch of a fresh network, where NOA
signing waits for the first handoff), or a certified key this validator can
never translate — and a pool that never fills. A demand parked on either
would otherwise sit in the queue for the rest of the epoch, and the sign
request behind it would wait forever for an assignment nobody will write.

So a parked demand is dropped once it has been parked for
`noa_presign_demand_park_rounds` consensus rounds — a `ProtocolConfig`
constant, `Some(70_000)` from protocol version 7 (`None` would never drop).
The queue element records the consensus round its demand was delivered in;
the drain at round *R* drops any still-unassigned demand delivered at *R_d*
once `R - R_d >= noa_presign_demand_park_rounds`.

### Why consensus rounds, and not elapsed time

The drop must be **consensus-uniform**: every validator must drop exactly the
same demands at exactly the same point, or they disagree about which demands
were assigned a presign — which is the divergence the whole assignment queue
exists to prevent, reintroduced through the drop path.

Both inputs to the predicate come from the consensus stream and are therefore
identical everywhere: the delivery round and the round being drained. The
third input, whether the demand is still unassigned, is a function of the
presign pool, which is filled from quorum-agreed outputs in round order and
is likewise uniform per round. Wall-clock time is not: validators observe
different elapsed times for the same rounds. The moment this validator
derived the signing key does not enter the predicate either: the bound
measures from the consensus delivery round, so a validator that never derives
the key drops the demand at the same round its peers would have.

The delivery rounds themselves survive a restart for the same reason: the
round cursor replays the epoch's rounds from the start, so the queue and the
rounds it measures from rebuild exactly as they were. The *decision*, though,
must not be recomputed on that replay — see the next section.

### The drop must be recorded durably, or a restart undoes it

The replay runs against a durable pool that was NOT rewound with the rounds.
That is safe for the park itself — a demand still in the queue means the pool
for its key was empty, and re-draining it either finds the pool still empty or
assigns from it, exactly as an uncrashed peer did. It is NOT safe for a drop:

1. demand *D* is parked past the bound and dropped at round *R_e*;
2. *D*'s key derives late and its pool fills at some *R_i > R_e* — the
   honest-lag case the bound deliberately drops anyway;
3. the validator restarts. The rounds replay, *D* re-enters the rebuilt queue
   at its delivery round, and the drain now sees a pool that can serve it.

With the drop held only in process memory, that replay pops a presign for a
demand the whole committee — including the same validator before the crash —
had already abandoned. The restarted validator would hold an assignment nobody
else has, and would consume a presign its peers pair with a DIFFERENT demand,
diverging the demand-to-presign pairing for every later demand on that pool.

So the drop is written to the SAME durable per-epoch table as the assignment,
as the second arm of one per-demand resolution
(`noa_presign_demand_resolutions`, keyed by the demand-id digest):

| resolution | meaning |
|---|---|
| `Assigned { … }` | this presign, drawn under this network key, is bound to the demand |
| `Evicted` | the park bound dropped the demand; it must never be assigned |

Every demand therefore has at most one terminal resolution per epoch, and a
replayed drain READS it instead of deciding again: an already-dropped demand
leaves the rebuilt queue without an assignment attempt, without re-logging at
error level, and without re-counting the metric. That read does not wait for
the signing key: a replay that runs before the restarted validator has
re-derived it (its overlay republishes a tick after boot) reads the durable
table directly, so a resolved demand leaves the queue instead of parking a
second time under a bound measured from a delivery round long past. The
write happens before the demand leaves the queue, and a failed write keeps
the demand parked for the next round — the same posture as a failed
assignment.

### The bound drops an honest-lag demand too, deliberately

No consensus-uniform signal distinguishes "a key this validator will never
derive, a pool that will never fill" from "still on its way", and any attempt
to distinguish them locally breaks uniformity. The bound therefore drops both
cases alike, and its only defence is being generous enough that no honest
window comes near it.

`noa_presign_demand_park_rounds = 70_000` is about an hour of mainnet
consensus at ~19.5 rounds/s. The honest windows it has to clear are:

- the network-key syncer publishes the overlay every 5s — ~100 rounds; the
  derivation waits at most one tick for a certified key's chain metadata;
- a restarting or joining validator translates a key outside the deployed
  constants at instantiation or by background derivation, after recovering a
  stranded key by chain read — minutes, so at most low tens of thousands of
  rounds;
- a freshly certified key's presign pool is filled by internal-presign MPC —
  again minutes.

The ceiling is the epoch: a 24h epoch is ~1.7M rounds, so the bound spends
~4% of an epoch waiting before giving up, and a demand that is going to be
dropped is dropped early enough for the epoch to finalize what it can.

The value lives in `ProtocolConfig` because it is consensus-affecting once
demands reach the wire: validators running different values drop different
demands, so a change has to be version-gated rather than binary-driven.

### What a drop means

It is terminal for that demand in that epoch, and durable (above). The drain
increments `ika_dwallet_mpc_noa_presign_demands_evicted_total` (labeled by
signature algorithm) and logs an `error!` carrying the demand id and its
digest, the signing key as this validator had derived it at the drop (or that
it had none), the announcing authority, the delivery round and the round of
the drop — including the statement that this demand's sign will not happen
in this epoch. It is deliberately not reported as an internal invariant
violation: a key this validator could not derive, or an honest lag that
outran the bound, is not a bug in our code. A replay of a drop that was
already recorded logs at debug and does not touch the counter, so the metric
counts drops, not restarts.

Two other paths read the same durable resolution rather than any process
memory, which is what makes them survive a restart as well:

- the **pending sign request** behind a dropped demand is released (it would
  otherwise wait forever for an assignment nobody will write, feeding the
  NOA-sign starvation warning). Only the assignment branch of that read needs
  the signing network key locally; a release must not, or a validator that
  never derives the key would hold the request forever;
- the **announcement** pass skips any demand that already has a resolution, so
  a dropped demand is not re-announced — a re-announcement would be
  deduplicated into nothing anyway, the consensus key being the demand-id
  digest alone.

Recovery, where it exists at all, comes from a HIGHER layer minting a
**fresh demand id**: a checkpoint demand carries a retry round, so a retry is
a different demand with a different digest and therefore a different dedup
key. Today that only happens after an on-chain failure quorum for the
checkpoint transaction, so a checkpoint sign whose demand was dropped stays
unsigned for the remainder of the epoch. That is the accepted outcome: a
bounded, loud, and network-uniform loss of one demand, rather than an
unbounded park that blocks the epoch's NOA checkpoint finalization.

## Fills complete out of sequence order

A top-up batch starts *s* sessions at once. They finish in consensus order,
not sequence order, so slot *n+1* is routinely filled before slot *n*. This is
normal and network-uniform (every validator sees the same completion order),
and the drain still takes the lowest sequence number present. It matters only
because it is what makes replay unsafe — see below.

## The replay contract

**A restart replays the epoch, and the pool paths see it as one stream.** The
consensus handler starts with empty in-memory derived state — there is nothing
to delete, because state the commits determine is never written to disk — and
refolds the epoch's commits from the consensus store in bounded batches,
handing each round to `DWalletMPCService` over a bounded channel as it goes.
There are no per-round tables, so the drain does not replay a stored stream;
it consumes the refold live. It
still sees every round of the epoch from the first, so it re-absorbs every
internal presign output and re-drains every global presign request and NOA
demand exactly as before. The demand queue and the delivery rounds the park
bound measures from are rebuilt by that pass and rebuild identically, because
they come from the same commits in the same order. The model is
[`event-sourced-epoch.md`](event-sourced-epoch.md); the consumption rules are
[`../conventions/consensus-output-consumption.md`](../conventions/consensus-output-consumption.md).

**The pool is NOT reset for that replay — by construction, not by
accident.** The per-epoch store keeps only state no replay reproduces
([`../preserved-epoch-state-audit.md`](../preserved-epoch-state-audit.md)),
and the pool tables, their size counters, their idempotency markers
(`filled_presign_pool_slots`, `served_global_presigns`,
`noa_presign_demand_resolutions`, `used_presigns`), the assigned-presign
pools and `presign_private_outputs` are all **preserved**. They have to be:
the replay does not re-run the cryptography that produced the presigns (the
catch-up gate suppresses it), and this validator's own VSS secret shares
were never published, so no commit could carry them back.

The consequence is the one this section has always been about — the replay
runs against a pool holding whatever survived the crash, which breaks the
naive assumption that re-executing the same rounds reproduces the same
decisions:

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
| `Noa { demand_id }` | `NOAPresignDemandId::digest()` | `noa_presign_demand_resolutions` |

The NOA row's table holds a RESOLUTION, not just an assignment: its value is
`Assigned { … }` or `Evicted`, the two terminal outcomes a demand can reach.
That second arm is what `evict_noa_presign_demand` writes when the park bound
expires, and it is why a drop survives a restart — see "A demand naming a
network key with no pool" above. A global request has no second arm: it has no
park bound, so its marker table holds served presigns alone.

There is deliberately no way to drain the pool without naming a demand: a
consumer that could pop bare would have to know this hazard to avoid it,
and the next consumer's author is exactly who the type is protecting. (The
`Noa` arm carries the identity type rather than a bare digest for the same
reason — any other 32-byte value would type-check while keying the
assignment wrong.)

A repeated fill is a no-op. A repeated drain returns the presign it returned
the first time — or, for a NOA demand the bound already dropped, reports that
drop — without touching the pool. Replay is then a no-op on the pool by
construction, and the restarted validator's checkpoint messages match its
peers' regardless of where it crashed.

The batching is load-bearing in both directions: a pool mutation that landed
without its marker is re-applied on the next replay, and a marker that landed
without its mutation loses the presigns (fill) or serves a presign the pool
never gave up (drain).

**A marker can never become in-memory state.** Losing a marker while the pool
it guards survives is precisely the double-absorb this contract exists to
prevent, and it produces no error — an inflated size counter reads as a full
pool and suppresses top-ups until the pool physically starves. Since the boot
replay rebuilds everything held in memory but never rewinds the pool, a
marker moved there would be re-derived against a pool that already consumed
what it records. The markers therefore stay tables, and the argument for each
is written out in the audit.

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

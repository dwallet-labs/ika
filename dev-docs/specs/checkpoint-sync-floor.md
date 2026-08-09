# On-chain checkpoint sequence floors (pull-mode cold start, and the validator aggregator)

Why a node whose checkpoint store sits far below the chain can never catch
up on its own, and the on-chain floor that fixes it — first for a notifier
(or any non-committee node) deployed with a fresh database, then for a
validator whose aggregator fell behind across an epoch boundary. Actors:
`ika-network` state sync (pull mode), the node's Sui connector (cursor
feed), every validator (as a serving peer and as a certifier).

## The failure this closes (2026-07 testnet epoch-close outages)

Checkpoint state sync demanded contiguous history: a node with an empty
store starts at sequence 1. But no peer on a long-lived network can serve
deep history — validators never pull (they only hold what consensus gave
them since their own last redeploy; there is no pruner but also no
backfill), so early sequences eventually exist on no serving peer. A
notifier redeployed fresh therefore looped on "no peers were able to help
sync checkpoint 1" forever: synced pinned at 0 while known grew — and since
the writer had nothing to submit, every epoch close was silently blocked
(issue #1892; the "gRPC migration" correlation was the fresh deploy that
came with it, not the transport).

## The floor

The chain itself defines what a writer still needs: everything at or below
the coordinator's / system object's `last_processed_checkpoint_sequence_number`
has already landed on Sui and is submit-useless. The node's Sui connector
feeds those two cursors into state sync
(`OnChainCheckpointCursors`, `watch` channels of `Option<u64>`,
`None` until the first successful chain read; values only move forward).

Rules (both checkpoint streams, dwallet and system):

1. **Start at `max(local_next, cursor + 1)`.** A fresh or deep-lagging
   store skips straight to what the chain still needs; peers hold those
   sequences because they are at the live tip. The skip is logged at info.
2. **Cold start defers until the cursor is known.** With a cursor feed
   configured, an EMPTY store does not start a sync job while the cursor is
   still `None` — otherwise the first job would race the connector's first
   read and chase history from sequence 1. At genesis the first read
   returns `Some(0)` within seconds and sync proceeds from sequence 1, so a
   brand-new network is never blocked (`Some(0)` ≠ `None` is exactly why
   the channel carries `Option`).
3. **Nodes without a cursor feed** (external users of the builder) keep
   the old from-1 behavior.

## The same floor on the validator side

Validators never pull, so the cursor feed above does not reach them — but
they have the same class of failure and the same on-chain answer.

A validator's checkpoint AGGREGATOR certifies from its own local certified
store. At each `advance_epoch` the chain records
`previous_epoch_last_checkpoint_sequence_number =
last_processed_checkpoint_sequence_number`, and the node reads it at epoch
entry. The BUILDER already floors its next sequence at that value; the
aggregator must too:

4. **The aggregator starts at `max(local_last_certified + 1, previous
   epoch's last + 1)`,** for both streams. Treating that floor as a
   fallback for an EMPTY store only — which is what it was — wedges any
   validator whose store sits below it at epoch entry: it asks for a
   sequence the new epoch's builder table never holds, so it certifies
   nothing, in that epoch and every later one. A validator gets there by
   ordinary means — a restart, crash or partition straddling the boundary,
   or merely lagging in consensus when the epoch's checkpoint tasks are
   aborted. The condition does not self-heal while the node stays in the
   committee (it never pulls, and nothing else writes that store), and it
   ACCUMULATES: each occurrence retires one more validator's aggregator,
   and the network stalls when the last healthy one goes. The skip is
   logged at info, as in pull mode.

## Consequences and invariants

1. A writer redeployed on a fresh database resumes submitting within one
   sync round of the connector's first chain read — no operator DB surgery.
2. A pull-mode store may legitimately contain a GAP (nothing below the
   first post-floor sequence). Nothing may assume contiguity from 1:
   serving peers already handle absent sequences (`None` response), and the
   writer only ever reads `cursor + 1` and above. The same now holds for a
   VALIDATOR's certified store, which may carry a gap where it was below
   the floor at an epoch entry.
3. The floor never regresses (monotonic forward in the connector feed) and
   never skips anything the chain still needs (it is derived from the
   chain's own processed cursor).
4. If the Sui connector cannot read the chain, a cold-start node defers
   sync — acceptable by construction for a writer (it could not submit
   anyway) and self-healing: sync starts the moment the first read lands.

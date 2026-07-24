# Pull-mode checkpoint sync floor (notifier cold start on a history-less network)

Why a notifier (or any non-committee node) deployed with a fresh database
could never sync on a long-lived network, and the on-chain floor that fixes
it. Actors: `ika-network` state sync (pull mode), the node's Sui connector
(cursor feed), every validator (as a serving peer).

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
3. **Pull mode only.** Validators build checkpoints from consensus and
   never pull; their behavior is untouched. Nodes without a cursor feed
   (external users of the builder) keep the old from-1 behavior.

## Consequences and invariants

1. A writer redeployed on a fresh database resumes submitting within one
   sync round of the connector's first chain read — no operator DB surgery.
2. A pull-mode store may legitimately contain a GAP (nothing below the
   first post-floor sequence). Nothing may assume contiguity from 1:
   serving peers already handle absent sequences (`None` response), and the
   writer only ever reads `cursor + 1` and above.
3. The floor never regresses (monotonic forward in the connector feed) and
   never skips anything the chain still needs (it is derived from the
   chain's own processed cursor).
4. If the Sui connector cannot read the chain, a cold-start node defers
   sync — acceptable by construction for a writer (it could not submit
   anyway) and self-healing: sync starts the moment the first read lands.

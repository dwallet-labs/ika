# Production alerts — the failure modes that don't page by themselves

The v4 off-chain pipeline has three designed halt/block modes. They are
safety-first BY DESIGN (a stopped validator beats one running with wrong
parameters), which means the node looks healthy from the outside while
blocked — no crash, no restart loop. The metrics exist; what must live
in the alerting config are the rules below.

## Alert 1: prepare-then-start barrier blocked

```promql
ika_handoff_prepare_waiting == 1
# for: 2× epoch duration
```

The barrier blocks epoch entry until the full verified handoff data for
the new epoch is local — indefinitely, by design. Sustained blocking
means the handoff cert or a certified network-key output blob never
arrived. **Operator action**: the node logs a breakdown every ~10s
(`have_anchor`, `empty_output_keys`, `stale_epoch_keys`) naming the
missing input; `ika_handoff_prepare_retries_total` and the duration
histogram quantify the wait. See `../specs/handoff.md`
("Prepare-then-start barrier").

## Alert 2: off-chain assembly permanently wedged

```promql
ika_off_chain_assembly_wedged != 0
# for: 5m (the gauge holds the wedged epoch; it clears on the next
#          successful assembly — non-zero is already the signal)
```

Fires when the mpc_data freeze excluded EVERY next-committee member
(`EverythingExcluded`): reconfiguration into that epoch cannot proceed
and there is **no self-heal** — this is the one mode that must page a
human immediately. **Operator action**: check each validator's
announcement/ready-signal logs for why attestation coverage collapsed
(propagation outage, mass restart inside the announcement window);
recovery requires operator intervention, not waiting.

## Alert 3 (log-based): joiner bootstrap fail-closed halt

There is no gauge for this one — the node **halts** when every
current-committee peer served a handoff certificate and none verified
(trust-anchor mismatch or eclipse; see `../specs/handoff.md`, "Joiner
bootstrap"). Alert on process exit plus the log line:

```
joiner bootstrap rejected: no peer-served certificate verified
```

(or the `Rejected` outcome marker in `JoinerBootstrapVerifier` logs).
**Operator action**: this is fail-closed on a real contradiction — do
NOT auto-restart into it; verify the node's configured trust anchors
and the peer set before bringing it back.

## Alert 4: the chain introduces dwallet types at versions the binary rejects

```
ika_dwallet_uncovered_introducing_versions > 0
```

**Meaning**: **session events are being dropped right now.**

A Move type's address is fixed at the package version that *first introduced*
it and never moves — Sui records this per datatype in the package's
`TypeOrigin` table. So an upgraded package's types are spread across every
version that introduced any of them, and that table is the exact set of
addresses its events can carry. The node reads it (verified) and compares
against the addresses it accepts (`ika_dwallet_2pc_mpc_package_id` and
`…_v2`). This gauge is how many introducing versions are NOT accepted; every
event type introduced at one of them fails the filter silently.

Not hypothetical: as of 2026-07-25 the deployed dwallet package introduces
types at **two** versions — 79 types at the original and 7 at the upgrade,
**five of the seven being events**.

**Operator action**: page. Ship a release carrying the missing package ids
(the warn log names them). There is no config workaround on public chains —
the override was removed in #1908. Grep `received an event from a wrong SUI
module` to see the rejected addresses.

**It clears by itself** once a release accepts the ids, and accepting *more*
versions than the chain introduces is not a gap — an unused id drops nothing.

## Secondary signals worth dashboarding (no page)

- `ika_last_pruned_authority_db_epoch` / `ika_last_pruned_consensus_db_epoch`
  not advancing across epochs → pruners dead, disk will grow.
- `ika_dwallet_mpc_global_presign_requests_waiting` climbing without
  draining → presign pool starvation (see
  [`mpc-stall-postmortem.md`](mpc-stall-postmortem.md)).
- `ika_dwallet_handoff_signatures_rejected_total` increasing → a peer is signing
  divergent attestations (benign if transient at boundaries).

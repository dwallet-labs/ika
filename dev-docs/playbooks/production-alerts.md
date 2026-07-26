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

## Alert 4: dwallet package upgraded past what the binary accepts

```
ika_dwallet_package_drift{state="executing"} > 0
```

**Meaning**: the chain is executing a dwallet Move package whose id is not
in the binary's accepted set, so **session events are being dropped right
now**. A Sui upgrade does not move existing types — Sui records type
identity per datatype, so types carried forward keep the ORIGINAL package
address while types **first defined in the upgrade** carry the UPGRADE
address. The event filter admits only the addresses the binary was compiled
with (`ika_dwallet_2pc_mpc_package_id` and `…_v2`), so any event type
introduced by an unknown upgrade fails it silently. As of 2026-07-25 the
deployed dwallet package has 7 upgrade-defined types, five of them events —
this is not hypothetical.

**Operator action**: page. Ship a release carrying the new package id. There
is no config workaround on public chains (the override was removed in
#1908). Grep `received an event from a wrong SUI module` to see the
rejected addresses.

```
ika_dwallet_package_drift{state="pending"} > 0
```

**Meaning**: an upgrade is **staged but not yet migrated to** — nothing is
being dropped yet. This is the lead time: ship the package id before the
migration epoch and the `executing` alert never fires. Warn, don't page.

Both clear automatically once the accepted set includes the id.

## Secondary signals worth dashboarding (no page)

- `ika_last_pruned_authority_db_epoch` / `ika_last_pruned_consensus_db_epoch`
  not advancing across epochs → pruners dead, disk will grow.
- `ika_dwallet_mpc_global_presign_requests_waiting` climbing without
  draining → presign pool starvation (see
  [`mpc-stall-postmortem.md`](mpc-stall-postmortem.md)).
- `ika_dwallet_handoff_signatures_rejected_total` increasing → a peer is signing
  divergent attestations (benign if transient at boundaries).

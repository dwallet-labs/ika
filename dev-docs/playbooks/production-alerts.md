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

## Secondary signals worth dashboarding (no page)

- `ika_last_pruned_authority_db_epoch` / `ika_last_pruned_consensus_db_epoch`
  not advancing across epochs → pruners dead, disk will grow.
- `ika_dwallet_mpc_global_presign_requests_waiting` climbing without
  draining → presign pool starvation (see
  [`mpc-stall-postmortem.md`](mpc-stall-postmortem.md)).
- `ika_dwallet_handoff_signatures_rejected_total` increasing → a peer is signing
  divergent attestations (benign if transient at boundaries).
- `rate(ika_dwallet_mpc_messages_after_terminal_session_total{terminal_status="completed"}[5m])`
  → expected late-delivery volume. Alert only on a sustained baseline change;
  an isolated increase is not a correctness failure.
- `rate(ika_dwallet_mpc_messages_after_terminal_session_total{terminal_status="failed"}[5m]) > 0`
  → investigate with the session failure/anomaly diagnostics. The counter does
  not replace the immediate failure diagnostic.
- `ika_off_chain_assembly_incomplete == 1` with
  `ika_off_chain_assembly_incomplete_duration_seconds > 300` → announcement or
  blob propagation is not converging. Split by the bounded
  `ika_off_chain_assembly_missing{reason}` gauges; a successful recovery clears
  them and updates `ika_off_chain_assembly_last_success_timestamp_seconds`.
- `time() - ika_consensus_last_committed_timestamp_seconds` is commit staleness
  after the gauge becomes non-zero. This is the Ika-owned progress signal for
  the dependency-owned Mysticeti warning
  `Skip scheduling new commit fetches: consensus handler is lagging`; Ika does
  not patch or rate-limit that upstream log line.
- `time() - ika_ocs_last_successful_relay_timestamp_seconds` is verified relay
  read staleness after the gauge becomes non-zero. Correlate it with
  `ika_ocs_proof_verify_failures_total`,
  `ika_ocs_high_water_violations_total`, and relay request/failure counters.

# Production alerts — failure modes that don't page by themselves

Several safety-first failures leave the process running but unable to make
progress, while broken-invariant events can be hidden in an operator's private
logs. The metrics exist; what must live in the alerting config are the rules
below.

## Alert 1: broken invariant observed

```promql
sum by (host, site) (increase(ika_invariant_violations_total[10m])) > 0
# no for-duration: fire immediately
```

Any event is investigation-worthy by definition; there is no benign threshold.
The bounded `site` label identifies the failing call site, and the matching
structured log carries the dynamic context. The counter is not pre-populated,
so an absent series means that site has recorded zero violations. **Operator
action**: inspect the matching `should_never_happen = true` log on the affected
host and correlate it with subsystem metrics around the event timestamp.

Invariant sites report incidents on **entry**, not on every retry tick. For a
persistent condition, alert its paired state gauge separately; the counter says
"a new episode began" while the gauge says "the episode is still active." The
network-key registry conditions use:

```promql
ika_network_key_registry_read_empty_condition_active == 1
or
ika_stranded_network_key_missing_from_registry_read_condition_active == 1
# for: 1m (filters a single read/convergence tick without delaying a real stall)
```

Both gauges clear on the first successful registry read that demonstrates
recovery. Transport errors preserve the last observed state and are counted by
the Sui RPC/OCS transport metrics; an error is not evidence that an active
condition recovered.

## Alert 2: a validator recognized ITSELF as malicious

```promql
sum by (host, reason, session_type) (
  increase(ika_dwallet_mpc_self_malicious_total[10m])
) > 0
# no for-duration: fire immediately
```

The validator concluded its own MPC output diverged from the peers' quorum, or
the majority output named it. It has effectively dropped itself out of that
session, and it will keep doing so for as long as the cause persists. There is
no benign threshold: a correct, agreeing validator never increments this.

Unlike Alert 1 this is NOT a broken invariant — a correct binary can reach it.
The two causes that matter operationally:

- **A genuine divergence** on this host (bad state, corrupted inputs, a real
  fault). Confined to that validator; quorum absorbs it.
- **A wire-format disagreement across a protocol upgrade** — the fleet-wide
  case. During a rollout that changes serialization, validators emitting
  different bytes compute different digests and reject each other while parsing
  each other's messages perfectly. **This alert firing on multiple hosts at once
  during an upgrade window is the signal that the rollout itself is splitting
  the network**, not that those operators are individually broken.

**Operator action**: check whether one host or many are firing, and whether the
window coincides with a binary rollout or protocol-version activation. One host
— investigate that node. Several, mid-upgrade — treat as a rollout-wide
serialization split and stop the rollout before it crosses quorum. Correlate
with `ika_dwallet_mpc_malicious_actors_count` on the *peers* (who they blame)
and with the `node recognized itself as malicious` log on the affected host,
which carries the session id the labels deliberately omit.

## Alert 3: prepare-then-start barrier blocked

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

## Alert 4: off-chain assembly permanently wedged

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

## Alert 5 (log-based): joiner bootstrap fail-closed halt

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

## Alert 6: MPC subsystem has stopped contributing

```promql
ika_mpc_stopped_contributing_condition_active == 1
# for: 5m (the condition is already latched and generous; this only filters
#          a single sample straddling an epoch boundary)
```

The node follows consensus, serves requests and exports every other metric
while contributing no MPC work — invisible from outside, and the reason this
gauge exists (#1978, #1980). It is computed locally: the MPC service publishes
the consensus round it has consumed and the **consensus commit path** compares,
because every way the MPC service stops also stops any check placed inside it.

**Do not alert on `ika_mpc_consensus_round_lag` directly.** A validator
restarted mid-epoch replays the epoch from round 0, so its raw lag legitimately
exceeds any stall threshold for as long as the replay runs. The gauge above
already accounts for the catch-up the MPC service is reporting (#2036); the raw
lag is a dashboard signal, not a page.

**Operator action**: look for an earlier fatal in the dWallet MPC service on
that host — the deliberate `break` on self-recognised maliciousness ends the
service loop for the life of the process (Alert 2 fires for that one) — and
restart the node if nothing else explains it. Recovery clears the gauge and logs
`MPC subsystem has caught back up with consensus`.

```promql
ika_mpc_catch_up_stuck_condition_active == 1
# no for-duration: the condition already carries a 15-minute bound
```

The complement: this validator IS draining a backlog, and the backlog has
stopped shrinking. **Operator action**: do not restart — a restart discards the
drain's progress and replays it. Check `ika_dwallet_mpc_catchup_gap_rounds` on
the host; while that gap falls the drain is healthy and this gauge reads 0, so a
`1` means it went flat or started growing, and something other than the backlog
is holding the service up.

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
- `rate(ika_ocs_watermark_implausible_total[15m]) > 0` → an upstream is
  claiming a latest-checkpoint height advancing faster than checkpoint
  production can explain (a desynced load-balancer backend, an endpoint on the
  wrong network, a corrupted response) — or this process was paused longer than
  the bound's burst covers, which a restart clears. Refused samples are
  skipped, so this is a configuration/upstream-health signal, not data loss;
  sustained refusals on `{consumer="folder"}` mean the checkpoint folder is
  skipping ticks and its cursor will lag *behind* the head (the opposite
  signature to a poisoned cursor). Check `ika_ocs_pusher_cursor_seq` against
  the chain head and see
  [`mpc-stall-postmortem.md`](mpc-stall-postmortem.md)'s interpretation rules
  plus
  [`../specs/ocs-verified-sui-reads.md`](../specs/ocs-verified-sui-reads.md).

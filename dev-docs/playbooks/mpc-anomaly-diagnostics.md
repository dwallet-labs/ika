# MPC anomaly diagnostics

## Operator rule

Search for `event="mpc_session_anomaly"`. A healthy session emits no
diagnostic snapshot at `WARN` or `ERROR`; its per-message history stays in a
bounded in-memory trace and is discarded when the session completes.

The snapshot is a metadata-only reconstruction aid implemented by
`dwallet_mpc/mpc_diagnostics.rs:BoundedSessionDiagnostics`. Each session keeps
at most 64 recent events. Once the buffer is full, the oldest event is dropped
and `recent_trace_dropped_events` is incremented. Each anomaly kind is emitted
at most once per session. Anomalies for sessions that have no local state are
also deduplicated and capped per epoch.

## Triggers

`DWalletMPCManager::emit_session_anomaly` flushes a snapshot when the node
observes any of these conditions:

- local computation failure or an update arriving after session completion;
- a locally produced rejected output, or the node's rejected output returning
  through consensus;
- invalid output, output conflict, protocol-message submission failure, or
  final-output submission failure;
- a non-threshold voting error;
- rejected quorum;
- quorum before the node's output returns through consensus;
- quorum while a local computation is still running;
- more than one report digest, a disagreeing voter, or malicious authorities
  embedded in the winning output report;
- any final malicious authority, especially the local authority;
- MPC service termination after the node recognizes itself as malicious.

The ordinary `ThresholdNotReached` result is not anomalous. It remains silent
because it is the expected state while reports accumulate.

## Reading malicious attribution

Do not treat `final_malicious_authorities` as a root cause. Read these fields
separately:

- `malicious_voters`: authorities whose complete submitted report differed
  from the stake-weighted winner;
- `reported_malicious_authorities`: authorities named by the MPC library in
  the winning report;
- `final_malicious_authorities`: the union used by the existing protocol
  behavior;
- `local_authority_malicious_reason`: `MaliciousVoter`,
  `ReportedByMajorityOutput`, both, or `Unknown` when attribution is no longer
  available.

The vote candidate is the public MPC output plus its embedded malicious list.
`report_digest` hashes that exact candidate. `output_digest` hashes only the
public output, so operators can distinguish different public results from
different malicious reports attached to the same result. `reports` records
the latest report per sender, sender authority/party ID, consensus round,
weight, both digests, rejection flag, and embedded malicious list.
`vote_groups` records the voters and total weight for each report digest.

## Important fields

The snapshot records the session identifier (whose debug form includes the
preimage), type, sequence, epoch, protocol/computation type, local
authority/party, session and quorum rounds, lifecycle state, local computation
counters/state, output production/submission/consensus-observation state,
local and winning digests, threshold and observed/winning weights, and network
key identifier/reconfiguration status. `source_authority` and
`source_party_id` identify the report that directly triggered an input error.
`recent_trace` reconstructs recent metadata-only request, message,
computation, output, quorum, cache, and status transitions.

The trace stores message sizes, types implied by the event variant, party IDs,
and rounds. It never stores raw protocol messages, private outputs, secret
shares, MPC private state, private keys, or tokens. Computation errors are
reduced to a stable error kind and a sanitized summary rather than formatting
error variants that can carry raw message bytes.

## Example shapes

Field order is not stable; examples omit unrelated `None` and empty fields.

### Quorum without local output

```text
WARN event="mpc_session_anomaly" anomaly_kind=QuorumAnomaly
anomaly_snapshot=MpcAnomalySnapshot {
  session_identifier: (...), local_party_id: 27,
  current_consensus_round: Some(844172), quorum_consensus_round: Some(844172),
  local_computation_state: Running, running_computation_count: 1,
  local_output_produced: false, local_output_submitted: false,
  local_output_observed: false, quorum_reached_without_local_output: true,
  quorum_output_cached_without_local_output: true,
  trigger_conditions: ["quorum_reached_before_local_output_observed",
                       "local_computation_pending_at_session_completion"],
  vote: Some(OutputVoteDiagnostics { threshold_required: 3,
    winning_weight: 3, reports: [...], vote_groups: [...] })
}
```

### Local rejection

```text
ERROR event="mpc_session_anomaly" anomaly_kind=LocalComputationFailed
anomaly_snapshot=MpcAnomalySnapshot {
  session_identifier: (...), local_computation_state: Failed,
  local_computation_attempts_failed: 1,
  error_kind: Some("invalid_mpc_output"),
  error: Some("MPC computation failed validation"),
  trigger_conditions: ["local_computation_returned_error"]
}
WARN event="mpc_session_anomaly" anomaly_kind=LocalRejectedOutput
anomaly_snapshot=MpcAnomalySnapshot {
  local_output_produced: true, local_output_submitted: true,
  local_output_rejected: Some(true),
  trigger_conditions: ["local_validator_submitted_rejected_output"]
}
```

### Self recognized as malicious

```text
WARN event="mpc_session_anomaly" anomaly_kind=QuorumAnomaly
anomaly_snapshot=MpcAnomalySnapshot {
  local_output_observed: false,
  vote: Some(OutputVoteDiagnostics {
    malicious_voters: [],
    reported_malicious_authorities: [<local authority>],
    final_malicious_authorities: [<local authority>],
    local_authority_malicious_reason: Some(ReportedByMajorityOutput), ...
  }),
  trigger_conditions: ["winning_output_reported_malicious_authorities",
                       "local_authority_in_final_malicious_set"]
}
ERROR event="mpc_session_anomaly" anomaly_kind=ServiceExitSelfMalicious
anomaly_snapshot=MpcAnomalySnapshot {
  service_loop_termination_reason:
    Some("local_validator_recognized_as_malicious"), ...
}
```

## Diagnosing quorum without the local validator

For the observed System session at round 844172, the quorum snapshot answers
the previously ambiguous questions directly:

1. `local_output_observed=false` and
   `quorum_reached_without_local_output=true` establish that quorum preceded
   the validator's own consensus report.
2. The local computation state and attempt counters distinguish not-started,
   running, waiting-for-input, failed, and output-produced states. Submission
   fields establish whether an output was handed to consensus but had not yet
   returned.
3. `reports`, `vote_groups`, and their weights reconstruct the winning report
   at quorum and every disagreeing report seen locally.
4. The three malicious sets and `local_authority_malicious_reason` establish
   whether the local authority disagreed with the winner, was named inside the
   winning MPC report, or both.
5. `quorum_output_cached_without_local_output` shows whether the node accepted
   the quorum result through the existing cache path, and the service-exit
   snapshot records why its MPC loop stopped.

Thus the same external symptom no longer conflates “the validator voted for a
different result” with “the winning MPC computation reported the validator as
malicious.” No voting, finalization, cache, or lifecycle decision is changed.

## Information the MPC library does not expose

- Protocol messages are opaque byte vectors at this layer. Diagnostics can
  record sender, size, and consensus/MPC round, but cannot safely infer the
  internal protocol phase, per-peer phase error, or message subtype.
- Rayon computation tasks do not expose a join handle, deadline, or explicit
  cancellation/drop reason. The manager can observe running computations,
  returned errors, unwind-to-error results where supported, and late results;
  it cannot distinguish a hard process abort, executor drop, or timeout that
  never returns.
- Consensus submission success means the adapter accepted the transaction. It
  does not expose a durable sequence or inclusion round until the transaction
  returns through consensus.
- A restarted process cannot reconstruct pre-restart in-memory trace events.

## Upgrade-test workflow coverage

The flows in `.github/workflows/upgrade-test.yaml` do not deliberately inject
an MPC anomaly. Rolling-restart and churn flows can legitimately reach quorum
before a restarted validator reproduces and observes its local output, so a
blanket assertion that these workflows contain no anomaly snapshots would be
incorrect. Diagnostic behavior is covered by focused manager tests; no upgrade
workflow log assertion is warranted unless a future flow injects a specific
anomaly and asserts its expected fields.

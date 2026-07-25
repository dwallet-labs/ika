# MPC anomaly diagnostics

## Operator rule

Search for `event="mpc_session_anomaly"`. A healthy session emits no
diagnostic snapshot at `WARN` or `ERROR`; its per-message history stays in a
bounded in-memory trace and is discarded when the session completes.

Snapshots remain in the validator's ordinary local log sink. The node does not
upload them through `ika-proxy` and does not contain a Loki client. Operators
choose whether to retain those local logs or collect them with their own Loki
agent.

The snapshot is a metadata-only reconstruction aid implemented by
`dwallet_mpc/mpc_diagnostics.rs:BoundedSessionDiagnostics`. Each session keeps
at most 64 recent events. Once the buffer is full, the oldest event is dropped
and `recent_trace_dropped_events` is incremented. Each anomaly kind is emitted
at most once per session. Anomalies for sessions that have no local state are
also deduplicated and capped per epoch. Once that store reaches 1,024 entries,
further snapshots are suppressed and
`ika_dwallet_mpc_anomaly_snapshots_dropped_total{reason="untracked_capacity"}`
increments, so the volume guard cannot silently blind operators.

## Triggers

`DWalletMPCManager::emit_session_anomaly` flushes a snapshot when the node
observes any of these conditions:

- local computation failure;
- a locally produced rejected output, or the node's rejected output returning
  through consensus;
- invalid output, output conflict, protocol-message submission failure, or
  final-output submission failure;
- a non-threshold voting error;
- rejected quorum;
- more than one report digest, a disagreeing voter, or malicious authorities
  embedded in the winning output report;
- any final malicious authority, especially the local authority;
- a network-key reconfiguration computation finishing after the session
  completed via the peers' output quorum (the late-output comparison below);
- MPC service termination after the node recognizes itself as malicious.

The ordinary `ThresholdNotReached` result is not anomalous. It remains silent
because it is the expected state while reports accumulate.

### Benign completion races are counted, not snapshotted

Quorum forming before a given validator's own output loops back through
consensus, quorum arriving while that validator's computation is still
running, and a computation update arriving after the session completed are
how threshold cryptography behaves for any validator outside the fastest
two-thirds of a session. They are deliberately NOT anomalies: with one
emission per session per kind, high internal-presign churn turned them into a
network-wide snapshot firehose (~9/sec observed on testnet) that buried the
defect-correlated kinds. They increment
`ika_dwallet_mpc_completion_races_total{race,session_type}` instead, where
`race` is one of:

- `quorum_reached_before_local_output_observed`
- `local_computation_pending_at_session_completion`
- `local_computation_update_received_after_session_became_non_active`

When a defect trigger fires for the same quorum (rejection, conflicting
reports, malicious attribution), the first two conditions are still attached
to that snapshot's `trigger_conditions` as context, and the snapshot fields
(`local_output_observed`, `quorum_reached_without_local_output`,
`running_computation_count`) carry the race state either way.

### Session origin: reconstructed sessions are not racing

Every session carries a provenance tag, `session_origin`:
`local_request` when the session request itself was processed locally
(at creation, or by activating a waiting entry later), or
`reconstructed_from_consensus` when the entry exists only because peer
artifacts (a stray message or output, a completion replayed at restart)
arrived through consensus. After a restart, reconstruction is the dominant
path — the node rebuilds pre-restart sessions it can never have local
output for.

Missing local output on a still-reconstructed session is definitional, not
a completion race: it does not increment the
`quorum_reached_before_local_output_observed` race counter and is not
attached as trigger context on defect snapshots. Instead, each
reconstructed session increments
`ika_dwallet_mpc_sessions_reconstructed_total{session_type}` once at
creation (a later upgrade to `local_request` does not retract it), and
`session_origin` appears both as a top-level field on snapshot log lines
and inside `diagnostic_json`, so forensic triage can split the two
populations directly.

### Late network-key reconfiguration outputs

One update-after-completion case carries extra evidence and is the only one
that still emits a `computation_update_after_session_completion` snapshot:
when a network-key reconfiguration computation returns `Finalize` after the
session already completed via the peers' output quorum, production still
discards the result (nothing is submitted, the session stays completed), but
it digests the discarded raw output bytes and compares them against the
quorum-agreed output's raw-bytes digest recorded at quorum time. The
comparison lands in the snapshot trigger
(`late_network_key_output_matched_quorum` /
`late_network_key_output_diverged_from_quorum` /
`late_network_key_output_unverified`), in the session trace as a
late-output-after-completion event, and in two scrapeable gauges:
`ika_dwallet_mpc_session_late_output_info{...,output_digest,quorum_output_digest}`
and `ika_dwallet_mpc_session_late_output_malicious_actors`. Both digest labels
are over raw output bytes — comparable with each other, not with
`ika_dwallet_mpc_session_output_info`'s envelope digests. This is what lets
the mixed-rollout release-validation scenario treat an honest straggler (any validator whose
computation legitimately finishes after quorum) as byte-level compatibility
evidence instead of a nondeterministic failure.

## How the trace is collected

This feature's "trace" is not OpenTelemetry tracing and does not depend on
`TRACE_FILTER`, `OTLP_ENDPOINT`, spans, or a tracing backend. Collection is a
local session lifecycle:

1. Every tracked MPC session owns a `VecDeque` capped at 64 metadata-only
   events.
2. Message receipt/submission, computation attempts, output observation,
   quorum, cache decisions, and status transitions append compact events. Raw
   protocol bytes and private computation values are never passed to this API.
3. A normal completion clears the deque without logging it.
4. An anomaly atomically deduplicates `(session, anomaly_kind)`, snapshots the
   current lifecycle and vote state, and clones the recent deque.
5. The snapshot is serialized with the versioned privacy-safe schema and
   emitted once through the ordinary Rust `tracing` subscriber at `WARN` or
   `ERROR`, using the dedicated target `ika_mpc_diagnostics`.
6. The node's existing telemetry subscriber writes that one line to stderr
   (normally captured by systemd journal) or to `RUST_LOG_FILE` when configured.
7. An optional local collector such as Grafana Alloy tails that operator-owned
   sink and forwards it to the operator's Loki tenant.

Nothing calls Loki from the MPC service loop. A stopped Alloy or unavailable
Loki cannot delay consensus or computation; the event remains subject to the
local journal/file retention policy and is forwarded when the collector
recovers. There is no `ika-proxy` path for these snapshots.

## Reading malicious attribution

Do not treat `final_malicious_authorities` as a root cause. Read these fields
separately:

- `malicious_voters`: authorities whose complete submitted report differed
  from the stake-weighted winner;
- `reported_malicious_authorities`: authorities named by the MPC library in
  the winning report;
- `final_malicious_authorities`: the union used by the existing protocol
  behavior;
- `local_authority_malicious_reason`: `malicious_voter`,
  `reported_by_majority_output`, or
  `malicious_voter_and_reported_by_majority_output`;
- `local_authority_malicious`: an explicit boolean indicating whether the local
  validator is in the final union. A snapshot is still emitted when this is
  `false` if another authority was identified as malicious.

The vote candidate is the public MPC output plus its embedded malicious list.
`report_digest` hashes that exact candidate. `output_digest` hashes only the
public output, so operators can distinguish different public results from
different malicious reports attached to the same result. `reports` records
the latest report per sender, sender authority/party ID, consensus round,
weight, both digests, rejection flag, and embedded malicious list.
`vote_groups` records the voters and total weight for each report digest.

## Important fields

The snapshot records the derived 32-byte session ID (not its preimage), type,
sequence, epoch, protocol/computation type, local
authority/party, session and quorum rounds, lifecycle state, local computation
counters/state, output production/submission/consensus-observation state,
local and winning digests, threshold and observed/winning weights, and network
key identifier/reconfiguration status. `source_authority` and
`source_party_id` identify the report that directly triggered an input error.
`recent_trace` reconstructs recent metadata-only request, message,
computation, output, quorum, cache, and status transitions.

The trace stores message sizes, types implied by the event variant, party IDs,
and rounds. It never stores raw protocol messages, private outputs, secret
shares, MPC private state, private keys, tokens, or digests of private values.
Computation errors are reduced to an allow-listed `error_code`; complete error
strings are never copied into the snapshot because several error variants can
carry arbitrary strings or bytes. Crypto-library errors also expose their
captured call-stack backtrace separately as `error_backtrace`, capped at 16 KiB,
with `error_backtrace_truncated` reporting truncation. Only the backtrace is
formatted—not the error kind or its values—so caller-provided private input or
output cannot enter the snapshot through an error message. When the MPC library
exposes party IDs for unresponsive, invalid-message, or malicious-message
errors, only those IDs are retained in `error_party_ids`. Non-crypto error
variants do not expose backtraces and leave `error_backtrace` unset.

Tracked-session lines use `diagnostic_shape="snapshot"`, and
`diagnostic_json` contains the complete `MpcAnomalySnapshot`. Untracked lines
use `diagnostic_shape="context"`; their JSON contains only the smaller
`MpcAnomalyContext` because session lifecycle state is unavailable. A
self-malicious service exit without a source session also has no `session_id`.
Parsers must branch on `diagnostic_shape` rather than assuming both JSON values
have the same fields.

The emitted line otherwise has stable top-level fields for filtering:
`event`, `schema_version`, `anomaly_kind`, `severity`, `session_id`,
`session_type`, `session_origin` (tracked sessions only), `epoch`,
`local_party_id`, `tracked_session`,
`local_output_observed`, `quorum_reached_without_local_output`, `error_code`,
`error_backtrace_present`, `error_backtrace_truncated`,
`local_authority_malicious`, and `recent_trace_dropped_events`.
`diagnostic_json` contains the complete
versioned, privacy-safe snapshot as one JSON value. This remains one physical
log line in both text and JSON logging modes.

## Local retention and Loki

The recommended production path is systemd journal -> Grafana Alloy -> a Loki
instance controlled by the validator operator. Loki can run on the same host or
in the operator's own infrastructure; it is never an Ika-operated destination.
Journald owns local persistence and rotation; Alloy owns delivery and its
positions. Enable newline-delimited JSON on the validator's systemd unit:

```ini
[Service]
Environment=RUST_LOG=info
Environment=RUST_LOG_JSON=1
Environment=RUST_BACKTRACE=1
UMask=0027
```

`WARN` and `ERROR` anomaly snapshots pass the normal `info` filter; enabling
global debug logging is not required. `RUST_BACKTRACE=1` must be present when
the crypto error is constructed; `std::backtrace::Backtrace::capture()` is
environment-gated. When capture is disabled or unsupported, diagnostics leave
`error_backtrace` unset instead of persisting the misleading `disabled
backtrace` placeholder. The validator infrastructure sets this variable, but
operators managing their own systemd unit must set it explicitly. Apply a
drop-in with `systemctl edit ika-node`, then run:

```bash
sudo systemctl daemon-reload
sudo systemctl restart ika-node
```

For journal persistence across reboots, configure a bounded local journal. The
exact capacity is an operator choice; for example:

```ini
# /etc/systemd/journald.conf.d/ika-retention.conf
[Journal]
Storage=persistent
SystemMaxUse=2G
MaxRetentionSec=30day
```

Restart journald after changing it. Confirm the node is producing JSON before
configuring Loki:

```bash
sudo journalctl -u ika-node.service -o cat -n 1 | jq .

sudo journalctl -u ika-node.service -o cat \
  | jq 'select(.fields.event == "mpc_session_anomaly")
        | .fields.diagnostic_json
        | fromjson'
```

The second command is normally empty on a healthy validator. When an anomaly
occurs it prints the complete local snapshot.

After `systemctl daemon-reload` and a validator restart, configure Alloy. Replace
the systemd unit name, network, validator, Loki URL, and authentication settings
for the operator's deployment. This example forwards only MPC anomaly records,
not the validator's normal log volume:

```alloy
loki.source.journal "ika_node" {
  matches    = "_SYSTEMD_UNIT=ika-node.service"
  max_age    = "24h"
  labels     = {
    service_name = "ika-node",
    network      = "mainnet",
    validator    = "validator-name",
  }
  forward_to = [loki.process.ika_node.receiver]
}

loki.process "ika_node" {
  stage.json {
    expressions = {
      target         = "target",
      event          = "fields.event",
      anomaly_kind   = "fields.anomaly_kind",
      session_type   = "fields.session_type",
      severity       = "fields.severity",
      session_id     = "fields.session_id",
      epoch          = "fields.epoch",
      local_party_id = "fields.local_party_id",
    }
  }

  // These values are fixed enums and therefore safe Loki index labels.
  stage.labels {
    values = {
      target       = "",
      event        = "",
      anomaly_kind = "",
      session_type = "",
      severity     = "",
    }
  }

  // The journal source reads the whole unit, but Loki receives only the
  // dedicated anomaly target. Remove this block only when the operator also
  // intends to retain every ordinary validator log in Loki.
  stage.match {
    selector            = "{service_name=\"ika-node\", target!=\"ika_mpc_diagnostics\"}"
    action              = "drop"
    drop_counter_reason = "non_mpc_anomaly"
  }

  // High-cardinality identifiers remain unindexed. This block requires Loki
  // structured metadata support; omit it when the Loki tenant disables it.
  stage.structured_metadata {
    values = {
      session_id     = "",
      epoch          = "",
      local_party_id = "",
    }
  }

  forward_to = [loki.write.operator.receiver]
}

loki.write "operator" {
  endpoint {
    // Same-host Loki needs no application-level encryption.
    url = "http://127.0.0.1:3100/loki/api/v1/push"
  }
}
```

For an operator-owned remote Loki, replace the URL and configure its normal TLS
and tenant authentication in `endpoint`; that is transport security chosen by
the validator operator, not encryption performed by the Ika node. Running Loki
on the validator host is simple but makes Loki's disk/CPU compete with the
validator, so journald plus an operator-hosted Loki is the safer production
topology.

The Alloy service account must be able to read the systemd journal. Package
installations commonly configure this already; otherwise add it to the
`adm` and `systemd-journal` groups and restart Alloy:

```bash
sudo usermod -aG adm,systemd-journal alloy
sudo systemctl restart alloy
```

Keep Alloy's data/positions directory persistent. `max_age = "24h"` limits the
initial catch-up window but does not replace journal retention. If Loki is down
longer than the journal retains the event, the event will be lost; increase
local retention when that operational tradeoff is unacceptable.

Do not promote `session_id`, output digests, rounds, network-key IDs, or snapshot
IDs to Loki labels: every session would create a new stream. They remain in the
JSON body/structured metadata.

If systemd is unavailable, set both `RUST_LOG_JSON=1` and
`RUST_LOG_FILE=/var/log/ika/ika-node.json`, give Alloy read-only ACL access, and
use `loki.source.file`. The telemetry layer writes to the file instead of
stderr, so the operator must configure rotation and retention for that path.
Application-level encryption is intentionally not used: the data is local and
the schema excludes secret material. Use ordinary filesystem permissions and
Loki access controls.

Useful LogQL queries:

```logql
{service_name="ika-node", target="ika_mpc_diagnostics"}
{service_name="ika-node", target="ika_mpc_diagnostics", anomaly_kind="quorum_anomaly"}
{service_name="ika-node", target="ika_mpc_diagnostics"}
  | json diagnostic_json="fields.diagnostic_json"
  | line_format "{{.diagnostic_json}}"
```

The first query finds every anomaly, the second narrows quorum anomalies, and
the third displays the complete safe snapshot without the outer tracing JSON.
To inspect a known session without making it a Loki label:

```logql
{service_name="ika-node", target="ika_mpc_diagnostics"}
  | session_id="c30d9d7d36fae7d5b341684eeea1b7a72c99ac4adae379e6e4a5317e522794a7"
```

That filter uses structured metadata when enabled. Without structured metadata,
filter the stored JSON line instead:

```logql
{service_name="ika-node", target="ika_mpc_diagnostics"}
  |= "c30d9d7d36fae7d5b341684eeea1b7a72c99ac4adae379e6e4a5317e522794a7"
```

## Alerting metrics

Four low-cardinality counters accompany the local log:

- `ika_dwallet_mpc_anomaly_snapshots_total{anomaly_kind,session_type,severity}`
  increments once per deduplicated snapshot (`session_type="unknown"` is used
  only when a service-exit event has no recoverable source session);
- `ika_dwallet_mpc_anomaly_triggers_total{trigger,session_type}` increments once
  for every reason contained in a snapshot;
- `ika_dwallet_mpc_completion_races_total{race,session_type}` counts the benign
  completion races described above, once per occurrence (no per-session
  dedup). A healthy validator under load grows this steadily; it is a trend
  panel, not an alert;
- `ika_dwallet_mpc_sessions_reconstructed_total{session_type}` counts sessions
  created from peer artifacts instead of a locally processed request. A
  bounded spike at restart that then flattens is healthy recovery. Still
  climbing at the network's session rate long after a restart while
  `ika_dwallet_mpc_advance_completions` stays flat is a validator that is
  not participating at all (the mid-epoch-restart wedge class) — this pair
  is directly alertable.

Because the benign races no longer emit snapshots, any increase of
`anomaly_snapshots_total` on a healthy network is worth investigating.
`anomaly_triggers_total{trigger="quorum_reached_before_local_output_observed"}`
now counts only races that co-occurred with a defect trigger; raw race volume
lives in `completion_races_total`.

Example PromQL:

```promql
increase(ika_dwallet_mpc_anomaly_snapshots_total[5m]) > 0

increase(ika_dwallet_mpc_anomaly_triggers_total{
  trigger="local_authority_in_final_malicious_set"
}[5m]) > 0

sum by (race) (rate(ika_dwallet_mpc_completion_races_total[5m]))
```

Metrics intentionally omit session IDs and authority sets. They alert an
operator; the local Loki snapshot supplies session-level evidence.

## Example shapes

Field order is not stable; examples omit unrelated `None` and empty fields.

### Quorum defect while the local validator lags

A quorum snapshot only exists when a defect trigger fired; the race
conditions then appear as context alongside it:

```text
WARN event="mpc_session_anomaly" anomaly_kind="quorum_anomaly"
diagnostic_json={"schema_version":1,"session_id":"c30d...94a7",
  "local_party_id":27,"current_consensus_round":844172,
  "quorum_consensus_round":844172,"local_computation_state":"running",
  "running_computation_count":1,"local_output_produced":false,
  "local_output_submitted":false,"local_output_observed":false,
  "quorum_reached_without_local_output":true,
  "quorum_output_cached_without_local_output":true,
  "trigger_conditions":["conflicting_output_reports_observed",
    "quorum_reached_before_local_output_observed",
    "local_computation_pending_at_session_completion"],
  "vote":{"threshold_required":3,"winning_weight":3,
    "reports":[...],"vote_groups":[...]}}
```

### Local rejection

```text
ERROR event="mpc_session_anomaly" anomaly_kind="local_computation_failed"
diagnostic_json={"schema_version":1,"session_id":"...",
  "local_computation_state":"failed","local_computation_attempts_failed":1,
  "error_code":"serialization",
  "trigger_conditions":["local_mpc_computation_returned_error"]}
WARN event="mpc_session_anomaly" anomaly_kind="local_rejected_output"
diagnostic_json={"schema_version":1,"local_output_produced":true,
  "local_output_submitted":true,"local_output_rejected":true,
  "trigger_conditions":["local_validator_submitting_rejected_output"]}
```

### Self recognized as malicious

```text
WARN event="mpc_session_anomaly" anomaly_kind="quorum_anomaly"
diagnostic_json={"schema_version":1,"local_output_observed":false,
  "local_authority_malicious":true,
  "vote":{"malicious_voters":[],
    "reported_malicious_authorities":["<local authority>"],
    "final_malicious_authorities":["<local authority>"],
    "local_authority_malicious_reason":"reported_by_majority_output"},
  "trigger_conditions":["winning_output_reported_malicious_authorities",
    "local_authority_in_final_malicious_set"]}
ERROR event="mpc_session_anomaly" anomaly_kind="service_exit_self_malicious"
diagnostic_json={"schema_version":1,
  "service_loop_termination_reason":"local_validator_recognized_as_malicious"}
```

## Diagnosing quorum without the local validator

Quorum forming before the local validator's output loops back is, on its own,
only a completion-race counter increment — no snapshot exists for it. When it
co-occurred with a defect trigger, the quorum snapshot answers the previously
ambiguous questions directly (for the observed System session at round
844172):

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
before a restarted validator reproduces and observes its local output; that
race no longer emits a snapshot, but an honest network-key reconfiguration
straggler still emits the matched-case
`computation_update_after_session_completion` snapshot, so a blanket
assertion that these workflows contain no anomaly snapshots would still be
incorrect. Diagnostic behavior is covered by focused manager tests; no
upgrade workflow log assertion is warranted unless a future flow injects a
specific anomaly and asserts its expected fields.

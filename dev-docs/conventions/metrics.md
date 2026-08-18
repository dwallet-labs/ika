# Prometheus metric names — convention and inventory

## Convention

**All NEW metrics use the `ika_` prefix** (`ika_<subsystem>_<what>_<unit>`).
Enforced in CI by `scripts/check-metric-names.sh`: a registered literal
name must either start with `ika_` or appear in the frozen legacy
allowlist (`scripts/metric-name-allowlist.txt`) — the allowlist is
never added to.

**As of 1.2.0, every metric ika exports carries the `ika_` prefix — the
allowlist is empty.** The rename happened in one shot at the 1.2.0
release boundary (when operators rebuild dashboards anyway), in three
parts:

- the ~97 ika-native legacy names and the ~35 live Sui-lineage names
  (`consensus_handler_*`, `sequencing_*`, `current_epoch`, epoch
  timings, …) were renamed with a mechanical `ika_` prefix — full
  old→new table at the bottom of this file;
- the **Mysticeti-internal metrics** (registered by upstream Sui's
  `consensus-core` crate, not by ika code) are prefixed via their
  per-epoch registry's namespace — `Registry::new_custom(Some("consensus_ika"))`
  in `consensus_manager/mod.rs` — so they export as `consensus_ika_*`
  without any upstream code change. Consequence: upstream Mysticeti
  Grafana dashboards need a prefix adjustment to be reused;

  **`ika_` is ika's namespace and nothing else's.** The two sides live in
  *different* registries that `RegistryService` merges at `/metrics`, and
  the prefix is applied at `gather()` rather than at registration — so
  prometheus's per-registry duplicate check never sees both names, and a
  collision is silent: the endpoint serves the same family twice and the
  scraper drops a sample per scrape ("duplicate sample for timestamp"),
  halving one series with nothing failing. That is ika #2022, from back
  when the vendored registry was prefixed `ika_consensus` and ika's own
  commit-boundary gauge landed on upstream's `last_committed_leader_round`.

  **The rule is a bipartition, so a collision is unrepresentable:**
  1. every metric ika registers starts with `ika_`;
  2. no re-export registry uses a prefix starting with `ika`.

  Both are properties of source, and both are enforced statically by
  `scripts/check-metric-names.sh`. Rule 2 needs no list of anyone's
  names and self-extends: a vendored registry added later is caught
  without anybody remembering to update anything — which was the failure
  mode of every list-based version of this rule.

  Note that `ika_consensus_*` **is** ika's to use — those are ika's own
  consensus-handling metrics (`ika_consensus_handler_processed` and
  friends), sitting alongside `ika_dwallet_*` and `ika_ocs_*`. They were
  never badly named; the vendored registry was squatting in their
  namespace, and it is the squatter that moved.
- ~85 registered-but-never-set fork-residue metrics (tx-deny, zklogin,
  Move-verifier/execution, transaction-manager caches, random-beacon —
  subsystems ika does not run) were **deleted**, not renamed: they only
  ever exported constant zeros.

**Before writing an alert or dashboard, check the name here or via
`./scripts/check-metric-names.sh --list`** — a wrong metric name in an
alert fails silently forever. (Alert rules for the designed halt/block
modes: `../playbooks/production-alerts.md`.)

Names built dynamically (`format!`) are invisible to the extractor and
documented in the allowlist by hand — currently the epoch-store pruner
family (`ika_last_pruned_{consensus,authority}_db_epoch`,
`successfully_pruned_*_dbs`, `error_pruning_*_dbs`).

## Types, suffixes, and labels

- **Counters** (monotonic) end in `_total` and register with
  `register_int_counter*` — e.g. `dwallet_mpc_global_presigns_served_total`,
  `dwallet_mpc_network_key_instantiation_failures_total`.
- **Gauges** (a current value) are a plain noun, often `_count` / `_size`
  / `_in_flight` — e.g. `dwallet_mpc_internal_presign_pool_size`,
  `ika_dwallet_mpc_malicious_actors_count`. Never give a gauge `_total`.
  One legacy exception: `ika_dwallet_mpc_session_start_count` is a genuine
  counter (converted from a gauge that was only ever incremented) whose
  `_count` name predates the suffix convention and is kept so existing
  dashboards keep working.
- **Per-protocol metrics are LABELLED, not duplicated per protocol.** The
  MPC computation gauges are `*_vec` keyed by
  `["curve", "signature_algorithm", "key_role"]`; the label values come
  from `DWalletSessionRequestMetricData`
  (`crates/ika-core/src/dwallet_session_request.rs`), whose
  `From<&ProtocolData>` / `From<&ProtocolCryptographicData>` impls are
  **exhaustive — no catch-all arm**. Consequence: a new signing protocol
  that reuses the existing `ProtocolData` variants (e.g. the Fast Schnorr
  VSS algorithms, which only add new `curve` / `signature_algorithm`
  enum values) is instrumented **automatically** — provided its
  curve/algorithm enum has a real `Display` so the label isn't `Unknown`.
  Add a brand-new metric only for a genuinely new dimension (e.g.
  `ika_dwallet_mpc_malicious_actors_count`, added by PR #1714 for a count
  no existing label captures).

## A metric vs. a log line

For a signal a **test or alert** must assert on, prefer a scrapable
metric over grepping logs (fragile, and it couples the test to a log
string). `ika_dwallet_mpc_malicious_actors_count` — an `IntGauge` set in
`mpc_manager.rs::record_malicious_actors` — exists precisely so the
cross-binary malicious-detection test asserts exclusion programmatically
instead of matching a log line. Log-level discipline itself lives in
[`logging.md`](logging.md).

`ika_dwallet_mpc_self_malicious_total{reason,session_type}` counts sessions for
which a validator concluded that IT ITSELF is malicious — its output diverged
from the peers' quorum, or the majority output named it. Before this counter the
conclusion existed only as an `error!` in that one operator's logs, so a
validator dropping itself out of MPC was invisible to the other ~93 on
testnet+mainnet. It is deliberately NOT an invariant violation: a correct binary
can reach this state (a genuine divergence, or a wire-format disagreement during
a protocol upgrade), so it must not be routed through
`report_invariant_violation!`, which means "should never happen" and would both
mislabel the condition and pollute that counter during a rollout.

Its labels are the whole reason it can be exported: `reason` is the fixed
`LocalAuthorityMaliciousReason` set (plus `unspecified`) and `session_type` is
the fixed session kind — at most a handful of series. Session ids, authority
names and output digests are excluded on purpose. They are unbounded, and on a
public metrics endpoint they identify which operator diverged and on what.

`ika_invariant_violations_total{site}` shadows every structured
`should_never_happen = true` error across the node. Call sites use
`report_invariant_violation!` with a stable literal `site`; the macro emits the
error and increments the counter together. Dynamic values must remain log
fields, never label values. The counter vector does not create a series until a
site fires, so an absent series means zero violations. CI rejects bare
`should_never_happen = true` markers outside the macro.

An invariant counter records an **occurrence**, not an ongoing state. A
condition inside a retry or service loop that can persist across ticks must fire
the macro only on transition into the condition, log recovery once, and expose
a paired `*_condition_active` gauge for the current state. Repeating the macro
on every retry destroys incident boundaries and makes `increase(...) > 0`
indistinguishable from a previously-known condition. Bounded reminder logs are
allowed when operators need them, but reminders do not increment the invariant
counter. The network-key registry sites are guarded structurally by
`scripts/check-invariant-violation-markers.sh`.

### A node must be able to tell it has stopped contributing

`ika_mpc_consensus_round_lag` is how far the MPC service trails the consensus
commit path, sampled on every commit. Small and roughly constant in normal
operation; unbounded growth means MPC has stopped while consensus keeps
running — the node follows consensus, serves requests, exports every other
metric, and contributes nothing.

The rule it encodes: **a subsystem cannot report its own stall.** Every path
that stops the MPC service also stops any check placed inside it — most
starkly the deliberate `break` on self-recognised maliciousness, which ends the
service loop for the life of the process. So the stalled side only publishes
its progress, and a path that is still running does the comparing.

It is deliberately computable from local state alone, needing no peer data and
no fleet context. Two validators went dark for hours in production this way
(#1978, #1980); both were diagnosed from a fleet-wide Grafana no external
operator can see, and both were cleared by a restart nobody knew to perform.
A signal that only we can read is not a signal for the people running the
network.

Paired with a latched log: the sample runs on every consensus commit, so the
loud line fires on transition into and out of the condition, and the gauge
carries the continuous signal. `-1` before the MPC service reports its first
round, since round 0 is a legitimate value.

**The raw lag is not the alert target** — `ika_mpc_stopped_contributing_condition_active`
is. Consensus rounds restart at zero each epoch and a restarted node builds a
fresh epoch store whose cursor starts there too, so a mid-epoch restart's replay
gap is simply "rounds elapsed this epoch": past the first three quarters of an
hour of a 24h epoch it exceeds any stall threshold while the node is recovering
perfectly normally, and the alarm fired on every restart of every production
validator (#2036).

Which forces the general rule: **a detector that lives outside a subsystem
because the subsystem cannot report its own stall must still be told what the
subsystem is deliberately doing** — otherwise "stopped" and "busy recovering"
are the same observation from outside. What it must not do is read that
intention from a flag the subsystem sets, because a flag outlives the loop that
set it — a "busy recovering" flag left behind by a dead service loop reads
exactly like a service still recovering. The MPC service publishes its catch-up
state on every consumed
round and the detector honours it only while it stays fresh, so the suppression
is a lease the stalled side stops renewing the moment it stalls — a service that
dies mid-catch-up alarms like any other stopped service. For the same reason the
state is sampled from the catch-up gate itself, never from the gate's Prometheus
gauge: that gauge is published by the service loop, so it latches at `1` exactly
when the loop dies.

Suppressing an alarm creates a hole, so it comes with the alarm that covers it:
`ika_mpc_catch_up_stuck_condition_active` is a reported catch-up whose gap has
stopped reaching new lows, over a bound generous against the observed drain
rate. Between them, "not contributing" and "not recovering" are both loud, and
the recovering-normally case is silent.

### Process-wide wire settings need a gauge, not just a log

`ika_authority_name_encoding_width_bytes` and
`ika_handoff_attestation_width_retry_total` existed for the v6 -> v7
`AuthorityName` width flip and were removed with it at MIN = 7: there is one
encoding now, so the gauge could only ever report one value, and the retry the
counter measured no longer exists. The rule they encoded outlives them and
governs the next wire change that needs a version boundary.

A setting the whole committee must agree on, held in process memory, needs a
fleet-scrapeable gauge for the duration of its transition — two distinct values
across hosts is then a visible split rather than something to deduce from what
breaks. Publish it from the setter rather than the caller, so every path is
covered, including test-only fault injection: a gate that injects a straggler
should be able to see the straggler it injected. If a compatibility retry
accompanies the flip, count it, and keep "recovered" separate from "the payload
was simply bad" — a successful retry is otherwise indistinguishable from one
that never fired, and "the boundary worked" cannot tell you which happened.
Retire both with the scaffolding.

Per-authority output observations are collected protocol-generically but
**exported only for an allow-listed set of protocols** (currently network-key
reconfiguration; see `OUTPUT_OBSERVATION_EXPORT_PROTOCOLS` in `mpc_manager.rs`).
`ika_dwallet_mpc_session_output_info` carries the protocol name, session,
authority, and canonical BCS-output digest; the paired
`ika_dwallet_mpc_session_reported_malicious_actors` and
`ika_dwallet_mpc_session_output_rejected` gauges preserve each authority's
report envelope. This lets one instrumented validator verify
consensus-submitted outputs, including reports from an unmodified historical
binary. The allow-list is deliberate: these series are labeled by session id
and authority, so exporting every protocol would add one series per
sign/presign session on production validators — extend it only when a scenario
actually scrapes another protocol's outputs. The series reset with the
per-epoch manager. `ika_dwallet_mpc_protocol_sessions_pending{protocol_name=...}`
is exported for every protocol (it is bounded — one series per protocol name)
and emits zero for a completed protocol while its session remains tracked, so
tests can distinguish a clean zero from a missing protocol observation.

## Validator host telemetry

Validator processes register host telemetry in the default registry, so the
existing authenticated metrics-push task sends it through `ika-proxy`. Fullnodes
and notifiers do not register these metrics. Collection refreshes every 15
seconds; `metrics.push-interval-seconds` still determines the remote-write
cadence.

`ika_validator_up` is the inventory/heartbeat series. Its value is `1` while the
process is running. A stopped validator cannot push a zero, so alerts must treat
an absent or stale series as down. The series carries bounded labels for binary
version and git revision, OS/kernel/architecture/hostname, deployment and cloud
placement/identity, memory technology, and container/Kubernetes identity.
`ika-proxy` adds the authenticated on-chain validator `host`, configured
`network`, and socket-observed `public_ip`; node-provided values cannot override
those labels.

The remaining families cover:

- binary SHA-256 and size;
- CPU hardware/frequency and logical/physical count, system CPU ratio, load
  averages, thermal sensors, and process CPU cores;
- host memory/swap, process resident/virtual memory, and Linux cgroup CPU and
  memory limits;
- DMI machine, motherboard, BIOS, virtualization, and hashed machine identity;
- database-volume identity/capacity and validator-process read/write bytes;
- aggregate interface receive/transmit bytes and errors;
- host boot time/uptime, process uptime/thread/file-descriptor pressure,
  collection freshness, and categorized collection errors.

The collector never exports arbitrary environment variables. They frequently
contain credentials and their unconstrained values would create unbounded
series. Operators can supply the following allow-listed metadata; values are
trimmed and limited to 128 characters:

| Variable | `ika_validator_up` label |
|---|---|
| `IKA_METRICS_ENVIRONMENT` | `deployment_environment` |
| `IKA_METRICS_CLOUD_PROVIDER` | `cloud_provider` |
| `IKA_METRICS_REGION` | `region` |
| `IKA_METRICS_ZONE` | `zone` |
| `IKA_METRICS_LOCATION` | `location` |
| `IKA_METRICS_INSTANCE_TYPE` | `instance_type` |
| `IKA_METRICS_CLOUD_INSTANCE_ID` | `cloud_instance_id` |
| `IKA_METRICS_CLOUD_IMAGE_ID` | `cloud_image_id` |
| `IKA_METRICS_PRIVATE_IP` | `private_ip` |
| `IKA_METRICS_MEMORY_TYPE` | `memory_type` |
| `IKA_METRICS_CONTAINER_RUNTIME` | `container_runtime` |
| `IKA_METRICS_CONTAINER_ID` | `container_id` |
| `IKA_METRICS_CONTAINER_IMAGE` | `container_image` |
| `IKA_METRICS_K8S_CLUSTER` | `kubernetes_cluster` |
| `IKA_METRICS_K8S_NAMESPACE` | `kubernetes_namespace` |
| `IKA_METRICS_K8S_POD` | `kubernetes_pod` |
| `IKA_METRICS_K8S_NODE` | `kubernetes_node` |

Common AWS region, generic region/zone/instance, and Kubernetes downward-API
variables are used as fallbacks. Container/runtime/ID, DMI/SMBIOS memory type,
virtualization, and cgroup limits are also detected locally when the platform
exposes them. The background collector requests only identity/placement fields
from the AWS, GCP, or Azure hardcoded link-local metadata endpoints with a
one-second timeout and proxying disabled; when DMI or environment data identifies
the provider, only that endpoint is queried. It never requests credentials,
tokens other than the short-lived AWS IMDSv2 request token, tags, or user data.
Set `IKA_DISABLE_CLOUD_METADATA=1` to disable these requests. Location is never
derived through a third-party IP-geolocation service.

## Inventory (generated)

Regenerate with: `./scripts/check-metric-names.sh --list`

CI enforces this block: the same script's default (validate) mode fails
when the list and the source disagree in either direction, so adding or
removing a metric without updating this block fails the build instead of
drifting silently.

```
ika_archive_actions_read
ika_archive_dwallet_checkpoints_read
ika_archive_system_checkpoints_read
ika_binary_max_protocol_version
ika_committee_quorum_threshold
ika_committee_total_stake
ika_committee_validity_threshold
ika_configured_max_protocol_version
ika_consensus_boot_replay_folded_commit_index
ika_consensus_boot_replay_latency_seconds
ika_consensus_boot_replay_target_commit_index
ika_consensus_calculated_throughput
ika_consensus_calculated_throughput_profile
ika_consensus_commit_silence_seconds
ika_consensus_fold_blocked_seconds_total
ika_consensus_fold_blocked_sends_total
ika_consensus_committed_messages
ika_consensus_committed_subdags
ika_consensus_committed_user_transactions
ika_consensus_handler_cancelled_transactions
ika_consensus_handler_num_low_scoring_authorities
ika_consensus_handler_processed
ika_consensus_round_channel_depth
ika_consensus_handler_scores
ika_consensus_handler_transaction_sizes
ika_consensus_last_committed_timestamp_seconds
ika_consensus_manager_shutdown_latency
ika_consensus_manager_start_latency
ika_current_epoch
ika_current_protocol_version
ika_current_voting_right
ika_dwallet_checkpoint_aggregator_committed_stake
ika_dwallet_checkpoint_aggregator_current_seq
ika_dwallet_checkpoint_aggregator_distinct_digests
ika_dwallet_checkpoint_aggregator_plurality_stake
ika_dwallet_checkpoint_aggregator_uncommitted_stake
ika_dwallet_checkpoint_creation_latency
ika_dwallet_checkpoint_errors
ika_dwallet_checkpoint_participation
ika_dwallet_checkpoint_pending_queue_depth
ika_dwallet_checkpoint_roots_count
ika_dwallet_checkpoint_signatures_verified
ika_dwallet_checkpoint_sync_stall_seconds
ika_dwallet_checkpoint_user_session_written_at_seq
ika_dwallet_handoff_cert_epoch
ika_dwallet_handoff_signatures_buffered
ika_dwallet_handoff_signatures_collected
ika_dwallet_handoff_signatures_rejected_total
ika_dwallet_handoff_signatures_stake
ika_dwallet_mpc_active_sessions_by_age
ika_dwallet_mpc_advance_calls
ika_dwallet_mpc_advance_completions
ika_dwallet_mpc_anomaly_snapshots_dropped_total
ika_dwallet_mpc_anomaly_snapshots_total
ika_dwallet_mpc_anomaly_triggers_total
ika_dwallet_mpc_catchup_gap_rounds
ika_dwallet_mpc_catchup_mode
ika_dwallet_mpc_catchup_suppressed_computations_total
ika_dwallet_mpc_completion_races_total
ika_dwallet_mpc_completions_count
ika_dwallet_mpc_computation_duration_avg
ika_dwallet_mpc_computation_duration_variance
ika_dwallet_mpc_cryptographic_computation_core_budget
ika_dwallet_mpc_cryptographic_computations_running
ika_dwallet_mpc_data_announcements_received
ika_dwallet_mpc_data_blob_fetch_total
ika_dwallet_mpc_data_excluded_validators
ika_dwallet_mpc_data_freeze_epoch
ika_dwallet_mpc_data_freeze_grace_rounds
ika_dwallet_mpc_data_freeze_round
ika_dwallet_mpc_data_locally_validated_peers
ika_dwallet_mpc_data_ready_quorum_round
ika_dwallet_mpc_data_ready_signal_deadline_timestamp_seconds
ika_dwallet_mpc_data_ready_signal_stake
ika_dwallet_mpc_data_ready_signals
ika_dwallet_mpc_global_presign_requests_waiting
ika_dwallet_mpc_global_presigns_served_total
ika_dwallet_mpc_internal_presign_ordinal_lag
ika_dwallet_mpc_internal_presign_ordinals_fast_forwarded_total
ika_dwallet_mpc_internal_presign_pool_size
ika_dwallet_mpc_internal_presign_requests_pending_for_network_key_data
ika_dwallet_mpc_last_completion_duration
ika_dwallet_mpc_malicious_actors_count
ika_dwallet_mpc_messages_after_terminal_session_total
ika_dwallet_mpc_network_encryption_key_canonical_dkg_output_version
ika_dwallet_mpc_network_encryption_key_latest_reconfiguration_output_version
ika_dwallet_mpc_network_key_instantiation_failures_total
ika_dwallet_mpc_network_key_instantiation_sub_call_duration_seconds
ika_dwallet_mpc_network_key_instantiations_in_flight
ika_dwallet_mpc_network_key_loaded_epoch
ika_dwallet_mpc_noa_presign_demands_evicted_total
ika_dwallet_mpc_number_of_expected_sign_sessions
ika_dwallet_mpc_number_of_unexpected_sign_sessions
ika_dwallet_mpc_prior_cert_blobs_missing
ika_dwallet_mpc_protocol_data_generation_errors_total
ika_dwallet_mpc_protocol_sessions_pending
ika_dwallet_mpc_ready_to_advance_result_total
ika_dwallet_mpc_received_requests_start_count
ika_dwallet_mpc_requests_pending_for_frozen_mpc_data
ika_dwallet_mpc_requests_pending_for_network_key
ika_dwallet_mpc_requests_pending_for_next_active_committee
ika_dwallet_mpc_self_malicious_total
ika_dwallet_mpc_self_output_to_quorum_consensus_rounds
ika_dwallet_mpc_service_end_of_publish_local
ika_dwallet_mpc_session_late_output_info
ika_dwallet_mpc_session_late_output_malicious_actors
ika_dwallet_mpc_session_output_info
ika_dwallet_mpc_session_output_rejected
ika_dwallet_mpc_session_reported_malicious_actors
ika_dwallet_mpc_session_start_count
ika_dwallet_mpc_session_state_count
ika_dwallet_mpc_sessions_reconstructed_total
ika_dwallet_mpc_sessions_rejected_total
ika_dwallet_mpc_sessions_with_self_output_no_quorum
ika_dwallet_mpc_user_session_distinct_output_authorities
ika_dwallet_mpc_user_session_distinct_output_digests
ika_dwallet_mpc_user_session_first_output_consensus_round
ika_dwallet_mpc_user_session_local_output_rejected
ika_dwallet_mpc_user_session_output_received_from
ika_dwallet_mpc_user_session_quorum_consensus_round
ika_dwallet_mpc_user_session_self_output_consensus_round
ika_dwallet_mpc_user_session_state
ika_dwallet_mpc_user_sessions_active_without_local_output
ika_dwallet_native_calls
ika_dwallet_native_completions
ika_effective_buffer_stake
ika_epoch_first_checkpoint_created_time_since_epoch_begin_ms
ika_epoch_first_system_checkpoint_created_time_since_epoch_begin_ms
ika_epoch_pending_dwallet_checkpoint_signatures
ika_epoch_pending_dwallet_checkpoints
ika_epoch_pending_system_checkpoint_signatures
ika_epoch_pending_system_checkpoints
ika_epoch_processed_consensus_messages
ika_epoch_reconfig_start_time_since_epoch_close_ms
ika_epoch_total_computation_reward
ika_epoch_total_duration
ika_epoch_validator_halt_duration_ms
ika_handoff_prepare_duration_seconds
ika_handoff_prepare_retries_total
ika_handoff_prepare_waiting
ika_highest_accumulated_system_checkpoint_epoch
ika_highest_known_dwallet_checkpoint
ika_highest_known_system_checkpoint
ika_highest_synced_dwallet_checkpoint
ika_highest_synced_system_checkpoint
ika_highest_verified_dwallet_checkpoint
ika_highest_verified_system_checkpoint
ika_invariant_violations_total
ika_joiner_bootstrap_outcomes_total
ika_last_certified_dwallet_checkpoint
ika_last_certified_dwallet_checkpoint_age
ika_last_certified_system_checkpoint
ika_last_certified_system_checkpoint_age
ika_last_committed_leader_consensus_round
ika_last_constructed_dwallet_checkpoint
ika_last_constructed_system_checkpoint
ika_last_created_dwallet_checkpoint_age
ika_last_created_system_checkpoint_age
ika_last_dwallet_checkpoint_pending_height
ika_last_ignored_dwallet_checkpoint_signature_received
ika_last_ignored_system_checkpoint_signature_received
ika_last_process_mpc_consensus_round
ika_last_received_dwallet_checkpoint_signatures
ika_last_received_system_checkpoint_signatures
ika_last_sent_dwallet_checkpoint_signature
ika_last_sent_system_checkpoint_signature
ika_last_skipped_dwallet_checkpoint_signature_submission
ika_last_skipped_system_checkpoint_signature_submission
ika_last_system_checkpoint_pending_height
ika_latest_dwallet_checkpoint_archived
ika_latest_system_checkpoint_archived
ika_messages_included_in_dwallet_checkpoint
ika_messages_included_in_system_checkpoint
ika_mpc_blob_store_evictions_total
ika_mpc_blob_store_size_bytes
ika_mpc_catch_up_stuck_condition_active
ika_mpc_consensus_round_lag
ika_mpc_data_announcement_blob_bytes
ika_mpc_stopped_contributing_condition_active
ika_network_key_overlay_incomplete
ika_network_key_registry_read_empty_condition_active
ika_num_peers_with_external_address
ika_ocs_anchor_info
ika_ocs_bag_omission_suspected_total
ika_ocs_cache_first_stale_total
ika_ocs_cache_read_total
ika_ocs_chain_latest_epoch
ika_ocs_committee_head_epoch
ika_ocs_dynamic_fields_walk_entries_returned_total
ika_ocs_dynamic_fields_walk_entries_seen_total
ika_ocs_dynamic_fields_walk_entries_skipped_transient_total
ika_ocs_high_water_violations_total
ika_ocs_identity_mismatch_total
ika_ocs_last_successful_relay_timestamp_seconds
ika_ocs_proof_build_failures_total
ika_ocs_proof_build_latency_seconds
ika_ocs_proof_built_total
ika_ocs_proof_snapshot_cache_hits_total
ika_ocs_proof_tree_cache_hits_total
ika_ocs_proof_tree_cache_misses_total
ika_ocs_proof_verify_failures_total
ika_ocs_proof_verify_total
ika_ocs_pusher_cursor_seq
ika_ocs_pusher_fetch_failures_total
ika_ocs_pusher_fold_verify_seconds
ika_ocs_pusher_gap_archive_repairs_total
ika_ocs_pusher_gap_dropped_total
ika_ocs_pusher_pushed_total
ika_ocs_pusher_skipped_irrelevant_total
ika_ocs_pusher_stalled
ika_ocs_ratchet_failures_total
ika_ocs_ratchet_stalled
ika_ocs_relay_failures_total
ika_ocs_relay_peer_failover_total
ika_ocs_relay_request_latency_seconds
ika_ocs_relay_request_total
ika_ocs_role_info
ika_ocs_serve_latency_seconds
ika_ocs_serve_request_by_peer_total
ika_ocs_serve_request_total
ika_ocs_verify_latency_seconds
ika_ocs_watermark_implausible_total
ika_off_chain_assembly_consecutive_incomplete_ticks
ika_off_chain_assembly_incomplete
ika_off_chain_assembly_incomplete_duration_seconds
ika_off_chain_assembly_incomplete_ticks_total
ika_off_chain_assembly_last_success_timestamp_seconds
ika_off_chain_assembly_missing
ika_off_chain_assembly_wedged
ika_own_mpc_data_blob_unhealthy
ika_protocol_upgrade_effective_threshold
ika_protocol_upgrade_supporting_stake
ika_reconfig_phase
ika_remote_dwallet_checkpoint_forks
ika_remote_system_checkpoint_forks
ika_sequencing_acknowledge_latency
ika_sequencing_certificate_attempt
ika_sequencing_certificate_authority_position
ika_sequencing_certificate_failures
ika_sequencing_certificate_inflight
ika_sequencing_certificate_latency
ika_sequencing_certificate_positions_moved
ika_sequencing_certificate_preceding_disconnected
ika_sequencing_certificate_processed
ika_sequencing_certificate_status
ika_sequencing_certificate_success
ika_sequencing_in_flight_semaphore_wait
ika_sequencing_in_flight_submissions
ika_skipped_consensus_txns
ika_skipped_consensus_txns_cache_hit
ika_split_brain_dwallet_checkpoint_forks
ika_split_brain_system_checkpoint_forks
ika_stranded_network_key_missing_from_registry_read_condition_active
ika_sui_client_chain_blob_reads
ika_sui_client_sui_rpc_errors
ika_sui_connector_chain_active_system_sessions_count
ika_sui_connector_chain_active_user_sessions_count
ika_sui_connector_chain_dwallet_checkpoint_writer_lag
ika_sui_connector_chain_epoch_overdue_seconds
ika_sui_connector_chain_received_end_of_publish
ika_sui_connector_chain_user_sessions_lag
ika_sui_connector_dwallet_checkpoint_sequence
ika_sui_connector_dwallet_checkpoint_write_requests_total
ika_sui_connector_dwallet_checkpoint_writes_failure_total
ika_sui_connector_dwallet_checkpoint_writes_success_total
ika_sui_connector_end_of_publish_blocked_reason
ika_sui_connector_epoch_switch_step_done
ika_sui_connector_gas_coin_balance
ika_sui_connector_last_synced_sui_checkpoints
ika_sui_connector_last_written_dwallet_checkpoint_sequence
ika_sui_connector_last_written_system_checkpoint_sequence
ika_sui_connector_system_checkpoint_sequence
ika_sui_connector_system_checkpoint_write_requests_total
ika_sui_connector_system_checkpoint_writes_failure_total
ika_sui_connector_system_checkpoint_writes_success_total
ika_sui_connector_uncompleted_events_backlog
ika_supported_protocol_version_max
ika_supported_protocol_version_min
ika_system_checkpoint_creation_latency
ika_system_checkpoint_errors
ika_system_checkpoint_participation
ika_system_checkpoint_roots_count
ika_system_checkpoint_signatures_verified
ika_system_checkpoint_sync_stall_seconds
ika_validator_binary_info
ika_validator_binary_size_bytes
ika_validator_cgroup_cpu_limit_cores
ika_validator_cgroup_memory_available_bytes
ika_validator_cgroup_memory_limit_bytes
ika_validator_cgroup_memory_rss_bytes
ika_validator_cloud_metadata_available
ika_validator_cpu_frequency_mhz
ika_validator_cpu_info
ika_validator_cpu_logical_count
ika_validator_cpu_physical_count
ika_validator_load_average_fifteen_minutes
ika_validator_load_average_five_minutes
ika_validator_load_average_one_minute
ika_validator_machine_info
ika_validator_memory_available_bytes
ika_validator_memory_total_bytes
ika_validator_memory_used_bytes
ika_validator_network_receive_bytes_total
ika_validator_network_receive_errors_total
ika_validator_network_transmit_bytes_total
ika_validator_network_transmit_errors_total
ika_validator_process_cpu_cores
ika_validator_process_disk_read_bytes_total
ika_validator_process_disk_written_bytes_total
ika_validator_process_open_file_descriptors
ika_validator_process_resident_memory_bytes
ika_validator_process_thread_count
ika_validator_process_uptime_seconds
ika_validator_process_virtual_memory_bytes
ika_validator_storage_available_bytes
ika_validator_storage_info
ika_validator_storage_total_bytes
ika_validator_swap_total_bytes
ika_validator_swap_used_bytes
ika_validator_system_boot_unixtime
ika_validator_system_cpu_usage_ratio
ika_validator_system_uptime_seconds
ika_validator_telemetry_collection_errors_total
ika_validator_telemetry_last_refresh_unixtime
ika_validator_temperature_celsius
ika_validator_temperature_critical_celsius
ika_validator_up
```

## 1.2.0 rename table (legacy → current)

Renamed in the 1.2.0 release; update dashboards/alerts accordingly.
(`dwallet_nativee_calls` also had its typo fixed.)

| legacy (≤1.1.x) | current |
|---|---|
| `archive_actions_read` | `ika_archive_actions_read` |
| `archive_dwallet_checkpoints_read` | `ika_archive_dwallet_checkpoints_read` |
| `archive_system_checkpoints_read` | `ika_archive_system_checkpoints_read` |
| `dwallet_checkpoint_creation_latency` | `ika_dwallet_checkpoint_creation_latency` |
| `dwallet_checkpoint_errors` | `ika_dwallet_checkpoint_errors` |
| `dwallet_checkpoint_participation` | `ika_dwallet_checkpoint_participation` |
| `dwallet_checkpoint_roots_count` | `ika_dwallet_checkpoint_roots_count` |
| `dwallet_checkpoint_signatures_verified` | `ika_dwallet_checkpoint_signatures_verified` |
| `dwallet_handoff_cert_epoch` | `ika_dwallet_handoff_cert_epoch` |
| `dwallet_handoff_signatures_buffered` | `ika_dwallet_handoff_signatures_buffered` |
| `dwallet_handoff_signatures_collected` | `ika_dwallet_handoff_signatures_collected` |
| `dwallet_handoff_signatures_rejected_total` | `ika_dwallet_handoff_signatures_rejected_total` |
| `dwallet_handoff_signatures_stake` | `ika_dwallet_handoff_signatures_stake` |
| `dwallet_mpc_advance_calls` | `ika_dwallet_mpc_advance_calls` |
| `dwallet_mpc_advance_completions` | `ika_dwallet_mpc_advance_completions` |
| `dwallet_mpc_completions_count` | `ika_dwallet_mpc_completions_count` |
| `dwallet_mpc_computation_duration_avg` | `ika_dwallet_mpc_computation_duration_avg` |
| `dwallet_mpc_computation_duration_variance` | `ika_dwallet_mpc_computation_duration_variance` |
| `dwallet_mpc_data_announcements_received` | `ika_dwallet_mpc_data_announcements_received` |
| `dwallet_mpc_data_blob_fetch_total` | `ika_dwallet_mpc_data_blob_fetch_total` |
| `dwallet_mpc_data_excluded_validators` | `ika_dwallet_mpc_data_excluded_validators` |
| `dwallet_mpc_data_freeze_epoch` | `ika_dwallet_mpc_data_freeze_epoch` |
| `dwallet_mpc_data_locally_validated_peers` | `ika_dwallet_mpc_data_locally_validated_peers` |
| `dwallet_mpc_data_ready_signal_stake` | `ika_dwallet_mpc_data_ready_signal_stake` |
| `dwallet_mpc_data_ready_signals` | `ika_dwallet_mpc_data_ready_signals` |
| `dwallet_mpc_global_presign_requests_waiting` | `ika_dwallet_mpc_global_presign_requests_waiting` |
| `dwallet_mpc_global_presigns_served_total` | `ika_dwallet_mpc_global_presigns_served_total` |
| `dwallet_mpc_internal_presign_pool_size` | `ika_dwallet_mpc_internal_presign_pool_size` |
| `dwallet_mpc_last_completion_duration` | `ika_dwallet_mpc_last_completion_duration` |
| `dwallet_mpc_network_key_instantiation_failures_total` | `ika_dwallet_mpc_network_key_instantiation_failures_total` |
| `dwallet_mpc_network_key_instantiation_sub_call_duration_seconds` | `ika_dwallet_mpc_network_key_instantiation_sub_call_duration_seconds` |
| `dwallet_mpc_network_key_instantiations_in_flight` | `ika_dwallet_mpc_network_key_instantiations_in_flight` |
| `dwallet_mpc_number_of_expected_sign_sessions` | `ika_dwallet_mpc_number_of_expected_sign_sessions` |
| `dwallet_mpc_number_of_unexpected_sign_sessions` | `ika_dwallet_mpc_number_of_unexpected_sign_sessions` |
| `dwallet_mpc_received_requests_start_count` | `ika_dwallet_mpc_received_requests_start_count` |
| `dwallet_mpc_session_start_count` | `ika_dwallet_mpc_session_start_count` |
| `dwallet_native_completions` | `ika_dwallet_native_completions` |
| `dwallet_nativee_calls` | `ika_dwallet_native_calls` |
| `epoch_first_system_checkpoint_created_time_since_epoch_begin_ms` | `ika_epoch_first_system_checkpoint_created_time_since_epoch_begin_ms` |
| `epoch_total_computation_reward` | `ika_epoch_total_computation_reward` |
| `highest_accumulated_system_checkpoint_epoch` | `ika_highest_accumulated_system_checkpoint_epoch` |
| `highest_known_dwallet_checkpoint` | `ika_highest_known_dwallet_checkpoint` |
| `highest_known_system_checkpoint` | `ika_highest_known_system_checkpoint` |
| `highest_synced_dwallet_checkpoint` | `ika_highest_synced_dwallet_checkpoint` |
| `highest_synced_system_checkpoint` | `ika_highest_synced_system_checkpoint` |
| `highest_verified_dwallet_checkpoint` | `ika_highest_verified_dwallet_checkpoint` |
| `highest_verified_system_checkpoint` | `ika_highest_verified_system_checkpoint` |
| `last_certified_dwallet_checkpoint` | `ika_last_certified_dwallet_checkpoint` |
| `last_certified_dwallet_checkpoint_age` | `ika_last_certified_dwallet_checkpoint_age` |
| `last_certified_system_checkpoint` | `ika_last_certified_system_checkpoint` |
| `last_certified_system_checkpoint_age` | `ika_last_certified_system_checkpoint_age` |
| `last_constructed_dwallet_checkpoint` | `ika_last_constructed_dwallet_checkpoint` |
| `last_constructed_system_checkpoint` | `ika_last_constructed_system_checkpoint` |
| `last_created_dwallet_checkpoint_age` | `ika_last_created_dwallet_checkpoint_age` |
| `last_created_system_checkpoint_age` | `ika_last_created_system_checkpoint_age` |
| `last_dwallet_checkpoint_pending_height` | `ika_last_dwallet_checkpoint_pending_height` |
| `last_ignored_dwallet_checkpoint_signature_received` | `ika_last_ignored_dwallet_checkpoint_signature_received` |
| `last_ignored_system_checkpoint_signature_received` | `ika_last_ignored_system_checkpoint_signature_received` |
| `last_process_mpc_consensus_round` | `ika_last_process_mpc_consensus_round` |
| `last_received_dwallet_checkpoint_signatures` | `ika_last_received_dwallet_checkpoint_signatures` |
| `last_received_system_checkpoint_signatures` | `ika_last_received_system_checkpoint_signatures` |
| `last_sent_dwallet_checkpoint_signature` | `ika_last_sent_dwallet_checkpoint_signature` |
| `last_sent_system_checkpoint_signature` | `ika_last_sent_system_checkpoint_signature` |
| `last_skipped_dwallet_checkpoint_signature_submission` | `ika_last_skipped_dwallet_checkpoint_signature_submission` |
| `last_skipped_system_checkpoint_signature_submission` | `ika_last_skipped_system_checkpoint_signature_submission` |
| `last_system_checkpoint_pending_height` | `ika_last_system_checkpoint_pending_height` |
| `latest_dwallet_checkpoint_archived` | `ika_latest_dwallet_checkpoint_archived` |
| `latest_system_checkpoint_archived` | `ika_latest_system_checkpoint_archived` |
| `messages_included_in_dwallet_checkpoint` | `ika_messages_included_in_dwallet_checkpoint` |
| `messages_included_in_system_checkpoint` | `ika_messages_included_in_system_checkpoint` |
| `network_key_overlay_incomplete` | `ika_network_key_overlay_incomplete` |
| `off_chain_assembly_incomplete_ticks_total` | `ika_off_chain_assembly_incomplete_ticks_total` |
| `off_chain_assembly_wedged` | `ika_off_chain_assembly_wedged` |
| `own_mpc_data_blob_unhealthy` | `ika_own_mpc_data_blob_unhealthy` |
| `remote_dwallet_checkpoint_forks` | `ika_remote_dwallet_checkpoint_forks` |
| `remote_system_checkpoint_forks` | `ika_remote_system_checkpoint_forks` |
| `split_brain_dwallet_checkpoint_forks` | `ika_split_brain_dwallet_checkpoint_forks` |
| `split_brain_system_checkpoint_forks` | `ika_split_brain_system_checkpoint_forks` |
| `sui_client_chain_blob_reads` | `ika_sui_client_chain_blob_reads` |
| `sui_client_sui_rpc_errors` | `ika_sui_client_sui_rpc_errors` |
| `sui_connector_dwallet_checkpoint_sequence` | `ika_sui_connector_dwallet_checkpoint_sequence` |
| `sui_connector_dwallet_checkpoint_write_requests_total` | `ika_sui_connector_dwallet_checkpoint_write_requests_total` |
| `sui_connector_dwallet_checkpoint_writes_failure_total` | `ika_sui_connector_dwallet_checkpoint_writes_failure_total` |
| `sui_connector_dwallet_checkpoint_writes_success_total` | `ika_sui_connector_dwallet_checkpoint_writes_success_total` |
| `sui_connector_gas_coin_balance` | `ika_sui_connector_gas_coin_balance` |
| `sui_connector_last_synced_sui_checkpoints` | `ika_sui_connector_last_synced_sui_checkpoints` |
| `sui_connector_last_written_dwallet_checkpoint_sequence` | `ika_sui_connector_last_written_dwallet_checkpoint_sequence` |
| `sui_connector_last_written_system_checkpoint_sequence` | `ika_sui_connector_last_written_system_checkpoint_sequence` |
| `sui_connector_system_checkpoint_sequence` | `ika_sui_connector_system_checkpoint_sequence` |
| `sui_connector_system_checkpoint_write_requests_total` | `ika_sui_connector_system_checkpoint_write_requests_total` |
| `sui_connector_system_checkpoint_writes_failure_total` | `ika_sui_connector_system_checkpoint_writes_failure_total` |
| `sui_connector_system_checkpoint_writes_success_total` | `ika_sui_connector_system_checkpoint_writes_success_total` |
| `system_checkpoint_creation_latency` | `ika_system_checkpoint_creation_latency` |
| `system_checkpoint_errors` | `ika_system_checkpoint_errors` |
| `system_checkpoint_participation` | `ika_system_checkpoint_participation` |
| `system_checkpoint_roots_count` | `ika_system_checkpoint_roots_count` |
| `system_checkpoint_signatures_verified` | `ika_system_checkpoint_signatures_verified` |
| `consensus_calculated_throughput` | `ika_consensus_calculated_throughput` |
| `consensus_calculated_throughput_profile` | `ika_consensus_calculated_throughput_profile` |
| `consensus_committed_messages` | `ika_consensus_committed_messages` |
| `consensus_committed_subdags` | `ika_consensus_committed_subdags` |
| `consensus_committed_user_transactions` | `ika_consensus_committed_user_transactions` |
| `consensus_handler_cancelled_transactions` | `ika_consensus_handler_cancelled_transactions` |
| `consensus_handler_num_low_scoring_authorities` | `ika_consensus_handler_num_low_scoring_authorities` |
| `consensus_handler_processed` | `ika_consensus_handler_processed` |
| `consensus_handler_scores` | `ika_consensus_handler_scores` |
| `consensus_handler_transaction_sizes` | `ika_consensus_handler_transaction_sizes` |
| `current_epoch` | `ika_current_epoch` |
| `current_voting_right` | `ika_current_voting_right` |
| `effective_buffer_stake` | `ika_effective_buffer_stake` |
| `epoch_first_checkpoint_created_time_since_epoch_begin_ms` | `ika_epoch_first_checkpoint_created_time_since_epoch_begin_ms` |
| `epoch_reconfig_start_time_since_epoch_close_ms` | `ika_epoch_reconfig_start_time_since_epoch_close_ms` |
| `epoch_total_duration` | `ika_epoch_total_duration` |
| `epoch_validator_halt_duration_ms` | `ika_epoch_validator_halt_duration_ms` |
| `num_peers_with_external_address` | `ika_num_peers_with_external_address` |
| `sequencing_acknowledge_latency` | `ika_sequencing_acknowledge_latency` |
| `sequencing_certificate_attempt` | `ika_sequencing_certificate_attempt` |
| `sequencing_certificate_authority_position` | `ika_sequencing_certificate_authority_position` |
| `sequencing_certificate_failures` | `ika_sequencing_certificate_failures` |
| `sequencing_certificate_inflight` | `ika_sequencing_certificate_inflight` |
| `sequencing_certificate_latency` | `ika_sequencing_certificate_latency` |
| `sequencing_certificate_positions_moved` | `ika_sequencing_certificate_positions_moved` |
| `sequencing_certificate_preceding_disconnected` | `ika_sequencing_certificate_preceding_disconnected` |
| `sequencing_certificate_processed` | `ika_sequencing_certificate_processed` |
| `sequencing_certificate_status` | `ika_sequencing_certificate_status` |
| `sequencing_certificate_success` | `ika_sequencing_certificate_success` |
| `sequencing_in_flight_semaphore_wait` | `ika_sequencing_in_flight_semaphore_wait` |
| `sequencing_in_flight_submissions` | `ika_sequencing_in_flight_submissions` |
| `skipped_consensus_txns` | `ika_skipped_consensus_txns` |
| `skipped_consensus_txns_cache_hit` | `ika_skipped_consensus_txns_cache_hit` |
| `consensus_manager_start_latency` | `ika_consensus_manager_start_latency` |
| `consensus_manager_shutdown_latency` | `ika_consensus_manager_shutdown_latency` |
| `last_pruned_{kind}_db_epoch` | `ika_last_pruned_{kind}_db_epoch` |
| `successfully_pruned_{kind}_dbs` | `ika_successfully_pruned_{kind}_dbs` |
| `error_pruning_{kind}_dbs` | `ika_error_pruning_{kind}_dbs` |

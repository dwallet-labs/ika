# Prometheus metric names — convention and inventory

## Convention

**All NEW metrics use the `ika_` prefix** (`ika_<subsystem>_<what>_<unit>`).
Enforced in CI by `scripts/check-metric-names.sh`: a registered literal
name must either start with `ika_` or appear in the frozen legacy
allowlist (`scripts/metric-name-allowlist.txt`) — the allowlist is
never added to.

**As of 1.2.0, every ika-native metric carries the `ika_` prefix** —
the legacy ika-native names (~97: `dwallet_*`, `sui_connector_*`,
checkpoint/state-sync families adapted to dwallet/system checkpoints,
handoff, off-chain assembly, …) were renamed in one shot at the 1.2.0
release boundary, when operators rebuild dashboards anyway. The full
old→new table is at the bottom of this file.

What deliberately KEEPS its un-prefixed name: any metric whose name a
Sui-lineage family carries verbatim or near-verbatim from upstream Sui
(`authority_*`, `consensus_*`, `sequencing_*`, `transaction_manager_*`,
`execution_*`, epoch/reconfiguration timings, …). Operators reuse Sui
dashboards for those, and renaming would diverge from upstream forever
(merge churn on every Sui sync). The allowlist now contains exactly this
upstream-matching set plus the dynamic pruner family.

**Before writing an alert or dashboard, check the name here or via
`./scripts/check-metric-names.sh --list`** — a wrong metric name in an
alert fails silently forever. (Alert rules for the designed halt/block
modes: `../playbooks/production-alerts.md`.)

Names built dynamically (`format!`) are invisible to the extractor and
documented in the allowlist by hand — currently the epoch-store pruner
family (`last_pruned_{consensus,authority}_db_epoch`,
`successfully_pruned_*_dbs`, `error_pruning_*_dbs`).

## Types, suffixes, and labels

- **Counters** (monotonic) end in `_total` and register with
  `register_int_counter*` — e.g. `dwallet_mpc_global_presigns_served_total`,
  `dwallet_mpc_network_key_instantiation_failures_total`.
- **Gauges** (a current value) are a plain noun, often `_count` / `_size`
  / `_in_flight` — e.g. `dwallet_mpc_session_start_count`,
  `dwallet_mpc_internal_presign_pool_size`,
  `ika_dwallet_mpc_malicious_actors_count`. Never give a gauge `_total`.
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

## Inventory (generated)

Regenerate with: `./scripts/check-metric-names.sh --list`

```
authority_load_shedding_percentage
authority_overload_status
authority_state_commit_certificate_latency
authority_state_execute_certificate_latency
authority_state_execution_load_input_objects_latency
authority_state_handle_transaction_latency
authority_state_handle_transaction_v2_latency
authority_state_internal_execution_latency
authority_state_prepare_certificate_latency
await_transaction_latency
batch_size
certificate_signatures_verified
consensus_calculated_throughput
consensus_calculated_throughput_profile
consensus_committed_messages
consensus_committed_subdags
consensus_committed_user_transactions
consensus_handler_cancelled_transactions
consensus_handler_congested_transactions
consensus_handler_deferred_transactions
consensus_handler_max_congestion_control_object_costs
consensus_handler_num_low_scoring_authorities
consensus_handler_processed
consensus_handler_scores
consensus_handler_transaction_sizes
consensus_manager_shutdown_latency
consensus_manager_start_latency
consensus_transaction_handler_fastpath_executions
consensus_transaction_handler_processed
current_epoch
current_voting_right
db_checkpoint_latency
effective_buffer_stake
epoch_checkpoint_count
epoch_first_checkpoint_created_time_since_epoch_begin_ms
epoch_last_checkpoint_created_time_since_epoch_close_ms
epoch_pending_certs_processed_time_since_epoch_close_ms
epoch_random_beacon_dkg_completion_time_ms
epoch_random_beacon_dkg_confirmation_time_ms
epoch_random_beacon_dkg_epoch_start_completion_time_ms
epoch_random_beacon_dkg_failed
epoch_random_beacon_dkg_message_time_ms
epoch_random_beacon_dkg_num_shares
epoch_reconfig_start_time_since_epoch_close_ms
epoch_total_duration
epoch_transaction_count
epoch_validator_halt_duration_ms
excessive_deleted_move_object_ids_size
excessive_estimated_effects_size
excessive_new_move_object_ids_size
excessive_object_runtime_cached_objects_size
excessive_object_runtime_store_entries_size
excessive_transferred_move_object_ids_size
excessive_written_objects_size
execution_driver_dispatch_queue
execution_driver_executed_transactions
execution_gas_latency_ratio
execution_queueing_delay_s
highest_accumulated_epoch
ika_archive_actions_read
ika_archive_dwallet_checkpoints_read
ika_archive_system_checkpoints_read
ika_binary_max_protocol_version
ika_configured_max_protocol_version
ika_current_protocol_version
ika_dwallet_checkpoint_creation_latency
ika_dwallet_checkpoint_errors
ika_dwallet_checkpoint_participation
ika_dwallet_checkpoint_roots_count
ika_dwallet_checkpoint_signatures_verified
ika_dwallet_handoff_cert_epoch
ika_dwallet_handoff_signatures_buffered
ika_dwallet_handoff_signatures_collected
ika_dwallet_handoff_signatures_rejected_total
ika_dwallet_handoff_signatures_stake
ika_dwallet_mpc_advance_calls
ika_dwallet_mpc_advance_completions
ika_dwallet_mpc_completions_count
ika_dwallet_mpc_computation_duration_avg
ika_dwallet_mpc_computation_duration_variance
ika_dwallet_mpc_data_announcements_received
ika_dwallet_mpc_data_blob_fetch_total
ika_dwallet_mpc_data_excluded_validators
ika_dwallet_mpc_data_freeze_epoch
ika_dwallet_mpc_data_locally_validated_peers
ika_dwallet_mpc_data_ready_signal_stake
ika_dwallet_mpc_data_ready_signals
ika_dwallet_mpc_global_presign_requests_waiting
ika_dwallet_mpc_global_presigns_served_total
ika_dwallet_mpc_internal_presign_pool_size
ika_dwallet_mpc_last_completion_duration
ika_dwallet_mpc_malicious_actors_count
ika_dwallet_mpc_network_encryption_key_canonical_dkg_output_version
ika_dwallet_mpc_network_key_instantiation_failures_total
ika_dwallet_mpc_network_key_instantiation_sub_call_duration_seconds
ika_dwallet_mpc_network_key_instantiations_in_flight
ika_dwallet_mpc_number_of_expected_sign_sessions
ika_dwallet_mpc_number_of_unexpected_sign_sessions
ika_dwallet_mpc_received_requests_start_count
ika_dwallet_mpc_session_start_count
ika_dwallet_native_calls
ika_dwallet_native_completions
ika_epoch_first_system_checkpoint_created_time_since_epoch_begin_ms
ika_epoch_total_computation_reward
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
ika_joiner_bootstrap_outcomes_total
ika_last_certified_dwallet_checkpoint
ika_last_certified_dwallet_checkpoint_age
ika_last_certified_system_checkpoint
ika_last_certified_system_checkpoint_age
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
ika_mpc_data_announcement_blob_bytes
ika_network_key_overlay_incomplete
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
ika_ocs_proof_build_failures_total
ika_ocs_proof_build_latency_seconds
ika_ocs_proof_built_total
ika_ocs_proof_tree_cache_hits_total
ika_ocs_proof_tree_cache_misses_total
ika_ocs_proof_verify_failures_total
ika_ocs_proof_verify_total
ika_ocs_pusher_cursor_seq
ika_ocs_pusher_fetch_failures_total
ika_ocs_pusher_fold_verify_seconds
ika_ocs_pusher_pushed_total
ika_ocs_pusher_skipped_irrelevant_total
ika_ocs_pusher_stalled
ika_ocs_relay_failures_total
ika_ocs_relay_peer_failover_total
ika_ocs_relay_request_latency_seconds
ika_ocs_relay_request_total
ika_ocs_role_info
ika_ocs_serve_latency_seconds
ika_ocs_serve_request_by_peer_total
ika_ocs_serve_request_total
ika_ocs_unverified_committee_fallback_total
ika_ocs_verify_latency_seconds
ika_off_chain_assembly_incomplete_ticks_total
ika_off_chain_assembly_wedged
ika_own_mpc_data_blob_unhealthy
ika_remote_dwallet_checkpoint_forks
ika_remote_system_checkpoint_forks
ika_split_brain_dwallet_checkpoint_forks
ika_split_brain_system_checkpoint_forks
ika_sui_client_chain_blob_reads
ika_sui_client_sui_rpc_errors
ika_sui_connector_dwallet_checkpoint_sequence
ika_sui_connector_dwallet_checkpoint_write_requests_total
ika_sui_connector_dwallet_checkpoint_writes_failure_total
ika_sui_connector_dwallet_checkpoint_writes_success_total
ika_sui_connector_gas_coin_balance
ika_sui_connector_last_synced_sui_checkpoints
ika_sui_connector_last_written_dwallet_checkpoint_sequence
ika_sui_connector_last_written_system_checkpoint_sequence
ika_sui_connector_system_checkpoint_sequence
ika_sui_connector_system_checkpoint_write_requests_total
ika_sui_connector_system_checkpoint_writes_failure_total
ika_sui_connector_system_checkpoint_writes_success_total
ika_system_checkpoint_creation_latency
ika_system_checkpoint_errors
ika_system_checkpoint_participation
ika_system_checkpoint_roots_count
ika_system_checkpoint_signatures_verified
multisig_sig_count
num_input_objects
num_peers_with_external_address
num_shared_obj_tx
num_shared_objects
num_sponsored_tx
num_tx_already_processed
post_processing_total_events_emitted
post_processing_total_failures
post_processing_total_tx_had_event_processed
post_processing_total_tx_indexed
prepare_cert_gas_latency_ratio
sequencing_acknowledge_latency
sequencing_certificate_attempt
sequencing_certificate_authority_position
sequencing_certificate_failures
sequencing_certificate_inflight
sequencing_certificate_latency
sequencing_certificate_positions_moved
sequencing_certificate_preceding_disconnected
sequencing_certificate_processed
sequencing_certificate_status
sequencing_certificate_success
sequencing_estimated_latency
sequencing_in_flight_semaphore_wait
sequencing_in_flight_submissions
sequencing_resubmission_interval_ms
skipped_consensus_txns
skipped_consensus_txns_cache_hit
total_handle_certificate_attempts
total_transaction_certificates
total_transaction_effects
total_transaction_orders
transaction_manager_num_enqueued_certificates
transaction_manager_num_executing_certificates
transaction_manager_num_missing_objects
transaction_manager_num_pending_certificates
transaction_manager_num_ready
transaction_manager_object_cache_evictions
transaction_manager_object_cache_hits
transaction_manager_object_cache_misses
transaction_manager_object_cache_size
transaction_manager_package_cache_evictions
transaction_manager_package_cache_hits
transaction_manager_package_cache_misses
transaction_manager_package_cache_size
transaction_manager_transaction_queue_age_s
transaction_overload_sources
tx_deny_config_num_denied_addresses
tx_deny_config_num_denied_objects
tx_deny_config_num_denied_packages
tx_deny_config_package_publish_disabled
tx_deny_config_package_upgrade_disabled
tx_deny_config_shared_object_disabled
tx_deny_config_user_transaction_disabled
verifier_runtime_per_module_success_latency
verifier_runtime_per_module_timeout_latency
verifier_runtime_per_ptb_success_latency
verifier_runtime_per_ptb_timeout_latency
verifier_timeout_metrics
zklogin_sig_count
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

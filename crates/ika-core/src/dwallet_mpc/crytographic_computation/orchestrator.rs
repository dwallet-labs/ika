// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! The orchestrator for dWallet MPC cryptographic computations.
//!
//! The orchestrator manages a task queue for cryptographic computations and
//! ensures efficient CPU resource utilization.
//! It tracks the number of available CPU cores and prevents launching
//! tasks when all cores are occupied.
//!
//! Key responsibilities:
//! — Manages a queue of pending cryptographic computations
//! — Tracks currently running sessions and available CPU cores
//! — Handles session spawning and completion notifications.
//! — Implements special handling for aggregated sign operations
//! — Ensures computations don't become redundant based on received messages
//!
//! The orchestrator uses a channel-based notification system to track completed computation.

use crate::dwallet_mpc::crytographic_computation::{ComputationId, ComputationRequest};
use crate::dwallet_mpc::dwallet_mpc_metrics::DWalletMPCMetrics;
use crate::dwallet_mpc::mpc_session::ComputationResultData;
use crate::dwallet_session_request::DWalletSessionRequestMetricData;
use crate::runtime::IkaRuntimes;
use dwallet_rng::RootSeed;
use group::PartyID;
use ika_types::dwallet_mpc_error::{DwalletMPCError, DwalletMPCResult};
use ika_types::messages_dwallet_mpc::SessionIdentifier;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;
// Only the non-msim path dispatches the completion via `Handle::spawn`; under
// msim the computation runs inline (see `try_spawn_cryptographic_computation`).
#[cfg(not(msim))]
use tokio::runtime::Handle;
use tokio::sync::mpsc::{Receiver, Sender};
use tracing::{debug, error, info};

/// Channel size for cryptographic computations state updates.
/// This channel should not reach a size even close to this.
/// But since this is critical to keep the computations running,
/// we are using a big buffer (this size of the data is small).
const COMPUTATION_UPDATE_CHANNEL_SIZE: usize = 10_000;

struct ComputationCompletionUpdate {
    computation_id: ComputationId,
    party_id: PartyID,
    protocol_metadata: DWalletSessionRequestMetricData,
    computation_result: DwalletMPCResult<mpc::GuaranteedOutputDeliveryRoundResult>,
    elapsed_ms: u128,
}

/// The orchestrator for DWallet MPC cryptographic computations.
///
/// The orchestrator manages cryptographic computation tasks and ensures efficient
///  CPU resource utilization.
/// It tracks available CPU cores and prevents launching tasks when all cores are occupied.
///
/// Key responsibilities:
/// — Manages a queue of pending cryptographic computations
/// — Tracks currently running sessions and available CPU cores
/// — Handles session spawning and completion notifications
/// — Implements special handling for aggregated sign operations
/// — Ensures computations don't become redundant based on received messages
pub(crate) struct CryptographicComputationsOrchestrator {
    /// The number of logical CPUs available for cryptographic computations on the validator's
    /// machine. Used to limit parallel task execution.
    available_cores_for_cryptographic_computations: usize,

    /// A channel sender to notify the manager about completed computations,
    /// allowing proper resource management.
    completed_computation_sender: Sender<ComputationCompletionUpdate>,
    completed_computation_receiver: Receiver<ComputationCompletionUpdate>,

    /// The currently running cryptographic computations.
    /// Tracks tasks that have been spawned with [`rayon::spawn_fifo`] but haven't completed yet.
    /// Used to prevent exceeding available CPU cores.
    pub(crate) currently_running_cryptographic_computations: HashSet<ComputationId>,

    /// The list of completed cryptographic computations in the current epoch.
    completed_cryptographic_computations: HashSet<ComputationId>,

    /// The root seed of this validator, used for deriving the per-round seed for
    /// advancing this session.
    /// SECURITY NOTICE: *MUST KEEP PRIVATE*.
    root_seed: RootSeed,

    /// Fast Schnorr (VSS) HPKE curve25519 secret key, derived once at startup
    /// from `root_seed` and reused for every VSS presign — avoids re-running
    /// the HPKE keypair generation per presign.
    vss_hpke_secret_key: group::curve25519::Scalar,
}

impl CryptographicComputationsOrchestrator {
    /// Creates a new orchestrator for cryptographic computations.
    pub(crate) fn try_new(
        root_seed: RootSeed,
        max_computation_cores: Option<usize>,
    ) -> DwalletMPCResult<Self> {
        let (report_computation_completed_sender, report_computation_completed_receiver) =
            tokio::sync::mpsc::channel(COMPUTATION_UPDATE_CHANNEL_SIZE);
        let mut available_cores_for_computations =
            IkaRuntimes::calculate_num_of_computations_cores();
        if available_cores_for_computations == 0 {
            // When `IkaRuntimes::calculate_num_of_computations_cores` returns 0,
            // Rayon will use the default number of threads, which is the number of available cores on the machine
            available_cores_for_computations = std::thread::available_parallelism()
                .map_err(|e| DwalletMPCError::FailedToGetAvailableParallelism(e.to_string()))?
                .into();
        }
        // Operator override (`NodeConfig::max_mpc_computation_cores`): cap the
        // concurrent-computation budget below the host core count. Bounds peak
        // CPU + memory when validators are co-located (e.g. CI test clusters).
        if let Some(max) = max_computation_cores {
            available_cores_for_computations = available_cores_for_computations.min(max).max(1);
        }
        info!(
            available_cores_for_computations =? available_cores_for_computations,
            ?max_computation_cores,
            "Available CPU cores for Rayon cryptographic computations"
        );

        let vss_hpke_secret_key =
            dwallet_classgroups_types::ValidatorMPCSecrets::vss_hpke_secret_key_from_seed(
                &root_seed,
            );

        Ok(CryptographicComputationsOrchestrator {
            available_cores_for_cryptographic_computations: available_cores_for_computations,
            completed_computation_sender: report_computation_completed_sender,
            completed_computation_receiver: report_computation_completed_receiver,
            currently_running_cryptographic_computations: HashSet::new(),
            completed_cryptographic_computations: HashSet::new(),
            root_seed,
            vss_hpke_secret_key,
        })
    }

    /// Check for completed computations, and return their results.
    pub(crate) fn receive_completed_computations(
        &mut self,
        dwallet_mpc_metrics: Arc<DWalletMPCMetrics>,
    ) -> HashMap<ComputationId, DwalletMPCResult<mpc::GuaranteedOutputDeliveryRoundResult>> {
        let mut completed_computation_results = HashMap::new();
        while let Ok(computation_update) = self.completed_computation_receiver.try_recv() {
            let party_id = computation_update.party_id;
            let protocol_metadata = computation_update.protocol_metadata.clone();
            let session_identifier = computation_update.computation_id.session_identifier;
            let mpc_round = computation_update.computation_id.mpc_round;
            let attempt_number = computation_update.computation_id.attempt_number;
            let elapsed_ms = computation_update.elapsed_ms;

            let computation_result_data = if let Some(mpc_round) = mpc_round {
                ComputationResultData::MPC { mpc_round }
            } else {
                ComputationResultData::Native
            };

            debug!(
                session_identifier=?computation_update.computation_id.session_identifier,
                ?computation_result_data,
                attempt_number=?computation_update.computation_id.attempt_number,
                currently_running_sessions_count =? self.currently_running_cryptographic_computations.len(),
                "Received a cryptographic computation completed update"
            );

            if let Err(err) = &computation_update.computation_result {
                error!(
                    party_id,
                    ?session_identifier,
                    ?computation_result_data,
                    attempt_number,
                    mpc_protocol=?protocol_metadata,
                    error=?err,
                    "Cryptographic computation failed"
                );
            } else {
                debug!(
                    party_id,
                    ?session_identifier,
                    ?computation_result_data,
                    attempt_number,
                    mpc_protocol =? protocol_metadata,
                    duration_ms = elapsed_ms,
                    duration_seconds = elapsed_ms / 1000,
                    "Cryptographic computation completed successfully"
                );

                match computation_result_data {
                    ComputationResultData::MPC { mpc_round } => {
                        dwallet_mpc_metrics.add_advance_completion(
                            &computation_update.protocol_metadata,
                            &mpc_round.to_string(),
                            elapsed_ms as i64,
                        );

                        dwallet_mpc_metrics.set_last_completion_duration(
                            &computation_update.protocol_metadata,
                            &mpc_round.to_string(),
                            elapsed_ms as i64,
                        );
                    }
                    ComputationResultData::Native => {
                        dwallet_mpc_metrics.add_native_completion(
                            &computation_update.protocol_metadata,
                            elapsed_ms as i64,
                        );
                        dwallet_mpc_metrics.set_last_completion_duration(
                            &computation_update.protocol_metadata,
                            "1",
                            elapsed_ms as i64,
                        );
                    }
                }
            }

            self.currently_running_cryptographic_computations
                .remove(&computation_update.computation_id);
            self.completed_cryptographic_computations
                .insert(computation_update.computation_id);

            completed_computation_results.insert(
                computation_update.computation_id,
                computation_update.computation_result,
            );
        }

        completed_computation_results
    }

    /// Check if sufficient CPU cores are available for computation.
    fn has_available_cores_to_perform_computation(&mut self) -> bool {
        self.currently_running_cryptographic_computations.len()
            < self.available_cores_for_cryptographic_computations
    }

    pub(crate) fn running_computation_count_for_session(
        &self,
        session_identifier: &SessionIdentifier,
    ) -> usize {
        self.currently_running_cryptographic_computations
            .iter()
            .filter(|computation_id| &computation_id.session_identifier == session_identifier)
            .count()
    }

    pub(crate) fn has_seen_computation(&self, computation_id: &ComputationId) -> bool {
        self.currently_running_cryptographic_computations
            .contains(computation_id)
            || self
                .completed_cryptographic_computations
                .contains(computation_id)
    }

    /// Try to spawn a cryptographic `computation_request` to execute in a different thread
    /// if a CPU core is available for it.
    ///
    /// Return `false` if no cores were available to execute it, and `true` otherwise
    /// (which might mean we spawned it, or we already spawned it in the past.)
    pub(crate) async fn try_spawn_cryptographic_computation(
        &mut self,
        computation_id: ComputationId,
        computation_request: ComputationRequest,
        dwallet_mpc_metrics: Arc<DWalletMPCMetrics>,
    ) -> bool {
        if self
            .currently_running_cryptographic_computations
            .contains(&computation_id)
            || self
                .completed_cryptographic_computations
                .contains(&computation_id)
        {
            // Don't run a task that we already spawned.
            return true;
        }

        if !self.has_available_cores_to_perform_computation() {
            debug!(
                session_identifier=?computation_id.session_identifier,
                mpc_round=?computation_id.mpc_round,
                attempt_number=?computation_id.attempt_number,
                mpc_protocol=?computation_request.protocol_data,
                available_cores=?self.available_cores_for_cryptographic_computations,
                currently_running_sessions_count =? self.currently_running_cryptographic_computations.len(),
                "No available CPU cores to perform cryptographic computation"
            );

            return false;
        }

        let party_id = computation_request.party_id;
        let protocol_metadata: DWalletSessionRequestMetricData =
            (&computation_request.protocol_cryptographic_data).into();

        debug!(
            party_id,
            session_identifier=?computation_id.session_identifier,
            current_round=?computation_id.mpc_round,
            attempt_number=?computation_id.attempt_number,
            mpc_protocol=?protocol_metadata,
            "Starting cryptographic computation",
        );

        // Simulation hook: lets a sim test degrade THIS validator's MPC
        // while its consensus stays alive (register_fail_point_if returning
        // true skips the computation) — the "MPC-dead validator" fault shape
        // that a whole-node stop cannot express without also halting
        // consensus. No-op outside msim/fail-point builds.
        let skip_computation = std::cell::Cell::new(false);
        sui_macros::fail_point_if!("dwallet-mpc-computation", || {
            skip_computation.set(true);
        });
        if skip_computation.get() {
            debug!(
                party_id,
                session_identifier=?computation_id.session_identifier,
                "fail point dwallet-mpc-computation active: skipping computation",
            );
            return false;
        }

        let computation_channel_sender = self.completed_computation_sender.clone();
        let root_seed = self.root_seed.clone();
        let vss_hpke_secret_key = self.vss_hpke_secret_key;

        // Under msim, run the computation INLINE in the calling task instead
        // of on rayon. Crypto is sequential under msim anyway (the `parallel`
        // feature is dropped in that profile), and a rayon worker has no
        // simulated-node context: even with a captured-NodeHandle re-entry
        // guard, msim's `Handle::spawn` re-resolves the CURRENT node at spawn
        // time, so a computation whose node was torn down mid-compute (an
        // epoch swap in the simulation) panics at
        // `NodeHandle::current().unwrap()` and rayon-core aborts the whole
        // process. Inline, the send happens in the same task context — which
        // dies cleanly WITH the node, dropping the now-moot result.
        #[cfg(msim)]
        {
            let advance_start_time = Instant::now();
            let computation_result = computation_request.compute(
                computation_id,
                root_seed,
                vss_hpke_secret_key,
                dwallet_mpc_metrics.clone(),
            );
            let elapsed_ms = advance_start_time.elapsed().as_millis();
            if let Err(err) = computation_channel_sender
                .send(ComputationCompletionUpdate {
                    computation_id,
                    party_id,
                    protocol_metadata,
                    computation_result,
                    elapsed_ms,
                })
                .await
            {
                error!(error=?err, "failed to send a computation completion update");
            }
        }

        #[cfg(not(msim))]
        {
            let handle = Handle::current();
            rayon::spawn_fifo(move || {
                let advance_start_time = Instant::now();

                // Catch a panic in `compute()` so this rayon closure does NOT
                // unwind: an unwound closure skips the `handle.spawn` send below,
                // so the completion update is never produced and the core slot
                // reserved at the end of this method is never reclaimed — leaking
                // it for the rest of the epoch until MPC wedges. A panic becomes
                // a failed result that is delivered like any other.
                let computation_result = compute_catching_panic(computation_id, move || {
                    computation_request.compute(
                        computation_id,
                        root_seed,
                        vss_hpke_secret_key,
                        dwallet_mpc_metrics,
                    )
                });

                let elapsed = advance_start_time.elapsed();
                let elapsed_ms = elapsed.as_millis();

                handle.spawn(async move {
                    if let Err(err) = computation_channel_sender
                        .send(ComputationCompletionUpdate {
                            computation_id,
                            party_id,
                            protocol_metadata,
                            computation_result,
                            elapsed_ms,
                        })
                        .await
                    {
                        error!(error=?err, "failed to send a computation completion update");
                    }
                });
            });
        }

        self.currently_running_cryptographic_computations
            .insert(computation_id);

        true
    }
}

/// Run `compute` under a panic boundary, converting a panic into a failed
/// `DwalletMPCResult` instead of letting it unwind the caller.
///
/// `compute()` dispatches into the external 2PC-MPC / class-groups `advance()`
/// (and in-tree `unreachable!()`/unwrap sites) on inputs aggregated from other,
/// possibly malicious, parties — so it can panic. Left unguarded that panic
/// either aborts the whole validator under `[profile.release] panic = "abort"`,
/// or — on an unwinding build (tests / simulator) — unwinds the orchestrator's
/// rayon closure so the `ComputationCompletionUpdate` is never sent and the
/// reserved core slot is never reclaimed, eventually wedging all MPC for the
/// epoch. Returning a failed result lets the caller send a completion update
/// unconditionally, so the slot is reclaimed and the session's error path runs.
///
/// `catch_unwind` only intercepts on an unwinding profile; under
/// `panic = "abort"` the abort stands (a fail-loud crash-restart, not a silent
/// wedge), which is this guard's deliberate boundary. The msim path runs
/// `compute()` inline and is intentionally left to die with its node (see the
/// caller), so it does not route through here — hence dead outside tests in
/// the msim build.
#[cfg(any(not(msim), test))]
fn compute_catching_panic(
    computation_id: ComputationId,
    compute: impl FnOnce() -> DwalletMPCResult<mpc::GuaranteedOutputDeliveryRoundResult>,
) -> DwalletMPCResult<mpc::GuaranteedOutputDeliveryRoundResult> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(compute)).unwrap_or_else(|panic| {
        let reason = panic
            .downcast_ref::<&str>()
            .map(|s| (*s).to_string())
            .or_else(|| panic.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "<non-string panic payload>".to_string());
        error!(
            session_identifier = ?computation_id.session_identifier,
            mpc_round = ?computation_id.mpc_round,
            attempt_number = computation_id.attempt_number,
            reason = %reason,
            "cryptographic computation panicked; converting to a failed result so the core slot is reclaimed"
        );
        Err(DwalletMPCError::MPCSessionError {
            session_identifier: computation_id.session_identifier,
            error: format!("cryptographic computation panicked: {reason}"),
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ika_types::messages_dwallet_mpc::{SessionIdentifier, SessionType};

    fn test_computation_id() -> ComputationId {
        ComputationId {
            session_identifier: SessionIdentifier::new(SessionType::System, [7u8; 32]),
            mpc_round: Some(1),
            attempt_number: 0,
            consensus_round: 0,
        }
    }

    /// A panic inside `compute()` (e.g. an `unreachable!()`/unwrap in the
    /// external 2PC-MPC advance on adversarial input) must surface as a failed
    /// result rather than unwinding the orchestrator's rayon closure — an
    /// unwound closure would skip the completion update and permanently leak the
    /// reserved core slot. (Removing the `catch_unwind` in
    /// `compute_catching_panic` makes this test itself panic, so it genuinely
    /// guards the property.)
    #[test]
    fn panic_in_compute_becomes_a_failed_result() {
        let id = test_computation_id();
        let err = compute_catching_panic(id, || panic!("boom inside advance()"))
            .expect_err("a panic must surface as a failed result, not Ok");
        match err {
            DwalletMPCError::MPCSessionError {
                error,
                session_identifier,
            } => {
                assert_eq!(session_identifier, id.session_identifier);
                assert!(
                    error.contains("panicked"),
                    "error should name the panic: {error}"
                );
                assert!(
                    error.contains("boom inside advance()"),
                    "panic message should be preserved: {error}"
                );
            }
            other => panic!("expected MPCSessionError, got {other:?}"),
        }
    }

    /// An ordinary (non-panicking) failure is passed through verbatim, not
    /// rewrapped as a panic.
    #[test]
    fn ordinary_failure_passes_through() {
        let id = test_computation_id();
        let err = compute_catching_panic(id, || {
            Err(DwalletMPCError::MPCSessionError {
                session_identifier: id.session_identifier,
                error: "ordinary failure".to_string(),
            })
        })
        .expect_err("the closure returned Err");
        match err {
            DwalletMPCError::MPCSessionError { error, .. } => {
                assert_eq!(error, "ordinary failure");
            }
            other => panic!("expected the original error, got {other:?}"),
        }
    }
}

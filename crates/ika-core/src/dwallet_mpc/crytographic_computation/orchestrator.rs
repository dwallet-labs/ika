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
use crate::runtime::IkaRuntimes;
use dwallet_rng::RootSeed;
use ika_types::dwallet_mpc_error::{DwalletMPCError, DwalletMPCResult};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;
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
    computation_request: ComputationRequest,
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
    currently_running_cryptographic_computations: HashSet<ComputationId>,

    /// The list of completed cryptographic computations in the current epoch.
    completed_cryptographic_computations: HashSet<ComputationId>,

    /// The root seed of this validator, used for deriving the per-round seed for
    /// advancing this session.
    /// SECURITY NOTICE: *MUST KEEP PRIVATE*.
    root_seed: RootSeed,
}

impl CryptographicComputationsOrchestrator {
    /// Creates a new orchestrator for cryptographic computations.
    pub(crate) fn try_new(root_seed: RootSeed) -> DwalletMPCResult<Self> {
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
        info!(
            available_cores_for_computations =? available_cores_for_computations,
            "Available CPU cores for Rayon cryptographic computations"
        );

        Ok(CryptographicComputationsOrchestrator {
            available_cores_for_cryptographic_computations: available_cores_for_computations,
            completed_computation_sender: report_computation_completed_sender,
            completed_computation_receiver: report_computation_completed_receiver,
            currently_running_cryptographic_computations: HashSet::new(),
            completed_cryptographic_computations: HashSet::new(),
            root_seed,
        })
    }

    /// Check for completed computations, and return their results.
    pub(crate) fn receive_completed_computations(
        &mut self,
        dwallet_mpc_metrics: Arc<DWalletMPCMetrics>,
    ) -> HashMap<ComputationId, DwalletMPCResult<mpc::GuaranteedOutputDeliveryRoundResult>> {
        let mut completed_computation_results = HashMap::new();
        while let Ok(computation_update) = self.completed_computation_receiver.try_recv() {
            let party_id = computation_update.computation_request.party_id;
            let request_input = computation_update.computation_request.request_input.clone();
            let session_identifier = computation_update.computation_id.session_identifier;
            let mpc_round = computation_update.computation_id.mpc_round;
            let attempt_number = computation_update.computation_id.attempt_number;
            let elapsed_ms = computation_update.elapsed_ms;

            debug!(
                session_identifier=?computation_update.computation_id.session_identifier,
                mpc_round=?computation_update.computation_id.mpc_round,
                attempt_number=?computation_update.computation_id.attempt_number,
                currently_running_sessions_count =? self.currently_running_cryptographic_computations.len(),
                "Received a cryptographic computation completed update"
            );

            if let Err(err) = &computation_update.computation_result {
                error!(
                    party_id,
                    ?session_identifier,
                    mpc_round,
                    attempt_number,
                    mpc_protocol=?request_input,
                    error=?err,
                    "Cryptographic computation failed"
                );
            } else {
                info!(
                    party_id,
                    ?session_identifier,
                    mpc_round,
                    attempt_number,
                    mpc_protocol=?request_input,
                    duration_ms = elapsed_ms,
                    duration_seconds = elapsed_ms / 1000,
                    "Cryptographic computation completed successfully"
                );

                dwallet_mpc_metrics.add_advance_completion(
                    &request_input,
                    &mpc_round.to_string(),
                    elapsed_ms as i64,
                );

                dwallet_mpc_metrics.set_last_completion_duration(
                    &request_input,
                    &mpc_round.to_string(),
                    elapsed_ms as i64,
                );
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
        if !self.has_available_cores_to_perform_computation() {
            info!(
                session_identifier=?computation_id.session_identifier,
                mpc_round=?computation_id.mpc_round,
                attempt_number=?computation_id.attempt_number,
                mpc_protocol=?computation_request.request_input,
                "No available CPU cores to perform cryptographic computation"
            );

            return false;
        }

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

        let handle = Handle::current();

        dwallet_mpc_metrics.add_advance_call(
            &computation_request.request_input,
            &computation_id.mpc_round.to_string(),
        );

        let party_id = computation_request.party_id;
        let request_input = computation_request.request_input.clone();
        info!(
            party_id,
            session_identifier=?computation_id.session_identifier,
            mpc_round=?computation_id.mpc_round,
            attempt_number=?computation_id.attempt_number,
            mpc_protocol=?request_input,
            "Starting cryptographic computation",
        );

        let computation_channel_sender = self.completed_computation_sender.clone();
        let root_seed = self.root_seed.clone();
        rayon::spawn_fifo(move || {
            let advance_start_time = Instant::now();

            let computation_result = computation_request.clone().compute(
                computation_id,
                root_seed,
                dwallet_mpc_metrics.clone(),
            );

            let elapsed = advance_start_time.elapsed();
            let elapsed_ms = elapsed.as_millis();

            handle.spawn(async move {
                if let Err(err) = computation_channel_sender
                    .send(ComputationCompletionUpdate {
                        computation_id,
                        computation_request,
                        computation_result,
                        elapsed_ms,
                    })
                    .await
                {
                    error!(error=?err, "failed to send a computation completion update");
                }
            });
        });

        self.currently_running_cryptographic_computations
            .insert(computation_id);

        true
    }
}

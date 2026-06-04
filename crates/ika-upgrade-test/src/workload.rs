// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Continuous dWallet workload driver.
//!
//! A dependency state machine (not a fire-and-forget loop): a Sign needs a
//! completed DKG + Presign first, and that chain must survive the epoch
//! boundary the harness is deliberately perturbing. Requests are built with
//! `ika-sui-client::ika_dwallet_transactions` and submitted as Sui txns to the
//! coordinator contract (there is no gRPC submission surface); user-side 2PC
//! inputs come from `dwallet-mpc-centralized-party`. Each issued session is
//! tracked to one terminal bucket; an orphan (neither completed nor cleanly
//! rejected by end of run) is the bug this asserts against.
//!
//! NOTE: submission/poll wiring is implemented in the workload-driver task; the
//! types below pin the contract the scenario layer depends on.

use ika_types::messages_dwallet_mpc::IkaNetworkConfig;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionKind {
    Dkg,
    Presign,
    Sign,
}

/// Terminal classification of an issued session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TerminalState {
    /// Reached `Completed` on-chain.
    Completed,
    /// Rejected for a documented reason (e.g. started in epoch N, ran past the
    /// boundary, rejected with `epoch != current`).
    RejectedWithDocumentedReason(String),
    /// Neither completed nor cleanly rejected by end of run — the bug.
    OrphanedAfterTimeout,
}

#[derive(Clone, Debug)]
pub struct InFlightSession {
    pub session_id: String,
    pub kind: SessionKind,
    pub started_epoch: u64,
}

/// Summary returned when the workload is stopped.
#[derive(Clone, Debug, Default)]
pub struct WorkloadReport {
    pub completed: usize,
    pub rejected: Vec<(String, String)>,
    pub orphaned: Vec<String>,
}

impl WorkloadReport {
    /// The assertion the cross-binary scenario makes: nothing orphaned.
    pub fn assert_no_silent_drops(&self) -> anyhow::Result<()> {
        if self.orphaned.is_empty() {
            Ok(())
        } else {
            anyhow::bail!(
                "{} session(s) orphaned (no terminal state): {:?}",
                self.orphaned.len(),
                self.orphaned,
            )
        }
    }
}

/// Drives continuous DKG→Presign→Sign traffic against the cluster's Sui RPC.
pub struct WorkloadDriver {
    #[allow(dead_code)]
    rpc_url: String,
    #[allow(dead_code)]
    network_config: IkaNetworkConfig,
}

impl WorkloadDriver {
    pub fn new(rpc_url: String, network_config: IkaNetworkConfig) -> Self {
        Self {
            rpc_url,
            network_config,
        }
    }

    /// Run continuous traffic until `stop` is signalled, returning the report.
    /// Implemented in the workload-driver task.
    pub async fn run_until_stopped(self) -> anyhow::Result<WorkloadReport> {
        anyhow::bail!("workload driver not yet wired (task #4)")
    }
}

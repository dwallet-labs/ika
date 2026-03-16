// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use async_trait::async_trait;
use ika_types::noa_checkpoint::NOACheckpointKind;
use tracing::info;

// === TxExecutionStatus ===

/// Tri-state result of checking a transaction's on-chain status.
#[derive(Clone, Debug)]
pub enum TxExecutionStatus {
    /// Transaction confirmed on-chain.
    Executed,
    /// Transaction not yet executed, still potentially valid.
    Pending,
    /// Transaction definitively failed (expired, reverted, etc.).
    Failed(String),
}

// === NOAChainSubmitter Trait ===

/// Abstracts submitting signed transactions to a destination chain and checking execution.
#[async_trait]
pub trait NOAChainSubmitter<K: NOACheckpointKind>: Send + Sync + 'static {
    /// Submit a signed transaction to the chain. Returns a chain-specific tx identifier.
    async fn submit_tx(&self, tx_bytes: &[u8], signature: &[u8]) -> Result<Vec<u8>, anyhow::Error>;

    /// Check a previously submitted transaction's on-chain status.
    async fn check_tx_status(
        &self,
        tx_identifier: &[u8],
    ) -> Result<TxExecutionStatus, anyhow::Error>;
}

/// No-op chain submitter that logs operations and always reports execution success.
/// Used as a placeholder until actual chain submission is implemented.
// TODO(noa-checkpoints): Remove LogOnlyChainSubmitter once SuiChainSubmitter is implemented
// and wired into the NOA checkpoint pipeline.
pub struct LogOnlyChainSubmitter;

#[async_trait]
impl<K: NOACheckpointKind> NOAChainSubmitter<K> for LogOnlyChainSubmitter {
    async fn submit_tx(&self, tx_bytes: &[u8], signature: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        info!(
            tx_len = tx_bytes.len(),
            sig_len = signature.len(),
            "LogOnly: would submit tx to chain"
        );
        Ok(tx_bytes.to_vec())
    }

    async fn check_tx_status(
        &self,
        _tx_identifier: &[u8],
    ) -> Result<TxExecutionStatus, anyhow::Error> {
        Ok(TxExecutionStatus::Executed)
    }
}

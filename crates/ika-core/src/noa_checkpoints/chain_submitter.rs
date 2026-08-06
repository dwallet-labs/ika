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

/// Ceiling on any single chain-submitter RPC.
///
/// These calls run inline in the MPC service loop (`poll_chain_status` and
/// the sign-output path are steps of `run_service_loop_iteration`), so a call
/// that never returns freezes ALL MPC processing on this validator — the
/// consensus-alive/MPC-dead silent-stall class from the #1978 audit. The
/// placeholder `LogOnlyChainSubmitter` cannot hang; this bound is armor for
/// the real chain submitter that replaces it (v8 NOA), where a black-holed
/// connection would otherwise become a service-wide wedge. A timeout surfaces
/// as an ordinary error, which every call site already handles by warning and
/// retrying on a later tick.
pub(crate) const CHAIN_SUBMITTER_CALL_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(15);

/// Run one chain-submitter call under [`CHAIN_SUBMITTER_CALL_TIMEOUT`],
/// converting a timeout into an ordinary error for the caller's existing
/// warn-and-retry paths.
pub(crate) async fn call_with_timeout<T>(
    what: &'static str,
    call: impl std::future::Future<Output = Result<T, anyhow::Error>>,
) -> Result<T, anyhow::Error> {
    tokio::time::timeout(CHAIN_SUBMITTER_CALL_TIMEOUT, call)
        .await
        .map_err(|_| anyhow::anyhow!("{what} timed out after {CHAIN_SUBMITTER_CALL_TIMEOUT:?}"))?
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A submitter call that never resolves must surface as a timeout error
    /// instead of hanging — these calls run inline in the MPC service loop,
    /// so "hangs forever" means "all MPC on this validator stops forever".
    /// (`start_paused` auto-advances tokio's clock once every future is
    /// pending, so the 15s ceiling elapses instantly in the test.)
    #[tokio::test(start_paused = true)]
    async fn hung_chain_submitter_call_times_out_instead_of_wedging() {
        let hung = std::future::pending::<Result<(), anyhow::Error>>();
        let err = call_with_timeout("test call", hung)
            .await
            .expect_err("a never-resolving call must become a timeout error");
        assert!(
            err.to_string().contains("timed out"),
            "error should name the timeout: {err}"
        );
    }

    /// Fast calls pass through untouched — successes and the callee's own
    /// errors are not rewrapped.
    #[tokio::test]
    async fn fast_chain_submitter_calls_pass_through() {
        let ok = call_with_timeout("ok call", async { Ok(7u32) }).await.unwrap();
        assert_eq!(ok, 7);

        let err = call_with_timeout("failing call", async {
            Err::<(), _>(anyhow::anyhow!("boom"))
        })
        .await
        .expect_err("the callee's error must pass through");
        assert!(err.to_string().contains("boom"), "{err}");
    }
}

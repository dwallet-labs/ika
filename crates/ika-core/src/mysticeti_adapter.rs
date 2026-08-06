// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use std::{sync::Arc, time::Duration};

use crate::{
    authority::authority_per_epoch_store::AuthorityPerEpochStore,
    consensus_adapter::{BlockStatusReceiver, ConsensusClient},
    consensus_handler::SequencedConsensusTransactionKey,
};
use arc_swap::{ArcSwapOption, Guard};
use consensus_core::{ClientError, TransactionClient};
use ika_types::messages_consensus::ConsensusPosition;
use ika_types::{
    error::{IkaError, IkaResult},
    messages_consensus::{ConsensusTransaction, ConsensusTransactionKind},
};
use tap::prelude::*;
use tokio::time::{Instant, sleep};
use tracing::{error, info, warn};

/// Gets a client to submit transactions to Mysticeti, or waits for one to be available.
/// This hides the complexities of async consensus initialization and submitting to different
/// instances of consensus across epochs.

#[derive(Default, Clone)]
pub struct LazyMysticetiClient {
    client: Arc<ArcSwapOption<TransactionClient>>,
}

impl LazyMysticetiClient {
    pub fn new() -> Self {
        Self {
            client: Arc::new(ArcSwapOption::empty()),
        }
    }

    async fn get(&self) -> Guard<Option<Arc<TransactionClient>>> {
        let client = self.client.load();
        if client.is_some() {
            return client;
        }

        // Consensus client is initialized after validators or epoch starts, and cleared after an epoch ends.
        // But calls to get() can happen during validator startup or epoch change, before consensus finished
        // initializations.
        // TODO: maybe listen to updates from consensus manager instead of polling.
        let mut count = 0;
        let start = Instant::now();
        const RETRY_INTERVAL: Duration = Duration::from_millis(100);
        loop {
            let client = self.client.load();
            if client.is_some() {
                return client;
            } else {
                sleep(RETRY_INTERVAL).await;
                count += 1;
                if count % 100 == 0 {
                    warn!(
                        "Waiting for consensus to initialize after {:?}",
                        Instant::now() - start
                    );
                }
            }
        }
    }

    pub fn set(&self, client: Arc<TransactionClient>) {
        self.client.store(Some(client));
    }

    pub fn clear(&self) {
        self.client.store(None);
    }
}

#[async_trait::async_trait]
impl ConsensusClient for LazyMysticetiClient {
    async fn submit(
        &self,
        transactions: &[ConsensusTransaction],
        _epoch_store: &Arc<AuthorityPerEpochStore>,
    ) -> IkaResult<(Vec<ConsensusPosition>, BlockStatusReceiver)> {
        // TODO(mysticeti): confirm comment is still true
        // The retrieved TransactionClient can be from the past epoch. Submit would fail after
        // Mysticeti shuts down, so there should be no correctness issue.
        let client = self.get().await;
        let transactions_bytes = transactions
            .iter()
            .map(|t| bcs::to_bytes(t).expect("Serializing consensus transaction cannot fail"))
            .collect::<Vec<_>>();
        let (block_ref, tx_indices, status_waiter) = client
            .as_ref()
            .expect("Client should always be returned")
            // Normal keeps the pre-1.76 single-lane behavior for ALL ika
            // traffic. High is a 128-slot reserved lane for low-volume
            // critical submissions; ika's dominant traffic here is MPC
            // messages (bulk), which would overflow it — routing select
            // kinds (EndOfPublish, checkpoint signatures) as High is a
            // possible follow-up tune, not a drop-in.
            .submit(transactions_bytes, consensus_core::Priority::Normal)
            .await
            .tap_err(|err| {
                // Will be logged by caller as well.
                let msg = format!("Transaction submission failed with: {err:?}");
                match err {
                    ClientError::ConsensusShuttingDown(_) => {
                        info!("{}", msg);
                    }
                    ClientError::OversizedTransaction(_, _)
                    | ClientError::OversizedTransactionBundleBytes(_, _)
                    | ClientError::OversizedTransactionBundleCount(_, _) => {
                        if cfg!(debug_assertions) {
                            panic!("{}", msg);
                        } else {
                            error!("{}", msg);
                        }
                    }
                };
            })
            .map_err(|err| IkaError::FailedToSubmitToConsensus(err.to_string()))?;

        let is_soft_bundle = transactions.len() > 1;

        if !is_soft_bundle
            && matches!(
                transactions[0].kind,
                    | ConsensusTransactionKind::CapabilityNotificationV1(_)
            )
        {
            let transaction_key = SequencedConsensusTransactionKey::External(transactions[0].key());
            tracing::info!("Transaction {transaction_key:?} was included in {block_ref}",)
        };

        // Calculate consensus tx positions
        let mut consensus_positions = Vec::new();
        for index in tx_indices {
            consensus_positions.push(ConsensusPosition {
                index,
                block: block_ref,
            });
        }
        Ok((consensus_positions, status_waiter))
    }
}

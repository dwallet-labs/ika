use crate::consensus_adapter::SubmitToConsensus;
use ika_types::error::IkaResult;
use ika_types::messages_consensus::ConsensusTransaction;
use std::sync::Arc;
use crate::authority::authority_per_epoch_store::AuthorityPerEpochStore;

#[async_trait::async_trait]
pub trait DWalletMPCSubmitToConsensus: Sync + Send + 'static {
    async fn submit_to_consensus(&self, transactions: &[ConsensusTransaction]) -> IkaResult;
}

#[async_trait::async_trait]
impl DWalletMPCSubmitToConsensus for EpochStoreSubmitToConsensus {
    async fn submit_to_consensus(&self, transactions: &[ConsensusTransaction]) -> IkaResult {
        self.consensus_adapter
            .submit_to_consensus(transactions, &self.epoch_store)
            .await
    }
}

pub struct EpochStoreSubmitToConsensus {
    pub(crate) epoch_store: Arc<AuthorityPerEpochStore>,
    pub(crate) consensus_adapter: Arc<dyn SubmitToConsensus>,
}

impl EpochStoreSubmitToConsensus {
    pub fn new(
        epoch_store: Arc<AuthorityPerEpochStore>,
        consensus_adapter: Arc<dyn SubmitToConsensus>,
    ) -> Self {
        Self {
            epoch_store,
            consensus_adapter,
        }
    }
}
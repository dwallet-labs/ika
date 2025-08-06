use crate::consensus_adapter::SubmitToConsensus;
use crate::dwallet_mpc::dwallet_mpc_service::EpochStoreSubmitToConsensus;
use ika_types::error::IkaResult;
use ika_types::messages_consensus::ConsensusTransaction;

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

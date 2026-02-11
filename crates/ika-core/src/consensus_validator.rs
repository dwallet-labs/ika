// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use std::sync::Arc;

use crate::{
    authority::AuthorityState, consensus_adapter::ConsensusOverloadChecker,
    dwallet_checkpoints::DWalletCheckpointServiceNotify,
    system_checkpoints::SystemCheckpointServiceNotify,
};
use consensus_core::{TransactionVerifier, ValidationError};
use consensus_types::block::TransactionIndex;
use ika_types::committee::Committee;
use ika_types::crypto::AuthoritySignInfoTrait;
use ika_types::crypto::VerificationObligation;
use ika_types::intent::Intent;
use ika_types::message_envelope::Message;
use ika_types::messages_dwallet_checkpoint::SignedDWalletCheckpointMessage;
use ika_types::messages_system_checkpoints::SignedSystemCheckpointMessage;
use ika_types::{
    error::{IkaError, IkaResult},
    messages_consensus::{ConsensusTransaction, ConsensusTransactionKind},
};
use mysten_metrics::monitored_scope;
use prometheus::{IntCounter, Registry, register_int_counter_with_registry};
use tap::TapFallible;
use tracing::{info, warn};

/// Allows verifying the validity of transactions
#[derive(Clone)]
pub struct IkaTxValidator {
    authority_state: Arc<AuthorityState>,
    // todo(zeev): why is it not used?
    #[allow(dead_code)]
    consensus_overload_checker: Arc<dyn ConsensusOverloadChecker>,
    dwallet_checkpoint_service: Arc<dyn DWalletCheckpointServiceNotify + Send + Sync>,
    system_checkpoint_service: Arc<dyn SystemCheckpointServiceNotify + Send + Sync>,
    metrics: Arc<IkaTxValidatorMetrics>,
}

impl IkaTxValidator {
    pub fn new(
        authority_state: Arc<AuthorityState>,
        consensus_overload_checker: Arc<dyn ConsensusOverloadChecker>,
        dwallet_checkpoint_service: Arc<dyn DWalletCheckpointServiceNotify + Send + Sync>,
        system_checkpoint_service: Arc<dyn SystemCheckpointServiceNotify + Send + Sync>,
        metrics: Arc<IkaTxValidatorMetrics>,
    ) -> Self {
        let epoch_store = authority_state.load_epoch_store_one_call_per_task().clone();
        info!(
            "IkaTxValidator constructed for epoch {}",
            epoch_store.epoch()
        );
        Self {
            authority_state,
            consensus_overload_checker,
            dwallet_checkpoint_service,
            system_checkpoint_service,
            metrics,
        }
    }

    fn validate_transactions(&self, txs: &[ConsensusTransactionKind]) -> Result<(), IkaError> {
        let epoch_store = self.authority_state.load_epoch_store_one_call_per_task();

        let mut ckpt_messages = Vec::new();
        let mut ckpt_batch = Vec::new();

        let mut system_checkpoints = Vec::new();
        let mut params_batch = Vec::new();

        for tx in txs.iter() {
            match tx {
                ConsensusTransactionKind::DWalletCheckpointSignature(signature) => {
                    ckpt_messages.push(signature.as_ref());
                    ckpt_batch.push(&signature.checkpoint_message);
                }
                ConsensusTransactionKind::CapabilityNotificationV1(_)
                | ConsensusTransactionKind::EndOfPublish(_)
                | ConsensusTransactionKind::DWalletMPCMessage(..)
                | ConsensusTransactionKind::DWalletMPCOutput(..)
                | ConsensusTransactionKind::DWalletInternalMPCOutput(..)
                | ConsensusTransactionKind::InternalSessionsStatusUpdate(..) => {}
                ConsensusTransactionKind::SystemCheckpointSignature(signature) => {
                    system_checkpoints.push(signature.as_ref());
                    params_batch.push(&signature.checkpoint_message);
                }
            }
        }

        // verify the certificate signatures as a batch
        let ckpt_count = ckpt_batch.len();

        Self::batch_verify_all_certificates_and_dwallet_checkpoints(
            epoch_store.committee(),
            &ckpt_batch,
        )
        .tap_err(|e| warn!("batch verification error: {}", e))?;

        // All checkpoint sigs have been verified, forward them to the checkpoint service
        for ckpt in ckpt_messages {
            self.dwallet_checkpoint_service
                .notify_checkpoint_signature(&epoch_store, ckpt)?;
        }

        self.metrics
            .dwallet_checkpoint_signatures_verified
            .inc_by(ckpt_count as u64);

        let params_count = params_batch.len();

        Self::batch_verify_all_certificates_and_system_checkpoints(
            epoch_store.committee(),
            &params_batch,
        )
        .tap_err(|e| warn!("batch verification error: {}", e))?;

        // All checkpoint sigs have been verified, forward them to the checkpoint service
        for ckpt in system_checkpoints {
            self.system_checkpoint_service
                .notify_checkpoint_signature(&epoch_store, ckpt)?;
        }

        self.metrics
            .system_checkpoint_signatures_verified
            .inc_by(params_count as u64);
        Ok(())
    }

    /// Verifies all certificates - if any fail return error.
    fn batch_verify_all_certificates_and_dwallet_checkpoints(
        committee: &Committee,
        dwallet_checkpoints: &[&SignedDWalletCheckpointMessage],
    ) -> IkaResult {
        // certs.data() is assumed to be verified already by the caller.

        for ckpt in dwallet_checkpoints {
            ckpt.data().verify_epoch(committee.epoch())?;
        }

        Self::batch_verify(committee, dwallet_checkpoints)
    }

    fn batch_verify(
        committee: &Committee,
        checkpoints: &[&SignedDWalletCheckpointMessage],
    ) -> IkaResult {
        let mut obligation = VerificationObligation::default();

        for ckpt in checkpoints {
            let idx =
                obligation.add_message(ckpt.data(), ckpt.epoch(), Intent::ika_app(ckpt.scope()));
            ckpt.auth_sig()
                .add_to_verification_obligation(committee, &mut obligation, idx)?;
        }

        obligation.verify_all()
    }

    /// Verifies all certificates - if any fail return error.
    fn batch_verify_all_certificates_and_system_checkpoints(
        committee: &Committee,
        checkpoints: &[&SignedSystemCheckpointMessage],
    ) -> IkaResult {
        // certs.data() is assumed to be verified already by the caller.

        for ckpt in checkpoints {
            ckpt.data().verify_epoch(committee.epoch())?;
        }

        Self::batch_verify_system_checkpoints(committee, checkpoints)
    }

    fn batch_verify_system_checkpoints(
        committee: &Committee,
        checkpoints: &[&SignedSystemCheckpointMessage],
    ) -> IkaResult {
        let mut obligation = VerificationObligation::default();

        for ckpt in checkpoints {
            let idx =
                obligation.add_message(ckpt.data(), ckpt.epoch(), Intent::ika_app(ckpt.scope()));
            ckpt.auth_sig()
                .add_to_verification_obligation(committee, &mut obligation, idx)?;
        }

        obligation.verify_all()
    }

    fn vote_transactions(&self, _txs: Vec<ConsensusTransactionKind>) -> Vec<TransactionIndex> {
        vec![]
        //let epoch_store = self.authority_state.load_epoch_store_one_call_per_task();
        // if !epoch_store.protocol_config().mysticeti_fastpath() {
        //     return vec![];
        // }
        //
        // let mut result = Vec::new();
        // for (i, tx) in txs.into_iter().enumerate() {
        //     let ConsensusTransactionKind::UserTransaction(tx) = tx else {
        //         continue;
        //     };
        //
        //     if let Err(e) = self.vote_transaction(&epoch_store, tx).await {
        //         debug!("Failed to vote transaction: {:?}", e);
        //         result.push(i as TransactionIndex);
        //     }
        // }
        //
        // result
    }

    // async fn vote_transaction(
    //     &self,
    //     epoch_store: &Arc<AuthorityPerEpochStore>,
    //     tx: Box<Transaction>,
    // ) -> IkaResult<()> {
    //     // Currently validity_check() and verify_transaction() are not required to be consistent across validators,
    //     // so they do not run in validate_transactions(). They can run there once we confirm it is safe.
    //     tx.validity_check(epoch_store.protocol_config(), epoch_store.epoch())?;
    //
    //     self.authority_state.check_system_overload(
    //         &*self.consensus_overload_checker,
    //         tx.data(),
    //         self.authority_state.check_system_overload_at_signing(),
    //     )?;
    //
    //     let tx = epoch_store.verify_transaction(*tx)?;
    //
    //     self.authority_state
    //         .handle_transaction_v2(epoch_store, tx)
    //         .await?;
    //
    //     Ok(())
    // }
}

fn tx_kind_from_bytes(tx: &[u8]) -> Result<ConsensusTransactionKind, ValidationError> {
    bcs::from_bytes::<ConsensusTransaction>(tx)
        .map_err(|e| {
            ValidationError::InvalidTransaction(format!("Failed to parse transaction bytes: {e:?}"))
        })
        .map(|tx| tx.kind)
}

#[async_trait::async_trait]
impl TransactionVerifier for IkaTxValidator {
    fn verify_batch(&self, batch: &[&[u8]]) -> Result<(), ValidationError> {
        let _scope = monitored_scope("ValidateBatch");

        let txs: Vec<_> = batch
            .iter()
            .map(|tx| tx_kind_from_bytes(tx))
            .collect::<Result<Vec<_>, _>>()?;

        self.validate_transactions(&txs)
            .map_err(|e| ValidationError::InvalidTransaction(e.to_string()))
    }

    fn verify_and_vote_batch(
        &self,
        _block_ref: &consensus_types::block::BlockRef,
        batch: &[&[u8]],
    ) -> Result<Vec<TransactionIndex>, ValidationError> {
        let _scope = monitored_scope("VerifyAndVoteBatch");

        let txs: Vec<_> = batch
            .iter()
            .map(|tx| tx_kind_from_bytes(tx))
            .collect::<Result<Vec<_>, _>>()?;

        self.validate_transactions(&txs)
            .map_err(|e| ValidationError::InvalidTransaction(e.to_string()))?;

        Ok(self.vote_transactions(txs))
    }
}

pub struct IkaTxValidatorMetrics {
    // todo(zeev): why is it not used?
    #[allow(dead_code)]
    certificate_signatures_verified: IntCounter,
    dwallet_checkpoint_signatures_verified: IntCounter,
    system_checkpoint_signatures_verified: IntCounter,
}

impl IkaTxValidatorMetrics {
    pub fn new(registry: &Registry) -> Arc<Self> {
        Arc::new(Self {
            certificate_signatures_verified: register_int_counter_with_registry!(
                "certificate_signatures_verified",
                "Number of certificates verified in consensus batch verifier",
                registry
            )
            .unwrap(),
            dwallet_checkpoint_signatures_verified: register_int_counter_with_registry!(
                "dwallet_checkpoint_signatures_verified",
                "Number of dwallet checkpoint verified in consensus batch verifier",
                registry
            )
            .unwrap(),
            system_checkpoint_signatures_verified: register_int_counter_with_registry!(
                "system_checkpoint_signatures_verified",
                "Number of system checkpoints signatures verified in consensus batch verifier",
                registry
            )
            .unwrap(),
        })
    }
}

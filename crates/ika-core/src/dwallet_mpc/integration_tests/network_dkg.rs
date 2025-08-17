// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! This module contains the DWalletMPCService struct.
//! It is responsible to read DWallet MPC messages from the
//! local DB every [`READ_INTERVAL_MS`] seconds
//! and forward them to the [`DWalletMPCManager`].

use crate::consensus_adapter::SubmitToConsensus;
use crate::dwallet_checkpoints::PendingDWalletCheckpoint;
use crate::dwallet_mpc::dwallet_mpc_service::DWalletMPCService;
use crate::dwallet_mpc::integration_tests::utils;
use crate::dwallet_mpc::integration_tests::utils::{
    TestingAuthorityPerEpochStore, TestingDWalletCheckpointNotify, TestingSubmitToConsensus,
    send_start_network_dkg_event,
};
use crate::dwallet_mpc::mpc_manager::DWalletMPCManager;
use crate::epoch::submit_to_consensus::DWalletMPCSubmitToConsensus;
use ika_types::committee::Committee;
use ika_types::messages_consensus::ConsensusTransactionKind;
use ika_types::messages_dwallet_mpc::{DBSuiEvent, IkaNetworkConfig};
use ika_types::messages_dwallet_mpc::{
    DWalletNetworkDKGEncryptionKeyRequestEvent, DWalletSessionEvent, DWalletSessionEventTrait,
};
use ika_types::sui::EpochStartSystemTrait;
use itertools::Itertools;
use std::sync::Arc;
use std::time::Duration;
use sui_types::messages_consensus::Round;
use tracing::{error, info};

#[tokio::test]
#[cfg(test)]
async fn test_network_dkg_full_flow() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let (committee, _) = Committee::new_simple_test_committee();
    let ika_network_config = IkaNetworkConfig::new_for_testing();
    let epoch_id = 1;
    let (
        mut dwallet_mpc_services,
        mut sui_data_senders,
        mut sent_consensus_messages_collectors,
        mut epoch_stores,
        mut notify_services,
    ) = utils::create_dwallet_mpc_services(4);
    send_start_network_dkg_event(&ika_network_config, epoch_id, &mut sui_data_senders);
    let mut mpc_round = 1;
    loop {
        if let Some(pending_checkpoint) = utils::advance_all_parties_and_wait_for_completions(
            &committee,
            &mut dwallet_mpc_services,
            &mut sent_consensus_messages_collectors,
            &epoch_stores,
            &notify_services,
        )
            .await
        {
            assert_eq!(mpc_round, 5, "Network DKG should complete after 4 rounds");
            info!(?pending_checkpoint, "MPC flow completed successfully");
            break;
        }

        utils::send_advance_results_between_parties(
            &committee,
            &mut sent_consensus_messages_collectors,
            &mut epoch_stores,
            mpc_round,
        );
        mpc_round += 1;
    }
}

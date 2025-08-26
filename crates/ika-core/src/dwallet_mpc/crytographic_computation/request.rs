// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::dwallet_mpc::crytographic_computation::ComputationId;
use crate::dwallet_mpc::crytographic_computation::protocol_cryptographic_data::ProtocolCryptographicData;
use crate::dwallet_mpc::dwallet_mpc_metrics::DWalletMPCMetrics;
use crate::dwallet_session_request::DWalletSessionRequestMetricData;
use dwallet_rng::RootSeed;
use group::PartyID;
use ika_protocol_config::ProtocolConfig;
use ika_types::crypto::AuthorityPublicKeyBytes;
use ika_types::dwallet_mpc_error::DwalletMPCResult;
use mpc::{GuaranteedOutputDeliveryRoundResult, WeightedThresholdAccessStructure};
use std::sync::Arc;
use tracing::info;

pub(crate) struct Request {
    pub(crate) party_id: PartyID,
    pub(crate) protocol_data: DWalletSessionRequestMetricData,
    pub(crate) validator_name: AuthorityPublicKeyBytes,
    pub(crate) access_structure: WeightedThresholdAccessStructure,
    pub(crate) protocol_cryptographic_data: ProtocolCryptographicData,
}

impl Request {
    /// Perform a cryptographic computation.
    /// Notice: `root_seed` must be kept private!
    pub(crate) fn compute(
        self,
        computation_id: ComputationId,
        root_seed: RootSeed,
        dwallet_mpc_metrics: Arc<DWalletMPCMetrics>,
        protocol_config: &ProtocolConfig,
    ) -> DwalletMPCResult<GuaranteedOutputDeliveryRoundResult> {
        info!(
            mpc_protocol=?self.protocol_data.to_string(),
            validator=?self.validator_name,
            session_identifier=?computation_id.session_identifier,
            current_round=?computation_id.mpc_round,
            access_structure=?self.access_structure,
            "Advancing session"
        );

        if let Some(mpc_round) = computation_id.mpc_round {
            self.protocol_cryptographic_data.compute_mpc(
                self.party_id,
                &self.access_structure,
                mpc_round,
                computation_id.consensus_round,
                computation_id.session_identifier,
                root_seed,
                dwallet_mpc_metrics,
            )
        } else {
            self.protocol_cryptographic_data
                .compute_native(computation_id.session_identifier, dwallet_mpc_metrics)
        }
    }
}

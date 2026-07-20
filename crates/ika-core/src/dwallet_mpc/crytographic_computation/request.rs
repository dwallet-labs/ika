// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::dwallet_mpc::crytographic_computation::ComputationId;
use crate::dwallet_mpc::crytographic_computation::protocol_cryptographic_data::ProtocolCryptographicData;
use crate::dwallet_mpc::dwallet_mpc_metrics::DWalletMPCMetrics;
use crate::dwallet_session_request::DWalletSessionRequestMetricData;
use dwallet_rng::RootSeed;
use group::PartyID;
use ika_types::crypto::AuthorityPublicKeyBytes;
use ika_types::dwallet_mpc_error::DwalletMPCResult;
use mpc::{GuaranteedOutputDeliveryRoundResult, WeightedThresholdAccessStructure};
use std::sync::Arc;
use tracing::debug;

pub(crate) struct Request {
    pub(crate) party_id: PartyID,
    pub(crate) protocol_data: DWalletSessionRequestMetricData,
    pub(crate) validator_name: AuthorityPublicKeyBytes,
    pub(crate) access_structure: WeightedThresholdAccessStructure,
    pub(crate) protocol_cryptographic_data: ProtocolCryptographicData,
    /// `ProtocolConfig::aggregated_network_key_public_outputs()` — when true,
    /// network-key RECONFIGURATION outputs are persisted V4-tagged in the
    /// aggregated wire format; when false, V3-tagged in the pre-aggregation
    /// format testnet persists. Protocol-gated so the whole committee flips
    /// together (MPC outputs must reach byte-identical quorum, and
    /// reconfiguration runs every epoch — including during a mixed-binary
    /// rollout). Network DKG outputs are NOT gated: they are always persisted
    /// V4 (no deployed network ever persisted a pre-aggregation fresh DKG
    /// output, and no DKG session runs during a rollout window).
    pub(crate) aggregated_network_key_public_outputs: bool,
}

impl Request {
    /// Perform a cryptographic computation.
    /// Notice: `root_seed` must be kept private!
    pub(crate) fn compute(
        self,
        computation_id: ComputationId,
        root_seed: RootSeed,
        vss_hpke_secret_key: group::curve25519::Scalar,
        dwallet_mpc_metrics: Arc<DWalletMPCMetrics>,
    ) -> DwalletMPCResult<GuaranteedOutputDeliveryRoundResult> {
        debug!(
            mpc_protocol=?self.protocol_data,
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
                vss_hpke_secret_key,
                dwallet_mpc_metrics,
                self.aggregated_network_key_public_outputs,
            )
        } else {
            self.protocol_cryptographic_data
                .compute_native(computation_id.session_identifier, dwallet_mpc_metrics)
        }
    }
}

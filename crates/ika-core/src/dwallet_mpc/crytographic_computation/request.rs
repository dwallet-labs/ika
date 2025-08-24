// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::dwallet_mpc::crytographic_computation::protocol_cryptographic_data::ProtocolCryptographicData;
use crate::dwallet_mpc::crytographic_computation::{ComputationId, MPC_SIGN_SECOND_ROUND};
use crate::dwallet_mpc::dwallet_dkg::{
    DWalletDKGFirstParty, DWalletDKGSecondParty, DWalletImportedKeyVerificationParty,
};
use crate::dwallet_mpc::dwallet_mpc_metrics::DWalletMPCMetrics;
use crate::dwallet_mpc::encrypt_user_share::verify_encrypted_share;
use crate::dwallet_mpc::make_dwallet_user_secret_key_shares_public::verify_secret_share;
use crate::dwallet_mpc::mpc_session::PublicInput;
use crate::dwallet_mpc::network_dkg::advance_network_dkg;
use crate::dwallet_mpc::presign::PresignParty;
use crate::dwallet_mpc::reconfiguration::ReconfigurationSecp256k1Party;
use crate::dwallet_mpc::sign::{SignParty, verify_partial_signature};
use crate::dwallet_session_request::DWalletSessionRequestMetricData;
use commitment::CommitmentSizedNumber;
use dwallet_mpc_types::dwallet_mpc::{
    VersionedDWalletImportedKeyVerificationOutput, VersionedDecryptionKeyReconfigurationOutput,
    VersionedDwalletDKGFirstRoundPublicOutput, VersionedDwalletDKGSecondRoundPublicOutput,
    VersionedPresignOutput, VersionedSignOutput,
};
use dwallet_rng::RootSeed;
use group::PartyID;
use ika_types::crypto::AuthorityPublicKeyBytes;
use ika_types::dwallet_mpc_error::{DwalletMPCError, DwalletMPCResult};
use message_digest::message_digest::message_digest;
use mpc::guaranteed_output_delivery::Party;
use mpc::{
    GuaranteedOutputDeliveryRoundResult, GuaranteesOutputDelivery, WeightedThresholdAccessStructure,
};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{error, info};

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
    ) -> DwalletMPCResult<GuaranteedOutputDeliveryRoundResult> {
        info!(
            mpc_protocol=?self.protocol_data.to_string(),
            validator=?self.validator_name,
            session_identifier=?computation_id.session_identifier,
            current_round=?computation_id.mpc_round,
            access_structure=?self.access_structure,
            "Advancing session"
        );

        let Some(mpc_round) = computation_id.mpc_round else {
            return self
                .protocol_cryptographic_data
                .compute_native(computation_id.session_identifier);
        };

        self.protocol_cryptographic_data.compute_mpc(
            self.party_id,
            &self.access_structure,
            mpc_round,
            computation_id.consensus_round,
            computation_id.session_identifier,
            root_seed,
        )
    }
}

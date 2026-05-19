// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! This module contains the network DKG protocol for the dWallet MPC sessions.
//! The network DKG protocol handles generating the network Decryption-Key shares.
//! The module provides the management of the network Decryption-Key shares and
//! the network DKG protocol.

use crate::dwallet_mpc::crytographic_computation::mpc_computations::network_owned_address_sign_dkg_emulation::compute_noa_dkg;
use crate::dwallet_mpc::crytographic_computation::protocol_public_parameters::ProtocolPublicParametersByCurve;
use crate::dwallet_mpc::reconfiguration::instantiate_dwallet_mpc_network_encryption_key_public_data_from_reconfiguration_public_output;
use class_groups::SecretKeyShareSizedInteger;
use commitment::CommitmentSizedNumber;
use dwallet_classgroups_types::ClassGroupsDecryptionKey;
use dwallet_mpc_types::dwallet_mpc::{
    DWalletCurve, NetworkDecryptionKeyPublicOutputType, NetworkEncryptionKeyPublicData,
    SerializedWrappedMPCPublicOutput, VersionedDecryptionKeyReconfigurationOutput,
    VersionedNetworkDkgOutput,
};
use group::PartyID;
use ika_types::committee::ClassGroupsEncryptionKeyAndProof;
use ika_types::dwallet_mpc_error::{DwalletMPCError, DwalletMPCResult};
use ika_types::messages_dwallet_mpc::{
    Curve25519AsyncDKGProtocol, DWalletNetworkEncryptionKeyData, DWalletNetworkEncryptionKeyState,
    RistrettoAsyncDKGProtocol, Secp256k1AsyncDKGProtocol, Secp256r1AsyncDKGProtocol,
};
use mpc::guaranteed_output_delivery::{AdvanceRequest, Party};
use mpc::{
    GuaranteedOutputDeliveryRoundResult, GuaranteesOutputDelivery, WeightedThresholdAccessStructure,
};
use rand_chacha::ChaCha20Rng;
use std::collections::HashMap;
use std::sync::Arc;
use sui_types::base_types::ObjectID;
use tokio::sync::oneshot;
use tracing::error;
use twopc_mpc::decentralized_party::dkg;
use twopc_mpc::decentralized_party_backward_compatible::dkg as bwd_compat_dkg;

/// Holds the network (decryption) keys of the network MPC protocols.
pub struct DwalletMPCNetworkKeys {
    /// Holds all network (decryption) keys for the current network in encrypted form.
    /// This data is identical for all the Validator nodes.
    pub(crate) network_encryption_keys: HashMap<ObjectID, NetworkEncryptionKeyPublicData>,
    pub(crate) validator_private_dec_key_data: ValidatorPrivateDecryptionKeyData,
}

/// Holds the private decryption key data for a validator node.
pub struct ValidatorPrivateDecryptionKeyData {
    /// The unique party ID of the validator, representing its index within the committee.
    pub party_id: PartyID,

    /// The validator's class groups decryption key.
    pub class_groups_decryption_key: ClassGroupsDecryptionKey,

    /// A map of the validator's decryption key shares.
    ///
    /// This structure maps each key ID (`ObjectID`) to a sub-map of `PartyID`
    /// to the corresponding decryption key share.
    /// These shares are used in multi-party cryptographic protocols.
    /// NOTE: EACH PARTY IN HERE IS A **VIRTUAL PARTY**.
    /// NOTE 2: `ObjectID` is the ID of the network decryption key, not the party.
    pub validator_decryption_key_shares:
        HashMap<ObjectID, HashMap<PartyID, SecretKeyShareSizedInteger>>,
}

async fn get_decryption_key_shares_from_public_output(
    shares: NetworkEncryptionKeyPublicData,
    party_id: PartyID,
    personal_decryption_key: ClassGroupsDecryptionKey,
    access_structure: WeightedThresholdAccessStructure,
) -> DwalletMPCResult<HashMap<PartyID, SecretKeyShareSizedInteger>> {
    let (key_shares_sender, key_shares_receiver) = oneshot::channel();

    rayon::spawn_fifo(move || {
        let res = match shares.state() {
            NetworkDecryptionKeyPublicOutputType::NetworkDkg => {
                match &shares.network_dkg_output() {
                    VersionedNetworkDkgOutput::V1(_) => {
                        unreachable!("V1 network DKG outputs are no longer produced")
                    }
                    VersionedNetworkDkgOutput::V2(public_output) => {
                        // mainnet-v1.1.8 / bwd-compat shape — decode under
                        // `bwd_compat_dkg::Party::PublicOutput`.
                        match bcs::from_bytes::<<bwd_compat_dkg::Party as mpc::Party>::PublicOutput>(
                            public_output,
                        ) {
                            Ok(dkg_public_output) => dkg_public_output
                                .decrypt_decryption_key_shares(
                                    party_id,
                                    &access_structure,
                                    personal_decryption_key,
                                )
                                .map_err(DwalletMPCError::from),
                            Err(e) => Err(e.into()),
                        }
                    }
                    VersionedNetworkDkgOutput::V3(public_output) => {
                        match bcs::from_bytes::<<dkg::Party as mpc::Party>::PublicOutput>(
                            public_output,
                        ) {
                            Ok(dkg_public_output) => dkg_public_output
                                .decrypt_decryption_key_shares(
                                    party_id,
                                    &access_structure,
                                    personal_decryption_key,
                                )
                                .map_err(DwalletMPCError::from),
                            Err(e) => Err(e.into()),
                        }
                    }
                }
            }
            NetworkDecryptionKeyPublicOutputType::Reconfiguration => {
                match &shares
                    .latest_network_reconfiguration_public_output()
                    .unwrap()
                {
                    VersionedDecryptionKeyReconfigurationOutput::V1(_) => {
                        unreachable!("V1 reconfiguration outputs are no longer produced")
                    }
                    VersionedDecryptionKeyReconfigurationOutput::V2(public_output) => {
                        // bwd-compat reconfig output shape.
                        match bcs::from_bytes::<
                            <twopc_mpc::decentralized_party_backward_compatible::reconfiguration::Party as mpc::Party>::PublicOutput,
                        >(public_output)
                        {
                            Ok(public_output) => public_output
                                .decrypt_decryption_key_shares(
                                    party_id,
                                    &access_structure,
                                    personal_decryption_key,
                                )
                                .map_err(DwalletMPCError::from),
                            Err(e) => Err(e.into()),
                        }
                    }
                    VersionedDecryptionKeyReconfigurationOutput::V3(public_output) => {
                        match bcs::from_bytes::<
                            <twopc_mpc::decentralized_party::reconfiguration::Party as mpc::Party>::PublicOutput,
                        >(public_output)
                        {
                            Ok(public_output) => public_output
                                .decrypt_decryption_key_shares(
                                    party_id,
                                    &access_structure,
                                    personal_decryption_key,
                                )
                                .map_err(DwalletMPCError::from),
                            Err(e) => Err(e.into()),
                        }
                    }
                }
            }
        };

        if let Err(err) = key_shares_sender.send(res) {
            error!(error=?err, "failed to send key shares");
        }
    });

    key_shares_receiver
        .await
        .map_err(|_| DwalletMPCError::TokioRecv)?
}

impl ValidatorPrivateDecryptionKeyData {
    /// Stores the new decryption key shares of the validator.
    /// Decrypts the decryption key shares (for all the virtual parties)
    /// from the public output of the network DKG protocol.
    pub async fn decrypt_and_store_secret_key_shares(
        &mut self,
        key_id: ObjectID,
        key: NetworkEncryptionKeyPublicData,
        access_structure: &WeightedThresholdAccessStructure,
    ) -> DwalletMPCResult<()> {
        let decryption_key_shares = get_decryption_key_shares_from_public_output(
            key.clone(),
            self.party_id,
            self.class_groups_decryption_key,
            access_structure.clone(),
        )
        .await?;

        self.validator_decryption_key_shares
            .insert(key_id, decryption_key_shares);
        Ok(())
    }
}

impl DwalletMPCNetworkKeys {
    pub fn new(node_context: ValidatorPrivateDecryptionKeyData) -> Self {
        Self {
            network_encryption_keys: Default::default(),
            validator_private_dec_key_data: node_context,
        }
    }

    pub async fn update_network_key(
        &mut self,
        key_id: ObjectID,
        key: &NetworkEncryptionKeyPublicData,
        access_structure: &WeightedThresholdAccessStructure,
    ) -> DwalletMPCResult<()> {
        self.network_encryption_keys.insert(key_id, key.clone());
        self.validator_private_dec_key_data
            .decrypt_and_store_secret_key_shares(key_id, key.clone(), access_structure)
            .await
    }

    /// Retrieves the decryption key shares for the current authority.
    pub(crate) fn decryption_key_shares(
        &self,
        key_id: &ObjectID,
    ) -> DwalletMPCResult<HashMap<PartyID, SecretKeyShareSizedInteger>> {
        self.validator_private_dec_key_data
            .validator_decryption_key_shares
            .get(key_id)
            .cloned()
            .ok_or(DwalletMPCError::WaitingForNetworkKey(*key_id))
    }

    pub fn key_public_data_exists(&self, key_id: &ObjectID) -> bool {
        self.network_encryption_keys.contains_key(key_id)
    }

    pub fn get_network_encryption_key_public_data(
        &self,
        key_id: &ObjectID,
    ) -> DwalletMPCResult<&NetworkEncryptionKeyPublicData> {
        self.network_encryption_keys
            .get(key_id)
            .ok_or(DwalletMPCError::WaitingForNetworkKey(*key_id))
    }

    /// Retrieves the protocol public parameters for the specified key ID.
    pub fn get_protocol_public_parameters(
        &self,
        curve: &DWalletCurve,
        key_id: &ObjectID,
    ) -> DwalletMPCResult<ProtocolPublicParametersByCurve> {
        let Some(result) = self.network_encryption_keys.get(key_id) else {
            error!(
                ?key_id,
                "failed to fetch the network decryption key shares for key ID"
            );
            return Err(DwalletMPCError::WaitingForNetworkKey(*key_id));
        };

        let protocol_public_parameters = match curve {
            DWalletCurve::Secp256k1 => ProtocolPublicParametersByCurve::Secp256k1(
                result.secp256k1_protocol_public_parameters().clone(),
            ),
            DWalletCurve::Secp256r1 => ProtocolPublicParametersByCurve::Secp256r1(
                result.secp256r1_protocol_public_parameters().clone(),
            ),
            DWalletCurve::Ristretto => ProtocolPublicParametersByCurve::Ristretto(
                result.ristretto_protocol_public_parameters().clone(),
            ),
            DWalletCurve::Curve25519 => ProtocolPublicParametersByCurve::Curve25519(
                result.curve25519_protocol_public_parameters().clone(),
            ),
        };

        Ok(protocol_public_parameters)
    }

    pub fn get_network_dkg_public_output(
        &self,
        key_id: &ObjectID,
    ) -> DwalletMPCResult<VersionedNetworkDkgOutput> {
        Ok(self
            .network_encryption_keys
            .get(key_id)
            .ok_or(DwalletMPCError::WaitingForNetworkKey(*key_id))?
            .network_dkg_output()
            .clone())
    }

    pub fn get_last_reconfiguration_output(
        &self,
        key_id: &ObjectID,
    ) -> Option<VersionedDecryptionKeyReconfigurationOutput> {
        let key = self.network_encryption_keys.get(key_id)?;
        key.latest_network_reconfiguration_public_output()
    }
}

/// Advances the network DKG protocol using the mainnet-v1.1.8-shape
/// decentralized party
/// (`twopc_mpc::decentralized_party_backward_compatible::dkg::Party`).
///
/// Used when the active `ProtocolConfig` reports
/// `network_encryption_key_version() == 2` (protocol_version ≤ 4), i.e. when
/// any peer in the committee may still be publishing the bare
/// `ClassGroupsEncryptionKeyAndProof` shape and therefore lacks PVSS HPKE
/// keys required by the main-shape DKG. The finalized public output is
/// wrapped as `VersionedNetworkDkgOutput::V2`; bytes are wire-compatible
/// with mainnet-v1.1.8 peers per audit §4 (`dkg::PublicOutput` is wire-stable
/// across the cryptography-private bump).
///
/// Invoked from `compute_mpc`'s `NetworkEncryptionKeyDkg` arm via
/// `NetworkEncryptionKeyDkgAdvanceArgs::BwdCompat`; selected by
/// `session_input_from_request` based on `is_network_encryption_key_version_v3()`.
pub(crate) fn advance_network_dkg_bwd_compat(
    session_id: CommitmentSizedNumber,
    access_structure: &WeightedThresholdAccessStructure,
    public_input: <bwd_compat_dkg::Party as mpc::Party>::PublicInput,
    party_id: PartyID,
    advance_request: AdvanceRequest<<bwd_compat_dkg::Party as mpc::Party>::Message>,
    class_groups_decryption_key: ClassGroupsDecryptionKey,
    rng: &mut ChaCha20Rng,
) -> DwalletMPCResult<GuaranteedOutputDeliveryRoundResult> {
    let result = Party::<bwd_compat_dkg::Party>::advance_with_guaranteed_output(
        session_id,
        party_id,
        access_structure,
        advance_request,
        Some(class_groups_decryption_key),
        &public_input,
        rng,
    );

    match result {
        Ok(GuaranteedOutputDeliveryRoundResult::Finalize {
            public_output_value,
            malicious_parties,
            private_output,
        }) => {
            let public_output_value =
                bcs::to_bytes(&VersionedNetworkDkgOutput::V2(public_output_value))?;
            Ok(GuaranteedOutputDeliveryRoundResult::Finalize {
                public_output_value,
                malicious_parties,
                private_output,
            })
        }
        other => other.map_err(Into::into),
    }
}

/// Builds the bwd-compat decentralized-party DKG public input from class-groups
/// encryption keys only — bwd-compat predates PVSS HPKE, so the constructor
/// signature is `(access_structure, encryption_keys_and_proofs_per_crt_prime)`.
pub(crate) fn network_dkg_bwd_compat_public_input(
    access_structure: &WeightedThresholdAccessStructure,
    encryption_keys_and_proofs: HashMap<PartyID, ClassGroupsEncryptionKeyAndProof>,
) -> DwalletMPCResult<<bwd_compat_dkg::Party as mpc::Party>::PublicInput> {
    bwd_compat_dkg::PublicInput::new(access_structure, encryption_keys_and_proofs)
        .map_err(|e| DwalletMPCError::InvalidMPCPartyType(e.to_string()))
}

/// Advances the network DKG protocol for the supported key types.
pub(crate) fn advance_network_dkg_v2(
    session_id: CommitmentSizedNumber,
    access_structure: &WeightedThresholdAccessStructure,
    public_input: <dkg::Party as mpc::Party>::PublicInput,
    party_id: PartyID,
    advance_request: AdvanceRequest<<dkg::Party as mpc::Party>::Message>,
    class_groups_decryption_key: ClassGroupsDecryptionKey,
    rng: &mut ChaCha20Rng,
) -> DwalletMPCResult<GuaranteedOutputDeliveryRoundResult> {
    let private_input = dkg::PrivateInput {
        decryption_key_per_crt_prime: class_groups_decryption_key,
    };
    let result = Party::<dkg::Party>::advance_with_guaranteed_output(
        session_id,
        party_id,
        access_structure,
        advance_request,
        Some(private_input),
        &public_input,
        rng,
    );

    let res = match result.clone() {
        Ok(GuaranteedOutputDeliveryRoundResult::Finalize {
            public_output_value,
            malicious_parties,
            private_output,
        }) => {
            let public_output_value =
                bcs::to_bytes(&VersionedNetworkDkgOutput::V3(public_output_value))?;

            Ok(GuaranteedOutputDeliveryRoundResult::Finalize {
                public_output_value,
                malicious_parties,
                private_output,
            })
        }
        _ => result,
    }?;

    Ok(res)
}

pub(crate) fn network_dkg_v2_public_input(
    access_structure: &WeightedThresholdAccessStructure,
    encryption_keys_and_proofs: HashMap<PartyID, ClassGroupsEncryptionKeyAndProof>,
    secp256k1_pvss_encryption_keys_and_proofs: HashMap<
        PartyID,
        ika_types::committee::Secp256k1PvssEncryptionKeyAndProof,
    >,
    secp256r1_pvss_encryption_keys_and_proofs: HashMap<
        PartyID,
        ika_types::committee::Secp256r1PvssEncryptionKeyAndProof,
    >,
    ristretto_pvss_encryption_keys_and_proofs: HashMap<
        PartyID,
        ika_types::committee::RistrettoPvssEncryptionKeyAndProof,
    >,
) -> DwalletMPCResult<<dkg::Party as mpc::Party>::PublicInput> {
    let public_input = <dkg::Party as mpc::Party>::PublicInput::new(
        access_structure,
        encryption_keys_and_proofs,
        secp256k1_pvss_encryption_keys_and_proofs,
        ristretto_pvss_encryption_keys_and_proofs,
        secp256r1_pvss_encryption_keys_and_proofs,
    )
    .map_err(|e| DwalletMPCError::InvalidMPCPartyType(e.to_string()))?;

    Ok(public_input)
}

pub(crate) async fn instantiate_dwallet_mpc_network_encryption_key_public_data_from_public_output(
    epoch: u64,
    access_structure: WeightedThresholdAccessStructure,
    key_data: DWalletNetworkEncryptionKeyData,
) -> DwalletMPCResult<NetworkEncryptionKeyPublicData> {
    let (key_public_data_sender, key_public_data_receiver) = oneshot::channel();

    rayon::spawn_fifo(move || {
        let res = if key_data.current_reconfiguration_public_output.is_empty() {
            if key_data.state == DWalletNetworkEncryptionKeyState::AwaitingNetworkDKG {
                Err(DwalletMPCError::WaitingForNetworkKey(key_data.id))
            } else {
                instantiate_dwallet_mpc_network_encryption_key_public_data_from_dkg_public_output(
                    epoch,
                    key_data.dkg_at_epoch,
                    &access_structure,
                    &key_data.network_dkg_public_output,
                    key_data.id.into_bytes(),
                )
            }
        } else {
            instantiate_dwallet_mpc_network_encryption_key_public_data_from_reconfiguration_public_output(
                epoch,
                key_data.dkg_at_epoch,
                &access_structure,
                &key_data.current_reconfiguration_public_output,
                &key_data.network_dkg_public_output,
                key_data.id.into_bytes(),
            )
        };

        if let Err(err) = key_public_data_sender.send(res) {
            error!(error=?err, "failed to send a network encryption key ");
        }
    });

    key_public_data_receiver
        .await
        .map_err(|_| DwalletMPCError::TokioRecv)?
}

/// Per-curve DKG output and public key for network-owned-address signing.
pub(crate) struct PerCurveNetworkOwnedAddressDkgData {
    pub dkg_output: Vec<u8>,
    pub public_key: Vec<u8>,
}

/// Holds per-curve DKG data for all 4 supported curves.
pub(crate) struct AllCurvesNetworkOwnedAddressDkgData {
    pub secp256k1: PerCurveNetworkOwnedAddressDkgData,
    pub secp256r1: PerCurveNetworkOwnedAddressDkgData,
    pub curve25519: PerCurveNetworkOwnedAddressDkgData,
    pub ristretto: PerCurveNetworkOwnedAddressDkgData,
}

/// Computes DKG outputs and public keys for all 4 curves.
pub(crate) fn compute_all_network_owned_address_dkg_outputs(
    network_key_id: &[u8; 32],
    secp256k1_protocol_public_parameters: &twopc_mpc::secp256k1::class_groups::ProtocolPublicParameters,
    secp256r1_protocol_public_parameters: &twopc_mpc::secp256r1::class_groups::ProtocolPublicParameters,
    ristretto_protocol_public_parameters: &twopc_mpc::ristretto::class_groups::ProtocolPublicParameters,
    curve25519_protocol_public_parameters: &twopc_mpc::curve25519::class_groups::ProtocolPublicParameters,
) -> DwalletMPCResult<AllCurvesNetworkOwnedAddressDkgData> {
    let secp256k1 = compute_noa_dkg::<Secp256k1AsyncDKGProtocol>(
        network_key_id,
        DWalletCurve::Secp256k1,
        secp256k1_protocol_public_parameters,
    )?;
    let secp256r1 = compute_noa_dkg::<Secp256r1AsyncDKGProtocol>(
        network_key_id,
        DWalletCurve::Secp256r1,
        secp256r1_protocol_public_parameters,
    )?;
    let curve25519 = compute_noa_dkg::<Curve25519AsyncDKGProtocol>(
        network_key_id,
        DWalletCurve::Curve25519,
        curve25519_protocol_public_parameters,
    )?;
    let ristretto = compute_noa_dkg::<RistrettoAsyncDKGProtocol>(
        network_key_id,
        DWalletCurve::Ristretto,
        ristretto_protocol_public_parameters,
    )?;
    Ok(AllCurvesNetworkOwnedAddressDkgData {
        secp256k1,
        secp256r1,
        curve25519,
        ristretto,
    })
}

/// Builds the `NetworkEncryptionKeyPublicData` from per-curve DKG data.
pub(crate) fn build_network_encryption_key_public_data(
    epoch: u64,
    dkg_at_epoch: u64,
    state: NetworkDecryptionKeyPublicOutputType,
    latest_network_reconfiguration_public_output: Option<
        VersionedDecryptionKeyReconfigurationOutput,
    >,
    network_dkg_output: VersionedNetworkDkgOutput,
    secp256k1_protocol_public_parameters: Arc<
        twopc_mpc::secp256k1::class_groups::ProtocolPublicParameters,
    >,
    secp256k1_decryption_key_share_public_parameters: Arc<
        class_groups::Secp256k1DecryptionKeySharePublicParameters,
    >,
    secp256r1_protocol_public_parameters: Arc<
        twopc_mpc::secp256r1::class_groups::ProtocolPublicParameters,
    >,
    secp256r1_decryption_key_share_public_parameters: Arc<
        class_groups::Secp256r1DecryptionKeySharePublicParameters,
    >,
    ristretto_protocol_public_parameters: Arc<
        twopc_mpc::ristretto::class_groups::ProtocolPublicParameters,
    >,
    ristretto_decryption_key_share_public_parameters: Arc<
        class_groups::RistrettoDecryptionKeySharePublicParameters,
    >,
    curve25519_protocol_public_parameters: Arc<
        twopc_mpc::curve25519::class_groups::ProtocolPublicParameters,
    >,
    curve25519_decryption_key_share_public_parameters: Arc<
        class_groups::Curve25519DecryptionKeySharePublicParameters,
    >,
    noa_dkg_data: &AllCurvesNetworkOwnedAddressDkgData,
) -> NetworkEncryptionKeyPublicData {
    NetworkEncryptionKeyPublicData {
        epoch,
        dkg_at_epoch,
        state,
        latest_network_reconfiguration_public_output,
        network_dkg_output,
        secp256k1_protocol_public_parameters,
        secp256k1_decryption_key_share_public_parameters,
        secp256r1_protocol_public_parameters,
        secp256r1_decryption_key_share_public_parameters,
        ristretto_protocol_public_parameters,
        ristretto_decryption_key_share_public_parameters,
        curve25519_protocol_public_parameters,
        curve25519_decryption_key_share_public_parameters,
        secp256k1_network_owned_address_dkg_output: noa_dkg_data.secp256k1.dkg_output.clone(),
        secp256r1_network_owned_address_dkg_output: noa_dkg_data.secp256r1.dkg_output.clone(),
        curve25519_network_owned_address_dkg_output: noa_dkg_data.curve25519.dkg_output.clone(),
        ristretto_network_owned_address_dkg_output: noa_dkg_data.ristretto.dkg_output.clone(),
        secp256k1_network_owned_address_public_key: noa_dkg_data.secp256k1.public_key.clone(),
        secp256r1_network_owned_address_public_key: noa_dkg_data.secp256r1.public_key.clone(),
        curve25519_network_owned_address_public_key: noa_dkg_data.curve25519.public_key.clone(),
        ristretto_network_owned_address_public_key: noa_dkg_data.ristretto.public_key.clone(),
    }
}

fn instantiate_dwallet_mpc_network_encryption_key_public_data_from_dkg_public_output(
    epoch: u64,
    dkg_at_epoch: u64,
    access_structure: &WeightedThresholdAccessStructure,
    public_output_bytes: &SerializedWrappedMPCPublicOutput,
    network_key_id: [u8; 32],
) -> DwalletMPCResult<NetworkEncryptionKeyPublicData> {
    let mpc_public_output: VersionedNetworkDkgOutput =
        bcs::from_bytes(public_output_bytes).map_err(DwalletMPCError::BcsError)?;

    // Macro extracts the 8 protocol+decryption-key-share Arcs from a decoded
    // DKG `PublicOutput` (either `bwd_compat_dkg::Party::PublicOutput` or
    // `dkg::Party::PublicOutput`; both expose the same per-curve accessor API).
    macro_rules! build_from_public_output {
        ($public_output:expr) => {{
            let public_output = $public_output;
            let secp256k1_protocol_public_parameters =
                Arc::new(public_output.secp256k1_protocol_public_parameters()?);
            let secp256k1_decryption_key_share_public_parameters = Arc::new(
                public_output
                    .secp256k1_decryption_key_share_public_parameters(access_structure)
                    .map_err(DwalletMPCError::from)?,
            );
            let secp256r1_protocol_public_parameters =
                Arc::new(public_output.secp256r1_protocol_public_parameters()?);
            let secp256r1_decryption_key_share_public_parameters = Arc::new(
                public_output.secp256r1_decryption_key_share_public_parameters(access_structure)?,
            );
            let ristretto_protocol_public_parameters =
                Arc::new(public_output.ristretto_protocol_public_parameters()?);
            let ristretto_decryption_key_share_public_parameters = Arc::new(
                public_output.ristretto_decryption_key_share_public_parameters(access_structure)?,
            );
            let curve25519_protocol_public_parameters =
                Arc::new(public_output.curve25519_protocol_public_parameters()?);
            let curve25519_decryption_key_share_public_parameters = Arc::new(
                public_output
                    .curve25519_decryption_key_share_public_parameters(access_structure)?,
            );

            let noa_dkg_data = compute_all_network_owned_address_dkg_outputs(
                &network_key_id,
                &secp256k1_protocol_public_parameters,
                &secp256r1_protocol_public_parameters,
                &ristretto_protocol_public_parameters,
                &curve25519_protocol_public_parameters,
            )?;

            Ok::<NetworkEncryptionKeyPublicData, DwalletMPCError>(
                build_network_encryption_key_public_data(
                    epoch,
                    dkg_at_epoch,
                    NetworkDecryptionKeyPublicOutputType::NetworkDkg,
                    None,
                    mpc_public_output.clone(),
                    secp256k1_protocol_public_parameters,
                    secp256k1_decryption_key_share_public_parameters,
                    secp256r1_protocol_public_parameters,
                    secp256r1_decryption_key_share_public_parameters,
                    ristretto_protocol_public_parameters,
                    ristretto_decryption_key_share_public_parameters,
                    curve25519_protocol_public_parameters,
                    curve25519_decryption_key_share_public_parameters,
                    &noa_dkg_data,
                ),
            )
        }};
    }

    match &mpc_public_output {
        VersionedNetworkDkgOutput::V1(_) => {
            unreachable!("V1 network DKG outputs are no longer produced")
        }
        VersionedNetworkDkgOutput::V2(public_output_bytes) => {
            // bwd-compat shape — decode under `bwd_compat_dkg::Party::PublicOutput`.
            let public_output: <bwd_compat_dkg::Party as mpc::Party>::PublicOutput =
                bcs::from_bytes(public_output_bytes)?;
            build_from_public_output!(public_output)
        }
        VersionedNetworkDkgOutput::V3(public_output_bytes) => {
            let public_output: <dkg::Party as mpc::Party>::PublicOutput =
                bcs::from_bytes(public_output_bytes)?;
            build_from_public_output!(public_output)
        }
    }
}

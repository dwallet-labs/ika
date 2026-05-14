// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! This module provides a wrapper around the Sign protocol from the 2PC-MPC library.
//!
//! It integrates the Sign party (representing a round in the protocol).

use crate::dwallet_mpc::crytographic_computation::mpc_computations;
use crate::dwallet_mpc::crytographic_computation::mpc_computations::parse_signature_from_sign_output;
use crate::dwallet_mpc::dwallet_dkg::DWalletDKGPublicInputByCurve;
use crate::dwallet_mpc::dwallet_mpc_metrics::DWalletMPCMetrics;
use crate::request_protocol_data::SignData;
use class_groups::CiphertextSpaceGroupElement;
use commitment::CommitmentSizedNumber;
use dwallet_mpc_types::dwallet_mpc::{
    DWalletCurve, DWalletSignatureAlgorithm, MPCPublicOutput, NetworkEncryptionKeyPublicData,
    SerializedWrappedMPCPublicOutput, VersionedDwalletDKGPublicOutput, VersionedPresignOutput,
    VersionedUserSignedMessage, public_key_from_decentralized_dkg_output_by_curve_v2,
};
use group::CsRng;
use group::{HashScheme, OsCsRng, PartyID};
use ika_types::dwallet_mpc_error::{DwalletMPCError, DwalletMPCResult};
use ika_types::messages_dwallet_mpc::{
    Curve25519AsyncDKGProtocol, Curve25519EdDSAProtocol, RistrettoAsyncDKGProtocol,
    RistrettoSchnorrkelSubstrateProtocol, Secp256k1AsyncDKGProtocol, Secp256k1ECDSAProtocol,
    Secp256k1TaprootProtocol, Secp256r1AsyncDKGProtocol, Secp256r1ECDSAProtocol, SessionIdentifier,
};
use mpc::guaranteed_output_delivery::AdvanceRequest;
use mpc::{AsynchronouslyAdvanceable, GuaranteesOutputDelivery};
use mpc::{GuaranteedOutputDeliveryRoundResult, Party, Weight, WeightedThresholdAccessStructure};
use rand_core::SeedableRng;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tracing::error;
use twopc_mpc::secp256k1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS;
use twopc_mpc::sign::SignData as UpstreamSignData;
use twopc_mpc::{dkg, sign};

pub(crate) type SignParty<P> = <P as twopc_mpc::sign::Protocol>::SignDecentralizedParty;
pub(crate) type DKGAndSignParty<P> = <P as twopc_mpc::sign::Protocol>::DKGSignDecentralizedParty;

/// Local extension trait that names the per-curve `DecryptionKeySharePublicParameters`
/// (which `twopc_mpc::sign::Protocol` no longer exposes as an associated type at
/// `9d35fa76`) and provides per-protocol struct-literal constructors for the sign
/// public inputs (since the upstream `From<(tuple)>` impls were removed).
///
/// All five sign protocols ika uses are AHE-mode at this bump; the `sign_data`
/// parameter is `SignData::Unverified(sign_message)` for user-driven sign and
/// `SignData::ToBeEmulated` for network-owned-address sign (per Phase 9).
///
/// TODO(vss): when VSS-mode sign protocols are activated, the sign-protocol private
/// input changes shape (HPKE blobs / nonce shares derived from the presign
/// `PrivateOutput`). Sign sessions will need to read each validator's own presign
/// `<P::PresignParty as mpc::Party>::PrivateOutput` (a concrete VSS type, not `()`)
/// keyed by `(presign_id, validator_id)` — that storage path does not exist today.
/// The generic shape stays the same; only the source of the value changes per
/// protocol. See `docs/plan-bump-crypto-private-to-main.md` §4d.
pub(crate) trait SignProtocolExt: twopc_mpc::sign::Protocol {
    type DecryptionKeySharePublicParameters: Send + Sync;

    fn build_sign_public_input(
        expected_decrypters: HashSet<PartyID>,
        protocol_public_parameters: Arc<
            <Self::DKGProtocol as twopc_mpc::dkg::Protocol>::ProtocolPublicParameters,
        >,
        message: Vec<u8>,
        hash_scheme: HashScheme,
        dkg_output: <Self::DKGProtocol as twopc_mpc::dkg::Protocol>::DecentralizedPartyDKGOutput,
        presign: <Self as twopc_mpc::presign::Protocol>::Presign,
        sign_data: UpstreamSignData<Self::SignMessage, Self::VerifiedSignData>,
        decryption_pp: Arc<Self::DecryptionKeySharePublicParameters>,
    ) -> Self::SignDecentralizedPartyPublicInput;

    fn build_dkg_and_sign_public_input(
        expected_decrypters: HashSet<PartyID>,
        protocol_public_parameters: Arc<
            <Self::DKGProtocol as twopc_mpc::dkg::Protocol>::ProtocolPublicParameters,
        >,
        message: Vec<u8>,
        hash_scheme: HashScheme,
        dkg_public_input: <Self::DKGProtocol as twopc_mpc::dkg::Protocol>::DKGDecentralizedPartyPublicInput,
        presign: <Self as twopc_mpc::presign::Protocol>::Presign,
        sign_data: UpstreamSignData<Self::SignMessage, Self::VerifiedSignData>,
        decryption_pp: Arc<Self::DecryptionKeySharePublicParameters>,
    ) -> Self::DKGSignDecentralizedPartyPublicInput;
}

impl SignProtocolExt for Secp256k1ECDSAProtocol {
    type DecryptionKeySharePublicParameters =
        class_groups::Secp256k1DecryptionKeySharePublicParameters;

    fn build_sign_public_input(
        expected_decrypters: HashSet<PartyID>,
        protocol_public_parameters: Arc<
            <Self::DKGProtocol as twopc_mpc::dkg::Protocol>::ProtocolPublicParameters,
        >,
        message: Vec<u8>,
        hash_scheme: HashScheme,
        dkg_output: <Self::DKGProtocol as twopc_mpc::dkg::Protocol>::DecentralizedPartyDKGOutput,
        presign: <Self as twopc_mpc::presign::Protocol>::Presign,
        sign_data: UpstreamSignData<Self::SignMessage, Self::VerifiedSignData>,
        decryption_pp: Arc<Self::DecryptionKeySharePublicParameters>,
    ) -> Self::SignDecentralizedPartyPublicInput {
        twopc_mpc::ecdsa::sign::decentralized_party::PublicInput {
            expected_decrypters,
            message,
            hash_type: hash_scheme,
            dkg_output,
            presign,
            sign_message: sign_data,
            decryption_key_share_public_parameters: decryption_pp,
            protocol_public_parameters,
        }
    }

    fn build_dkg_and_sign_public_input(
        expected_decrypters: HashSet<PartyID>,
        protocol_public_parameters: Arc<
            <Self::DKGProtocol as twopc_mpc::dkg::Protocol>::ProtocolPublicParameters,
        >,
        message: Vec<u8>,
        hash_scheme: HashScheme,
        dkg_public_input: <Self::DKGProtocol as twopc_mpc::dkg::Protocol>::DKGDecentralizedPartyPublicInput,
        presign: <Self as twopc_mpc::presign::Protocol>::Presign,
        sign_data: UpstreamSignData<Self::SignMessage, Self::VerifiedSignData>,
        decryption_pp: Arc<Self::DecryptionKeySharePublicParameters>,
    ) -> Self::DKGSignDecentralizedPartyPublicInput {
        twopc_mpc::ecdsa::sign::decentralized_party::DKGSignPublicInput {
            expected_decrypters,
            message,
            hash_type: hash_scheme,
            dkg_public_input,
            presign,
            sign_message: sign_data,
            decryption_key_share_public_parameters: decryption_pp,
            protocol_public_parameters,
        }
    }
}

impl SignProtocolExt for Secp256r1ECDSAProtocol {
    type DecryptionKeySharePublicParameters =
        class_groups::Secp256r1DecryptionKeySharePublicParameters;

    fn build_sign_public_input(
        expected_decrypters: HashSet<PartyID>,
        protocol_public_parameters: Arc<
            <Self::DKGProtocol as twopc_mpc::dkg::Protocol>::ProtocolPublicParameters,
        >,
        message: Vec<u8>,
        hash_scheme: HashScheme,
        dkg_output: <Self::DKGProtocol as twopc_mpc::dkg::Protocol>::DecentralizedPartyDKGOutput,
        presign: <Self as twopc_mpc::presign::Protocol>::Presign,
        sign_data: UpstreamSignData<Self::SignMessage, Self::VerifiedSignData>,
        decryption_pp: Arc<Self::DecryptionKeySharePublicParameters>,
    ) -> Self::SignDecentralizedPartyPublicInput {
        twopc_mpc::ecdsa::sign::decentralized_party::PublicInput {
            expected_decrypters,
            message,
            hash_type: hash_scheme,
            dkg_output,
            presign,
            sign_message: sign_data,
            decryption_key_share_public_parameters: decryption_pp,
            protocol_public_parameters,
        }
    }

    fn build_dkg_and_sign_public_input(
        expected_decrypters: HashSet<PartyID>,
        protocol_public_parameters: Arc<
            <Self::DKGProtocol as twopc_mpc::dkg::Protocol>::ProtocolPublicParameters,
        >,
        message: Vec<u8>,
        hash_scheme: HashScheme,
        dkg_public_input: <Self::DKGProtocol as twopc_mpc::dkg::Protocol>::DKGDecentralizedPartyPublicInput,
        presign: <Self as twopc_mpc::presign::Protocol>::Presign,
        sign_data: UpstreamSignData<Self::SignMessage, Self::VerifiedSignData>,
        decryption_pp: Arc<Self::DecryptionKeySharePublicParameters>,
    ) -> Self::DKGSignDecentralizedPartyPublicInput {
        twopc_mpc::ecdsa::sign::decentralized_party::DKGSignPublicInput {
            expected_decrypters,
            message,
            hash_type: hash_scheme,
            dkg_public_input,
            presign,
            sign_message: sign_data,
            decryption_key_share_public_parameters: decryption_pp,
            protocol_public_parameters,
        }
    }
}

impl SignProtocolExt for Secp256k1TaprootProtocol {
    type DecryptionKeySharePublicParameters =
        class_groups::Secp256k1DecryptionKeySharePublicParameters;

    fn build_sign_public_input(
        expected_decrypters: HashSet<PartyID>,
        protocol_public_parameters: Arc<
            <Self::DKGProtocol as twopc_mpc::dkg::Protocol>::ProtocolPublicParameters,
        >,
        message: Vec<u8>,
        hash_scheme: HashScheme,
        dkg_output: <Self::DKGProtocol as twopc_mpc::dkg::Protocol>::DecentralizedPartyDKGOutput,
        presign: <Self as twopc_mpc::presign::Protocol>::Presign,
        sign_data: UpstreamSignData<Self::SignMessage, Self::VerifiedSignData>,
        decryption_pp: Arc<Self::DecryptionKeySharePublicParameters>,
    ) -> Self::SignDecentralizedPartyPublicInput {
        twopc_mpc::schnorr::ahe::sign::decentralized_party::PublicInput {
            expected_decrypters,
            message,
            hash_scheme,
            dkg_output,
            presign,
            centralized_party_partial_signature: sign_data,
            decryption_key_share_public_parameters: decryption_pp,
            protocol_public_parameters,
        }
    }

    fn build_dkg_and_sign_public_input(
        expected_decrypters: HashSet<PartyID>,
        protocol_public_parameters: Arc<
            <Self::DKGProtocol as twopc_mpc::dkg::Protocol>::ProtocolPublicParameters,
        >,
        message: Vec<u8>,
        hash_scheme: HashScheme,
        dkg_public_input: <Self::DKGProtocol as twopc_mpc::dkg::Protocol>::DKGDecentralizedPartyPublicInput,
        presign: <Self as twopc_mpc::presign::Protocol>::Presign,
        sign_data: UpstreamSignData<Self::SignMessage, Self::VerifiedSignData>,
        decryption_pp: Arc<Self::DecryptionKeySharePublicParameters>,
    ) -> Self::DKGSignDecentralizedPartyPublicInput {
        twopc_mpc::schnorr::ahe::sign::decentralized_party::DKGSignPublicInput {
            expected_decrypters,
            message,
            hash_scheme,
            dkg_public_input,
            presign,
            centralized_party_partial_signature: sign_data,
            decryption_key_share_public_parameters: decryption_pp,
            protocol_public_parameters,
        }
    }
}

impl SignProtocolExt for Curve25519EdDSAProtocol {
    type DecryptionKeySharePublicParameters =
        class_groups::Curve25519DecryptionKeySharePublicParameters;

    fn build_sign_public_input(
        expected_decrypters: HashSet<PartyID>,
        protocol_public_parameters: Arc<
            <Self::DKGProtocol as twopc_mpc::dkg::Protocol>::ProtocolPublicParameters,
        >,
        message: Vec<u8>,
        hash_scheme: HashScheme,
        dkg_output: <Self::DKGProtocol as twopc_mpc::dkg::Protocol>::DecentralizedPartyDKGOutput,
        presign: <Self as twopc_mpc::presign::Protocol>::Presign,
        sign_data: UpstreamSignData<Self::SignMessage, Self::VerifiedSignData>,
        decryption_pp: Arc<Self::DecryptionKeySharePublicParameters>,
    ) -> Self::SignDecentralizedPartyPublicInput {
        twopc_mpc::schnorr::ahe::sign::decentralized_party::PublicInput {
            expected_decrypters,
            message,
            hash_scheme,
            dkg_output,
            presign,
            centralized_party_partial_signature: sign_data,
            decryption_key_share_public_parameters: decryption_pp,
            protocol_public_parameters,
        }
    }

    fn build_dkg_and_sign_public_input(
        expected_decrypters: HashSet<PartyID>,
        protocol_public_parameters: Arc<
            <Self::DKGProtocol as twopc_mpc::dkg::Protocol>::ProtocolPublicParameters,
        >,
        message: Vec<u8>,
        hash_scheme: HashScheme,
        dkg_public_input: <Self::DKGProtocol as twopc_mpc::dkg::Protocol>::DKGDecentralizedPartyPublicInput,
        presign: <Self as twopc_mpc::presign::Protocol>::Presign,
        sign_data: UpstreamSignData<Self::SignMessage, Self::VerifiedSignData>,
        decryption_pp: Arc<Self::DecryptionKeySharePublicParameters>,
    ) -> Self::DKGSignDecentralizedPartyPublicInput {
        twopc_mpc::schnorr::ahe::sign::decentralized_party::DKGSignPublicInput {
            expected_decrypters,
            message,
            hash_scheme,
            dkg_public_input,
            presign,
            centralized_party_partial_signature: sign_data,
            decryption_key_share_public_parameters: decryption_pp,
            protocol_public_parameters,
        }
    }
}

impl SignProtocolExt for RistrettoSchnorrkelSubstrateProtocol {
    type DecryptionKeySharePublicParameters =
        class_groups::RistrettoDecryptionKeySharePublicParameters;

    fn build_sign_public_input(
        expected_decrypters: HashSet<PartyID>,
        protocol_public_parameters: Arc<
            <Self::DKGProtocol as twopc_mpc::dkg::Protocol>::ProtocolPublicParameters,
        >,
        message: Vec<u8>,
        hash_scheme: HashScheme,
        dkg_output: <Self::DKGProtocol as twopc_mpc::dkg::Protocol>::DecentralizedPartyDKGOutput,
        presign: <Self as twopc_mpc::presign::Protocol>::Presign,
        sign_data: UpstreamSignData<Self::SignMessage, Self::VerifiedSignData>,
        decryption_pp: Arc<Self::DecryptionKeySharePublicParameters>,
    ) -> Self::SignDecentralizedPartyPublicInput {
        twopc_mpc::schnorr::ahe::sign::decentralized_party::PublicInput {
            expected_decrypters,
            message,
            hash_scheme,
            dkg_output,
            presign,
            centralized_party_partial_signature: sign_data,
            decryption_key_share_public_parameters: decryption_pp,
            protocol_public_parameters,
        }
    }

    fn build_dkg_and_sign_public_input(
        expected_decrypters: HashSet<PartyID>,
        protocol_public_parameters: Arc<
            <Self::DKGProtocol as twopc_mpc::dkg::Protocol>::ProtocolPublicParameters,
        >,
        message: Vec<u8>,
        hash_scheme: HashScheme,
        dkg_public_input: <Self::DKGProtocol as twopc_mpc::dkg::Protocol>::DKGDecentralizedPartyPublicInput,
        presign: <Self as twopc_mpc::presign::Protocol>::Presign,
        sign_data: UpstreamSignData<Self::SignMessage, Self::VerifiedSignData>,
        decryption_pp: Arc<Self::DecryptionKeySharePublicParameters>,
    ) -> Self::DKGSignDecentralizedPartyPublicInput {
        twopc_mpc::schnorr::ahe::sign::decentralized_party::DKGSignPublicInput {
            expected_decrypters,
            message,
            hash_scheme,
            dkg_public_input,
            presign,
            centralized_party_partial_signature: sign_data,
            decryption_key_share_public_parameters: decryption_pp,
            protocol_public_parameters,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, strum_macros::Display)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum SignPublicInputByProtocol {
    #[strum(to_string = "Sign Public Input - curve: Secp256k1, protocol: ECDSA")]
    Secp256k1ECDSA(<SignParty<Secp256k1ECDSAProtocol> as mpc::Party>::PublicInput),
    #[strum(to_string = "Sign Public Input - curve: Secp256k1, protocol: Taproot")]
    Secp256k1Taproot(<SignParty<Secp256k1TaprootProtocol> as mpc::Party>::PublicInput),
    #[strum(to_string = "Sign Public Input - curve: Secp256r1, protocol: ECDSA")]
    Secp256r1(<SignParty<Secp256r1ECDSAProtocol> as mpc::Party>::PublicInput),
    #[strum(to_string = "Sign Public Input - curve: Curve25519, protocol: EdDSA")]
    Curve25519(<SignParty<Curve25519EdDSAProtocol> as mpc::Party>::PublicInput),
    #[strum(to_string = "Sign Public Input - curve: Ristretto, protocol: SchnorrkelSubstrate")]
    Ristretto(<SignParty<RistrettoSchnorrkelSubstrateProtocol> as mpc::Party>::PublicInput),
}

#[derive(Clone, Debug, Eq, PartialEq, strum_macros::Display)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum DKGAndSignPublicInputByProtocol {
    #[strum(to_string = "DKG and Sign Public Input - curve: Secp256k1, protocol: ECDSA")]
    Secp256k1ECDSA(<DKGAndSignParty<Secp256k1ECDSAProtocol> as mpc::Party>::PublicInput),
    #[strum(to_string = "DKG and Sign Public Input - curve: Secp256k1, protocol: Taproot")]
    Secp256k1Taproot(<DKGAndSignParty<Secp256k1TaprootProtocol> as mpc::Party>::PublicInput),
    #[strum(to_string = "DKG and Sign Public Input - curve: Secp256r1, protocol: ECDSA")]
    Secp256r1(<DKGAndSignParty<Secp256r1ECDSAProtocol> as mpc::Party>::PublicInput),
    #[strum(to_string = "DKG and Sign Public Input - curve: Curve25519, protocol: EdDSA")]
    Curve25519(<DKGAndSignParty<Curve25519EdDSAProtocol> as mpc::Party>::PublicInput),
    #[strum(
        to_string = "DKG and Sign Public Input - curve: Ristretto, protocol: SchnorrkelSubstrate"
    )]
    Ristretto(<DKGAndSignParty<RistrettoSchnorrkelSubstrateProtocol> as mpc::Party>::PublicInput),
}

#[derive(strum_macros::Display)]
pub(crate) enum SignAdvanceRequestByProtocol {
    #[strum(to_string = "Sign Advance Request - curve: Secp256k1, protocol: ECDSA")]
    Secp256k1ECDSA(
        mpc::guaranteed_output_delivery::AdvanceRequest<
            <SignParty<Secp256k1ECDSAProtocol> as mpc::Party>::Message,
        >,
    ),
    #[strum(to_string = "Sign Advance Request - curve: Secp256k1, protocol: Taproot")]
    Secp256k1Taproot(
        mpc::guaranteed_output_delivery::AdvanceRequest<
            <SignParty<Secp256k1TaprootProtocol> as mpc::Party>::Message,
        >,
    ),
    #[strum(to_string = "Sign Advance Request - curve: Secp256r1, protocol: ECDSA")]
    Secp256r1(
        mpc::guaranteed_output_delivery::AdvanceRequest<
            <SignParty<Secp256r1ECDSAProtocol> as mpc::Party>::Message,
        >,
    ),
    #[strum(to_string = "Sign Advance Request - curve: Curve25519, protocol: EdDSA")]
    Curve25519(
        mpc::guaranteed_output_delivery::AdvanceRequest<
            <SignParty<Curve25519EdDSAProtocol> as mpc::Party>::Message,
        >,
    ),
    #[strum(to_string = "Sign Advance Request - curve: Ristretto, protocol: SchnorrkelSubstrate")]
    Ristretto(
        mpc::guaranteed_output_delivery::AdvanceRequest<
            <SignParty<RistrettoSchnorrkelSubstrateProtocol> as mpc::Party>::Message,
        >,
    ),
}

#[derive(strum_macros::Display)]
pub(crate) enum DWalletDKGAndSignAdvanceRequestByProtocol {
    #[strum(to_string = "DKG and Sign Advance Request - curve: Secp256k1, protocol: ECDSA")]
    Secp256k1ECDSA(
        mpc::guaranteed_output_delivery::AdvanceRequest<
            <DKGAndSignParty<Secp256k1ECDSAProtocol> as mpc::Party>::Message,
        >,
    ),
    #[strum(to_string = "DKG and Sign Advance Request - curve: Secp256k1, protocol: Taproot")]
    Secp256k1Taproot(
        mpc::guaranteed_output_delivery::AdvanceRequest<
            <DKGAndSignParty<Secp256k1TaprootProtocol> as mpc::Party>::Message,
        >,
    ),
    #[strum(to_string = "DKG and Sign Advance Request - curve: Secp256r1, protocol: ECDSA")]
    Secp256r1(
        mpc::guaranteed_output_delivery::AdvanceRequest<
            <DKGAndSignParty<Secp256r1ECDSAProtocol> as mpc::Party>::Message,
        >,
    ),
    #[strum(to_string = "DKG and Sign Advance Request - curve: Curve25519, protocol: EdDSA")]
    Curve25519(
        mpc::guaranteed_output_delivery::AdvanceRequest<
            <DKGAndSignParty<Curve25519EdDSAProtocol> as mpc::Party>::Message,
        >,
    ),
    #[strum(
        to_string = "DKG and Sign Advance Request - curve: Ristretto, protocol: SchnorrkelSubstrate"
    )]
    Ristretto(
        mpc::guaranteed_output_delivery::AdvanceRequest<
            <DKGAndSignParty<RistrettoSchnorrkelSubstrateProtocol> as mpc::Party>::Message,
        >,
    ),
}

/// Deterministically determine the set of expected decrypters for an optimization of the
/// threshold decryption in the Sign protocol.
/// Pseudo-randomly samples a subset of size `t + 10% * n`,
/// i.e., we add an extra ten-percent of validators,
/// of which at least `t` should be online (sent a message) during the first round of
/// Sign, i.e., they are expected to decrypt the signature.
///
/// This is a non-stateful way to agree on a subset (that has to be the same for all validators);
/// in the future, we may consider generating this subset in a stateful manner that takes into
/// account the validators' online/offline states, malicious activities etc.
/// This would be better, though harder to implement in practice, and will only be done
/// if we see that the current method is ineffective;
/// however, we expect 10% to cover for these effects successfully.
///
/// Note: this is only an optimization: if we don't have at least `t` online decrypters out of
/// the `expected_decrypters` subset, the Sign protocol still completes successfully, only slower.
fn generate_expected_decrypters(
    access_structure: &WeightedThresholdAccessStructure,
    session_identifier: SessionIdentifier,
) -> DwalletMPCResult<HashSet<PartyID>> {
    let total_weight = access_structure.total_weight();
    let expected_decrypters_weight =
        access_structure.threshold + (total_weight as f64 * 0.10).floor() as Weight;

    let mut seed_rng = rand_chacha::ChaCha20Rng::from_seed(session_identifier.into_bytes());
    let expected_decrypters = access_structure
        .random_subset_with_target_weight(expected_decrypters_weight, &mut seed_rng)
        .map_err(DwalletMPCError::from)?;

    Ok(expected_decrypters)
}

impl SignAdvanceRequestByProtocol {
    pub fn try_new(
        protocol: &DWalletSignatureAlgorithm,
        party_id: PartyID,
        access_structure: &WeightedThresholdAccessStructure,
        consensus_round: u64,
        serialized_messages_by_consensus_round: HashMap<u64, HashMap<PartyID, Vec<u8>>>,
    ) -> DwalletMPCResult<Option<Self>> {
        let advance_request = match protocol {
            DWalletSignatureAlgorithm::ECDSASecp256k1 => {
                let advance_request =
                    mpc_computations::try_ready_to_advance::<SignParty<Secp256k1ECDSAProtocol>>(
                        party_id,
                        access_structure,
                        consensus_round,
                        HashMap::new(),
                        &serialized_messages_by_consensus_round,
                    )?;

                advance_request.map(SignAdvanceRequestByProtocol::Secp256k1ECDSA)
            }
            DWalletSignatureAlgorithm::Taproot => {
                let advance_request =
                    mpc_computations::try_ready_to_advance::<SignParty<Secp256k1TaprootProtocol>>(
                        party_id,
                        access_structure,
                        consensus_round,
                        HashMap::new(),
                        &serialized_messages_by_consensus_round,
                    )?;

                advance_request.map(SignAdvanceRequestByProtocol::Secp256k1Taproot)
            }
            DWalletSignatureAlgorithm::SchnorrkelSubstrate => {
                let advance_request = mpc_computations::try_ready_to_advance::<
                    SignParty<RistrettoSchnorrkelSubstrateProtocol>,
                >(
                    party_id,
                    access_structure,
                    consensus_round,
                    HashMap::new(),
                    &serialized_messages_by_consensus_round,
                )?;

                advance_request.map(SignAdvanceRequestByProtocol::Ristretto)
            }
            DWalletSignatureAlgorithm::EdDSA => {
                let advance_request =
                    mpc_computations::try_ready_to_advance::<SignParty<Curve25519EdDSAProtocol>>(
                        party_id,
                        access_structure,
                        consensus_round,
                        HashMap::new(),
                        &serialized_messages_by_consensus_round,
                    )?;

                advance_request.map(SignAdvanceRequestByProtocol::Curve25519)
            }
            DWalletSignatureAlgorithm::ECDSASecp256r1 => {
                let advance_request =
                    mpc_computations::try_ready_to_advance::<SignParty<Secp256r1ECDSAProtocol>>(
                        party_id,
                        access_structure,
                        consensus_round,
                        HashMap::new(),
                        &serialized_messages_by_consensus_round,
                    )?;

                advance_request.map(SignAdvanceRequestByProtocol::Secp256r1)
            }
        };

        Ok(advance_request)
    }
}

impl DWalletDKGAndSignAdvanceRequestByProtocol {
    pub fn try_new(
        protocol: &DWalletSignatureAlgorithm,
        party_id: PartyID,
        access_structure: &WeightedThresholdAccessStructure,
        consensus_round: u64,
        serialized_messages_by_consensus_round: HashMap<u64, HashMap<PartyID, Vec<u8>>>,
    ) -> DwalletMPCResult<Option<Self>> {
        let advance_request = match protocol {
            DWalletSignatureAlgorithm::ECDSASecp256k1 => {
                let advance_request = mpc_computations::try_ready_to_advance::<
                    DKGAndSignParty<Secp256k1ECDSAProtocol>,
                >(
                    party_id,
                    access_structure,
                    consensus_round,
                    HashMap::new(),
                    &serialized_messages_by_consensus_round,
                )?;

                advance_request.map(Self::Secp256k1ECDSA)
            }
            DWalletSignatureAlgorithm::Taproot => {
                let advance_request = mpc_computations::try_ready_to_advance::<
                    DKGAndSignParty<Secp256k1TaprootProtocol>,
                >(
                    party_id,
                    access_structure,
                    consensus_round,
                    HashMap::new(),
                    &serialized_messages_by_consensus_round,
                )?;

                advance_request.map(Self::Secp256k1Taproot)
            }
            DWalletSignatureAlgorithm::SchnorrkelSubstrate => {
                let advance_request = mpc_computations::try_ready_to_advance::<
                    DKGAndSignParty<RistrettoSchnorrkelSubstrateProtocol>,
                >(
                    party_id,
                    access_structure,
                    consensus_round,
                    HashMap::new(),
                    &serialized_messages_by_consensus_round,
                )?;

                advance_request.map(Self::Ristretto)
            }
            DWalletSignatureAlgorithm::EdDSA => {
                let advance_request = mpc_computations::try_ready_to_advance::<
                    DKGAndSignParty<Curve25519EdDSAProtocol>,
                >(
                    party_id,
                    access_structure,
                    consensus_round,
                    HashMap::new(),
                    &serialized_messages_by_consensus_round,
                )?;

                advance_request.map(Self::Curve25519)
            }
            DWalletSignatureAlgorithm::ECDSASecp256r1 => {
                let advance_request = mpc_computations::try_ready_to_advance::<
                    DKGAndSignParty<Secp256r1ECDSAProtocol>,
                >(
                    party_id,
                    access_structure,
                    consensus_round,
                    HashMap::new(),
                    &serialized_messages_by_consensus_round,
                )?;

                advance_request.map(Self::Secp256r1)
            }
        };

        Ok(advance_request)
    }
}

impl SignPublicInputByProtocol {
    pub(crate) fn try_new(
        session_identifier: SessionIdentifier,
        dwallet_decentralized_public_output: &SerializedWrappedMPCPublicOutput,
        message: Vec<u8>,
        presign: &SerializedWrappedMPCPublicOutput,
        message_centralized_signature: &SerializedWrappedMPCPublicOutput,
        hash_scheme: HashScheme,
        access_structure: &WeightedThresholdAccessStructure,
        network_encryption_key_public_data: &NetworkEncryptionKeyPublicData,
        protocol: DWalletSignatureAlgorithm,
    ) -> DwalletMPCResult<Self> {
        let expected_decrypters =
            generate_expected_decrypters(access_structure, session_identifier)?;

        match protocol {
            DWalletSignatureAlgorithm::ECDSASecp256k1 => {
                let decryption_pp = network_encryption_key_public_data
                    .secp256k1_decryption_key_share_public_parameters();
                let protocol_public_parameters =
                    network_encryption_key_public_data.secp256k1_protocol_public_parameters();

                Ok(SignPublicInputByProtocol::Secp256k1ECDSA(
                    match bcs::from_bytes(presign).map_err(|_| {
                        DwalletMPCError::BcsError(bcs::Error::Custom(
                            "Failed to deserialize presign output".to_string(),
                        ))
                    })? {
                        VersionedPresignOutput::V1(presign) => {
                            let dkg_output = bcs::from_bytes(dwallet_decentralized_public_output)
                                .map_err(|_| {
                                DwalletMPCError::BcsError(bcs::Error::Custom(
                                    "Failed to deserialize decentralized DKG versioned output v1"
                                        .to_string(),
                                ))
                            })?;

                            let centralized_signed_message =
                                bcs::from_bytes(message_centralized_signature).map_err(|_| {
                                    DwalletMPCError::BcsError(bcs::Error::Custom(
                                        "Failed to deserialize centralized signed message"
                                            .to_string(),
                                    ))
                                })?;

                            let decentralized_dkg_output = match dkg_output {
                                VersionedDwalletDKGPublicOutput::V1(output) => {
                                    bcs::from_bytes::<<Secp256k1AsyncDKGProtocol as dkg::Protocol>::DecentralizedPartyTargetedDKGOutput>(output.as_slice()).map_err(
                                        |_| DwalletMPCError::BcsError(bcs::Error::Custom(
                                            "Failed to deserialize decentralized DKG output V1"
                                                .to_string(),
                                        )),
                                    )?.into()
                                }
                                VersionedDwalletDKGPublicOutput::V2{dkg_output, ..} => {
                                    bcs::from_bytes::<<Secp256k1AsyncDKGProtocol as dkg::Protocol>::DecentralizedPartyDKGOutput>(dkg_output.as_slice()).map_err(
                                        |_| DwalletMPCError::BcsError(bcs::Error::Custom(
                                            "Failed to deserialize decentralized DKG output V2"
                                                .to_string(),
                                        ))
                                    )?
                                }
                            };

                            let VersionedUserSignedMessage::V1(centralized_signed_message) =
                                centralized_signed_message;

                            let presign: twopc_mpc::ecdsa::presign::Presign<
                                group::secp256k1::group_element::Value,
                                group::Value<
                                    CiphertextSpaceGroupElement<
                                        { NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                                    >,
                                >,
                            > = bcs::from_bytes(&presign).map_err(|_| {
                                DwalletMPCError::BcsError(bcs::Error::Custom(
                                    "Failed to deserialize presign V1".to_string(),
                                ))
                            })?;

                            let sign_message = bcs::from_bytes::<
                                <Secp256k1ECDSAProtocol as twopc_mpc::sign::Protocol>::SignMessage,
                            >(
                                &centralized_signed_message
                            )
                            .map_err(|_| {
                                DwalletMPCError::BcsError(bcs::Error::Custom(
                                    "Failed to deserialize sign message".to_string(),
                                ))
                            })?;
                            <Secp256k1ECDSAProtocol as SignProtocolExt>::build_sign_public_input(
                                expected_decrypters,
                                protocol_public_parameters,
                                message,
                                hash_scheme,
                                decentralized_dkg_output,
                                presign.into(),
                                UpstreamSignData::Unverified(sign_message),
                                decryption_pp,
                            )
                        }
                        VersionedPresignOutput::V2(_) => {
                            generate_sign_public_input::<Secp256k1ECDSAProtocol>(
                                protocol_public_parameters,
                                dwallet_decentralized_public_output,
                                message,
                                presign,
                                message_centralized_signature,
                                decryption_pp,
                                expected_decrypters,
                                hash_scheme,
                            )?
                        }
                    },
                ))
            }
            DWalletSignatureAlgorithm::Taproot => {
                let decryption_pp = network_encryption_key_public_data
                    .secp256k1_decryption_key_share_public_parameters();
                let protocol_public_parameters =
                    network_encryption_key_public_data.secp256k1_protocol_public_parameters();

                let public_input = generate_sign_public_input::<Secp256k1TaprootProtocol>(
                    protocol_public_parameters,
                    dwallet_decentralized_public_output,
                    message,
                    presign,
                    message_centralized_signature,
                    decryption_pp,
                    expected_decrypters,
                    hash_scheme,
                )?;

                Ok(SignPublicInputByProtocol::Secp256k1Taproot(public_input))
            }
            DWalletSignatureAlgorithm::SchnorrkelSubstrate => {
                let decryption_pp = network_encryption_key_public_data
                    .ristretto_decryption_key_share_public_parameters();
                let protocol_public_parameters =
                    network_encryption_key_public_data.ristretto_protocol_public_parameters();

                let public_input =
                    generate_sign_public_input::<RistrettoSchnorrkelSubstrateProtocol>(
                        protocol_public_parameters,
                        dwallet_decentralized_public_output,
                        message,
                        presign,
                        message_centralized_signature,
                        decryption_pp,
                        expected_decrypters,
                        hash_scheme,
                    )?;

                Ok(SignPublicInputByProtocol::Ristretto(public_input))
            }
            DWalletSignatureAlgorithm::EdDSA => {
                let decryption_pp = network_encryption_key_public_data
                    .curve25519_decryption_key_share_public_parameters();
                let protocol_public_parameters =
                    network_encryption_key_public_data.curve25519_protocol_public_parameters();

                let public_input = generate_sign_public_input::<Curve25519EdDSAProtocol>(
                    protocol_public_parameters,
                    dwallet_decentralized_public_output,
                    message,
                    presign,
                    message_centralized_signature,
                    decryption_pp,
                    expected_decrypters,
                    hash_scheme,
                )?;

                Ok(SignPublicInputByProtocol::Curve25519(public_input))
            }
            DWalletSignatureAlgorithm::ECDSASecp256r1 => {
                let decryption_pp = network_encryption_key_public_data
                    .secp256r1_decryption_key_share_public_parameters();
                let protocol_public_parameters =
                    network_encryption_key_public_data.secp256r1_protocol_public_parameters();

                let public_input = generate_sign_public_input::<Secp256r1ECDSAProtocol>(
                    protocol_public_parameters,
                    dwallet_decentralized_public_output,
                    message,
                    presign,
                    message_centralized_signature,
                    decryption_pp,
                    expected_decrypters,
                    hash_scheme,
                )?;

                Ok(SignPublicInputByProtocol::Secp256r1(public_input))
            }
        }
    }
}

impl DKGAndSignPublicInputByProtocol {
    pub(crate) fn try_new(
        session_identifier: SessionIdentifier,
        dwallet_dkg_public_input: DWalletDKGPublicInputByCurve,
        message: Vec<u8>,
        presign: &SerializedWrappedMPCPublicOutput,
        message_centralized_signature: &SerializedWrappedMPCPublicOutput,
        hash_scheme: HashScheme,
        access_structure: &WeightedThresholdAccessStructure,
        network_encryption_key_public_data: &NetworkEncryptionKeyPublicData,
        protocol: DWalletSignatureAlgorithm,
    ) -> DwalletMPCResult<Self> {
        let expected_decrypters =
            generate_expected_decrypters(access_structure, session_identifier)?;
        match protocol {
            DWalletSignatureAlgorithm::ECDSASecp256k1 => {
                let decryption_pp = network_encryption_key_public_data
                    .secp256k1_decryption_key_share_public_parameters();
                let protocol_public_parameters =
                    network_encryption_key_public_data.secp256k1_protocol_public_parameters();

                let DWalletDKGPublicInputByCurve::Secp256k1DWalletDKG(public_input) =
                    dwallet_dkg_public_input
                else {
                    unreachable!("Curve and DKG public input type mismatch");
                };

                Ok(DKGAndSignPublicInputByProtocol::Secp256k1ECDSA(
                    generate_dkg_and_sign_public_input::<Secp256k1ECDSAProtocol>(
                        protocol_public_parameters,
                        public_input,
                        message,
                        presign,
                        message_centralized_signature,
                        decryption_pp,
                        expected_decrypters,
                        hash_scheme,
                    )?,
                ))
            }
            DWalletSignatureAlgorithm::Taproot => {
                let decryption_pp = network_encryption_key_public_data
                    .secp256k1_decryption_key_share_public_parameters();
                let protocol_public_parameters =
                    network_encryption_key_public_data.secp256k1_protocol_public_parameters();
                let DWalletDKGPublicInputByCurve::Secp256k1DWalletDKG(public_input) =
                    dwallet_dkg_public_input
                else {
                    unreachable!("Curve and DKG public input type mismatch ");
                };

                let public_input = generate_dkg_and_sign_public_input::<Secp256k1TaprootProtocol>(
                    protocol_public_parameters,
                    public_input,
                    message,
                    presign,
                    message_centralized_signature,
                    decryption_pp,
                    expected_decrypters,
                    hash_scheme,
                )?;

                Ok(DKGAndSignPublicInputByProtocol::Secp256k1Taproot(
                    public_input,
                ))
            }
            DWalletSignatureAlgorithm::SchnorrkelSubstrate => {
                let decryption_pp = network_encryption_key_public_data
                    .ristretto_decryption_key_share_public_parameters();
                let protocol_public_parameters =
                    network_encryption_key_public_data.ristretto_protocol_public_parameters();
                let DWalletDKGPublicInputByCurve::RistrettoDWalletDKG(public_input) =
                    dwallet_dkg_public_input
                else {
                    unreachable!("Curve and DKG public input type mismatch ");
                };

                let public_input =
                    generate_dkg_and_sign_public_input::<RistrettoSchnorrkelSubstrateProtocol>(
                        protocol_public_parameters,
                        public_input,
                        message,
                        presign,
                        message_centralized_signature,
                        decryption_pp,
                        expected_decrypters,
                        hash_scheme,
                    )?;

                Ok(DKGAndSignPublicInputByProtocol::Ristretto(public_input))
            }
            DWalletSignatureAlgorithm::EdDSA => {
                let decryption_pp = network_encryption_key_public_data
                    .curve25519_decryption_key_share_public_parameters();
                let protocol_public_parameters =
                    network_encryption_key_public_data.curve25519_protocol_public_parameters();
                let DWalletDKGPublicInputByCurve::Curve25519DWalletDKG(public_input) =
                    dwallet_dkg_public_input
                else {
                    unreachable!("Curve and DKG public input type mismatch ");
                };

                let public_input = generate_dkg_and_sign_public_input::<Curve25519EdDSAProtocol>(
                    protocol_public_parameters,
                    public_input,
                    message,
                    presign,
                    message_centralized_signature,
                    decryption_pp,
                    expected_decrypters,
                    hash_scheme,
                )?;

                Ok(DKGAndSignPublicInputByProtocol::Curve25519(public_input))
            }
            DWalletSignatureAlgorithm::ECDSASecp256r1 => {
                let decryption_pp = network_encryption_key_public_data
                    .secp256r1_decryption_key_share_public_parameters();
                let protocol_public_parameters =
                    network_encryption_key_public_data.secp256r1_protocol_public_parameters();
                let DWalletDKGPublicInputByCurve::Secp256r1DWalletDKG(public_input) =
                    dwallet_dkg_public_input
                else {
                    unreachable!("Curve and DKG public input type mismatch ");
                };

                let public_input = generate_dkg_and_sign_public_input::<Secp256r1ECDSAProtocol>(
                    protocol_public_parameters,
                    public_input,
                    message,
                    presign,
                    message_centralized_signature,
                    decryption_pp,
                    expected_decrypters,
                    hash_scheme,
                )?;

                Ok(DKGAndSignPublicInputByProtocol::Secp256r1(public_input))
            }
        }
    }
}

fn generate_sign_public_input<P: SignProtocolExt>(
    protocol_public_parameters: Arc<
        <P::DKGProtocol as twopc_mpc::dkg::Protocol>::ProtocolPublicParameters,
    >,
    dwallet_decentralized_public_output: &SerializedWrappedMPCPublicOutput,
    message: Vec<u8>,
    presign: &SerializedWrappedMPCPublicOutput,
    message_centralized_signature: &SerializedWrappedMPCPublicOutput,
    decryption_pp: Arc<P::DecryptionKeySharePublicParameters>,
    expected_decrypters: HashSet<PartyID>,
    hash_scheme: HashScheme,
) -> DwalletMPCResult<<SignParty<P> as Party>::PublicInput> {
    let presign_bytes = match bcs::from_bytes(presign).map_err(|e| {
        DwalletMPCError::BcsError(bcs::Error::Custom(format!(
            "Failed to deserialize presign output: {e}"
        )))
    })? {
        VersionedPresignOutput::V1(_) => {
            unreachable!("Presign V1 should have been handled separately")
        }
        VersionedPresignOutput::V2(p) => p,
    };

    let dkg_output_bytes = bcs::from_bytes(dwallet_decentralized_public_output).map_err(|e| {
        DwalletMPCError::BcsError(bcs::Error::Custom(format!(
            "Failed to deserialize decentralized DKG versioned output: {e}"
        )))
    })?;

    let decentralized_dkg_output = match dkg_output_bytes {
        VersionedDwalletDKGPublicOutput::V1(output) => bcs::from_bytes::<
            <P::DKGProtocol as twopc_mpc::dkg::Protocol>::DecentralizedPartyTargetedDKGOutput,
        >(output.as_slice())
        .map_err(|e| {
            DwalletMPCError::BcsError(bcs::Error::Custom(format!(
                "Failed to deserialize decentralized DKG output V1: {e}"
            )))
        })?
        .into(),
        VersionedDwalletDKGPublicOutput::V2 { dkg_output, .. } => bcs::from_bytes::<
            <P::DKGProtocol as twopc_mpc::dkg::Protocol>::DecentralizedPartyDKGOutput,
        >(dkg_output.as_slice())
        .map_err(|e| {
            DwalletMPCError::BcsError(bcs::Error::Custom(format!(
                "Failed to deserialize presign: {e}"
            )))
        })?,
    };

    let presign_value: <P as twopc_mpc::presign::Protocol>::Presign =
        bcs::from_bytes(&presign_bytes).map_err(|e| {
            DwalletMPCError::BcsError(bcs::Error::Custom(format!(
                "Failed to deserialize presign: {e}"
            )))
        })?;

    // Phase 9 + Phase 4f: empty `message_centralized_signature` means NOA — no centralized
    // party participated; dispatch SignData::ToBeEmulated so the upstream protocol emulates
    // the partial signature internally (in Rayon, not synchronously off-Rayon as ika's
    // deleted emulator did). Otherwise this is user-driven sign — wrap as Unverified.
    let sign_data: UpstreamSignData<
        <P as twopc_mpc::sign::Protocol>::SignMessage,
        <P as twopc_mpc::sign::Protocol>::VerifiedSignData,
    > = if message_centralized_signature.is_empty() {
        UpstreamSignData::ToBeEmulated
    } else {
        let centralized_signed_message =
            bcs::from_bytes(message_centralized_signature).map_err(|e| {
                DwalletMPCError::BcsError(bcs::Error::Custom(format!(
                    "Failed to deserialize centralized signed message: {e}"
                )))
            })?;
        let VersionedUserSignedMessage::V1(centralized_signed_message) = centralized_signed_message;
        let sign_message: <P as twopc_mpc::sign::Protocol>::SignMessage =
            bcs::from_bytes(&centralized_signed_message).map_err(|e| {
                DwalletMPCError::BcsError(bcs::Error::Custom(format!(
                    "Failed to deserialize sign message: {e}"
                )))
            })?;
        UpstreamSignData::Unverified(sign_message)
    };

    Ok(P::build_sign_public_input(
        expected_decrypters,
        protocol_public_parameters,
        message,
        hash_scheme,
        decentralized_dkg_output,
        presign_value,
        sign_data,
        decryption_pp,
    ))
}

fn generate_dkg_and_sign_public_input<P: SignProtocolExt>(
    protocol_public_parameters: Arc<
        <P::DKGProtocol as twopc_mpc::dkg::Protocol>::ProtocolPublicParameters,
    >,
    dwallet_dkg_public_input: <P::DKGProtocol as twopc_mpc::dkg::Protocol>::DKGDecentralizedPartyPublicInput,
    message: Vec<u8>,
    presign: &SerializedWrappedMPCPublicOutput,
    message_centralized_signature: &SerializedWrappedMPCPublicOutput,
    decryption_pp: Arc<P::DecryptionKeySharePublicParameters>,
    expected_decrypters: HashSet<PartyID>,
    hash_scheme: HashScheme,
) -> DwalletMPCResult<<DKGAndSignParty<P> as Party>::PublicInput> {
    let presign_bytes = match bcs::from_bytes(presign)? {
        VersionedPresignOutput::V1(_) => {
            unreachable!("Presign V1 should have been handled separately")
        }
        VersionedPresignOutput::V2(p) => p,
    };

    let centralized_signed_message = bcs::from_bytes(message_centralized_signature)?;
    let VersionedUserSignedMessage::V1(centralized_signed_message) = centralized_signed_message;

    let presign_value: <P as twopc_mpc::presign::Protocol>::Presign =
        bcs::from_bytes(&presign_bytes)?;
    let sign_message: <P as twopc_mpc::sign::Protocol>::SignMessage =
        bcs::from_bytes(&centralized_signed_message)?;

    Ok(P::build_dkg_and_sign_public_input(
        expected_decrypters,
        protocol_public_parameters,
        message,
        hash_scheme,
        dwallet_dkg_public_input,
        presign_value,
        UpstreamSignData::Unverified(sign_message),
        decryption_pp,
    ))
}

/// Update metrics on whether we are in the expected or unexpected case during threshold decryption.
/// The unexpected case is slower, but still completes successfully - we want to tune the system such that
/// there will be as little unexpected cases with minimum  delay, which makes reporting these metrics useful.
pub(crate) fn update_expected_decrypters_metrics(
    expected_decrypters: &HashSet<PartyID>,
    decrypters: HashSet<PartyID>,
    access_structure: &WeightedThresholdAccessStructure,
    dwallet_mpc_metrics: Arc<DWalletMPCMetrics>,
) {
    let participating_expected_decrypters: HashSet<PartyID> = expected_decrypters
        .iter()
        .filter(|party_id| decrypters.contains(*party_id))
        .copied()
        .collect();

    if access_structure
        .is_authorized_subset(&participating_expected_decrypters)
        .is_ok()
    {
        dwallet_mpc_metrics.number_of_expected_sign_sessions.inc();
    } else {
        dwallet_mpc_metrics.number_of_unexpected_sign_sessions.inc();
    }
}

/// Verifies that a single partial signature — i.e., a message that has only been signed by the
/// client side in the 2PC-MPC protocol — is valid regarding the given dWallet DKG output.
/// Returns Ok if the message is valid, Err otherwise.
pub(crate) fn verify_partial_signature<P: sign::Protocol>(
    message: &[u8],
    hash_scheme: &HashScheme,
    dwallet_decentralized_output: &SerializedWrappedMPCPublicOutput,
    presign: &SerializedWrappedMPCPublicOutput,
    partially_signed_message: &SerializedWrappedMPCPublicOutput,
    protocol_public_parameters: &<P::DKGProtocol as twopc_mpc::dkg::Protocol>::ProtocolPublicParameters,
) -> DwalletMPCResult<()> {
    let presign = match bcs::from_bytes::<VersionedPresignOutput>(presign)? {
        VersionedPresignOutput::V1(_) => {
            unreachable!("Presign V1 should have been handled separately")
        }
        VersionedPresignOutput::V2(presign) => presign,
    };
    let dkg_output: VersionedDwalletDKGPublicOutput =
        bcs::from_bytes(dwallet_decentralized_output)?;
    let partially_signed_message: VersionedUserSignedMessage =
        bcs::from_bytes(partially_signed_message)?;
    let decentralized_dkg_output = match dkg_output {
        VersionedDwalletDKGPublicOutput::V1(output) => bcs::from_bytes::<
            <P::DKGProtocol as twopc_mpc::dkg::Protocol>::DecentralizedPartyTargetedDKGOutput,
        >(output.as_slice())?
        .into(),
        VersionedDwalletDKGPublicOutput::V2 { dkg_output, .. } => bcs::from_bytes::<
            <P::DKGProtocol as twopc_mpc::dkg::Protocol>::DecentralizedPartyDKGOutput,
        >(dkg_output.as_slice())?,
    };

    let presign: <P as twopc_mpc::presign::Protocol>::Presign = bcs::from_bytes(&presign)?;
    let VersionedUserSignedMessage::V1(partially_signed_message) = partially_signed_message;
    let partial: <P as twopc_mpc::sign::Protocol>::SignMessage =
        bcs::from_bytes(&partially_signed_message)?;

    // Phase 4e: capture VerifiedSignData (upstream return type changed Result<()> →
    // Result<P::VerifiedSignData>) but discard for now; verifier-only call site. A follow-up
    // PR can surface it on this function's return signature so callers can pass
    // SignData::Verified(...) into the next sign-public-input construction (skipping
    // re-verification and shrinking wire size — see plan §4e).
    let _verified: <P as sign::Protocol>::VerifiedSignData =
        <P as sign::Protocol>::verify_centralized_party_partial_signature(
            message,
            *hash_scheme,
            decentralized_dkg_output,
            presign,
            partial,
            protocol_public_parameters,
            &mut OsCsRng,
        )
        .map_err(DwalletMPCError::from)?;
    Ok(())
}

pub fn compute_sign<P: twopc_mpc::sign::Protocol>(
    party_id: PartyID,
    access_structure: &WeightedThresholdAccessStructure,
    session_id: CommitmentSizedNumber,
    advance_request: AdvanceRequest<<SignParty<P> as mpc::Party>::Message>,
    public_input: <SignParty<P> as mpc::Party>::PublicInput,
    decryption_key_shares: Option<<SignParty<P> as AsynchronouslyAdvanceable>::PrivateInput>,
    sign_data: &SignData,
    rng: &mut impl CsRng,
) -> DwalletMPCResult<GuaranteedOutputDeliveryRoundResult> {
    let result =
        mpc::guaranteed_output_delivery::Party::<SignParty<P>>::advance_with_guaranteed_output(
            session_id,
            party_id,
            access_structure,
            advance_request,
            decryption_key_shares,
            &public_input,
            rng,
        )
        .map_err(|e| DwalletMPCError::FailedToAdvanceMPC(e.into()))?;

    match result {
        GuaranteedOutputDeliveryRoundResult::Advance { message } => {
            Ok(GuaranteedOutputDeliveryRoundResult::Advance { message })
        }
        GuaranteedOutputDeliveryRoundResult::Finalize {
            public_output_value,
            malicious_parties,
            private_output,
        } => {
            let signature = match parse_signature_from_sign_output(
                &sign_data.signature_algorithm,
                public_output_value,
            ) {
                Ok(signature) => Ok(signature),
                Err(e) => {
                    error!(
                        session_identifier=?session_id,
                        ?e,
                        ?malicious_parties,
                        signature_algorithm=?sign_data.signature_algorithm,
                        should_never_happen = true,
                        "failed to deserialize sign session result "
                    );

                    Err(e)
                }
            }?;

            // For Sign protocol, we don't need to wrap the output with version like presign does
            // since the output is already in the correct format
            Ok(GuaranteedOutputDeliveryRoundResult::Finalize {
                public_output_value: signature,
                malicious_parties,
                private_output,
            })
        }
    }
}

pub fn compute_dwallet_dkg_and_sign<P: twopc_mpc::sign::Protocol>(
    curve: DWalletCurve,
    party_id: PartyID,
    access_structure: &WeightedThresholdAccessStructure,
    session_id: CommitmentSizedNumber,
    advance_request: AdvanceRequest<<DKGAndSignParty<P> as mpc::Party>::Message>,
    public_input: <DKGAndSignParty<P> as mpc::Party>::PublicInput,
    decryption_key_shares: Option<<DKGAndSignParty<P> as AsynchronouslyAdvanceable>::PrivateInput>,
    signature_algorithm: &DWalletSignatureAlgorithm,
    rng: &mut impl CsRng,
) -> DwalletMPCResult<GuaranteedOutputDeliveryRoundResult> {
    let result =
        mpc::guaranteed_output_delivery::Party::<DKGAndSignParty<P>>::advance_with_guaranteed_output(
            session_id,
            party_id,
            access_structure,
            advance_request,
            decryption_key_shares,
            &public_input,
            rng,
        )
        .map_err(|e| DwalletMPCError::FailedToAdvanceMPC(e.into()))?;

    match result {
        GuaranteedOutputDeliveryRoundResult::Advance { message } => {
            Ok(GuaranteedOutputDeliveryRoundResult::Advance { message })
        }
        GuaranteedOutputDeliveryRoundResult::Finalize {
            public_output_value,
            malicious_parties,
            private_output,
        } => {
            let (dwallet_dkg_output, signature_output): <P::DKGSignDecentralizedParty as mpc::Party>::PublicOutput = bcs::from_bytes(&public_output_value)?;

            let signature = match parse_signature_from_sign_output(
                signature_algorithm,
                bcs::to_bytes(&signature_output)?,
            ) {
                Ok(signature) => Ok(signature),
                Err(e) => {
                    error!(
                        session_identifier=?session_id,
                        ?e,
                        ?malicious_parties,
                        ?signature_algorithm,
                        should_never_happen = true,
                        "failed to deserialize sign session result "
                    );

                    Err(e)
                }
            }?;

            let dwallet_dkg_output = bcs::to_bytes(&dwallet_dkg_output)?;
            let public_key_bytes =
                public_key_from_decentralized_dkg_output_by_curve_v2(curve, &dwallet_dkg_output)
                    .map_err(|e| DwalletMPCError::InternalError(e.to_string()))?;
            let dkg_public_output_value = bcs::to_bytes(&VersionedDwalletDKGPublicOutput::V2 {
                public_key_bytes,
                dkg_output: dwallet_dkg_output,
            })?;

            Ok(GuaranteedOutputDeliveryRoundResult::Finalize {
                public_output_value: bcs::to_bytes(&(
                    dkg_public_output_value,
                    // For Sign protocol, we don't need to wrap the output with version like presign does
                    // since the output is a standardized signature
                    signature,
                ))?,
                malicious_parties,
                private_output,
            })
        }
    }
}

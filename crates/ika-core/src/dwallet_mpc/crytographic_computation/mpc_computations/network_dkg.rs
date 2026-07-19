// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! This module contains the network DKG protocol for the dWallet MPC sessions.
//! The network DKG protocol handles generating the network Decryption-Key shares.
//! The module provides the management of the network Decryption-Key shares and
//! the network DKG protocol.

use crate::dwallet_mpc::crytographic_computation::mpc_computations::network_owned_address_sign_dkg_emulation::compute_noa_dkg;
use crate::dwallet_mpc::crytographic_computation::protocol_public_parameters::ProtocolPublicParametersByCurve;
use crate::dwallet_mpc::dwallet_mpc_metrics::DWalletMPCMetrics;
use crate::dwallet_mpc::reconfiguration::instantiate_dwallet_mpc_network_encryption_key_public_data_from_reconfiguration_public_output;
use class_groups::SecretKeyShareSizedInteger;
use commitment::CommitmentSizedNumber;
use dwallet_classgroups_types::{
    ClassGroupsDecryptionKey, RistrettoPvssDecryptionKey, Secp256k1PvssDecryptionKey,
};
use dwallet_mpc_centralized_party::{
    network_dkg_public_output_to_protocol_pp_inner,
    reconfiguration_public_output_to_protocol_pp_inner,
};
use dwallet_mpc_types::dwallet_mpc::{
    DWalletCurve, NetworkDecryptionKeyPublicOutputType, NetworkEncryptionKeyPublicData,
    NetworkKeyId, SerializedWrappedMPCPublicOutput, VersionedDecryptionKeyReconfigurationOutput,
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
use std::time::Instant;
use sui_types::base_types::ObjectID;
use tokio::sync::oneshot;
use tracing::{error, info};
use twopc_mpc::decentralized_party::dkg;
use twopc_mpc::decentralized_party_backward_compatible::dkg as bwd_compat_dkg;

/// Holds the network (decryption) keys of the network MPC protocols.
pub struct DwalletMPCNetworkKeys {
    /// Holds all network (decryption) keys for the current network in encrypted form.
    /// This data is identical for all the Validator nodes.
    pub(crate) network_encryption_keys: HashMap<ObjectID, NetworkEncryptionKeyPublicData>,
    pub(crate) validator_private_dec_key_data: ValidatorPrivateDecryptionKeyData,
}

/// SECRET. Validator's own PVSS HPKE decryption keys (secp256k1 + ristretto)
/// used by `compute_*_shamir_shares_of_secret_key_share_parts` at network-key
/// ingestion. secp256r1 PVSS isn't used by VSS at all; the Curve25519 `EdDSA`
/// VSS curve also decrypts off the *ristretto* PVSS key (same
/// `RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS`).
///
/// Holds only secret material — the matching public encryption keys live
/// alongside in [`ValidatorPvssEncryptionKeysForVss`].
#[derive(Clone, Debug)]
pub struct ValidatorPvssSecretsForVss {
    pub secp256k1_decryption_key: Secp256k1PvssDecryptionKey,
    pub ristretto_decryption_key: RistrettoPvssDecryptionKey,
}

/// Validator's own PVSS HPKE encryption keys (public). Co-input to the
/// `compute_*_shamir_shares_of_secret_key_share_parts` derivation alongside
/// [`ValidatorPvssSecretsForVss`]; kept separate from the secrets so this
/// struct (public) doesn't share a type with the secret one.
#[derive(Clone, Debug)]
pub struct ValidatorPvssEncryptionKeysForVss {
    pub secp256k1_encryption_key: class_groups::CompactIbqf<
        { twopc_mpc::secp256k1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
    >,
    pub ristretto_encryption_key: class_groups::CompactIbqf<
        { twopc_mpc::ristretto::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
    >,
}

/// Pre-derived Fast Schnorr (VSS) Shamir shares + secret-key polynomial
/// commitments for the secp256k1 curve, computed once per network key at
/// ingestion (`decrypt_and_store_secret_key_shares`) and consumed verbatim by
/// VSS sign without any per-sign re-derivation.
#[derive(Clone, Debug)]
pub struct VssSecp256k1ShamirCache {
    pub secret_key_share_first_part: group::Value<group::secp256k1::Scalar>,
    pub secret_key_share_second_part: group::Value<group::secp256k1::Scalar>,
    pub first_secret_key_polynomial_commitments: Vec<group::Value<group::secp256k1::GroupElement>>,
    pub second_secret_key_polynomial_commitments: Vec<group::Value<group::secp256k1::GroupElement>>,
}

#[derive(Clone, Debug)]
pub struct VssCurve25519ShamirCache {
    pub secret_key_share_first_part: group::Value<group::curve25519::Scalar>,
    pub secret_key_share_second_part: group::Value<group::curve25519::Scalar>,
    pub first_secret_key_polynomial_commitments: Vec<group::Value<group::curve25519::GroupElement>>,
    pub second_secret_key_polynomial_commitments:
        Vec<group::Value<group::curve25519::GroupElement>>,
}

#[derive(Clone, Debug)]
pub struct VssRistrettoShamirCache {
    pub secret_key_share_first_part: group::Value<group::ristretto::Scalar>,
    pub secret_key_share_second_part: group::Value<group::ristretto::Scalar>,
    pub first_secret_key_polynomial_commitments: Vec<group::Value<group::ristretto::GroupElement>>,
    pub second_secret_key_polynomial_commitments: Vec<group::Value<group::ristretto::GroupElement>>,
}

/// Per-network-key Fast Schnorr (VSS) Shamir-share cache, all three curves.
///
/// Computed once at network-key ingestion via
/// [`ValidatorPrivateDecryptionKeyData::decrypt_and_store_secret_key_shares`];
/// VSS sign reads from here at compute time without re-deserializing the DKG /
/// reconfiguration output and without redoing the Shamir derivation.
///
/// All three curves are populated atomically — they all derive from the same
/// (V3) DKG / reconfiguration output.
#[derive(Clone, Debug)]
pub struct VssShamirCachePerKey {
    /// The epoch of the key data this cache was derived from. The cache map
    /// is keyed by ObjectID only, so across an epoch switch a stale entry
    /// (previous epoch's shares) sits under the current key id until this
    /// validator's re-derivation lands; readers must treat an epoch mismatch
    /// exactly like a missing entry (see `vss_shamir_cache`), or VSS
    /// computations mix the new epoch's public parameters with the old
    /// epoch's shares and fail round one with `InvalidParameters`.
    pub derived_for_epoch: u64,
    pub secp256k1: VssSecp256k1ShamirCache,
    pub curve25519: VssCurve25519ShamirCache,
    pub ristretto: VssRistrettoShamirCache,
}

/// The stored outcome of a VSS Shamir-cache derivation for one network key.
/// Storing the outcome (not only successes) lets the VSS sign path tell
/// "still coming" (park and retry) from "will never come" (fail, traceably)
/// instead of collapsing all three to a bare missing entry.
///
/// EVERY variant carries the epoch of the key data it was derived from, and
/// the accessor treats an epoch mismatch exactly like a missing entry — the
/// terminal variants included. A terminal entry derived from a PREVIOUS view
/// of the key (e.g. the boundary window where the first ingest carried the
/// pre-V3 key view and the fresh V3 re-derivation is still running on rayon)
/// is "re-derivation in flight", not "will never come"; without the epoch
/// tag a consumer trusting the terminal/transient distinction would drop out
/// of VSS signing for the whole re-derivation window while its peers sign.
#[derive(Clone, Debug)]
pub enum VssCacheEntry {
    /// The three-curve cache derived successfully (carries its epoch as
    /// `VssShamirCachePerKey::derived_for_epoch`). Boxed: it dwarfs the
    /// other variants, so an unboxed enum would carry that size everywhere.
    Derived(Box<VssShamirCachePerKey>),
    /// The key data had no V3 DKG / reconfiguration output, so VSS material
    /// does not exist for it (a pre-V3 key). Terminal FOR THAT KEY-DATA
    /// EPOCH, not a transient wait.
    NotApplicable { derived_for_epoch: u64 },
    /// A real deserialization / derivation failure (logged once at
    /// insertion). Terminal for that key-data epoch; the operator has an
    /// `error!` line to act on.
    Failed { derived_for_epoch: u64 },
}

/// Holds the private decryption key data for a validator node.
pub struct ValidatorPrivateDecryptionKeyData {
    /// The unique party ID of the validator, representing its index within the committee.
    pub party_id: PartyID,

    /// The validator's class groups decryption key.
    pub class_groups_decryption_key: ClassGroupsDecryptionKey,

    /// Validator-private PVSS HPKE secret decryption keys (secp256k1 +
    /// ristretto). Used at network-key ingestion to pre-derive the Fast
    /// Schnorr (VSS) Shamir shares; paired with `validator_pvss_publics_for_vss`
    /// (the matching public encryption keys). Always derived from this
    /// validator's `RootSeed` at startup. The VSS HPKE curve25519 **secret**
    /// key isn't here — it's needed only at the presign hot path and is
    /// cached on `CryptographicComputationsOrchestrator`.
    pub validator_pvss_secrets_for_vss: ValidatorPvssSecretsForVss,

    /// Public counterpart of [`Self::validator_pvss_secrets_for_vss`]: this
    /// validator's own PVSS encryption keys (per curve). Kept separate from
    /// the secrets struct so the secret type never shares a struct with
    /// public material.
    pub validator_pvss_publics_for_vss: ValidatorPvssEncryptionKeysForVss,

    /// A map of the validator's decryption key shares.
    ///
    /// This structure maps each key ID (`ObjectID`) to a sub-map of `PartyID`
    /// to the corresponding decryption key share.
    /// These shares are used in multi-party cryptographic protocols.
    /// NOTE: EACH PARTY IN HERE IS A **VIRTUAL PARTY**.
    /// NOTE 2: `ObjectID` is the ID of the network decryption key, not the party.
    pub validator_decryption_key_shares:
        HashMap<ObjectID, HashMap<PartyID, SecretKeyShareSizedInteger>>,

    /// Per-network-key Fast Schnorr (VSS) Shamir-share + polynomial-commitments
    /// cache outcome, populated alongside `validator_decryption_key_shares`
    /// from the same network DKG / reconfiguration output. Stores the
    /// derivation OUTCOME per key (`Derived`/`NotApplicable`/`Failed`), not
    /// only successes, so the VSS sign path distinguishes a still-running
    /// derivation (absent entry → park) from a completed-but-unusable one
    /// (`NotApplicable`/`Failed` → terminal). Read verbatim by VSS sign (no
    /// per-sign re-derivation).
    pub validator_vss_shamir_cache: HashMap<ObjectID, VssCacheEntry>,
}

async fn get_decryption_key_shares_from_public_output(
    shares: NetworkEncryptionKeyPublicData,
    party_id: PartyID,
    personal_decryption_key: ClassGroupsDecryptionKey,
    access_structure: WeightedThresholdAccessStructure,
) -> DwalletMPCResult<HashMap<PartyID, SecretKeyShareSizedInteger>> {
    let (key_shares_sender, key_shares_receiver) = oneshot::channel();

    // msim: rayon worker threads have no simulated-node context, so capture
    // the originating NodeHandle and enter it before any tracing or tokio
    // call inside the worker.
    #[cfg(msim)]
    let originating_sim_node = sui_simulator::runtime::NodeHandle::try_current();

    rayon::spawn_fifo(move || {
        #[cfg(msim)]
        let _node_guard = originating_sim_node.as_ref().map(|n| n.enter_node());

        let res = match shares.state() {
            NetworkDecryptionKeyPublicOutputType::NetworkDkg => {
                match &shares.network_dkg_output() {
                    VersionedNetworkDkgOutput::V1(_) => Err(DwalletMPCError::InternalError(
                        "V1 network DKG anchors are not supported on the initial-DKG                          instantiation path (deployed keys instantiate from their                          reconfiguration output)."
                            .to_string(),
                    )),
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
                        match bcs::from_bytes::<
                            twopc_mpc::decentralized_party::dkg::NonAggregatedPublicOutput,
                        >(public_output)
                        {
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
                    VersionedNetworkDkgOutput::V4(public_output) => {
                        match bcs::from_bytes::<
                            twopc_mpc::decentralized_party::dkg::PublicOutput,
                        >(public_output)
                        {
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
                        Err(DwalletMPCError::InternalError(
                            "V1 reconfiguration outputs are no longer supported.".to_string(),
                        ))
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
                    VersionedDecryptionKeyReconfigurationOutput::V4(public_output) => {
                        match bcs::from_bytes::<
                            twopc_mpc::decentralized_party::reconfiguration::PublicOutput,
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
    /// from the public output of the network DKG protocol, and ALSO pre-derives
    /// the Fast Schnorr (VSS) Shamir shares + secret-key polynomial commitments
    /// for all three VSS curves from the same output — so the VSS sign hot path
    /// is a cache lookup, not a deserialize-and-derive.
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

        // Pre-derive VSS Shamir shares + commitments at ingestion. The
        // OUTCOME is always recorded (`Derived`/`NotApplicable`/`Failed`),
        // epoch-tagged with the source key data's epoch, so VSS sign sites
        // can tell a still-running derivation (absent/stale entry → wait)
        // from a completed-but-unusable one for the CURRENT key data
        // (terminal → fail traceably).
        //
        // The derivation is heavy class-groups crypto (three curves), so run it
        // off the runtime thread on rayon — mirroring the AHE decrypt above —
        // rather than inline. On a single-threaded runtime an inline run would
        // peg the one thread for the whole derivation, freezing this node's
        // async (including the consensus-commit handler that feeds the MPC
        // engine) at the epoch boundary with cores idle (see issue #1736).
        let (vss_sender, vss_receiver) = oneshot::channel();
        #[cfg(msim)]
        let originating_sim_node = sui_simulator::runtime::NodeHandle::try_current();
        let party_id = self.party_id;
        let secrets = self.validator_pvss_secrets_for_vss.clone();
        let publics = self.validator_pvss_publics_for_vss.clone();
        // The epoch of the key data this derivation reads — tagged onto every
        // outcome variant so the accessor can treat an entry derived from a
        // superseded key view as missing (re-derivation in flight), never as
        // terminal.
        let key_data_epoch = key.epoch();
        rayon::spawn_fifo(move || {
            #[cfg(msim)]
            let _node_guard = originating_sim_node.as_ref().map(|n| n.enter_node());

            let vss_cache = derive_vss_shamir_cache_for_key(&key, party_id, &secrets, &publics);
            if vss_sender.send(vss_cache).is_err() {
                error!("failed to send VSS shamir cache");
            }
        });
        // Always record the outcome (overwriting the previous update's entry —
        // this runs on every network-key update, so a Failed/NotApplicable
        // entry is re-derived and overwritten on the next update of the key).
        // Storing NotApplicable and Failed — not only successes — is what lets
        // the VSS sign path fail fast (traceably) instead of parking forever
        // on a completed-but-unusable derivation.
        let entry = match vss_receiver.await.map_err(|_| DwalletMPCError::TokioRecv)? {
            VssCacheDerivation::Derived(cache) => VssCacheEntry::Derived(cache),
            VssCacheDerivation::NotApplicable => VssCacheEntry::NotApplicable {
                derived_for_epoch: key_data_epoch,
            },
            VssCacheDerivation::Failed(reason) => {
                error!(
                    ?key_id,
                    reason, "VSS Shamir cache derivation failed for network key"
                );
                VssCacheEntry::Failed {
                    derived_for_epoch: key_data_epoch,
                }
            }
        };
        self.validator_vss_shamir_cache.insert(key_id, entry);

        Ok(())
    }
}

/// The outcome of deriving the VSS Shamir cache for one key: distinguishes a
/// genuinely-inapplicable key (pre-V3) from a real derivation failure, so the
/// caller can log the latter and the sign path can fail rather than park
/// forever on either.
enum VssCacheDerivation {
    Derived(Box<VssShamirCachePerKey>),
    NotApplicable,
    Failed(String),
}

/// Pre-derive the Fast Schnorr (VSS) Shamir shares + secret-key polynomial
/// commitments for all three VSS curves from a single network DKG /
/// reconfiguration output. The output is deserialized at most once. Returns
/// `NotApplicable` if the network key has no V3 output (pre-V3), or `Failed`
/// if deserialization / any per-curve derivation fails — the three curves are
/// always populated together.
fn derive_vss_shamir_cache_for_key(
    key: &NetworkEncryptionKeyPublicData,
    party_id: PartyID,
    secrets: &ValidatorPvssSecretsForVss,
    publics: &ValidatorPvssEncryptionKeysForVss,
) -> VssCacheDerivation {
    use twopc_mpc::decentralized_party::{dkg as dec_dkg, reconfiguration as dec_reconf};

    // Share derivation runs on the AGGREGATED output form (a single decryption
    // per curve-part). A V4 output is already aggregated; a V3 (pre-aggregation)
    // output is upgraded first — a local, deterministic per-receiver homomorphic
    // summation, done once per epoch per key on this cache path.
    enum DeserializedSource {
        Reconfiguration(Box<dec_reconf::PublicOutput>),
        NetworkDkg(Box<dec_dkg::PublicOutput>),
    }

    let source: DeserializedSource = match key.latest_network_reconfiguration_public_output() {
        Some(VersionedDecryptionKeyReconfigurationOutput::V3(bytes)) => {
            match bcs::from_bytes::<<dec_reconf::Party as mpc::Party>::PublicOutput>(&bytes)
                .map_err(|e| e.to_string())
                .and_then(|output| output.upgrade().map_err(|e| e.to_string()))
            {
                Ok(output) => DeserializedSource::Reconfiguration(Box::new(output)),
                Err(e) => {
                    return VssCacheDerivation::Failed(format!(
                        "decoding/upgrading the V3 reconfiguration output: {e}"
                    ));
                }
            }
        }
        Some(VersionedDecryptionKeyReconfigurationOutput::V4(bytes)) => {
            match bcs::from_bytes(&bytes) {
                Ok(output) => DeserializedSource::Reconfiguration(Box::new(output)),
                Err(e) => {
                    return VssCacheDerivation::Failed(format!(
                        "decoding the V4 reconfiguration output: {e}"
                    ));
                }
            }
        }
        // Pre-V3 reconfiguration (or none yet) → fall through to network DKG output.
        _ => match key.network_dkg_output() {
            VersionedNetworkDkgOutput::V3(bytes) => {
                match bcs::from_bytes::<dec_dkg::NonAggregatedPublicOutput>(bytes)
                    .map_err(|e| e.to_string())
                    .and_then(|output| output.upgrade().map_err(|e| e.to_string()))
                {
                    Ok(output) => DeserializedSource::NetworkDkg(Box::new(output)),
                    Err(e) => {
                        return VssCacheDerivation::Failed(format!(
                            "decoding/upgrading the V3 network DKG output: {e}"
                        ));
                    }
                }
            }
            VersionedNetworkDkgOutput::V4(bytes) => match bcs::from_bytes(bytes) {
                Ok(output) => DeserializedSource::NetworkDkg(Box::new(output)),
                Err(e) => {
                    return VssCacheDerivation::Failed(format!(
                        "decoding the V4 network DKG output: {e}"
                    ));
                }
            },
            _ => return VssCacheDerivation::NotApplicable,
        },
    };

    let (secp256k1_shares, secp256k1_first_commitments, secp256k1_second_commitments) =
        match &source {
            DeserializedSource::Reconfiguration(o) => (
                o.compute_secp256k1_shamir_shares_of_secret_key_share_parts(
                    party_id,
                    secrets.secp256k1_decryption_key,
                    publics.secp256k1_encryption_key,
                ),
                o.secp256k1_polynomial_commitments().0.clone(),
                o.secp256k1_polynomial_commitments().1.clone(),
            ),
            DeserializedSource::NetworkDkg(o) => (
                o.derive_shamir_shares_of_secp256k1_secret_key_share_parts(
                    party_id,
                    secrets.secp256k1_decryption_key,
                    publics.secp256k1_encryption_key,
                ),
                o.secp256k1_polynomial_commitments().0.clone(),
                o.secp256k1_polynomial_commitments().1.clone(),
            ),
        };
    let (curve25519_shares, curve25519_first_commitments, curve25519_second_commitments) =
        match &source {
            DeserializedSource::Reconfiguration(o) => (
                o.compute_curve25519_shamir_shares_of_secret_key_share_parts(
                    party_id,
                    secrets.ristretto_decryption_key,
                    publics.ristretto_encryption_key,
                ),
                o.curve25519_polynomial_commitments().0.clone(),
                o.curve25519_polynomial_commitments().1.clone(),
            ),
            DeserializedSource::NetworkDkg(o) => (
                o.derive_shamir_shares_of_curve25519_secret_key_share_parts(
                    party_id,
                    secrets.ristretto_decryption_key,
                    publics.ristretto_encryption_key,
                ),
                o.curve25519_polynomial_commitments().0.clone(),
                o.curve25519_polynomial_commitments().1.clone(),
            ),
        };
    let (ristretto_shares, ristretto_first_commitments, ristretto_second_commitments) =
        match &source {
            DeserializedSource::Reconfiguration(o) => (
                o.compute_ristretto_shamir_shares_of_secret_key_share_parts(
                    party_id,
                    secrets.ristretto_decryption_key,
                    publics.ristretto_encryption_key,
                ),
                o.ristretto_polynomial_commitments().0.clone(),
                o.ristretto_polynomial_commitments().1.clone(),
            ),
            DeserializedSource::NetworkDkg(o) => (
                o.derive_shamir_shares_of_ristretto_secret_key_share_parts(
                    party_id,
                    secrets.ristretto_decryption_key,
                    publics.ristretto_encryption_key,
                ),
                o.ristretto_polynomial_commitments().0.clone(),
                o.ristretto_polynomial_commitments().1.clone(),
            ),
        };

    let (secp256k1_first, secp256k1_second) = match secp256k1_shares {
        Ok(shares) => shares,
        Err(e) => {
            return VssCacheDerivation::Failed(format!("secp256k1 Shamir-share derivation: {e:?}"));
        }
    };
    let (curve25519_first, curve25519_second) = match curve25519_shares {
        Ok(shares) => shares,
        Err(e) => {
            return VssCacheDerivation::Failed(format!(
                "curve25519 Shamir-share derivation: {e:?}"
            ));
        }
    };
    let (ristretto_first, ristretto_second) = match ristretto_shares {
        Ok(shares) => shares,
        Err(e) => {
            return VssCacheDerivation::Failed(format!("ristretto Shamir-share derivation: {e:?}"));
        }
    };

    VssCacheDerivation::Derived(Box::new(VssShamirCachePerKey {
        derived_for_epoch: key.epoch(),
        secp256k1: VssSecp256k1ShamirCache {
            secret_key_share_first_part: secp256k1_first,
            secret_key_share_second_part: secp256k1_second,
            first_secret_key_polynomial_commitments: secp256k1_first_commitments,
            second_secret_key_polynomial_commitments: secp256k1_second_commitments,
        },
        curve25519: VssCurve25519ShamirCache {
            secret_key_share_first_part: curve25519_first,
            secret_key_share_second_part: curve25519_second,
            first_secret_key_polynomial_commitments: curve25519_first_commitments,
            second_secret_key_polynomial_commitments: curve25519_second_commitments,
        },
        ristretto: VssRistrettoShamirCache {
            secret_key_share_first_part: ristretto_first,
            secret_key_share_second_part: ristretto_second,
            first_secret_key_polynomial_commitments: ristretto_first_commitments,
            second_secret_key_polynomial_commitments: ristretto_second_commitments,
        },
    }))
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
        // Record the temporary ObjectID <-> NetworkKeyId mapping so the
        // handoff cert (keyed by the content-derived NetworkKeyId) can be
        // built and consumed for this key. The NOA pubkey is already in
        // `key`. TODO(NetworkKeyId-from-event): remove with the mapping
        // once the request event carries the NetworkKeyId directly.
        match key.network_key_id() {
            Ok(network_key_id) => crate::network_key_id_mapping::register(key_id, network_key_id),
            Err(e) => error!(
                ?key_id,
                error = ?e,
                "could not derive NetworkKeyId for the temporary ObjectID mapping"
            ),
        }
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

    /// Retrieves the pre-derived Fast Schnorr (VSS) Shamir-share + commitments
    /// cache for the given network key. Mirrors [`Self::decryption_key_shares`]
    /// for the AHE path: derivation happens once at network-key ingestion
    /// (`decrypt_and_store_secret_key_shares`); VSS sign reads from here.
    pub(crate) fn vss_shamir_cache(
        &self,
        key_id: &ObjectID,
    ) -> DwalletMPCResult<&VssShamirCachePerKey> {
        // Absent entry: derivation hasn't completed yet (still running on
        // rayon) — park and retry, same as the AHE wait path.
        let entry = self
            .validator_private_dec_key_data
            .validator_vss_shamir_cache
            .get(key_id)
            .ok_or(DwalletMPCError::WaitingForNetworkKey(*key_id))?;
        // Staleness FIRST, for EVERY variant: an entry (success or terminal)
        // derived from a superseded view of the key is "re-derivation in
        // flight", not an answer about the current key data. For `Derived`,
        // mixing a previous epoch's shares with the current epoch's public
        // parameters fails MPC round one with `InvalidParameters` (the
        // per-validator epoch-entry failure window of issue #1736: the
        // re-derivation is heavy class-groups work that lands seconds to
        // minutes after the key update). For the terminal variants, the
        // boundary window where the first ingest carried the pre-V3 key view
        // records `NotApplicable` — reporting that as terminal while the
        // fresh V3 re-derivation runs would drop this validator out of every
        // VSS sign for the window. Treat all stale entries exactly like a
        // missing one — park and retry until this validator's re-derivation
        // lands.
        let current_key_epoch = self.get_network_encryption_key_public_data(key_id)?.epoch();
        let derived_for_epoch = match entry {
            VssCacheEntry::Derived(cache) => cache.derived_for_epoch,
            VssCacheEntry::NotApplicable { derived_for_epoch }
            | VssCacheEntry::Failed { derived_for_epoch } => *derived_for_epoch,
        };
        if derived_for_epoch != current_key_epoch {
            return Err(DwalletMPCError::WaitingForNetworkKey(*key_id));
        }
        match entry {
            VssCacheEntry::Derived(cache) => Ok(cache.as_ref()),
            // Completed but unusable FOR THE CURRENT KEY DATA: a pre-V3 key
            // (NotApplicable) or a real derivation failure (Failed, already
            // logged once). This is NOT the not-ready class, so the VSS sign
            // session fails with a named, traceable error instead of parking
            // forever.
            VssCacheEntry::NotApplicable { .. } | VssCacheEntry::Failed { .. } => {
                Err(DwalletMPCError::VssShamirCacheUnavailable(*key_id))
            }
        }
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
/// `network_encryption_key_version() == 2` (protocol_version < 4), i.e. when
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
            // The DKG Party's output IS the primary (aggregated) form — the
            // protocol aggregates at output formation, unconditionally, NOT
            // behind the aggregated-outputs protocol gate that reconfiguration
            // honors: no deployed network ever persisted a pre-aggregation
            // (V3-tagged) fresh network DKG output (the deployed keys carry V1
            // anchors), and no network DKG session runs during the mixed-binary
            // rollout window, so there is no byte-identical-quorum constraint
            // on this producer. Tag the bytes V4 as-is.
            info!(
                session_id=?session_id,
                "persisting aggregated (V4) network DKG output"
            );
            let public_output_value =
                bcs::to_bytes(&VersionedNetworkDkgOutput::V4(public_output_value))?;

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
    // Selects the equality-of-coefficients discrete-log bound: `true` picks the
    // `-10` relaxed (+519) bound the deployed network transcribes, `false` the
    // strict (+529) bound reserved for a future, not-yet-deployed format. Derived
    // from the protocol version (`is_network_encryption_key_version_v3()`) at the
    // call site; TEMPORARY until the network migrates off the relaxed bound.
    backward_compatible: bool,
) -> DwalletMPCResult<<dkg::Party as mpc::Party>::PublicInput> {
    let public_input = <dkg::Party as mpc::Party>::PublicInput::new(
        access_structure,
        encryption_keys_and_proofs,
        secp256k1_pvss_encryption_keys_and_proofs,
        ristretto_pvss_encryption_keys_and_proofs,
        secp256r1_pvss_encryption_keys_and_proofs,
        backward_compatible,
    )
    .map_err(|e| DwalletMPCError::InvalidMPCPartyType(e.to_string()))?;

    Ok(public_input)
}

/// Spawns the network-key public-data instantiation on the rayon pool
/// and returns the receiver for its result WITHOUT awaiting it. The
/// instantiation (per-curve protocol + decryption-key-share public
/// parameters, plus the NOA DKG outputs) is an expensive, long-running
/// class-groups computation; the MPC service loop polls the receiver
/// across ticks so session processing keeps advancing while the key
/// instantiates, instead of freezing the whole validator pipeline for
/// its duration.
pub(crate) fn spawn_network_encryption_key_public_data_instantiation(
    epoch: u64,
    access_structure: WeightedThresholdAccessStructure,
    key_data: DWalletNetworkEncryptionKeyData,
    metrics: Arc<DWalletMPCMetrics>,
) -> oneshot::Receiver<DwalletMPCResult<NetworkEncryptionKeyPublicData>> {
    let (key_public_data_sender, key_public_data_receiver) = oneshot::channel();

    // msim: rayon worker threads have no simulated-node context, so capture
    // the originating NodeHandle and enter it before any tracing or tokio
    // call inside the worker.
    #[cfg(msim)]
    let originating_sim_node = sui_simulator::runtime::NodeHandle::try_current();

    rayon::spawn_fifo(move || {
        #[cfg(msim)]
        let _node_guard = originating_sim_node.as_ref().map(|n| n.enter_node());

        let res = if key_data.current_reconfiguration_public_output.is_empty() {
            if key_data.state == DWalletNetworkEncryptionKeyState::AwaitingNetworkDKG {
                Err(DwalletMPCError::WaitingForNetworkKey(key_data.id))
            } else {
                instantiate_dwallet_mpc_network_encryption_key_public_data_from_dkg_public_output(
                    epoch,
                    key_data.dkg_at_epoch,
                    &access_structure,
                    &key_data.network_dkg_public_output,
                    &metrics,
                )
            }
        } else {
            instantiate_dwallet_mpc_network_encryption_key_public_data_from_reconfiguration_public_output(
                epoch,
                key_data.dkg_at_epoch,
                &access_structure,
                &key_data.current_reconfiguration_public_output,
                &key_data.network_dkg_public_output,
                &metrics,
            )
        };

        if let Err(err) = key_public_data_sender.send(res) {
            error!(error=?err, "failed to send a network encryption key ");
        }
    });

    key_public_data_receiver
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
    secp256k1_protocol_public_parameters: &twopc_mpc::secp256k1::class_groups::ProtocolPublicParameters,
    secp256r1_protocol_public_parameters: &twopc_mpc::secp256r1::class_groups::ProtocolPublicParameters,
    ristretto_protocol_public_parameters: &twopc_mpc::ristretto::class_groups::ProtocolPublicParameters,
    curve25519_protocol_public_parameters: &twopc_mpc::curve25519::class_groups::ProtocolPublicParameters,
) -> DwalletMPCResult<AllCurvesNetworkOwnedAddressDkgData> {
    // Seed each curve's NOA DKG with that curve's class-groups encryption
    // public-key parameters (which embed the network encryption key) rather
    // than the network key's Sui ObjectID. This makes the network-owned
    // addresses a pure function of cryptographic key material, with no Sui
    // dependency. The encryption key is stable across reconfiguration, so the
    // addresses are stable too.
    let secp256k1_encryption_key =
        bcs::to_bytes(&secp256k1_protocol_public_parameters.encryption_scheme_public_parameters)?;
    let secp256k1 = compute_noa_dkg::<Secp256k1AsyncDKGProtocol>(
        &secp256k1_encryption_key,
        DWalletCurve::Secp256k1,
        secp256k1_protocol_public_parameters,
    )?;
    let secp256r1_encryption_key =
        bcs::to_bytes(&secp256r1_protocol_public_parameters.encryption_scheme_public_parameters)?;
    let secp256r1 = compute_noa_dkg::<Secp256r1AsyncDKGProtocol>(
        &secp256r1_encryption_key,
        DWalletCurve::Secp256r1,
        secp256r1_protocol_public_parameters,
    )?;
    // curve25519 shares ristretto's scalar field and has no separate encryption
    // key of its own; its protocol public parameters carry the same encryption
    // key. The `curve` tag in the session id keeps the two curves' addresses
    // distinct.
    let curve25519_encryption_key =
        bcs::to_bytes(&curve25519_protocol_public_parameters.encryption_scheme_public_parameters)?;
    let curve25519 = compute_noa_dkg::<Curve25519AsyncDKGProtocol>(
        &curve25519_encryption_key,
        DWalletCurve::Curve25519,
        curve25519_protocol_public_parameters,
    )?;
    let ristretto_encryption_key =
        bcs::to_bytes(&ristretto_protocol_public_parameters.encryption_scheme_public_parameters)?;
    let ristretto = compute_noa_dkg::<RistrettoAsyncDKGProtocol>(
        &ristretto_encryption_key,
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

/// Derives a network key's content-derived identity material — its
/// curve25519 network-owned-address ed25519 public key (the value used
/// as the `NetworkKeyId`) — from the key's serialized curve25519
/// protocol public parameters. Callers obtain those from
/// `dwallet_mpc_centralized_party::{network_dkg_public_output,reconfiguration_public_output}_to_protocol_pp_inner`,
/// which handle the V1/V2/V3 + reconfiguration cases (deployed keys have
/// a V1 DKG output kept current via reconfiguration, so the params come
/// from the reconfiguration output). The result matches what
/// instantiation computes because both seed `compute_noa_dkg` on the
/// curve25519 encryption-key parameters.
pub(crate) fn derive_curve25519_network_owned_address_public_key(
    curve25519_protocol_public_parameters: &[u8],
) -> DwalletMPCResult<Vec<u8>> {
    let protocol_public_parameters: twopc_mpc::curve25519::class_groups::ProtocolPublicParameters =
        bcs::from_bytes(curve25519_protocol_public_parameters).map_err(DwalletMPCError::BcsError)?;
    let encryption_key =
        bcs::to_bytes(&protocol_public_parameters.encryption_scheme_public_parameters)
            .map_err(DwalletMPCError::BcsError)?;
    let noa = compute_noa_dkg::<Curve25519AsyncDKGProtocol>(
        &encryption_key,
        DWalletCurve::Curve25519,
        &protocol_public_parameters,
    )?;
    Ok(noa.public_key)
}

/// Derives a network key's content-derived [`NetworkKeyId`] from its raw
/// chain blobs and records the temporary `ObjectID` <-> `NetworkKeyId`
/// mapping, on the rayon pool.
///
/// Normally the mapping registers at instantiation
/// ([`DwalletMPCNetworkKeys::update_network_key`]), but a validator
/// consuming a handoff cert for a key it never instantiated (a joiner on
/// any key absent from the seeded map) needs the mapping *before*
/// instantiation — the cert keys by `NetworkKeyId`, and cert-gated
/// adoption is what leads to instantiation in the first place. The
/// derivation is an expensive class-groups computation (deserialize the
/// curve25519 protocol public parameters + the deterministic NOA DKG),
/// so it runs off the MPC service loop; the adoption pass re-evaluates
/// each tick and proceeds once the registration lands.
pub(crate) fn spawn_network_key_id_registration(
    key_id: ObjectID,
    network_dkg_public_output: Vec<u8>,
    current_reconfiguration_public_output: Vec<u8>,
) {
    // msim: rayon worker threads have no simulated-node context, so capture
    // the originating NodeHandle and enter it before any tracing call
    // inside the worker.
    #[cfg(msim)]
    let originating_sim_node = sui_simulator::runtime::NodeHandle::try_current();

    rayon::spawn_fifo(move || {
        #[cfg(msim)]
        let _node_guard = originating_sim_node.as_ref().map(|n| n.enter_node());

        // Derive from the same source instantiation would use: the
        // reconfiguration output when present, else the DKG output. The
        // resulting id is identical either way — resharing preserves the
        // collective encryption key the id is derived from.
        let curve25519_protocol_pp = if current_reconfiguration_public_output.is_empty() {
            network_dkg_public_output_to_protocol_pp_inner(
                DWalletCurve::Curve25519 as u32,
                network_dkg_public_output,
            )
        } else {
            reconfiguration_public_output_to_protocol_pp_inner(
                DWalletCurve::Curve25519 as u32,
                current_reconfiguration_public_output,
                network_dkg_public_output,
            )
        };
        let network_key_id = curve25519_protocol_pp
            .map_err(|e| DwalletMPCError::InternalError(e.to_string()))
            .and_then(|pp| derive_curve25519_network_owned_address_public_key(&pp))
            .and_then(|public_key| {
                NetworkKeyId::from_bytes(&public_key)
                    .map_err(|e| DwalletMPCError::InternalError(e.to_string()))
            });
        match network_key_id {
            Ok(network_key_id) => {
                crate::network_key_id_mapping::register(key_id, network_key_id);
                info!(
                    ?key_id,
                    ?network_key_id,
                    "derived and registered the NetworkKeyId from locally-held key data"
                );
            }
            Err(e) => error!(
                ?key_id,
                error = ?e,
                "failed to derive the NetworkKeyId from locally-held key data — \
                 cert-anchored adoption for this key stays deferred"
            ),
        }
    });
}

/// One-off tool (not a unit test): fetches the deployed network key from
/// testnet/mainnet and prints its `NetworkKeyId` (curve25519 NOA ed25519
/// pubkey) for baking into the temporary static ObjectID->NetworkKeyId
/// map. Run with:
///   cargo test -p ika-core --release print_deployed_network_key_ids -- --ignored --nocapture
#[cfg(test)]
mod network_key_id_derivation_tool {
    use super::{
        derive_curve25519_network_owned_address_public_key,
        network_dkg_public_output_to_protocol_pp_inner,
        reconfiguration_public_output_to_protocol_pp_inner,
    };
    use dwallet_mpc_types::dwallet_mpc::{
        VersionedDecryptionKeyReconfigurationOutput, VersionedNetworkDkgOutput,
    };
    use ika_sui_client::SuiConnectorClient;
    use ika_sui_client::metrics::SuiClientMetrics;
    use ika_types::messages_dwallet_mpc::IkaNetworkConfig;
    use ika_types::sui::DWalletCoordinatorInner;
    use std::str::FromStr;
    use sui_types::base_types::ObjectID;
    use twopc_mpc::decentralized_party_backward_compatible::reconfiguration as bwd_compat_reconfig;

    // (env, rpcs, ika, common, twopc, system_pkg, system_obj, coordinator_obj) — from ika_sui_config.yaml.
    // rpcs: canonical Mysten endpoint first, public fallback second — these
    // are read-only tools and either endpoint can be temporarily down.
    type DeployedEnv<'a> = (
        &'a str,
        &'a [&'a str],
        &'a str,
        &'a str,
        &'a str,
        &'a str,
        &'a str,
        &'a str,
    );

    const DEPLOYED_ENVS: &[DeployedEnv<'static>] = &[
        (
            "testnet",
            &[
                "https://fullnode.testnet.sui.io:443",
                "https://sui-testnet-rpc.publicnode.com",
            ],
            "0x1f26bb2f711ff82dcda4d02c77d5123089cb7f8418751474b9fb744ce031526a",
            "0x96fc75633b6665cf84690587d1879858ff76f88c10c945e299f90bf4e0985eb0",
            "0x6573a6c13daf26a64eb8a37d3c7a4391b353031e223072ca45b1ff9366f59293",
            "0xde05f49e5f1ee13ed06c1e243c0a8e8fe858e1d8689476fdb7009af8ddc3c38b",
            "0x2172c6483ccd24930834e30102e33548b201d0607fb1fdc336ba3267d910dec6",
            "0x4d157b7415a298c56ec2cb1dcab449525fa74aec17ddba376a83a7600f2062fc",
        ),
        (
            "mainnet",
            &[
                "https://fullnode.mainnet.sui.io:443",
                "https://sui-rpc.publicnode.com",
            ],
            "0x7262fb2f7a3a14c888c438a3cd9b912469a58cf60f367352c46584262e8299aa",
            "0x9e1e9f8e4e51ee2421a8e7c0c6ab3ef27c337025d15333461b72b1b813c44175",
            "0x23b5bd96051923f800c3a2150aacdcdd8d39e1df2dce4dac69a00d2d8c7f7e77",
            "0xd69f947d7ee6f224dd0dd31ec3ec30c0dd0f713a1de55d564e8e98910c4f9553",
            "0x215de95d27454d102d6f82ff9c54d8071eb34d5706be85b5c73cbd8173013c80",
            "0x5ea59bce034008a006425df777da925633ef384ce25761657ea89e2a08ec75f3",
        ),
    ];

    fn ika_network_config(env: &DeployedEnv<'_>) -> IkaNetworkConfig {
        let (_, _, ika, common, twopc, sys_pkg, sys_obj, coord) = env;
        let oid = |s: &str| ObjectID::from_str(s).unwrap();
        IkaNetworkConfig::new(
            oid(ika),
            oid(common),
            oid(twopc),
            None,
            oid(sys_pkg),
            oid(sys_obj),
            oid(coord),
        )
    }

    /// Tries each of the env's RPC endpoints in order; `None` (with a printed
    /// reason) when none is reachable, so one downed endpoint doesn't sink
    /// the other env's run.
    async fn connect(env: &DeployedEnv<'_>) -> Option<SuiConnectorClient> {
        let (name, rpcs, ..) = env;
        for rpc in rpcs.iter().copied() {
            match SuiConnectorClient::new(
                rpc,
                SuiClientMetrics::new_for_testing(),
                ika_network_config(env),
            )
            .await
            {
                Ok(client) => {
                    println!("CONNECT {name}: using {rpc}");
                    return Some(client);
                }
                Err(e) => println!("CONNECT {name}: {rpc} failed: {e}"),
            }
        }
        println!("SKIP {name}: no RPC endpoint reachable");
        None
    }

    #[ignore = "real-network tool; run manually to derive deployed NetworkKeyIds"]
    #[tokio::test]
    async fn print_deployed_network_key_ids() {
        for env in DEPLOYED_ENVS {
            let (name, ..) = env;
            let Some(client) = connect(env).await else {
                continue;
            };
            let (_, coordinator_inner) = client.must_get_dwallet_coordinator_inner().await;
            let DWalletCoordinatorInner::V1(inner) = &coordinator_inner;
            let epoch = inner.current_epoch;
            let network_keys = client
                .get_dwallet_mpc_network_keys(&coordinator_inner)
                .await
                .unwrap();
            for (id, key) in &network_keys {
                let key_data = client
                    .get_network_encryption_key_with_full_data_by_epoch(key, epoch)
                    .await
                    .unwrap();
                // curve25519 curve id = 2 (DWalletCurve::Curve25519). Deployed keys
                // have a V1 DKG output kept current via reconfiguration, so derive
                // the curve25519 protocol params from the reconfiguration output
                // when present (matching the binary's instantiation path).
                let curve25519_protocol_pp =
                    if key_data.current_reconfiguration_public_output.is_empty() {
                        network_dkg_public_output_to_protocol_pp_inner(
                            2,
                            key_data.network_dkg_public_output,
                        )
                        .unwrap()
                    } else {
                        reconfiguration_public_output_to_protocol_pp_inner(
                            2,
                            key_data.current_reconfiguration_public_output,
                            key_data.network_dkg_public_output,
                        )
                        .unwrap()
                    };
                let network_key_id =
                    derive_curve25519_network_owned_address_public_key(&curve25519_protocol_pp)
                        .unwrap();
                println!(
                    "NETWORK_KEY_ID {name}: object_id={id} network_key_id=0x{}",
                    hex::encode(network_key_id)
                );
            }
        }
    }

    /// One-off release-evidence tool: fetches the DEPLOYED network keys from
    /// testnet/mainnet and proves their on-chain bytes decode on the exact
    /// types the v3 backward-compatible reconfiguration arm consumes — the
    /// real-chain-bytes check the synthesized-anchor regression tests cannot
    /// provide (those re-encode a fresh output under the current crypto
    /// crates, so a bcs layout drift against the deployed bytes would not
    /// trip them). Run with:
    ///   cargo test -p ika-core --release decode_deployed_network_key_bytes -- --ignored --nocapture
    #[ignore = "real-network tool; run manually to verify deployed key bytes decode under the pinned crypto crates"]
    #[tokio::test]
    async fn decode_deployed_network_key_bytes() {
        for env in DEPLOYED_ENVS {
            let (name, ..) = env;
            let Some(client) = connect(env).await else {
                continue;
            };
            let (_, coordinator_inner) = client.must_get_dwallet_coordinator_inner().await;
            let DWalletCoordinatorInner::V1(inner) = &coordinator_inner;
            let epoch = inner.current_epoch;
            let network_keys = client
                .get_dwallet_mpc_network_keys(&coordinator_inner)
                .await
                .unwrap();
            for (id, key) in &network_keys {
                let key_data = client
                    .get_network_encryption_key_with_full_data_by_epoch(key, epoch)
                    .await
                    .unwrap();

                let anchor: VersionedNetworkDkgOutput =
                    bcs::from_bytes(&key_data.network_dkg_public_output)
                        .expect("anchor bytes must decode as VersionedNetworkDkgOutput");
                match &anchor {
                    VersionedNetworkDkgOutput::V1(v1_inner) => {
                        // The exact decode the v3 bwd-compat V1 arm performs on
                        // every reconfiguration of a deployed key.
                        let decoded: class_groups::dkg::PublicOutput<
                            { twopc_mpc::secp256k1::SCALAR_LIMBS },
                            { twopc_mpc::secp256k1::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
                            {
                                twopc_mpc::secp256k1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS
                            },
                        > = bcs::from_bytes(v1_inner).expect(
                            "V1 anchor inner bytes must decode as the class-groups DKG output",
                        );
                        let reencoded = bcs::to_bytes(&decoded).unwrap();
                        println!(
                            "DECODE {name}: key {id}: V1 anchor OK ({} bytes, re-encode {})",
                            v1_inner.len(),
                            if reencoded == *v1_inner {
                                "byte-identical".to_string()
                            } else {
                                format!("DIFFERS ({} bytes)", reencoded.len())
                            }
                        );
                    }
                    VersionedNetworkDkgOutput::V2(bytes) => println!(
                        "DECODE {name}: key {id}: V2-tagged anchor ({} bytes) — not the deployed V1 shape",
                        bytes.len()
                    ),
                    VersionedNetworkDkgOutput::V3(bytes) => println!(
                        "DECODE {name}: key {id}: V3-tagged anchor ({} bytes) — not the deployed V1 shape",
                        bytes.len()
                    ),
                    VersionedNetworkDkgOutput::V4(bytes) => println!(
                        "DECODE {name}: key {id}: V4-tagged anchor ({} bytes) — not the deployed V1 shape",
                        bytes.len()
                    ),
                }

                if key_data.current_reconfiguration_public_output.is_empty() {
                    println!("DECODE {name}: key {id}: no reconfiguration output on chain");
                    continue;
                }
                let reconfiguration: VersionedDecryptionKeyReconfigurationOutput =
                    bcs::from_bytes(&key_data.current_reconfiguration_public_output).expect(
                        "reconfiguration bytes must decode as VersionedDecryptionKeyReconfigurationOutput",
                    );
                match &reconfiguration {
                    VersionedDecryptionKeyReconfigurationOutput::V2(bytes) => {
                        // The exact decode the v3 bwd-compat V1 arm performs on
                        // the prior reconfiguration output.
                        let _: <bwd_compat_reconfig::Party as mpc::Party>::PublicOutput =
                            bcs::from_bytes(bytes).expect(
                                "V2 reconfiguration output must decode as the bwd-compat PublicOutput",
                            );
                        println!(
                            "DECODE {name}: key {id}: V2 reconfiguration output OK ({} bytes)",
                            bytes.len()
                        );
                    }
                    VersionedDecryptionKeyReconfigurationOutput::V1(bytes) => println!(
                        "DECODE {name}: key {id}: V1-tagged reconfiguration output ({} bytes) — unsupported by the bwd-compat arm",
                        bytes.len()
                    ),
                    VersionedDecryptionKeyReconfigurationOutput::V3(bytes) => println!(
                        "DECODE {name}: key {id}: V3-tagged reconfiguration output ({} bytes) — main-path shape",
                        bytes.len()
                    ),
                    VersionedDecryptionKeyReconfigurationOutput::V4(bytes) => println!(
                        "DECODE {name}: key {id}: V4-tagged reconfiguration output ({} bytes) — aggregated shape",
                        bytes.len()
                    ),
                }
            }
        }
    }
}

/// Reconstructs the full-shape (V3) network DKG output in memory from a V1 or
/// V2 (backward-compatible) DKG output and a full V3 reconfiguration output.
///
/// Neither pre-V3 anchor carries the trailing
/// `threshold_encryption_to_sharing_output` that the full V3
/// `decentralized_party::dkg::PublicOutput` carries; that field is produced
/// only by the threshold-encryption-to-sharing sub-protocol, which the
/// backward-compatible reconfiguration predates. Once a full V3 reconfiguration
/// output is available it supplies that field, and the full V3 DKG output is
/// reconstructed by combining the anchor's reconfiguration-invariant
/// class-group DKG output with the V3 reconfiguration output
/// (`PublicOutput::new_from_reconfiguration_output`). A V2 anchor is a
/// `decentralized_party::dkg::PublicOutputCore`, whose class-group DKG output
/// `PublicOutputCore::class_group_dkg_output` projects out; a V1 anchor (the
/// deployed mainnet/testnet shape, written by a pre-1.1.8 binary) IS the raw
/// `class_groups::dkg::PublicOutput` and decodes directly.
///
/// Returns `Some(V3)` only when `network_dkg_output` is V1 or V2 AND a V3
/// reconfiguration output is available; `None` otherwise. The reconstruction is
/// a pure (RNG-free) function of its inputs, so every validator holding the same
/// anchor and the same quorum-agreed V3 reconfiguration output derives
/// byte-identical V3 bytes.
fn reconstruct_full_network_dkg_output(
    network_dkg_output: &VersionedNetworkDkgOutput,
    latest_network_reconfiguration_public_output: Option<
        &VersionedDecryptionKeyReconfigurationOutput,
    >,
) -> DwalletMPCResult<Option<VersionedNetworkDkgOutput>> {
    // The reconstructed anchor's version follows the reconfiguration output's
    // version (V3 pre-aggregation → V3 anchor; V4 aggregated → V4 anchor) —
    // input-driven, so every validator holding the same quorum-agreed
    // reconfiguration output reconstructs byte-identical anchor bytes without
    // consulting the protocol config.
    let (reconfiguration_output_bytes, aggregated) =
        match latest_network_reconfiguration_public_output {
            Some(VersionedDecryptionKeyReconfigurationOutput::V3(bytes)) => (bytes, false),
            Some(VersionedDecryptionKeyReconfigurationOutput::V4(bytes)) => (bytes, true),
            _ => return Ok(None),
        };

    let class_group_dkg_output = match network_dkg_output {
        VersionedNetworkDkgOutput::V1(class_group_dkg_output_bytes) => {
            bcs::from_bytes(class_group_dkg_output_bytes)?
        }
        VersionedNetworkDkgOutput::V2(dkg_public_output_core_bytes) => {
            let dkg_public_output_core: dkg::PublicOutputCore =
                bcs::from_bytes(dkg_public_output_core_bytes)?;
            dkg_public_output_core.class_group_dkg_output()
        }
        VersionedNetworkDkgOutput::V3(_) | VersionedNetworkDkgOutput::V4(_) => return Ok(None),
    };

    if aggregated {
        let reconfiguration_output: twopc_mpc::decentralized_party::reconfiguration::PublicOutput =
            bcs::from_bytes(reconfiguration_output_bytes)?;

        let full_network_dkg_output = dkg::PublicOutput::new_from_reconfiguration_output(
            class_group_dkg_output,
            reconfiguration_output,
        )
        .map_err(DwalletMPCError::from)?;

        Ok(Some(VersionedNetworkDkgOutput::V4(bcs::to_bytes(
            &full_network_dkg_output,
        )?)))
    } else {
        let reconfiguration_output: twopc_mpc::decentralized_party::reconfiguration::NonAggregatedPublicOutput =
            bcs::from_bytes(reconfiguration_output_bytes)?;

        let full_network_dkg_output =
            dkg::NonAggregatedPublicOutput::new_from_reconfiguration_output(
                class_group_dkg_output,
                reconfiguration_output,
            )
            .map_err(DwalletMPCError::from)?;

        Ok(Some(VersionedNetworkDkgOutput::V3(bcs::to_bytes(
            &full_network_dkg_output,
        )?)))
    }
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
) -> DwalletMPCResult<NetworkEncryptionKeyPublicData> {
    let reconstructed_full_network_dkg_output = reconstruct_full_network_dkg_output(
        &network_dkg_output,
        latest_network_reconfiguration_public_output.as_ref(),
    )?;

    Ok(NetworkEncryptionKeyPublicData {
        epoch,
        dkg_at_epoch,
        state,
        latest_network_reconfiguration_public_output,
        network_dkg_output,
        reconstructed_full_network_dkg_output,
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
    })
}

/// Times one instantiation sub-call, logs its duration at info level, and
/// feeds the `dwallet_mpc_network_key_instantiation_sub_call_duration_seconds`
/// histogram for cross-epoch/release trending. The instantiation dominates
/// the epoch-boundary cost; the per-sub-call breakdown localizes any
/// slowdown to a concrete operation instead of one opaque call.
pub(crate) fn timed_sub_call<T, E>(
    metrics: &DWalletMPCMetrics,
    label: &str,
    sub_call: impl FnOnce() -> Result<T, E>,
) -> Result<T, E> {
    let start = Instant::now();
    let result = sub_call();
    let elapsed = start.elapsed();
    metrics
        .network_key_instantiation_sub_call_duration_seconds
        .with_label_values(&[label])
        .observe(elapsed.as_secs_f64());
    info!(
        sub_call = label,
        elapsed_ms = elapsed.as_millis() as u64,
        "network key instantiation sub-call finished"
    );
    result
}

fn instantiate_dwallet_mpc_network_encryption_key_public_data_from_dkg_public_output(
    epoch: u64,
    dkg_at_epoch: u64,
    access_structure: &WeightedThresholdAccessStructure,
    public_output_bytes: &SerializedWrappedMPCPublicOutput,
    metrics: &DWalletMPCMetrics,
) -> DwalletMPCResult<NetworkEncryptionKeyPublicData> {
    let mpc_public_output: VersionedNetworkDkgOutput =
        bcs::from_bytes(public_output_bytes).map_err(DwalletMPCError::BcsError)?;

    // Macro extracts the 8 protocol+decryption-key-share Arcs from a decoded
    // DKG `PublicOutput` (either `bwd_compat_dkg::Party::PublicOutput` or
    // `dkg::Party::PublicOutput`; both expose the same per-curve accessor API).
    // Each sub-call is individually timed: the instantiation dominates the
    // epoch-boundary cost, and the per-sub-call breakdown localizes any
    // slowdown to a concrete operation instead of one opaque call.
    macro_rules! build_from_public_output {
        ($public_output:expr) => {{
            let public_output = $public_output;
            let secp256k1_protocol_public_parameters = Arc::new(timed_sub_call(
                metrics,
                "secp256k1_protocol_public_parameters",
                || public_output.secp256k1_protocol_public_parameters(),
            )?);
            let secp256k1_decryption_key_share_public_parameters = Arc::new(timed_sub_call(
                metrics,
                "secp256k1_decryption_key_share",
                || public_output.secp256k1_decryption_key_share_public_parameters(access_structure),
            )?);
            let secp256r1_protocol_public_parameters = Arc::new(timed_sub_call(
                metrics,
                "secp256r1_protocol_public_parameters",
                || public_output.secp256r1_protocol_public_parameters(),
            )?);
            let secp256r1_decryption_key_share_public_parameters = Arc::new(timed_sub_call(
                metrics,
                "secp256r1_decryption_key_share",
                || public_output.secp256r1_decryption_key_share_public_parameters(access_structure),
            )?);
            let ristretto_protocol_public_parameters = Arc::new(timed_sub_call(
                metrics,
                "ristretto_protocol_public_parameters",
                || public_output.ristretto_protocol_public_parameters(),
            )?);
            let ristretto_decryption_key_share_public_parameters = Arc::new(timed_sub_call(
                metrics,
                "ristretto_decryption_key_share",
                || public_output.ristretto_decryption_key_share_public_parameters(access_structure),
            )?);
            let curve25519_protocol_public_parameters = Arc::new(timed_sub_call(
                metrics,
                "curve25519_protocol_public_parameters",
                || public_output.curve25519_protocol_public_parameters(),
            )?);
            let curve25519_decryption_key_share_public_parameters = Arc::new(timed_sub_call(
                metrics,
                "curve25519_decryption_key_share",
                || {
                    public_output
                        .curve25519_decryption_key_share_public_parameters(access_structure)
                },
            )?);

            let noa_dkg_data = timed_sub_call(metrics, "noa_dkg_outputs", || {
                compute_all_network_owned_address_dkg_outputs(
                    &secp256k1_protocol_public_parameters,
                    &secp256r1_protocol_public_parameters,
                    &ristretto_protocol_public_parameters,
                    &curve25519_protocol_public_parameters,
                )
            })?;

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
            )
        }};
    }

    match &mpc_public_output {
        VersionedNetworkDkgOutput::V1(_) => Err(DwalletMPCError::InternalError(
            "V1 network DKG anchors are not supported on this instantiation path              (deployed keys instantiate from their reconfiguration output)."
                .to_string(),
        )),
        VersionedNetworkDkgOutput::V2(public_output_bytes) => {
            // bwd-compat shape — decode under `bwd_compat_dkg::Party::PublicOutput`.
            let public_output: <bwd_compat_dkg::Party as mpc::Party>::PublicOutput =
                bcs::from_bytes(public_output_bytes)?;
            build_from_public_output!(public_output)
        }
        VersionedNetworkDkgOutput::V3(public_output_bytes) => {
            let public_output: twopc_mpc::decentralized_party::dkg::NonAggregatedPublicOutput =
                bcs::from_bytes(public_output_bytes)?;
            build_from_public_output!(public_output)
        }
        VersionedNetworkDkgOutput::V4(public_output_bytes) => {
            let public_output: twopc_mpc::decentralized_party::dkg::PublicOutput =
                bcs::from_bytes(public_output_bytes)?;
            build_from_public_output!(public_output)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::reconstruct_full_network_dkg_output;
    use dwallet_mpc_types::dwallet_mpc::{
        VersionedDecryptionKeyReconfigurationOutput, VersionedNetworkDkgOutput,
    };

    /// The reconstruction must fire ONLY for a V1 or V2 DKG anchor paired with
    /// a full V3 reconfiguration output. Every other combination returns `None`
    /// without touching the crypto decoders (so dummy bytes are fine there).
    /// The `Some` paths need real anchor + V3 reconfiguration bytes and are
    /// exercised end-to-end by the v4 reconfiguration integration tests
    /// (`test_v2_to_v3_reconfiguration_migration`,
    /// `test_v1_anchor_main_reconfiguration_and_anchor_migration`).
    #[test]
    fn reconstruct_full_network_dkg_output_gating() {
        use VersionedDecryptionKeyReconfigurationOutput as Reconfiguration;
        use VersionedNetworkDkgOutput as Dkg;

        // Natively-V3 DKG output: already full shape, no reconstruction.
        assert!(
            reconstruct_full_network_dkg_output(
                &Dkg::V3(vec![]),
                Some(&Reconfiguration::V3(vec![])),
            )
            .unwrap()
            .is_none()
        );

        // V2 DKG output but no reconfiguration output yet (e.g. fresh DKG).
        assert!(
            reconstruct_full_network_dkg_output(&Dkg::V2(vec![]), None)
                .unwrap()
                .is_none()
        );

        // V2 DKG output with a V2 (core-only) reconfiguration output: the
        // trailing threshold-encryption-to-sharing field is absent, so the full
        // V3 DKG output cannot be reconstructed.
        assert!(
            reconstruct_full_network_dkg_output(
                &Dkg::V2(vec![]),
                Some(&Reconfiguration::V2(vec![])),
            )
            .unwrap()
            .is_none()
        );

        // V1 anchor (the deployed shape) with only a V2 reconfiguration
        // output: no threshold-encryption-to-sharing field yet, no
        // reconstruction.
        assert!(
            reconstruct_full_network_dkg_output(
                &Dkg::V1(vec![]),
                Some(&Reconfiguration::V2(vec![])),
            )
            .unwrap()
            .is_none()
        );

        // V1 anchor + V3 reconfiguration output DOES engage the
        // reconstruction — with garbage bytes it must fail decoding rather
        // than return `None` (a `None` here would silently skip the deployed
        // keys' one-time anchor migration).
        assert!(
            reconstruct_full_network_dkg_output(
                &Dkg::V1(vec![]),
                Some(&Reconfiguration::V3(vec![])),
            )
            .is_err()
        );
    }
}

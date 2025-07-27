// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use super::{Element, ExtendedField, PendingValues};
use crate::crypto::{AuthorityPublicKey, AuthorityPublicKeyBytes, NetworkPublicKey};
use fastcrypto::traits::ToFromBytes;
use jsonrpsee::core::Serialize;
use mysten_network::Multiaddr;
use once_cell::sync::OnceCell;
use serde::Deserialize;
use sui_types::balance::Balance;
use sui_types::base_types::ObjectID;
use sui_types::collection_types::{Bag, Table, TableVec, VecMap};

#[allow(dead_code)]
const E_METADATA_INVALID_POP: u64 = 0;
const E_METADATA_INVALID_PUBKEY: u64 = 1;
const E_METADATA_INVALID_NET_PUBKEY: u64 = 2;
const E_METADATA_INVALID_WORKER_PUBKEY: u64 = 3;
const E_METADATA_INVALID_NET_ADDR: u64 = 4;
const E_METADATA_INVALID_P2P_ADDR: u64 = 5;
#[allow(dead_code)]
const E_METADATA_INVALID_PRIMARY_ADDR: u64 = 6;
#[allow(dead_code)]
const E_METADATA_INVALID_WORKER_ADDR: u64 = 7;
const E_METADATA_MPC_DATA_NOT_FOUND: u64 = 8;

#[derive(derive_more::Debug, Clone, Eq, PartialEq)]
pub struct VerifiedValidatorInfo {
    pub protocol_pubkey: AuthorityPublicKey,
    pub network_pubkey: NetworkPublicKey,
    pub consensus_pubkey: NetworkPublicKey,
    pub mpc_data_bytes: TableVec,
    pub name: String,
    pub network_address: Multiaddr,
    pub p2p_address: Multiaddr,
    pub consensus_address: Multiaddr,
    pub next_epoch_protocol_pubkey: Option<AuthorityPublicKey>,
    pub next_epoch_network_pubkey: Option<NetworkPublicKey>,
    pub next_epoch_consensus_pubkey: Option<NetworkPublicKey>,
    pub next_epoch_network_address: Option<Multiaddr>,
    pub next_epoch_mpc_data_bytes: Option<TableVec>,
    pub next_epoch_p2p_address: Option<Multiaddr>,
    pub next_epoch_consensus_address: Option<Multiaddr>,
    pub previous_mpc_data_bytes: Option<TableVec>,
}

impl VerifiedValidatorInfo {
    pub fn ika_pubkey_bytes(&self) -> AuthorityPublicKeyBytes {
        (&self.protocol_pubkey).into()
    }
}

impl ValidatorInfo {
    /// Verify validator info and return a verified version (on success) or error code (on failure)
    pub fn verify(&self) -> anyhow::Result<VerifiedValidatorInfo, u64> {
        let protocol_pubkey = AuthorityPublicKey::from_bytes(self.protocol_pubkey_bytes.as_ref())
            .map_err(|_| E_METADATA_INVALID_PUBKEY)?;

        let network_pubkey = NetworkPublicKey::from_bytes(self.network_pubkey_bytes.as_ref())
            .map_err(|_| E_METADATA_INVALID_NET_PUBKEY)?;
        let consensus_pubkey = NetworkPublicKey::from_bytes(self.consensus_pubkey_bytes.as_ref())
            .map_err(|_| E_METADATA_INVALID_WORKER_PUBKEY)?;
        if consensus_pubkey == network_pubkey {
            return Err(E_METADATA_INVALID_WORKER_PUBKEY);
        }

        let network_address = Multiaddr::try_from(self.network_address.clone())
            .map_err(|_| E_METADATA_INVALID_NET_ADDR)?;

        // Ensure p2p, primary, and worker addresses are both Multiaddr's and valid anemo addresses
        let p2p_address = Multiaddr::try_from(self.p2p_address.clone())
            .map_err(|_| E_METADATA_INVALID_P2P_ADDR)?;
        p2p_address
            .to_anemo_address()
            .map_err(|_| E_METADATA_INVALID_P2P_ADDR)?;

        let consensus_address = Multiaddr::try_from(self.consensus_address.clone())
            .map_err(|_| E_METADATA_INVALID_PRIMARY_ADDR)?;
        consensus_address
            .to_anemo_address()
            .map_err(|_| E_METADATA_INVALID_PRIMARY_ADDR)?;

        let next_epoch_protocol_pubkey = match self.next_epoch_protocol_pubkey_bytes.clone() {
            None => Ok::<Option<AuthorityPublicKey>, u64>(None),
            Some(bytes) => Ok(Some(
                AuthorityPublicKey::from_bytes(bytes.as_ref())
                    .map_err(|_| E_METADATA_INVALID_PUBKEY)?,
            )),
        }?;

        let next_epoch_network_pubkey = match self.next_epoch_network_pubkey_bytes.clone() {
            None => Ok::<Option<NetworkPublicKey>, u64>(None),
            Some(bytes) => Ok(Some(
                NetworkPublicKey::from_bytes(bytes.as_ref())
                    .map_err(|_| E_METADATA_INVALID_NET_PUBKEY)?,
            )),
        }?;

        let next_epoch_consensus_pubkey: Option<NetworkPublicKey> =
            match self.next_epoch_consensus_pubkey_bytes.clone() {
                None => Ok::<Option<NetworkPublicKey>, u64>(None),
                Some(bytes) => Ok(Some(
                    NetworkPublicKey::from_bytes(bytes.as_ref())
                        .map_err(|_| E_METADATA_INVALID_WORKER_PUBKEY)?,
                )),
            }?;
        if next_epoch_network_pubkey.is_some()
            && next_epoch_network_pubkey == next_epoch_consensus_pubkey
        {
            return Err(E_METADATA_INVALID_WORKER_PUBKEY);
        }

        let next_epoch_network_address = match self.next_epoch_network_address.clone() {
            None => Ok::<Option<Multiaddr>, u64>(None),
            Some(address) => Ok(Some(
                Multiaddr::try_from(address).map_err(|_| E_METADATA_INVALID_NET_ADDR)?,
            )),
        }?;

        let next_epoch_p2p_address = match self.next_epoch_p2p_address.clone() {
            None => Ok::<Option<Multiaddr>, u64>(None),
            Some(address) => {
                let address =
                    Multiaddr::try_from(address).map_err(|_| E_METADATA_INVALID_P2P_ADDR)?;
                address
                    .to_anemo_address()
                    .map_err(|_| E_METADATA_INVALID_P2P_ADDR)?;

                Ok(Some(address))
            }
        }?;

        let next_epoch_consensus_address = match self.next_epoch_consensus_address.clone() {
            None => Ok::<Option<Multiaddr>, u64>(None),
            Some(address) => {
                let address =
                    Multiaddr::try_from(address).map_err(|_| E_METADATA_INVALID_PRIMARY_ADDR)?;
                address
                    .to_anemo_address()
                    .map_err(|_| E_METADATA_INVALID_PRIMARY_ADDR)?;

                Ok(Some(address))
            }
        }?;

        let mpc_data_bytes = self
            .mpc_data_bytes
            .clone()
            .ok_or(E_METADATA_MPC_DATA_NOT_FOUND)?;

        Ok(VerifiedValidatorInfo {
            protocol_pubkey,
            network_pubkey,
            consensus_pubkey,
            mpc_data_bytes,
            name: self.name.clone(),
            network_address,
            p2p_address,
            consensus_address,
            next_epoch_protocol_pubkey,
            next_epoch_network_pubkey,
            next_epoch_consensus_pubkey,
            next_epoch_network_address,
            next_epoch_mpc_data_bytes: self.next_epoch_mpc_datd_bytes.clone(),
            next_epoch_p2p_address,
            next_epoch_consensus_address,
            previous_mpc_data_bytes: self.previous_mpc_data_bytes.clone(),
        })
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct ValidatorMetadata {
    pub image_url: String,
    pub project_url: String,
    pub description: String,
    pub extra_fields: VecMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct ValidatorInfo {
    pub name: String,
    pub validator_id: ObjectID,
    pub network_address: String,
    pub p2p_address: String,
    pub consensus_address: String,
    pub protocol_pubkey_bytes: Vec<u8>,
    pub protocol_pubkey: Element,
    pub network_pubkey_bytes: Vec<u8>,
    pub consensus_pubkey_bytes: Vec<u8>,
    pub mpc_data_bytes: Option<TableVec>,
    pub next_epoch_protocol_pubkey_bytes: Option<Vec<u8>>,
    pub next_epoch_network_pubkey_bytes: Option<Vec<u8>>,
    pub next_epoch_consensus_pubkey_bytes: Option<Vec<u8>>,
    pub next_epoch_mpc_datd_bytes: Option<TableVec>,
    pub next_epoch_network_address: Option<String>,
    pub next_epoch_p2p_address: Option<String>,
    pub next_epoch_consensus_address: Option<String>,
    previous_mpc_data_bytes: Option<TableVec>,
    pub metadata: ExtendedField,
}

/// Rust version of the Move ika::validator_inner::ValidatorInner type
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct StakingPool {
    pub id: ObjectID,
    pub validator_info: ValidatorInfo,
    #[serde(skip)]
    verified_validator_info: OnceCell<VerifiedValidatorInfo>,
    pub state: PoolState,
    pub activation_epoch: Option<u64>,
    pub latest_epoch: u64,
    pub ika_balance: u64,
    pub num_shares: u64,
    pub pending_shares_withdraw: PendingValues,
    pub pre_active_withdrawals: PendingValues,
    pub pending_commission_rate: PendingValues,
    pub commission_rate: u16,
    pub exchange_rates: Table,
    pub pending_stake: PendingValues,
    pub rewards_pool: Balance,
    pub commission: Balance,
    pub validator_cap_id: ObjectID,
    pub operation_cap_id: ObjectID,
    pub commission_cap_id: ObjectID,
    pub extra_fields: Bag,
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub enum PoolState {
    PreActive,
    Active,
    Withdrawing(u64),
}

impl StakingPool {
    pub fn verified_validator_info(&self) -> &VerifiedValidatorInfo {
        // Todo (#1298): Remove unwrap.
        self.verified_validator_info
            .get_or_init(|| self.validator_info.verify().unwrap()) // Why unwrap? this could fail
    }
}

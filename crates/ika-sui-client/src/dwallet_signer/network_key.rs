// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Network encryption-key lookup and protocol public-parameter derivation.

use anyhow::{Context, Result};
use dwallet_mpc_centralized_party::{
    network_dkg_public_output_to_protocol_pp_inner,
    reconfiguration_public_output_to_protocol_pp_inner,
};
use sui_types::base_types::ObjectID;

use crate::SuiConnectorClient;

pub struct NetworkKeyInfo {
    pub network_encryption_key_id: ObjectID,
    /// Protocol public parameters derived from the network key.
    /// Accounts for reconfiguration if the key was created in a prior epoch.
    pub protocol_public_parameters: Vec<u8>,
}

/// Fetch network key info for the latest network encryption key.
pub async fn get_network_key_info(
    client: &SuiConnectorClient,
    curve_id: u32,
) -> Result<NetworkKeyInfo> {
    get_network_key_info_for(client, None, curve_id).await
}

/// Fetch network key info, optionally for a specific key ID (e.g. from a dWallet's
/// `dwallet_network_encryption_key_id`).
pub async fn get_network_key_info_for(
    client: &SuiConnectorClient,
    specific_key_id: Option<ObjectID>,
    curve_id: u32,
) -> Result<NetworkKeyInfo> {
    let (_, coordinator_inner) = client.must_get_dwallet_coordinator_inner().await;
    let network_keys = client
        .get_dwallet_mpc_network_keys(&coordinator_inner)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get network encryption keys: {e}"))?;

    let (id, key) = if let Some(target_id) = specific_key_id {
        network_keys
            .iter()
            .find(|(id, _)| **id == target_id)
            .ok_or_else(|| {
                anyhow::anyhow!("Network encryption key {target_id} not found in coordinator")
            })?
    } else {
        network_keys
            .iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("No network encryption keys found"))?
    };

    let epoch = match &coordinator_inner {
        ika_types::sui::DWalletCoordinatorInner::V1(inner) => inner.current_epoch,
    };

    let key_data = client
        .get_network_encryption_key_with_full_data_by_epoch(key, epoch)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get network key data: {e}"))?;

    let protocol_public_parameters = if key_data.current_reconfiguration_public_output.is_empty() {
        network_dkg_public_output_to_protocol_pp_inner(curve_id, key_data.network_dkg_public_output)
            .context("Failed to derive protocol parameters from network DKG output")?
    } else {
        reconfiguration_public_output_to_protocol_pp_inner(
            curve_id,
            key_data.current_reconfiguration_public_output,
            key_data.network_dkg_public_output,
        )
        .context("Failed to derive protocol parameters from reconfiguration output")?
    };

    Ok(NetworkKeyInfo {
        network_encryption_key_id: *id,
        protocol_public_parameters,
    })
}

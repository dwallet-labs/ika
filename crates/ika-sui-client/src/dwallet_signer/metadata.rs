// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! dWallet object metadata reads.

use anyhow::Result;
use sui_types::base_types::ObjectID;

use super::common::{extract_bytes_from_json, fetch_object_fields};

/// Snapshot of the on-chain dWallet object fields a signer needs.
pub struct DWalletMetadata {
    pub curve: u32,
    /// The DKG public output bytes, if the dWallet is in Active state.
    pub dkg_output: Option<Vec<u8>>,
    /// Whether this dWallet was created from an imported key.
    pub is_imported_key_dwallet: bool,
    /// The network encryption key ID used for this dWallet's DKG.
    pub network_encryption_key_id: Option<ObjectID>,
}

/// Fetch dWallet metadata (curve, DKG output, imported-key flag, network key id) from chain.
pub async fn fetch_dwallet_metadata(
    sdk_client: &sui_sdk::SuiClient,
    dwallet_id: ObjectID,
) -> Result<DWalletMetadata> {
    let fields = fetch_object_fields(sdk_client, dwallet_id).await?;

    let curve = fields
        .get("curve")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow::anyhow!("Could not read curve from dWallet object"))?
        as u32;

    let dkg_output = fields
        .get("state")
        .and_then(|state| state.get("fields"))
        .and_then(|f| f.get("public_output"))
        .and_then(extract_bytes_from_json);

    let is_imported_key_dwallet = fields
        .get("is_imported_key_dwallet")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let network_encryption_key_id = fields
        .get("dwallet_network_encryption_key_id")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<ObjectID>().ok());

    Ok(DWalletMetadata {
        curve,
        dkg_output,
        is_imported_key_dwallet,
        network_encryption_key_id,
    })
}

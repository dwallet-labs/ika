// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Presign cap inspection and presign output reads.

use anyhow::{Context, Result};
use sui_json_rpc_types::SuiObjectDataOptions;
use sui_types::base_types::ObjectID;

use super::common::{extract_bytes_from_json, fetch_object_fields};

/// Check if a presign cap is already verified by inspecting its on-chain type.
///
/// Returns `true` if the object type contains "VerifiedPresignCap",
/// `false` if it contains "UnverifiedPresignCap".
pub async fn is_presign_cap_verified(
    sdk_client: &sui_sdk::SuiClient,
    presign_cap_id: ObjectID,
) -> Result<bool> {
    let response = sdk_client
        .read_api()
        .get_object_with_options(presign_cap_id, SuiObjectDataOptions::new().with_type())
        .await?;
    let data = response
        .data
        .ok_or_else(|| anyhow::anyhow!("Presign cap not found: {presign_cap_id}"))?;
    let type_str = data
        .type_
        .ok_or_else(|| anyhow::anyhow!("No type info for presign cap: {presign_cap_id}"))?
        .to_string();
    if type_str.contains("VerifiedPresignCap") {
        Ok(true)
    } else if type_str.contains("UnverifiedPresignCap") {
        Ok(false)
    } else {
        anyhow::bail!("Object {presign_cap_id} is not a presign cap (type: {type_str})")
    }
}

/// Fetch presign output bytes from chain using a presign cap ID.
///
/// Reads the cap to get the presign session ID, then reads the session to extract
/// `state.Completed.presign` bytes.
pub async fn fetch_presign_output(
    sdk_client: &sui_sdk::SuiClient,
    presign_cap_id: ObjectID,
) -> Result<Vec<u8>> {
    let cap_fields = fetch_object_fields(sdk_client, presign_cap_id).await?;
    let presign_id_str = cap_fields
        .get("presign_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            anyhow::anyhow!("Could not read presign_id from presign cap: {presign_cap_id}")
        })?;
    let presign_id: ObjectID = presign_id_str
        .parse()
        .context("Invalid presign_id in presign cap")?;

    let session_fields = fetch_object_fields(sdk_client, presign_id).await?;
    let presign_bytes = session_fields
        .get("state")
        .and_then(|state| state.get("fields"))
        .and_then(|f| f.get("presign"))
        .and_then(extract_bytes_from_json)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Presign session {presign_id} is not in Completed state. \
                 The presign may still be processing."
            )
        })?;
    Ok(presign_bytes)
}

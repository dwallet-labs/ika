// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! JSON / event-extraction helpers and basic Sui object reads.

use anyhow::{Context, Result};
use sui_json_rpc_types::{SuiEvent, SuiObjectDataOptions};
use sui_types::base_types::ObjectID;

/// Fetch a Sui object's JSON fields by object ID.
///
/// Handles `SuiMoveStruct::WithTypes` serialization, which wraps fields as
/// `{ "type": "...", "fields": { actual fields } }`, by unwrapping one level.
pub async fn fetch_object_fields(
    sdk_client: &sui_sdk::SuiClient,
    object_id: ObjectID,
) -> Result<serde_json::Value> {
    let response = sdk_client
        .read_api()
        .get_object_with_options(object_id, SuiObjectDataOptions::full_content())
        .await?;
    let data = response
        .data
        .ok_or_else(|| anyhow::anyhow!("Object not found: {object_id}"))?;
    let content = data
        .content
        .ok_or_else(|| anyhow::anyhow!("No content for object: {object_id}"))?;
    let json = serde_json::to_value(&content)?;
    let fields = json
        .get("fields")
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("No fields in object: {object_id}"))?;
    if fields.get("type").is_some()
        && let Some(inner) = fields.get("fields")
    {
        return Ok(inner.clone());
    }
    Ok(fields)
}

/// Fetch transaction events by digest.
pub async fn fetch_tx_events(
    sdk_client: &sui_sdk::SuiClient,
    digest: &str,
) -> Option<Vec<SuiEvent>> {
    let tx_digest: sui_types::digests::TransactionDigest = digest.parse().ok()?;
    sdk_client.event_api().get_events(tx_digest).await.ok()
}

/// Extract a string field from the first event whose type contains `event_type_substr`.
pub fn extract_event_field(
    events: &[SuiEvent],
    event_type_substr: &str,
    field_name: &str,
) -> Option<String> {
    for event in events {
        let type_str = event.type_.to_string();
        if type_str.contains(event_type_substr) {
            if let Some(val) = event.parsed_json.get(field_name) {
                return val.as_str().map(|s| s.to_string());
            }
            if let Some(event_data) = event.parsed_json.get("event_data")
                && let Some(val) = event_data.get(field_name)
            {
                return val.as_str().map(|s| s.to_string());
            }
        }
    }
    None
}

/// Extract a deeply nested field from event data, traversing through Move enum variant `fields`.
///
/// `path` is a chain of field names. For each step, it first looks for a direct child, then
/// checks inside a `fields` sub-object (Move enum variant serialization: `{ variant, fields }`).
pub fn extract_nested_event_field(
    events: &[SuiEvent],
    event_type_substr: &str,
    path: &[&str],
) -> Option<String> {
    for event in events {
        let type_str = event.type_.to_string();
        if !type_str.contains(event_type_substr) {
            continue;
        }
        let root = event
            .parsed_json
            .get("event_data")
            .unwrap_or(&event.parsed_json);
        let mut current = root;
        for (i, key) in path.iter().enumerate() {
            let next = current
                .get(key)
                .or_else(|| current.get("fields").and_then(|f| f.get(key)));
            match next {
                Some(val) if i == path.len() - 1 => {
                    return val.as_str().map(|s| s.to_string());
                }
                Some(val) => current = val,
                None => break,
            }
        }
    }
    None
}

/// Extract byte array from Sui JSON representation.
///
/// Sui encodes `vector<u8>` as either a JSON array of numbers or a base64 string.
/// Hex strings are supported only with an explicit `0x` prefix.
pub fn extract_bytes_from_json(value: &serde_json::Value) -> Option<Vec<u8>> {
    match value {
        serde_json::Value::Array(arr) => arr.iter().map(|v| v.as_u64().map(|n| n as u8)).collect(),
        serde_json::Value::String(s) => {
            if let Some(hex_str) = s.strip_prefix("0x") {
                return hex::decode(hex_str).ok();
            }
            use base64::{Engine, engine::general_purpose::STANDARD};
            STANDARD.decode(s).ok()
        }
        _ => None,
    }
}

/// Decode a hex string (with or without 0x prefix) into bytes.
pub fn hex_decode(s: &str) -> Result<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).context("invalid hex")
}

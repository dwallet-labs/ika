// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Sign-session lookup and polling.

use anyhow::Result;
use sui_types::base_types::ObjectID;

use super::common::{
    extract_bytes_from_json, extract_event_field, fetch_object_fields, fetch_tx_events,
};

/// Outcome of polling a sign session.
pub enum SignSessionResult {
    Completed { signature: String },
    Rejected,
}

/// Extract the sign session object ID from a sign transaction's events.
///
/// `SignRequestEvent` is wrapped in `DWalletSessionEvent`, which has a top-level
/// `session_object_id` referring to a transient SessionManager record. The
/// actual `SignSession` object — the one that flips to `Completed` /
/// `NetworkRejected` — is `event_data.sign_id`. Polling
/// `session_object_id` instead times out at 300s because it gets cleaned up
/// almost immediately after dispatch.
pub async fn find_sign_session_id(sdk_client: &sui_sdk::SuiClient, digest: &str) -> Option<String> {
    fetch_tx_events(sdk_client, digest)
        .await
        .as_deref()
        .and_then(|evts| extract_event_field(evts, "SignRequestEvent", "sign_id"))
}

/// Poll a sign session until it reaches `Completed` or `NetworkRejected`.
///
/// `poll_interval` defaults to 3s; `timeout` defaults to 300s. Pass `None` for the defaults.
pub async fn poll_sign_session(
    sdk_client: &sui_sdk::SuiClient,
    sign_session_id: ObjectID,
    poll_interval: Option<std::time::Duration>,
    timeout: Option<std::time::Duration>,
) -> Result<SignSessionResult> {
    let poll_interval = poll_interval.unwrap_or_else(|| std::time::Duration::from_secs(3));
    let timeout = timeout.unwrap_or_else(|| std::time::Duration::from_secs(300));
    let start = std::time::Instant::now();

    loop {
        if start.elapsed() > timeout {
            anyhow::bail!(
                "Timeout waiting for sign session {sign_session_id} to complete ({}s)",
                timeout.as_secs()
            );
        }

        match fetch_object_fields(sdk_client, sign_session_id).await {
            Ok(fields) => {
                if let Some(state) = fields.get("state") {
                    // Sui's parsedJson represents Move enums as
                    // `{ "type": "<EnumStructTag>", "fields": { ...inner fields of the active variant... } }`
                    // — there's no `variant` tag, the active variant is
                    // inferred from which inner fields are present. For
                    // SignState: `Completed` carries `signature`, while
                    // `Requested` and `NetworkRejected` both have empty fields.
                    //
                    // We can detect Completed unambiguously via `signature`.
                    // Distinguishing Requested from NetworkRejected requires
                    // another signal; we treat both empty-field cases as
                    // "still pending" until the polling timeout. (TODO: detect
                    // NetworkRejected via the rejection event emitted by
                    // validators rather than via the SignSession object.)
                    let inner = state.get("fields");
                    if let Some(sig_value) = inner.and_then(|f| f.get("signature")) {
                        let sig_bytes = extract_bytes_from_json(sig_value).unwrap_or_default();
                        return Ok(SignSessionResult::Completed {
                            signature: hex::encode(sig_bytes),
                        });
                    }
                } else if start.elapsed().as_secs() == 30 {
                    let keys: Vec<&str> = fields
                        .as_object()
                        .map(|m| m.keys().map(|k| k.as_str()).collect())
                        .unwrap_or_default();
                    tracing::warn!("sign session object has no 'state' field. Keys: {:?}", keys);
                }
            }
            Err(e) => {
                if start.elapsed().as_secs() == 30 {
                    tracing::warn!("failed to fetch sign session: {e}");
                }
            }
        }
        tokio::time::sleep(poll_interval).await;
    }
}

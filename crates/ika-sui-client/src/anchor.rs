// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Helpers for producing OCS bootstrap material from a Sui fullnode.
//!
//! - [`fetch_last_eoe_checkpoint_digest`]: walks back to the most
//!   recent end-of-epoch summary and returns its digest. This is the
//!   production trust anchor; operators paste it into
//!   `NodeConfig.sui_connector_config.sui_trusted_anchor`.
//! - [`fetch_genesis_committee`]: returns `committee[0]`. Used only by
//!   localnet/test bootstrap (the unsafe-genesis-committee path) when
//!   the chain hasn't reached its first end-of-epoch yet.
//!
//! Both used by `ika-swarm-config` for JIT bootstrap and by operator
//! tooling. Same code path either way.

use sui_rpc_api::Client as SuiRpcClient;
use sui_rpc_api::proto::sui::rpc::v2 as proto;
use sui_types::committee::Committee;
use sui_types::digests::CheckpointDigest;
use sui_types::message_envelope::Message;

use crate::transport::TransportError;

/// Connect to `grpc_url` and return the digest of the *latest
/// end-of-epoch* `CertifiedCheckpointSummary`. The validator looks
/// this up by digest at boot, asserts the digest match, and extracts
/// `committee[E+1]` from `summary.end_of_epoch_data`.
///
/// Errors with [`TransportError::NotFound`] when the chain hasn't
/// reached its first end-of-epoch yet (epoch 0 still in progress).
/// Callers in localnet flows should fall back to
/// [`fetch_genesis_committee`] in that case.
pub async fn fetch_last_eoe_checkpoint_digest(
    grpc_url: &str,
) -> Result<CheckpointDigest, TransportError> {
    let mut client = SuiRpcClient::new(grpc_url)
        .map_err(|e| TransportError::Network(format!("connect {grpc_url}: {e}")))?;

    // We want the last checkpoint of the previous epoch (= the last
    // *end-of-epoch* checkpoint up to now). The latest summary's
    // `end_of_epoch_data` is `Some` only when it sits exactly on a
    // boundary, so we resolve via "epoch E-1's last checkpoint" via
    // `GetEpoch`, then fetch that summary.
    let latest = client
        .get_latest_checkpoint()
        .await
        .map_err(|s| TransportError::Network(format!("get_latest_checkpoint: {s}")))?;
    let current_epoch = latest.epoch();
    if current_epoch == 0 {
        return Err(TransportError::NotFound(
            "chain has not reached its first end-of-epoch yet (still in epoch 0); \
             use sui_unsafe_genesis_committee for localnet bootstrap"
                .into(),
        ));
    }

    let prev_epoch = current_epoch - 1;
    let mut request = proto::GetEpochRequest::default();
    request.epoch = Some(prev_epoch);
    let response = client
        .inner_mut()
        .clone()
        .ledger_client()
        .get_epoch(request)
        .await
        .map_err(|s| TransportError::Network(format!("get_epoch({prev_epoch}): {s}")))?
        .into_inner();
    let info = response
        .epoch
        .ok_or_else(|| TransportError::NotFound(format!("epoch {prev_epoch} info not found")))?;
    let last_seq = info.last_checkpoint.ok_or_else(|| {
        TransportError::NotFound(format!(
            "last_checkpoint not yet set for epoch {prev_epoch}"
        ))
    })?;

    let summary = client
        .get_checkpoint_summary(last_seq)
        .await
        .map_err(|s| TransportError::Network(format!("get_checkpoint_summary({last_seq}): {s}")))?;
    if summary.data().end_of_epoch_data.is_none() {
        return Err(TransportError::Network(format!(
            "checkpoint {last_seq} (epoch {prev_epoch} last) is missing end_of_epoch_data"
        )));
    }
    Ok(summary.data().digest())
}

/// Connect to `grpc_url` and return the genesis committee
/// (`committee[0]`). Used only by localnet/test bootstrap when no
/// end-of-epoch summary exists yet.
pub async fn fetch_genesis_committee(grpc_url: &str) -> Result<Committee, TransportError> {
    let client = SuiRpcClient::new(grpc_url)
        .map_err(|e| TransportError::Network(format!("connect {grpc_url}: {e}")))?;
    client
        .get_committee(Some(0))
        .await
        .map_err(|s| TransportError::Network(format!("get_committee(0): {s}")))
}

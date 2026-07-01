// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Helpers for producing OCS bootstrap material from a Sui fullnode.
//!
//! - [`fetch_genesis_committee`]: returns `committee[0]`. Used by
//!   localnet/test bootstrap when the chain hasn't reached its first
//!   end-of-epoch yet. Used by `ika-swarm-config` for JIT bootstrap.

use sui_rpc_api::Client as SuiRpcClient;
use sui_types::committee::Committee;

use crate::transport::TransportError;

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

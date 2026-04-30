// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! IKA coin lookups.

use anyhow::{Context, Result};
use ika_types::messages_dwallet_mpc::IkaNetworkConfig;
use sui_types::base_types::{ObjectID, SuiAddress};

/// Auto-find an IKA coin owned by `owner`.
pub async fn find_ika_coin(
    sdk_client: &sui_sdk::SuiClient,
    owner: SuiAddress,
    config: &IkaNetworkConfig,
) -> Result<ObjectID> {
    let coin_type = format!("{}::ika::IKA", config.packages.ika_package_id);
    let coins = sdk_client
        .coin_read_api()
        .get_coins(owner, Some(coin_type.clone()), None, Some(1))
        .await
        .context("Failed to query IKA coins")?;
    let coin =
        coins.data.into_iter().next().ok_or_else(|| {
            anyhow::anyhow!("No IKA coins found for {owner}. Coin type: {coin_type}")
        })?;
    Ok(coin.coin_object_id)
}

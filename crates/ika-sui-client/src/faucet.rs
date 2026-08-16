// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use sui_rpc::faucet::FaucetClient;
use sui_types::base_types::SuiAddress;

/// Requests test SUI using the standalone SDK faucet client.
///
/// Ika historically accepted the full legacy `/gas` endpoint. The standalone
/// client accepts the service root and calls `/v2/gas`, so normalize both old
/// and new endpoint forms at this boundary.
pub async fn request_tokens_from_faucet(
    address: SuiAddress,
    faucet_url: impl AsRef<str>,
) -> Result<(), anyhow::Error> {
    let faucet_url = normalize_faucet_url(faucet_url.as_ref());
    let address = address.to_string().parse()?;

    FaucetClient::new(faucet_url)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?
        .request(address)
        .await
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    Ok(())
}

fn normalize_faucet_url(faucet_url: &str) -> String {
    let faucet_url = faucet_url.trim_end_matches('/');
    let faucet_url = faucet_url
        .strip_suffix("/v2/gas")
        .or_else(|| faucet_url.strip_suffix("/gas"))
        .unwrap_or(faucet_url);
    format!("{faucet_url}/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_faucet_urls_are_accepted() {
        for url in [
            "http://127.0.0.1:9123",
            "http://127.0.0.1:9123/",
            "http://127.0.0.1:9123/gas",
            "http://127.0.0.1:9123/v2/gas",
        ] {
            assert_eq!(normalize_faucet_url(url), "http://127.0.0.1:9123/");
        }
    }
}

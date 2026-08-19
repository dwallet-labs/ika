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
    if faucet_url.ends_with("/gas") && !faucet_url.ends_with("/v2/gas") {
        let response = reqwest::Client::new()
            .post(&faucet_url)
            .json(&serde_json::json!({
                "FixedAmountRequest": { "recipient": address.to_string() }
            }))
            .send()
            .await?;
        anyhow::ensure!(
            response.status().is_success(),
            "faucet request was unsuccessful: {}",
            response.status()
        );
        // The legacy local faucet can return an error-shaped body after a
        // successful 2xx drip. Callers only need delivery, not response coins.
        return Ok(());
    }
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
    if faucet_url.ends_with("/gas") && !faucet_url.ends_with("/v2/gas") {
        return faucet_url.to_owned();
    }
    let faucet_url = faucet_url.strip_suffix("/v2/gas").unwrap_or(faucet_url);
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
            "http://127.0.0.1:9123/v2/gas",
        ] {
            assert_eq!(normalize_faucet_url(url), "http://127.0.0.1:9123/");
        }
        assert_eq!(
            normalize_faucet_url("http://127.0.0.1:9123/gas"),
            "http://127.0.0.1:9123/gas"
        );
        assert_eq!(
            normalize_faucet_url("http://127.0.0.1:9123/v1/gas"),
            "http://127.0.0.1:9123/v1/gas"
        );
    }
}

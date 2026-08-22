// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Validation of the **Sui** chain a proxy instance is pointed at.
//!
//! The proxy resolves ika's on-chain IDs over a Sui gRPC endpoint, so a
//! misconfigured endpoint (mainnet config against a testnet fullnode) must fail
//! the boot loudly. The comparison lives here — separated from the client call
//! in `main.rs` — so it can be unit tested without a live Sui endpoint; the
//! proxy's `SuiConnectorClient` is a concrete type alias with no trait seam to
//! mock.
//!
//! The identifiers below MUST come from [`sui_types::digests`]. `ika_types`
//! exports functions with the very same names that return **ika's** chain
//! identifiers; comparing a Sui chain identifier against those can never match,
//! which is what crash-looped `ika-proxy` v1.4.0 (#2091).

use anyhow::Result;
use ika_config::node::SuiChainIdentifier;
use sui_types::digests::{get_mainnet_chain_identifier, get_testnet_chain_identifier};

/// The Sui chain identifier a proxy configured for `chain` must observe, or
/// `None` when the chain is not a well-known public one and therefore cannot be
/// pinned to a compiled-in expectation.
pub fn expected_sui_chain_identifier(chain: SuiChainIdentifier) -> Option<String> {
    match chain {
        SuiChainIdentifier::Mainnet => Some(get_mainnet_chain_identifier().to_string()),
        SuiChainIdentifier::Testnet => Some(get_testnet_chain_identifier().to_string()),
        SuiChainIdentifier::Devnet | SuiChainIdentifier::Custom => None,
    }
}

/// Compare the chain identifier reported by the configured gRPC endpoint against
/// the compiled-in expectation for `expected_chain`. Devnet/Custom always pass.
pub fn check_sui_chain_identifier(
    expected_chain: SuiChainIdentifier,
    actual_chain: &str,
) -> Result<()> {
    let Some(expected_identifier) = expected_sui_chain_identifier(expected_chain) else {
        return Ok(());
    };
    if expected_identifier != actual_chain {
        anyhow::bail!(
            "expected Sui chain {expected_chain} ({expected_identifier}), \
             but connected to {actual_chain}"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The public Sui chain identifiers, as reported by a fullnode's
    /// `getChainIdentifier` and logged by `ika_sui_client` on connect.
    const SUI_MAINNET: &str = "35834a8a";
    const SUI_TESTNET: &str = "4c78adac";

    /// The regression guard for #2091: the proxy's expectations must be **Sui's**
    /// chain identifiers, never ika's namesake constants from `ika_types::digests`.
    /// Pre-fix these expectations were ika's own chain IDs, so every Mainnet- or
    /// Testnet-configured proxy rejected the legitimate chain it had just
    /// connected to and exited non-zero.
    #[test]
    fn expectations_are_sui_chain_ids_not_ika_ones() {
        let mainnet = expected_sui_chain_identifier(SuiChainIdentifier::Mainnet).unwrap();
        let testnet = expected_sui_chain_identifier(SuiChainIdentifier::Testnet).unwrap();

        assert_eq!(
            mainnet,
            sui_types::digests::get_mainnet_chain_identifier().to_string(),
            "the Mainnet expectation must be Sui's mainnet chain identifier"
        );
        assert_eq!(
            testnet,
            sui_types::digests::get_testnet_chain_identifier().to_string(),
            "the Testnet expectation must be Sui's testnet chain identifier"
        );
        assert_eq!(mainnet, SUI_MAINNET);
        assert_eq!(testnet, SUI_TESTNET);

        assert_ne!(
            mainnet,
            ika_types::digests::get_ika_mainnet_chain_identifier().to_string(),
            "ika's own mainnet chain identifier is NOT a Sui chain identifier"
        );
        assert_ne!(
            testnet,
            ika_types::digests::get_ika_testnet_chain_identifier().to_string(),
            "ika's own testnet chain identifier is NOT a Sui chain identifier"
        );
    }

    /// Devnet and Custom have no compiled-in expectation, so any chain passes.
    #[test]
    fn unpinned_chains_have_no_expectation() {
        assert!(expected_sui_chain_identifier(SuiChainIdentifier::Devnet).is_none());
        assert!(expected_sui_chain_identifier(SuiChainIdentifier::Custom).is_none());
        check_sui_chain_identifier(SuiChainIdentifier::Devnet, "deadbeef").unwrap();
        check_sui_chain_identifier(SuiChainIdentifier::Custom, "deadbeef").unwrap();
    }

    /// The exact reproduction from #2091: a Testnet-configured proxy pointed at
    /// `https://fullnode.testnet.sui.io:443`, which reports `4c78adac`.
    #[test]
    fn public_sui_chains_are_accepted() {
        check_sui_chain_identifier(SuiChainIdentifier::Testnet, SUI_TESTNET)
            .expect("a Testnet-configured proxy must accept Sui testnet");
        check_sui_chain_identifier(SuiChainIdentifier::Mainnet, SUI_MAINNET)
            .expect("a Mainnet-configured proxy must accept Sui mainnet");
    }

    /// A genuinely wrong endpoint must still fail the boot, and the message must
    /// name the expected identifier — printing only the chain *name* is what made
    /// #2091 read as "Testnet != 4c78adac" and hid the real cause.
    #[test]
    fn crossed_chains_are_rejected_with_the_expected_identifier() {
        let err = check_sui_chain_identifier(SuiChainIdentifier::Mainnet, SUI_TESTNET)
            .expect_err("a Mainnet-configured proxy must reject Sui testnet");
        let msg = err.to_string();
        assert_eq!(
            msg,
            format!("expected Sui chain Mainnet ({SUI_MAINNET}), but connected to {SUI_TESTNET}")
        );

        let err = check_sui_chain_identifier(SuiChainIdentifier::Testnet, SUI_MAINNET)
            .expect_err("a Testnet-configured proxy must reject Sui mainnet");
        assert_eq!(
            err.to_string(),
            format!("expected Sui chain Testnet ({SUI_TESTNET}), but connected to {SUI_MAINNET}")
        );
    }
}

// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Load and verify a Sui **genesis blob** as the OCS trust root.
//!
//! This replaces the operator-pinned end-of-epoch "anchor" (a recent,
//! out-of-band, weak-subjectivity digest). The genesis checkpoint digest *is*
//! the Sui chain identifier, which ika already hardcodes per chain
//! ([`ika_types::digests::get_mainnet_chain_identifier`] /
//! [`get_testnet_chain_identifier`](ika_types::digests::get_testnet_chain_identifier)).
//!
//! So the trust root shrinks to a 32-byte compiled-in constant: we load the
//! genesis blob, recompute its checkpoint digest, assert it equals the
//! compiled-in identifier for the configured chain, and only then return
//! `committee[0]`. Verify everything, trust nothing — the blob itself is
//! checked against the constant, never trusted wholesale. From `committee[0]`
//! the OCS committee ratchet walks the end-of-epoch checkpoint chain forward to
//! the live epoch (see the OCS spec).
//!
//! On localnet / private nets (`Devnet` / `Custom`) there is no canonical
//! compiled-in identifier, so the genesis blob's own digest is taken as the
//! root — the swarm/operator is responsible for supplying a trusted blob, the
//! same trust placement Sui's own nodes use for a local genesis.

use std::path::Path;

use ika_config::node::SuiChainIdentifier;
use ika_types::digests::{
    ChainIdentifier, get_mainnet_chain_identifier, get_testnet_chain_identifier,
};
use sui_config::genesis::Genesis;
use sui_types::base_types::ObjectID;
use sui_types::committee::Committee;
use sui_types::message_envelope::Message;

/// Error loading or verifying a Sui genesis blob.
#[derive(Debug, thiserror::Error)]
pub enum GenesisError {
    #[error("failed to load Sui genesis blob from {path}: {source}")]
    Load {
        path: String,
        #[source]
        source: anyhow::Error,
    },
    #[error("failed to decode embedded Sui genesis blob: {0}")]
    Decode(#[source] anyhow::Error),
    #[error(
        "Sui genesis chain identifier mismatch for {chain}: blob's genesis \
         checkpoint digest is {got}, but the binary's compiled-in identifier \
         for this chain is {expected} — wrong genesis blob for this chain"
    )]
    ChainMismatch {
        chain: SuiChainIdentifier,
        got: String,
        expected: String,
    },
}

/// The verified bootstrap material extracted from a Sui genesis blob: the
/// epoch-0 committee and the (verified) chain identifier.
#[derive(Clone, Debug)]
pub struct SuiGenesisBootstrap {
    /// `committee[0]` — the genesis Sui committee the OCS ratchet starts from.
    pub committee: Committee,
    /// The genesis checkpoint digest, i.e. the Sui chain identifier this blob
    /// belongs to. For `Mainnet`/`Testnet` this has been verified to equal the
    /// compiled-in constant; for `Devnet`/`Custom` it is the blob's own digest.
    pub chain_identifier: ChainIdentifier,
}

/// Load a Sui genesis blob from `path` and verify it against the compiled-in
/// chain identifier for `chain`.
pub fn load_and_verify_sui_genesis(
    path: impl AsRef<Path>,
    chain: SuiChainIdentifier,
) -> Result<SuiGenesisBootstrap, GenesisError> {
    let path = path.as_ref();
    let genesis = Genesis::load(path).map_err(|source| GenesisError::Load {
        path: path.display().to_string(),
        source,
    })?;
    verify_genesis(genesis, chain)
}

/// Decode a Sui genesis blob from in-memory bytes (e.g. release-embedded via
/// `include_bytes!`) and verify it against the compiled-in chain identifier.
pub fn load_and_verify_sui_genesis_bytes(
    bytes: &[u8],
    chain: SuiChainIdentifier,
) -> Result<SuiGenesisBootstrap, GenesisError> {
    let genesis: Genesis = bcs::from_bytes(bytes).map_err(|e| GenesisError::Decode(e.into()))?;
    verify_genesis(genesis, chain)
}

fn verify_genesis(
    genesis: Genesis,
    chain: SuiChainIdentifier,
) -> Result<SuiGenesisBootstrap, GenesisError> {
    // The genesis checkpoint digest IS the chain identifier.
    let checkpoint = genesis.checkpoint();
    let genesis_digest = checkpoint.data().digest();
    let chain_identifier = ChainIdentifier::from(ObjectID::new(genesis_digest.into_inner()));

    // Verify the blob against the binary's compiled-in 32-byte root for the
    // public chains. A swapped/forged blob is caught here.
    if let Some(expected) = compiled_in_chain_identifier(chain) {
        if chain_identifier != expected {
            return Err(GenesisError::ChainMismatch {
                chain,
                got: chain_identifier.base58_encode(),
                expected: expected.base58_encode(),
            });
        }
    }

    Ok(SuiGenesisBootstrap {
        committee: genesis.committee(),
        chain_identifier,
    })
}

/// The binary's compiled-in Sui chain identifier (= genesis checkpoint digest)
/// for the public chains. `None` for `Devnet`/`Custom`, where the genesis
/// blob's own digest is the root.
pub fn compiled_in_chain_identifier(chain: SuiChainIdentifier) -> Option<ChainIdentifier> {
    match chain {
        SuiChainIdentifier::Mainnet => Some(get_mainnet_chain_identifier()),
        SuiChainIdentifier::Testnet => Some(get_testnet_chain_identifier()),
        SuiChainIdentifier::Devnet | SuiChainIdentifier::Custom => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A real Sui genesis blob (a local test chain, not mainnet/testnet),
    // vendored from the pinned Sui upstream's light-client test fixtures.
    const FIXTURE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/sui_genesis.blob"
    );

    #[test]
    fn loads_genesis_and_derives_chain_identifier_for_custom() {
        let boot = load_and_verify_sui_genesis(FIXTURE, SuiChainIdentifier::Custom)
            .expect("a Custom chain skips the compiled-in check, so a test genesis loads");
        assert!(
            boot.committee.num_members() > 0,
            "committee[0] must be non-empty"
        );
        assert_ne!(
            boot.chain_identifier,
            ChainIdentifier::default(),
            "the chain identifier is the genesis checkpoint digest"
        );
    }

    #[test]
    fn rejects_genesis_whose_digest_is_not_the_compiled_in_mainnet_identifier() {
        // The test genesis is not mainnet, so verifying it against the
        // compiled-in mainnet identifier must fail closed.
        let err = load_and_verify_sui_genesis(FIXTURE, SuiChainIdentifier::Mainnet)
            .expect_err("a non-mainnet blob must be rejected against the mainnet root");
        assert!(
            matches!(err, GenesisError::ChainMismatch { .. }),
            "expected ChainMismatch, got {err:?}"
        );
    }

    #[test]
    fn bytes_and_path_loaders_agree() {
        let from_path = load_and_verify_sui_genesis(FIXTURE, SuiChainIdentifier::Custom).unwrap();
        let bytes = std::fs::read(FIXTURE).unwrap();
        let from_bytes =
            load_and_verify_sui_genesis_bytes(&bytes, SuiChainIdentifier::Custom).unwrap();
        assert_eq!(from_path.chain_identifier, from_bytes.chain_identifier);
    }

    #[test]
    fn corrupt_genesis_bytes_fail_closed() {
        // Garbage / truncated bytes must not deserialize into a Genesis — the
        // loader fails closed rather than bootstrapping from junk.
        let garbage = b"not a valid Sui genesis blob";
        let err = load_and_verify_sui_genesis_bytes(garbage, SuiChainIdentifier::Custom)
            .expect_err("garbage bytes must be rejected");
        assert!(matches!(err, GenesisError::Decode(_)), "got {err:?}");

        // A truncated prefix of a real blob is also rejected.
        let real = std::fs::read(FIXTURE).unwrap();
        let truncated = &real[..real.len() / 2];
        let err = load_and_verify_sui_genesis_bytes(truncated, SuiChainIdentifier::Custom)
            .expect_err("a truncated blob must be rejected");
        assert!(matches!(err, GenesisError::Decode(_)), "got {err:?}");
    }

    #[test]
    fn compiled_in_identifiers_map_public_chains_only() {
        assert_eq!(
            compiled_in_chain_identifier(SuiChainIdentifier::Mainnet),
            Some(get_mainnet_chain_identifier())
        );
        assert_eq!(
            compiled_in_chain_identifier(SuiChainIdentifier::Testnet),
            Some(get_testnet_chain_identifier())
        );
        assert_eq!(
            compiled_in_chain_identifier(SuiChainIdentifier::Devnet),
            None
        );
        assert_eq!(
            compiled_in_chain_identifier(SuiChainIdentifier::Custom),
            None
        );
    }
}

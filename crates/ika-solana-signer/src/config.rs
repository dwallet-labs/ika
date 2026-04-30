// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use std::time::Duration;

use ika_types::messages_dwallet_mpc::IkaNetworkConfig;
use sui_types::{base_types::ObjectID, crypto::SuiKeyPair};

/// How [`crate::IkaSigner`] obtains the user's secret key share for the dWallet.
#[derive(Clone)]
pub enum SecretShareSource {
    /// Raw bytes already on hand (e.g. read from disk by the caller).
    Bytes(Vec<u8>),

    /// The signer should fetch the encrypted share from chain and decrypt it
    /// using the supplied class-groups decryption key. Pair this with the
    /// `derive_encryption_keys` helper from `ika-sui-client::dwallet_signer`
    /// applied to the user's seed.
    OnChainEncrypted {
        /// Class-groups decryption key derived from the user's seed.
        decryption_key: Vec<u8>,
        /// `encryption_key_address` (Ed25519 signing keypair public key, as
        /// `SuiAddress`) used to find the matching encrypted share on chain.
        encryption_key_address: sui_types::base_types::SuiAddress,
    },
}

/// Presign strategy.
#[derive(Clone)]
pub enum PresignMode {
    /// Each [`crate::IkaSigner::sign_message`] call internally requests a fresh
    /// global presign, polls until completion, auto-verifies, and uses it once.
    /// Stateless but adds an extra MPC round-trip per signature.
    PerSignGlobal,

    /// Use a pre-verified presign cap. Single-shot — once consumed, subsequent
    /// `sign_message` calls return [`crate::IkaSignerError::PresignCapConsumed`].
    /// Reconstruct the signer with a fresh cap to sign again.
    SingleProvided(ObjectID),
}

/// Configuration for [`crate::IkaSigner::create`].
pub struct IkaSignerConfig {
    /// Full Sui JSON-RPC URL the signer will talk to.
    pub sui_rpc_url: String,

    /// On-chain locations of the Ika packages and shared objects.
    pub ika_network_config: IkaNetworkConfig,

    /// Keypair that pays Sui gas and IKA fees, and signs the on-chain
    /// `request_sign` / `request_global_presign` transactions.
    pub payer: SuiKeyPair,

    /// dWallet object ID. Must be ed25519 and in `Active` state.
    pub dwallet_id: ObjectID,

    /// dWallet capability object the user owns (passed to `request_sign`).
    pub dwallet_cap_id: ObjectID,

    /// How to source the user secret key share for centralized signing.
    pub share_source: SecretShareSource,

    pub presign_mode: PresignMode,

    /// IKA payment coin object. Must exist before signing — the CLI's
    /// "auto-create zero IKA coin" path is not done here.
    pub ika_coin_id: ObjectID,

    /// Optional explicit SUI coin to pay with. `None` uses the gas coin
    /// (matches the TS SDK's `transaction.gas` pattern).
    pub sui_coin_id: Option<ObjectID>,

    pub gas_budget: u64,

    /// Sign-session poll timeout. Defaults to 300s if `None`.
    pub poll_timeout: Option<Duration>,

    /// Sign-session poll interval. Defaults to 3s if `None`.
    pub poll_interval: Option<Duration>,
}

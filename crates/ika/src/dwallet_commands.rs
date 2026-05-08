// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::*;
use dwallet_mpc_centralized_party::{
    advance_centralized_sign_party, create_dkg_output_by_curve_v2,
    create_imported_dwallet_centralized_step_inner_v2, decrypt_user_share_v2,
    encrypt_secret_key_share_and_prove_v2, generate_cg_keypair_from_seed,
    network_dkg_public_output_to_protocol_pp_inner,
    reconfiguration_public_output_to_protocol_pp_inner,
};
use fastcrypto::ed25519::Ed25519KeyPair;
use fastcrypto::traits::{KeyPair, Signer, ToFromBytes};
use ika_config::{IKA_SUI_CONFIG, ika_config_dir};
use ika_sui_client::SuiConnectorClient;
use ika_sui_client::ika_dwallet_transactions;
use ika_sui_client::metrics::SuiClientMetrics;
use ika_types::messages_dwallet_mpc::{IkaNetworkConfig, SessionIdentifier};
use serde::Serialize;
use sui_json_rpc_types::{SuiObjectDataOptions, SuiTransactionBlockEffectsAPI};
use sui_keys::keystore::AccountKeystore;
use sui_sdk::wallet_context::WalletContext;
use sui_types::base_types::{ObjectID, SuiAddress};

use dwallet_mpc_types::dwallet_mpc;

use crate::output::CommandOutput;
use crate::read_ika_sui_config_yaml;

const DEFAULT_GAS_BUDGET: u64 = 200_000_000; // 0.2 SUI

/// Common payment arguments for dWallet transactions.
#[derive(Args, Debug, Default, Clone)]
pub struct PaymentArgs {
    /// IKA coin object ID for payment. Auto-detected from wallet if omitted.
    #[arg(long)]
    pub ika_coin_id: Option<ObjectID>,
    /// SUI coin object ID for payment. Uses the gas coin if omitted.
    #[arg(long)]
    pub sui_coin_id: Option<ObjectID>,
}

/// Common transaction arguments (gas budget + config override).
#[derive(Args, Debug, Default, Clone)]
pub struct TxArgs {
    /// Override the default gas budget (in MIST).
    #[arg(long)]
    pub gas_budget: Option<u64>,
    /// Override the Ika network config path.
    #[arg(long)]
    pub ika_config: Option<PathBuf>,
}

/// Seed derivation arguments for encryption key operations.
#[derive(Args, Debug, Default, Clone)]
pub struct SeedArgs {
    /// Path to a 32-byte seed file. Mutually exclusive with address-based derivation.
    #[arg(long, conflicts_with_all = ["address"])]
    pub seed_file: Option<PathBuf>,
    /// Derive seed from a specific Sui address in the keystore (default: active address).
    #[arg(long)]
    pub address: Option<SuiAddress>,
    /// Key derivation index (default: 0). Used with address-based seed derivation.
    #[arg(long = "encryption-key-index", default_value = "0")]
    pub index: u32,
    /// Use legacy V1 hash (curve byte always 0). Only needed for keys registered before the fix.
    #[arg(long)]
    pub legacy_hash: bool,
}

/// Future sign subcommands: create (partial signature) and fulfill (complete signature).
#[derive(Subcommand)]
#[clap(rename_all = "kebab-case")]
pub enum IkaDWalletFutureSignCommand {
    /// Create a partial user signature (first step of future signing).
    ///
    /// Pass --dwallet-id to auto-fetch curve and DKG output from chain.
    #[clap(name = "create")]
    Create {
        /// The dWallet ID.
        #[clap(long)]
        dwallet_id: ObjectID,
        /// The message to sign (hex-encoded).
        #[clap(long)]
        message: String,
        /// The hash scheme (keccak256, sha256, double-sha256, sha512, merlin).
        #[clap(long, value_parser = ["keccak256", "sha256", "double-sha256", "sha512", "merlin"])]
        hash_scheme: String,
        /// The verified presign cap ID.
        #[clap(long)]
        presign_cap_id: ObjectID,
        /// Path to the user secret share file. If omitted, decrypts from chain.
        #[clap(long, conflicts_with = "secret_share_hex")]
        secret_share: Option<PathBuf>,
        /// The user secret share as a hex string (alternative to --secret-share file).
        #[clap(long, conflicts_with = "secret_share")]
        secret_share_hex: Option<String>,
        /// The presign output (hex-encoded). Auto-fetched from --presign-cap-id if omitted.
        #[clap(long)]
        presign_output: Option<String>,
        /// The signature algorithm (ecdsa, taproot, eddsa, schnorrkel).
        #[clap(long, value_parser = ["ecdsa", "taproot", "eddsa", "schnorrkel"])]
        signature_algorithm: String,
        /// The curve used by the dWallet. Auto-detected from --dwallet-id if omitted.
        #[clap(long, value_parser = ["secp256k1", "secp256r1", "ed25519", "ristretto"])]
        curve: Option<String>,
        /// The dWallet's decentralized DKG public output (hex-encoded).
        /// Auto-fetched from --dwallet-id if omitted.
        #[clap(long)]
        dkg_output: Option<String>,
        #[command(flatten)]
        payment: PaymentArgs,
        #[command(flatten)]
        seed: SeedArgs,
        #[command(flatten)]
        tx: TxArgs,
    },
    /// Fulfill a future sign using a partial user signature cap (second step).
    ///
    /// Verifies the partial user signature cap, approves the message, and submits
    /// the final sign request to the network.
    #[clap(name = "fulfill")]
    Fulfill {
        /// The partial user signature cap ID (from `future-sign create`).
        #[clap(long)]
        partial_cap_id: ObjectID,
        /// The dWallet cap ID (for message approval).
        #[clap(long)]
        dwallet_cap_id: ObjectID,
        /// The dWallet ID (used to resolve curve for algorithm/hash validation).
        #[clap(long)]
        dwallet_id: ObjectID,
        /// The message to sign (hex-encoded).
        #[clap(long)]
        message: String,
        /// The signature algorithm (ecdsa, taproot, eddsa, schnorrkel).
        #[clap(long, value_parser = ["ecdsa", "taproot", "eddsa", "schnorrkel"])]
        signature_algorithm: String,
        /// The hash scheme (keccak256, sha256, double-sha256, sha512, merlin).
        #[clap(long, value_parser = ["keccak256", "sha256", "double-sha256", "sha512", "merlin"])]
        hash_scheme: String,
        #[command(flatten)]
        payment: PaymentArgs,
        #[command(flatten)]
        tx: TxArgs,
        /// Wait for the sign session to complete and return the signature.
        #[clap(long)]
        wait: bool,
    },
}

/// dWallet share management subcommands.
#[derive(Subcommand)]
#[clap(rename_all = "kebab-case")]
pub enum IkaDWalletShareCommand {
    /// Make user secret key shares public (enables autonomous signing).
    #[clap(name = "make-public")]
    MakePublic {
        /// The dWallet ID to make shares public for.
        #[clap(long)]
        dwallet_id: ObjectID,
        /// Path to the user secret share file. If omitted, decrypts from chain.
        #[clap(long, conflicts_with = "secret_share_hex")]
        secret_share: Option<PathBuf>,
        /// The user secret share as a hex string.
        #[clap(long, conflicts_with = "secret_share")]
        secret_share_hex: Option<String>,
        #[command(flatten)]
        seed: SeedArgs,
        #[command(flatten)]
        payment: PaymentArgs,
        #[command(flatten)]
        tx: TxArgs,
    },
    /// Re-encrypt user share for a different encryption key.
    #[clap(name = "re-encrypt")]
    ReEncrypt {
        /// The dWallet ID to re-encrypt shares for.
        #[clap(long)]
        dwallet_id: ObjectID,
        /// The destination address to re-encrypt for.
        #[clap(long)]
        destination_address: SuiAddress,
        /// Path to the user secret share file. If omitted, decrypts from chain.
        #[clap(long, conflicts_with = "secret_share_hex")]
        secret_share: Option<PathBuf>,
        /// The user secret share as a hex string.
        #[clap(long, conflicts_with = "secret_share")]
        secret_share_hex: Option<String>,
        /// The source encrypted user secret key share ID.
        #[clap(long)]
        source_encrypted_share_id: ObjectID,
        /// The destination user's encryption key value (hex-encoded).
        #[clap(long)]
        destination_encryption_key: String,
        /// The curve used for this dWallet.
        #[clap(long, value_parser = ["secp256k1", "secp256r1", "ed25519", "ristretto"])]
        curve: String,
        #[command(flatten)]
        seed: SeedArgs,
        #[command(flatten)]
        payment: PaymentArgs,
        #[command(flatten)]
        tx: TxArgs,
    },
    /// Accept a re-encrypted user share.
    #[clap(name = "accept")]
    Accept {
        /// The dWallet ID.
        #[clap(long)]
        dwallet_id: ObjectID,
        /// The encrypted share object ID.
        #[clap(long)]
        encrypted_share_id: ObjectID,
        /// User output signature (hex-encoded).
        #[clap(long)]
        user_output_signature: String,
        #[command(flatten)]
        tx: TxArgs,
    },
}

/// dWallet operations: create, sign, presign, import, and key management.
#[derive(Subcommand)]
#[clap(rename_all = "kebab-case")]
pub enum IkaDWalletCommand {
    /// Create a new dWallet via DKG (Distributed Key Generation).
    #[clap(name = "create")]
    Create {
        /// The elliptic curve to use.
        #[clap(long, value_parser = ["secp256k1", "secp256r1", "ed25519", "ristretto"])]
        curve: String,
        /// Where to save the user secret share. If omitted, the secret share is printed
        /// as hex in the command output (and included in JSON mode) but NOT saved to disk.
        #[clap(long)]
        output_secret: Option<PathBuf>,
        /// Use public user secret key share variant (shared dWallet).
        #[clap(long)]
        public_share: bool,
        /// Optional message to sign during DKG (hex-encoded).
        #[clap(long)]
        sign_message: Option<String>,
        /// Hash scheme for sign-during-DKG (keccak256, sha256, double-sha256, sha512, merlin).
        #[clap(long, value_parser = ["keccak256", "sha256", "double-sha256", "sha512", "merlin"])]
        hash_scheme: Option<String>,
        #[command(flatten)]
        payment: PaymentArgs,
        #[command(flatten)]
        seed: SeedArgs,
        #[command(flatten)]
        tx: TxArgs,
    },

    /// Request a signature from a dWallet.
    ///
    /// Pass --dwallet-id to auto-fetch curve and DKG output from chain.
    /// Or provide --curve and --dkg-output manually for offline use.
    ///
    /// The secret share can be provided in three ways (in priority order):
    /// 1. `--secret-share <file>` — read from a local file
    /// 2. `--secret-share-hex <hex>` — pass directly as hex
    /// 3. Omit both — the CLI derives the decryption key from your Sui keystore
    ///    (seed args), fetches the encrypted share from chain, and decrypts it.
    ///    Requires `--dwallet-id`.
    #[clap(name = "sign")]
    Sign {
        /// The dWallet capability object ID.
        #[clap(long)]
        dwallet_cap_id: ObjectID,
        /// The message to sign (hex-encoded).
        #[clap(long)]
        message: String,
        /// The signature algorithm (ecdsa, taproot, eddsa, schnorrkel).
        #[clap(long, value_parser = ["ecdsa", "taproot", "eddsa", "schnorrkel"])]
        signature_algorithm: String,
        /// The hash scheme (keccak256, sha256, double-sha256, sha512, merlin).
        #[clap(long, value_parser = ["keccak256", "sha256", "double-sha256", "sha512", "merlin"])]
        hash_scheme: String,
        /// Pre-existing presign cap ID (verified or unverified — auto-verified if needed).
        #[clap(long)]
        presign_cap_id: ObjectID,
        /// Path to the user secret share file. If omitted, the CLI will decrypt the
        /// on-chain encrypted share using your keystore-derived decryption key.
        #[clap(long, conflicts_with = "secret_share_hex")]
        secret_share: Option<PathBuf>,
        /// The user secret share as a hex string (alternative to --secret-share file).
        #[clap(long, conflicts_with = "secret_share")]
        secret_share_hex: Option<String>,
        /// The presign output (hex-encoded). Auto-fetched from --presign-cap-id if omitted.
        #[clap(long)]
        presign_output: Option<String>,
        /// The dWallet object ID. When provided, curve and DKG output are fetched from chain.
        /// Required when using on-chain secret share decryption.
        #[clap(long)]
        dwallet_id: Option<ObjectID>,
        /// The curve used by the dWallet. Auto-detected if --dwallet-id is provided.
        #[clap(long, value_parser = ["secp256k1", "secp256r1", "ed25519", "ristretto"])]
        curve: Option<String>,
        /// The dWallet's decentralized DKG public output (hex-encoded).
        /// Auto-fetched if --dwallet-id is provided.
        #[clap(long)]
        dkg_output: Option<String>,
        #[command(flatten)]
        payment: PaymentArgs,
        #[command(flatten)]
        seed: SeedArgs,
        #[command(flatten)]
        tx: TxArgs,
        /// Wait for the sign session to complete and return the signature.
        #[clap(long)]
        wait: bool,
    },

    /// Future/conditional signing operations.
    #[clap(name = "future-sign")]
    FutureSign {
        #[clap(subcommand)]
        cmd: IkaDWalletFutureSignCommand,
    },

    /// Request presigns for a dWallet.
    ///
    /// Use `--count` to create multiple presigns in a single transaction (max 20).
    /// With `--wait`, polls until all presigns complete and auto-verifies them.
    #[clap(name = "presign")]
    Presign {
        /// The dWallet ID.
        #[clap(long)]
        dwallet_id: ObjectID,
        /// The signature algorithm (ecdsa, taproot, eddsa, schnorrkel).
        #[clap(long, value_parser = ["ecdsa", "taproot", "eddsa", "schnorrkel"])]
        signature_algorithm: String,
        /// Number of presigns to create in a single transaction (1-20).
        #[clap(long, default_value = "1", value_parser = clap::value_parser!(u32).range(1..=20))]
        count: u32,
        #[command(flatten)]
        payment: PaymentArgs,
        #[command(flatten)]
        tx: TxArgs,
        /// Wait for presigns to complete and auto-verify the caps.
        #[clap(long)]
        wait: bool,
    },

    /// Request a global presign using network encryption key.
    ///
    /// With `--wait`, polls until the presign completes, auto-verifies it,
    /// and returns the verified presign cap ID ready for signing.
    #[clap(name = "global-presign")]
    GlobalPresign {
        /// The curve.
        #[clap(long, value_parser = ["secp256k1", "secp256r1", "ed25519", "ristretto"])]
        curve: String,
        /// The signature algorithm (ecdsa, taproot, eddsa, schnorrkel).
        #[clap(long, value_parser = ["ecdsa", "taproot", "eddsa", "schnorrkel"])]
        signature_algorithm: String,
        #[command(flatten)]
        payment: PaymentArgs,
        #[command(flatten)]
        tx: TxArgs,
        /// Wait for presign to complete and auto-verify the cap.
        #[clap(long)]
        wait: bool,
    },

    /// Import an external key as a dWallet.
    ///
    /// The secret key file format depends on the curve:
    /// - **secp256k1 / secp256r1**: 33 bytes (compressed public key prefix byte + 32-byte scalar)
    /// - **ed25519 / ristretto**: 32 bytes (raw scalar, must be a valid scalar for the curve)
    #[clap(name = "import")]
    Import {
        /// The curve.
        #[clap(long, value_parser = ["secp256k1", "secp256r1", "ed25519", "ristretto"])]
        curve: String,
        /// Path to the secret key file to import.
        ///
        /// For secp256k1/secp256r1: 33-byte file (compressed point prefix + 32-byte scalar).
        /// For ed25519/ristretto: 32-byte file (raw scalar, must be valid for the curve).
        #[clap(long = "secret-key")]
        secret_key: PathBuf,
        /// Where to save the user secret share. If omitted, the secret share is printed
        /// as hex in the command output (and included in JSON mode) but NOT saved to disk.
        #[clap(long)]
        output_secret: Option<PathBuf>,
        #[command(flatten)]
        payment: PaymentArgs,
        #[command(flatten)]
        seed: SeedArgs,
        #[command(flatten)]
        tx: TxArgs,
    },

    /// Register a user encryption key for dWallet operations.
    #[clap(name = "register-encryption-key")]
    RegisterEncryptionKey {
        /// The curve for which to register the encryption key.
        #[clap(long, value_parser = ["secp256k1", "secp256r1", "ed25519", "ristretto"])]
        curve: String,
        #[command(flatten)]
        seed: SeedArgs,
        #[command(flatten)]
        tx: TxArgs,
    },

    /// Get an encryption key by its object ID (returned from register-encryption-key).
    #[clap(name = "get-encryption-key")]
    GetEncryptionKey {
        /// The encryption key object ID (returned from register-encryption-key).
        #[clap(long)]
        encryption_key_id: ObjectID,
        #[command(flatten)]
        tx: TxArgs,
    },

    /// Verify a presign capability.
    #[clap(name = "verify-presign")]
    VerifyPresign {
        /// The unverified presign cap ID.
        #[clap(long)]
        presign_cap_id: ObjectID,
        #[command(flatten)]
        tx: TxArgs,
    },

    /// Query dWallet information.
    #[clap(name = "get")]
    Get {
        /// The dWallet ID to query.
        #[clap(long)]
        dwallet_id: ObjectID,
        #[command(flatten)]
        tx: TxArgs,
    },

    /// Query current pricing information.
    #[clap(name = "pricing")]
    Pricing {
        #[command(flatten)]
        tx: TxArgs,
    },

    /// Generate a class-groups encryption keypair (offline utility).
    ///
    /// Outputs the encryption key (public) and decryption key in hex format.
    /// Useful for debugging or pre-generating keys before registration.
    #[clap(name = "generate-keypair")]
    GenerateKeypair {
        /// The curve for the keypair.
        #[clap(long, value_parser = ["secp256k1", "secp256r1", "ed25519", "ristretto"])]
        curve: String,
        #[command(flatten)]
        seed: SeedArgs,
    },

    /// List dWallet capabilities owned by the active address.
    #[clap(name = "list")]
    List {
        #[command(flatten)]
        tx: TxArgs,
    },

    /// List presign caps owned by the active address, grouped by status and curve.
    #[clap(name = "list-presigns")]
    ListPresigns {
        #[command(flatten)]
        tx: TxArgs,
    },

    /// Extract the signing public key from a dWallet.
    #[clap(name = "public-key")]
    PublicKey {
        /// The dWallet ID.
        #[clap(long)]
        dwallet_id: ObjectID,
        #[command(flatten)]
        tx: TxArgs,
    },

    /// Decrypt a user secret share from the on-chain encrypted share (offline utility).
    #[clap(name = "decrypt")]
    Decrypt {
        /// The dWallet ID.
        #[clap(long)]
        dwallet_id: ObjectID,
        /// Save decrypted secret share to this file.
        #[clap(long)]
        output_secret: Option<PathBuf>,
        #[command(flatten)]
        seed: SeedArgs,
        #[command(flatten)]
        tx: TxArgs,
    },

    /// Query current network epoch.
    #[clap(name = "epoch")]
    Epoch {
        #[command(flatten)]
        tx: TxArgs,
    },

    /// User share management operations.
    #[clap(name = "share")]
    Share {
        #[clap(subcommand)]
        cmd: IkaDWalletShareCommand,
    },
}

#[derive(Serialize)]
#[serde(tag = "type")]
pub enum IkaDWalletCommandResponse {
    #[serde(rename = "create")]
    Create {
        dwallet_id: String,
        dwallet_cap_id: String,
        public_key: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        encrypted_share_id: Option<String>,
        /// Hex-encoded secret share (present when --output-secret is not used).
        #[serde(skip_serializing_if = "Option::is_none")]
        secret_share: Option<String>,
        /// File path where the secret share was saved (present when --output-secret is used).
        #[serde(skip_serializing_if = "Option::is_none")]
        secret_share_path: Option<String>,
    },
    #[serde(rename = "sign")]
    Sign {
        digest: String,
        status: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        sign_session_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        signature: Option<String>,
    },
    #[serde(rename = "presign")]
    Presign {
        digest: String,
        status: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        presign_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        presign_cap_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        verified_presign_cap_id: Option<String>,
    },
    #[serde(rename = "register_encryption_key")]
    RegisterEncryptionKeyResponse {
        encryption_key_id: String,
        digest: String,
        status: String,
    },
    #[serde(rename = "get")]
    Get { dwallet: serde_json::Value },
    #[serde(rename = "pricing")]
    Pricing { pricing: serde_json::Value },
    #[serde(rename = "keypair")]
    Keypair {
        encryption_key: String,
        decryption_key: String,
        signer_public_key: String,
        seed: String,
    },
    #[serde(rename = "verify_presign")]
    VerifyPresign {
        digest: String,
        status: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        verified_presign_cap_id: Option<String>,
    },
    #[serde(rename = "list")]
    List { dwallets: Vec<serde_json::Value> },
    #[serde(rename = "list_presigns")]
    ListPresigns {
        verified: Vec<serde_json::Value>,
        unverified: Vec<serde_json::Value>,
    },
    #[serde(rename = "public_key")]
    PublicKey {
        dwallet_id: String,
        public_key: String,
    },
    #[serde(rename = "decrypt")]
    DecryptShare {
        dwallet_id: String,
        secret_share: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        secret_share_path: Option<String>,
    },
    #[serde(rename = "epoch")]
    Epoch { epoch: u64 },
    #[serde(rename = "transaction")]
    Transaction { digest: String, status: String },
}

impl CommandOutput for IkaDWalletCommandResponse {
    fn print_human(&self) {
        match self {
            Self::Create {
                dwallet_id,
                dwallet_cap_id,
                public_key,
                encrypted_share_id,
                secret_share,
                secret_share_path,
            } => {
                println!("dWallet created successfully.");
                println!("  dWallet ID: {dwallet_id}");
                println!("  Cap ID:     {dwallet_cap_id}");
                println!("  Public Key: {public_key}");
                if let Some(esid) = encrypted_share_id {
                    println!("  Encrypted Share ID: {esid}");
                }
                if let Some(path) = secret_share_path {
                    println!("  Secret share saved to: {path}");
                }
                if let Some(share) = secret_share {
                    println!("  Secret Share (hex): {share}");
                }
            }
            Self::Sign {
                digest,
                status,
                sign_session_id,
                signature,
            } => {
                println!("Sign request submitted.");
                println!("  Transaction: {digest}");
                println!("  Status:      {status}");
                if let Some(id) = sign_session_id {
                    println!("  Session ID:  {id}");
                }
                if let Some(sig) = signature {
                    println!("  Signature:   {sig}");
                }
            }
            Self::Presign {
                digest,
                status,
                presign_id,
                presign_cap_id,
                verified_presign_cap_id,
            } => {
                println!("Presign request submitted.");
                println!("  Transaction: {digest}");
                println!("  Status:      {status}");
                if let Some(pid) = presign_id {
                    println!("  Presign ID:  {pid}");
                }
                if let Some(cid) = presign_cap_id {
                    println!("  Presign Cap ID (unverified): {cid}");
                }
                if let Some(vcid) = verified_presign_cap_id {
                    println!("  Verified Presign Cap ID: {vcid}");
                }
            }
            Self::RegisterEncryptionKeyResponse {
                encryption_key_id,
                digest,
                status,
            } => {
                println!("Encryption key registered.");
                println!("  Encryption Key ID: {encryption_key_id}");
                println!("  Transaction:       {digest}");
                println!("  Status:            {status}");
            }
            Self::Get { dwallet } => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(dwallet).unwrap_or_default()
                );
            }
            Self::Pricing { pricing } => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(pricing).unwrap_or_default()
                );
            }
            Self::Keypair {
                encryption_key,
                decryption_key,
                signer_public_key,
                seed,
            } => {
                println!("Encryption Key (public): {encryption_key}");
                println!("Decryption Key (secret): {decryption_key}");
                println!("Signer Public Key:       {signer_public_key}");
                println!("Seed:                    {seed}");
            }
            Self::VerifyPresign {
                digest,
                status,
                verified_presign_cap_id,
            } => {
                println!("Presign cap verified.");
                println!("  Transaction: {digest}");
                println!("  Status:      {status}");
                if let Some(cap_id) = verified_presign_cap_id {
                    println!("  Verified Presign Cap ID: {cap_id}");
                }
            }
            Self::List { dwallets } => {
                if dwallets.is_empty() {
                    println!("No dWallets found.");
                } else {
                    for dw in dwallets {
                        println!("{}", serde_json::to_string_pretty(dw).unwrap_or_default());
                    }
                }
            }
            Self::ListPresigns {
                verified,
                unverified,
            } => {
                if verified.is_empty() && unverified.is_empty() {
                    println!("No presign caps found.");
                    return;
                }
                if !verified.is_empty() {
                    println!("Verified ({}):", verified.len());
                    for p in verified {
                        let cap_id = p.get("cap_id").and_then(|v| v.as_str()).unwrap_or("?");
                        let presign_id =
                            p.get("presign_id").and_then(|v| v.as_str()).unwrap_or("?");
                        let dwallet_id = p
                            .get("dwallet_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("global");
                        let curve = p.get("curve").and_then(|v| v.as_str()).unwrap_or("?");
                        println!(
                            "  {cap_id}  curve={curve}  dwallet={dwallet_id}  presign={presign_id}"
                        );
                    }
                }
                if !unverified.is_empty() {
                    println!("Unverified ({}):", unverified.len());
                    for p in unverified {
                        let cap_id = p.get("cap_id").and_then(|v| v.as_str()).unwrap_or("?");
                        let presign_id =
                            p.get("presign_id").and_then(|v| v.as_str()).unwrap_or("?");
                        let dwallet_id = p
                            .get("dwallet_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("global");
                        let curve = p.get("curve").and_then(|v| v.as_str()).unwrap_or("?");
                        println!(
                            "  {cap_id}  curve={curve}  dwallet={dwallet_id}  presign={presign_id}"
                        );
                    }
                }
            }
            Self::PublicKey {
                dwallet_id,
                public_key,
            } => {
                println!("dWallet ID:  {dwallet_id}");
                println!("Public Key:  {public_key}");
            }
            Self::DecryptShare {
                dwallet_id,
                secret_share,
                secret_share_path,
            } => {
                println!("dWallet ID:    {dwallet_id}");
                if let Some(path) = secret_share_path {
                    println!("Saved to:      {path}");
                } else {
                    println!("Secret Share:  {secret_share}");
                }
            }
            Self::Epoch { epoch } => {
                println!("Current epoch: {epoch}");
            }
            Self::Transaction { digest, status } => {
                println!("Transaction: {digest}");
                println!("Status: {status}");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Resolve gas budget and config from per-command and global overrides.
/// Returns `(gas_budget, config_path, config)`.
macro_rules! resolve_config {
    ($gas_budget:expr, $ika_sui_config:expr, $global_gas_budget:expr, $global_ika_config:expr, $context:expr) => {{
        let gas_budget = $gas_budget
            .or($global_gas_budget)
            .unwrap_or(DEFAULT_GAS_BUDGET);
        let config_path = $ika_sui_config
            .or($global_ika_config.clone())
            .unwrap_or(ika_config_dir()?.join(IKA_SUI_CONFIG));
        let config = read_ika_sui_config_yaml($context, &config_path)?;
        (gas_budget, config_path, config)
    }};
}

/// Extract transaction digest and status from a response.
fn tx_digest_and_status(
    response: &sui_json_rpc_types::SuiTransactionBlockResponse,
) -> (String, String) {
    let digest = response
        .effects
        .as_ref()
        .map(|e| e.transaction_digest().to_string())
        .unwrap_or_default();
    let status = response
        .effects
        .as_ref()
        .map(|e| format!("{:?}", e.status()))
        .unwrap_or_else(|| "unknown".to_string());
    (digest, status)
}

/// Build a generic Transaction response from a transaction block response.
fn tx_response_to_output(
    response: &sui_json_rpc_types::SuiTransactionBlockResponse,
) -> IkaDWalletCommandResponse {
    let (digest, status) = tx_digest_and_status(response);
    IkaDWalletCommandResponse::Transaction { digest, status }
}

/// Find the first created object whose type name contains `type_substr`.
async fn find_created_object_by_type(
    context: &mut WalletContext,
    response: &sui_json_rpc_types::SuiTransactionBlockResponse,
    type_substr: &str,
) -> Option<ObjectID> {
    let effects = response.effects.as_ref()?;
    let created_ids: Vec<ObjectID> = effects
        .created()
        .iter()
        .map(|o| o.reference.object_id)
        .collect();

    let mut grpc_client = context.grpc_client().ok()?;
    for obj_id in created_ids {
        if let Ok(obj) = grpc_client.get_object(obj_id).await
            && let Some(move_obj) = obj.data.try_as_move()
        {
            let type_str = move_obj.type_().to_string();
            // Skip dynamic field wrapper types (e.g. Field<ID, SignSession>)
            // to avoid matching wrappers instead of the actual object.
            if type_str.contains("dynamic_field") || type_str.contains("dynamic_object_field") {
                continue;
            }
            if type_str.contains(type_substr) {
                return Some(obj_id);
            }
        }
    }
    None
}

/// Fetch transaction events by digest.
async fn fetch_tx_events(
    context: &WalletContext,
    digest: &str,
) -> Option<Vec<sui_json_rpc_types::SuiEvent>> {
    let sdk_client = create_sdk_client(context).await.ok()?;
    let tx_digest: sui_types::digests::TransactionDigest = digest.parse().ok()?;
    sdk_client.event_api().get_events(tx_digest).await.ok()
}

/// Extract a string field from the first event whose type contains `event_type_substr`.
fn extract_event_field(
    events: &[sui_json_rpc_types::SuiEvent],
    event_type_substr: &str,
    field_name: &str,
) -> Option<String> {
    for event in events {
        let type_str = event.type_.to_string();
        if type_str.contains(event_type_substr) {
            if let Some(val) = event.parsed_json.get(field_name) {
                return val.as_str().map(|s| s.to_string());
            }
            // Also check nested event_data (for DWalletSessionEvent wrappers)
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
fn extract_nested_event_field(
    events: &[sui_json_rpc_types::SuiEvent],
    event_type_substr: &str,
    path: &[&str],
) -> Option<String> {
    for event in events {
        let type_str = event.type_.to_string();
        if !type_str.contains(event_type_substr) {
            continue;
        }
        // Start from event_data (DWalletSessionEvent wrapper) or top-level
        let root = event
            .parsed_json
            .get("event_data")
            .unwrap_or(&event.parsed_json);
        let mut current = root;
        for (i, key) in path.iter().enumerate() {
            let next = current.get(key).or_else(|| {
                // Try inside enum variant's "fields" sub-object
                current.get("fields").and_then(|f| f.get(key))
            });
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

/// Extract the sign session object ID from a sign transaction's events.
async fn find_sign_session_id(context: &WalletContext, digest: &str) -> Option<String> {
    fetch_tx_events(context, digest)
        .await
        .as_deref()
        .and_then(|evts| extract_event_field(evts, "SignRequestEvent", "session_object_id"))
}

/// Result of polling a sign session.
enum SignSessionResult {
    Completed { signature: String },
    Rejected,
}

/// Poll a sign session until it reaches Completed or NetworkRejected state.
async fn poll_sign_session(
    context: &WalletContext,
    sign_session_id: ObjectID,
) -> Result<SignSessionResult> {
    let sdk_client = create_sdk_client(context).await?;
    let poll_interval = std::time::Duration::from_secs(3);
    let timeout = std::time::Duration::from_secs(300);
    let start = std::time::Instant::now();

    loop {
        if start.elapsed() > timeout {
            anyhow::bail!(
                "Timeout waiting for sign session {sign_session_id} to complete ({}s)",
                timeout.as_secs()
            );
        }

        match fetch_object_fields(&sdk_client, sign_session_id).await {
            Ok(fields) => {
                if let Some(state) = fields.get("state") {
                    let variant = state.get("variant").and_then(|v| v.as_str()).unwrap_or("");
                    match variant {
                        "Completed" => {
                            let sig_bytes = state
                                .get("fields")
                                .and_then(|f| f.get("signature"))
                                .and_then(extract_bytes_from_json)
                                .unwrap_or_default();
                            return Ok(SignSessionResult::Completed {
                                signature: hex::encode(sig_bytes),
                            });
                        }
                        "NetworkRejected" => {
                            return Ok(SignSessionResult::Rejected);
                        }
                        _ => {
                            // Still "Requested", keep polling
                        }
                    }
                } else {
                    // Log unexpected structure once at 30s to aid debugging
                    if start.elapsed().as_secs() == 30 {
                        let keys: Vec<&str> = fields
                            .as_object()
                            .map(|m| m.keys().map(|k| k.as_str()).collect())
                            .unwrap_or_default();
                        eprintln!(
                            "Warning: sign session object has no 'state' field. Keys: {:?}",
                            keys
                        );
                    }
                }
            }
            Err(e) => {
                // Log fetch errors once at 30s
                if start.elapsed().as_secs() == 30 {
                    eprintln!("Warning: failed to fetch sign session: {e}");
                }
            }
        }
        tokio::time::sleep(poll_interval).await;
    }
}

/// Poll a dWallet until its state contains `public_output` (meaning DKG succeeded and state
/// is either `AwaitingKeyHolderSignature` or `Active`). Returns the dWallet fields JSON.
///
/// The Sui JSON-RPC doesn't include enum variant names, so we detect DKG completion
/// by checking for the presence of `public_output` in the state fields.
async fn poll_dwallet_until_dkg_complete(
    sdk_client: &sui_sdk::SuiClient,
    dwallet_id: ObjectID,
    timeout_secs: u64,
) -> Result<serde_json::Value> {
    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(timeout_secs);
    let mut interval_ms = 1000u64;
    let max_interval_ms = 5000u64;

    loop {
        if start.elapsed() > timeout {
            anyhow::bail!("Timeout waiting for dWallet {dwallet_id} DKG to complete");
        }

        if let Ok(fields) = fetch_object_fields(sdk_client, dwallet_id).await
            && let Some(state) = fields.get("state")
        {
            // Check for public_output — present in AwaitingKeyHolderSignature and Active
            let has_public_output = state
                .get("fields")
                .and_then(|f| f.get("public_output"))
                .is_some();
            if has_public_output {
                return Ok(fields);
            }
            // Check if state has no fields at all (unit variant like DKGRequested or Rejected)
            let state_fields = state.get("fields");
            let is_empty = state_fields
                .map(|f| f.is_null() || f.as_object().map(|o| o.is_empty()).unwrap_or(false))
                .unwrap_or(true);
            // If it's a unit variant with a name-like field, check for rejection
            if is_empty {
                let state_str = serde_json::to_string(state).unwrap_or_default();
                if state_str.contains("Rejected") {
                    anyhow::bail!("dWallet {dwallet_id} DKG was rejected. State: {state_str}");
                }
            }
        }

        tokio::time::sleep(std::time::Duration::from_millis(interval_ms)).await;
        interval_ms = (interval_ms * 3 / 2).min(max_interval_ms);
    }
}

/// Decode a hex string (with or without 0x prefix) into bytes.
fn hex_decode(s: &str) -> Result<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    Ok(hex::decode(s)?)
}

/// Generate a random 32-byte value.
fn random_bytes() -> [u8; 32] {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    bytes
}

/// Parse curve name string to u32 curve ID.
fn curve_name_to_id(curve: &str) -> Result<u32> {
    match curve {
        "secp256k1" => Ok(0),
        "secp256r1" => Ok(1),
        "ed25519" => Ok(2),
        "ristretto" => Ok(3),
        _ => anyhow::bail!("Unknown curve: {curve}"),
    }
}

/// Parse u32 curve ID to name string.
#[allow(dead_code)]
fn curve_id_to_name(id: u32) -> Result<&'static str> {
    match id {
        0 => Ok("secp256k1"),
        1 => Ok("secp256r1"),
        2 => Ok("ed25519"),
        3 => Ok("ristretto"),
        _ => anyhow::bail!("Unknown curve ID: {id}"),
    }
}

/// Parse a signature algorithm name to its curve-relative numeric ID.
///
/// Signature algorithm numbers are **relative to the curve**:
/// - secp256k1: ecdsa=0, taproot=1
/// - secp256r1: ecdsa=0
/// - ed25519:   eddsa=0
/// - ristretto: schnorrkel=0
fn signature_algorithm_name_to_id(curve_id: u32, name: &str) -> Result<u32> {
    match (curve_id, name) {
        (0, "ecdsa") => Ok(0),
        (0, "taproot") => Ok(1),
        (1, "ecdsa") => Ok(0),
        (2, "eddsa") => Ok(0),
        (3, "schnorrkel") => Ok(0),
        _ => {
            let curve = curve_id_to_name(curve_id).unwrap_or("unknown");
            let valid = valid_signature_algorithms_for_curve(curve_id);
            anyhow::bail!(
                "Invalid signature algorithm '{name}' for curve '{curve}'. \
                 Valid options: {valid}"
            )
        }
    }
}

/// List valid signature algorithm names for a curve.
fn valid_signature_algorithms_for_curve(curve_id: u32) -> String {
    match curve_id {
        0 => "ecdsa, taproot".to_string(),
        1 => "ecdsa".to_string(),
        2 => "eddsa".to_string(),
        3 => "schnorrkel".to_string(),
        _ => "unknown".to_string(),
    }
}

/// Parse a hash scheme name to its numeric ID (relative to curve + signature algorithm).
///
/// Hash numbers are **relative to the curve + signature algorithm**:
/// - secp256k1 + ecdsa:      keccak256=0, sha256=1, double-sha256=2
/// - secp256k1 + taproot:    sha256=0
/// - secp256r1 + ecdsa:      sha256=0
/// - ed25519 + eddsa:        sha512=0
/// - ristretto + schnorrkel: merlin=0
fn hash_scheme_name_to_id(curve_id: u32, sig_algo_id: u32, name: &str) -> Result<u32> {
    match (curve_id, sig_algo_id, name) {
        (0, 0, "keccak256") => Ok(0),
        (0, 0, "sha256") => Ok(1),
        (0, 0, "double-sha256") => Ok(2),
        (0, 1, "sha256") => Ok(0),
        (1, 0, "sha256") => Ok(0),
        (2, 0, "sha512") => Ok(0),
        (3, 0, "merlin") => Ok(0),
        _ => {
            let valid = valid_hash_schemes_for(curve_id, sig_algo_id);
            anyhow::bail!(
                "Invalid hash scheme '{name}' for this curve/algorithm combo. \
                 Valid options: {valid}"
            )
        }
    }
}

/// List valid hash scheme names for a curve + signature algorithm combination.
fn valid_hash_schemes_for(curve_id: u32, sig_algo_id: u32) -> String {
    match (curve_id, sig_algo_id) {
        (0, 0) => "keccak256, sha256, double-sha256".to_string(),
        (0, 1) => "sha256".to_string(),
        (1, 0) => "sha256".to_string(),
        (2, 0) => "sha512".to_string(),
        (3, 0) => "merlin".to_string(),
        _ => "unknown".to_string(),
    }
}

/// Compute the session identifier preimage as it would be computed on-chain by
/// `register_session_identifier`: `keccak256(sender_address || user_bytes)`.
/// This must match the on-chain computation so the MPC network sees the correct session ID.
fn on_chain_session_preimage(sender: &SuiAddress, user_bytes: &[u8]) -> [u8; 32] {
    use fastcrypto::hash::{HashFunction, Keccak256};
    let mut hasher = Keccak256::default();
    hasher.update(sender.to_vec());
    hasher.update(user_bytes);
    let digest = hasher.finalize();
    let mut preimage = [0u8; 32];
    preimage.copy_from_slice(digest.as_ref());
    preimage
}

/// Derive encryption keys from a seed: (encryption_key, decryption_key, signing_keypair).
///
/// Hash matches the TS SDK `UserShareEncryptionKeys.hash()`:
///   `keccak256(ASCII(domain_separator) || curve_byte || seed)`
///
/// By default uses the numeric curve byte (matching TS SDK V2 hash).
/// With `legacy_hash = true`, uses 0x00 as curve byte (matching TS SDK V1 bug).
fn derive_encryption_keys(
    curve: u32,
    seed: [u8; 32],
    legacy_hash: bool,
) -> Result<(Vec<u8>, Vec<u8>, Ed25519KeyPair)> {
    let curve_byte = if legacy_hash {
        0u8
    } else {
        u8::try_from(curve)
            .map_err(|_| anyhow::anyhow!("Curve number {curve} does not fit in a single byte"))?
    };

    let cg_seed = {
        use fastcrypto::hash::{HashFunction, Keccak256};
        let mut hasher = Keccak256::default();
        hasher.update(b"CLASS_GROUPS_DECRYPTION_KEY_V1");
        hasher.update([curve_byte]);
        hasher.update(seed);
        let digest = hasher.finalize();
        let mut cg_seed = [0u8; 32];
        cg_seed.copy_from_slice(digest.as_ref());
        cg_seed
    };

    let signing_seed = {
        use fastcrypto::hash::{HashFunction, Keccak256};
        let mut hasher = Keccak256::default();
        hasher.update(b"ED25519_SIGNING_KEY_V1");
        hasher.update([curve_byte]);
        hasher.update(seed);
        let digest = hasher.finalize();
        let mut signing_seed = [0u8; 32];
        signing_seed.copy_from_slice(digest.as_ref());
        signing_seed
    };

    let (encryption_key, decryption_key) = generate_cg_keypair_from_seed(curve, cg_seed)
        .context("Failed to generate class groups keypair")?;

    let signing_keypair = {
        use fastcrypto::ed25519::Ed25519PrivateKey;
        let private_key = Ed25519PrivateKey::from_bytes(&signing_seed)
            .map_err(|e| anyhow::anyhow!("Failed to derive Ed25519 private key: {e}"))?;
        Ed25519KeyPair::from(private_key)
    };

    Ok((encryption_key, decryption_key, signing_keypair))
}

/// Resolve the 32-byte seed for encryption key derivation.
///
/// Three modes:
/// 1. `seed_file` provided: read raw 32 bytes from file (no hashing).
/// 2. `address` provided: derive from that Sui keystore address + index.
/// 3. Neither: derive from the active Sui keystore address + index.
///
/// Address-based formula: `seed = keccak256(keypair_bytes || index_le_bytes)`
fn resolve_seed(
    context: &mut WalletContext,
    seed_file: Option<PathBuf>,
    address: Option<SuiAddress>,
    index: u32,
) -> Result<[u8; 32]> {
    if let Some(path) = seed_file {
        let bytes = std::fs::read(&path)
            .with_context(|| format!("Failed to read seed file: {}", path.display()))?;
        anyhow::ensure!(
            bytes.len() == 32,
            "Seed file must contain exactly 32 bytes, got {}",
            bytes.len()
        );
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes);
        return Ok(seed);
    }

    // Address-based derivation
    let addr = match address {
        Some(a) => a,
        None => context.active_address()?,
    };

    let sui_keypair = context.config.keystore.export(&addr).with_context(|| {
        format!("Cannot export key for address {addr}. Is it in your Sui keystore?")
    })?;
    let sk_bytes = sui_keypair.to_bytes();

    use fastcrypto::hash::{HashFunction, Keccak256};
    let mut hasher = Keccak256::default();
    hasher.update(&sk_bytes);
    hasher.update(index.to_le_bytes());
    let digest = hasher.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(digest.as_ref());
    Ok(seed)
}

/// Create a sui_sdk::SuiClient for direct RPC queries (read_api, coin_read_api).
async fn create_sdk_client(context: &WalletContext) -> Result<sui_sdk::SuiClient> {
    let rpc_url = context.get_active_env()?.rpc.clone();
    sui_sdk::SuiClientBuilder::default()
        .build(rpc_url)
        .await
        .context("Failed to create Sui SDK client")
}

/// Create a SuiConnectorClient for read-only queries (coordinator, network keys, pricing).
async fn create_sui_client(
    context: &WalletContext,
    config_path: &PathBuf,
) -> Result<SuiConnectorClient> {
    let config = read_ika_sui_config_yaml(context, config_path)?;
    SuiConnectorClient::new(
        &context.get_active_env()?.rpc,
        SuiClientMetrics::new_for_testing(),
        config,
    )
    .await
    .context("Failed to create Sui connector client")
}

/// Get the network DKG public output for deriving protocol parameters.
struct NetworkKeyInfo {
    network_encryption_key_id: ObjectID,
    /// Protocol public parameters derived from the network key.
    /// Accounts for reconfiguration if the key was created in a prior epoch.
    protocol_public_parameters: Vec<u8>,
}

/// Fetch network key info, optionally for a specific key ID (from a dWallet).
///
/// When `specific_key_id` is provided (e.g. from `dWallet.dwallet_network_encryption_key_id`),
/// uses that exact key. Otherwise falls back to the latest network key.
async fn get_network_key_info(
    context: &WalletContext,
    config_path: &PathBuf,
    curve_id: u32,
) -> Result<NetworkKeyInfo> {
    get_network_key_info_for(context, config_path, None, curve_id).await
}

async fn get_network_key_info_for(
    context: &WalletContext,
    config_path: &PathBuf,
    specific_key_id: Option<ObjectID>,
    curve_id: u32,
) -> Result<NetworkKeyInfo> {
    let client = create_sui_client(context, config_path).await?;
    let (_, coordinator_inner) = client.must_get_dwallet_coordinator_inner().await;
    let network_keys = client
        .get_dwallet_mpc_network_keys(&coordinator_inner)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get network encryption keys: {e}"))?;

    let (id, key) = if let Some(target_id) = specific_key_id {
        network_keys
            .iter()
            .find(|(id, _)| **id == target_id)
            .ok_or_else(|| {
                anyhow::anyhow!("Network encryption key {target_id} not found in coordinator")
            })?
    } else {
        network_keys
            .iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("No network encryption keys found"))?
    };

    let epoch = match &coordinator_inner {
        ika_types::sui::DWalletCoordinatorInner::V1(inner) => inner.current_epoch,
    };

    let key_data = client
        .get_network_encryption_key_with_full_data_by_epoch(key, epoch)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get network key data: {e}"))?;

    // Derive protocol parameters: use reconfiguration output if the key was created
    // in a prior epoch (matching TS SDK behavior).
    let protocol_public_parameters = if key_data.current_reconfiguration_public_output.is_empty() {
        network_dkg_public_output_to_protocol_pp_inner(curve_id, key_data.network_dkg_public_output)
            .context("Failed to derive protocol parameters from network DKG output")?
    } else {
        reconfiguration_public_output_to_protocol_pp_inner(
            curve_id,
            key_data.current_reconfiguration_public_output,
            key_data.network_dkg_public_output,
        )
        .context("Failed to derive protocol parameters from reconfiguration output")?
    };

    Ok(NetworkKeyInfo {
        network_encryption_key_id: *id,
        protocol_public_parameters,
    })
}

/// Auto-find an IKA coin owned by the active address.
async fn find_ika_coin(
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

/// Resolve payment coins from CLI args.
///
/// IKA coin: use provided value or auto-detect from wallet. When no IKA coins exist
/// (common on localnet with zero fees), creates a zero-value IKA coin.
/// SUI coin: passed through as-is. When `None`, the transaction functions use the
/// gas coin directly (like the TypeScript SDK's `transaction.gas`).
async fn resolve_payment_coins(
    context: &mut WalletContext,
    config: &IkaNetworkConfig,
    payment: &PaymentArgs,
) -> Result<ika_dwallet_transactions::PaymentCoinArgs> {
    let ika_coin_id = match payment.ika_coin_id {
        Some(id) => id,
        None => {
            let owner = context.active_address()?;
            let sdk_client = create_sdk_client(context).await?;
            match find_ika_coin(&sdk_client, owner, config).await {
                Ok(id) => id,
                Err(_) => {
                    // No IKA coins found. Create a zero-value IKA coin (needed even for
                    // zero-fee operations since the Move contract requires a Coin<IKA> argument).
                    let response = ika_dwallet_transactions::create_zero_ika_coin(
                        context,
                        config.packages.ika_package_id,
                        DEFAULT_GAS_BUDGET,
                    )
                    .await
                    .context("Failed to create zero-value IKA coin")?;

                    // Extract the created coin ID from the transaction response
                    find_created_object_by_type(context, &response, "Coin")
                        .await
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "Failed to find created IKA coin in transaction response"
                            )
                        })?
                }
            }
        }
    };
    Ok(ika_dwallet_transactions::PaymentCoinArgs {
        ika_coin_id,
        sui_coin_id: payment.sui_coin_id,
    })
}

/// Check if a presign cap is already verified by inspecting its on-chain type.
///
/// Returns `true` if the object type contains "VerifiedPresignCap",
/// `false` if it contains "UnverifiedPresignCap".
async fn is_presign_cap_verified(
    context: &WalletContext,
    presign_cap_id: ObjectID,
) -> Result<bool> {
    let sdk_client = create_sdk_client(context).await?;
    let response = sdk_client
        .read_api()
        .get_object_with_options(presign_cap_id, SuiObjectDataOptions::new().with_type())
        .await?;
    let data = response
        .data
        .ok_or_else(|| anyhow::anyhow!("Presign cap not found: {presign_cap_id}"))?;
    let type_str = data
        .type_
        .ok_or_else(|| anyhow::anyhow!("No type info for presign cap: {presign_cap_id}"))?
        .to_string();
    if type_str.contains("VerifiedPresignCap") {
        Ok(true)
    } else if type_str.contains("UnverifiedPresignCap") {
        Ok(false)
    } else {
        anyhow::bail!("Object {presign_cap_id} is not a presign cap (type: {type_str})")
    }
}

/// Fetch a Sui object's JSON fields by object ID.
async fn fetch_object_fields(
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
    // Handle SuiMoveStruct::WithTypes serialization which wraps as
    // { "type": "...", "fields": { actual fields } }
    if fields.get("type").is_some()
        && let Some(inner) = fields.get("fields")
    {
        return Ok(inner.clone());
    }
    Ok(fields)
}

/// Fetch dWallet metadata (curve, DKG output) from chain using the dWallet object ID.
async fn fetch_dwallet_metadata(
    context: &WalletContext,
    dwallet_id: ObjectID,
) -> Result<DWalletMetadata> {
    let sdk_client = create_sdk_client(context).await?;
    let fields = fetch_object_fields(&sdk_client, dwallet_id).await?;

    let curve = fields
        .get("curve")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow::anyhow!("Could not read curve from dWallet object"))?
        as u32;

    // Extract DKG output from state.Active.public_output
    let dkg_output = fields
        .get("state")
        .and_then(|state| state.get("fields"))
        .and_then(|f| f.get("public_output"))
        .and_then(extract_bytes_from_json);

    let is_imported_key_dwallet = fields
        .get("is_imported_key_dwallet")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let network_encryption_key_id = fields
        .get("dwallet_network_encryption_key_id")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<ObjectID>().ok());

    Ok(DWalletMetadata {
        curve,
        dkg_output,
        is_imported_key_dwallet,
        network_encryption_key_id,
    })
}

struct DWalletMetadata {
    curve: u32,
    /// The DKG public output bytes, if the dWallet is in Active state.
    dkg_output: Option<Vec<u8>>,
    /// Whether this dWallet was created from an imported key.
    is_imported_key_dwallet: bool,
    /// The network encryption key ID used for this dWallet's DKG.
    network_encryption_key_id: Option<ObjectID>,
}

/// Fetch presign output from chain using the verified presign cap ID.
///
/// Reads the VerifiedPresignCap to get the presign_id, then reads the PresignSession
/// to extract state.Completed.presign bytes.
async fn fetch_presign_output(
    context: &WalletContext,
    presign_cap_id: ObjectID,
) -> Result<Vec<u8>> {
    let sdk_client = create_sdk_client(context).await?;

    // 1. Read the VerifiedPresignCap to get presign_id
    let cap_fields = fetch_object_fields(&sdk_client, presign_cap_id).await?;
    let presign_id_str = cap_fields
        .get("presign_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            anyhow::anyhow!("Could not read presign_id from presign cap: {presign_cap_id}")
        })?;
    let presign_id: ObjectID = presign_id_str
        .parse()
        .context("Invalid presign_id in presign cap")?;

    // 2. Read the PresignSession to get state.Completed.presign
    let session_fields = fetch_object_fields(&sdk_client, presign_id).await?;
    let presign_bytes = session_fields
        .get("state")
        .and_then(|state| state.get("fields"))
        .and_then(|f| f.get("presign"))
        .and_then(extract_bytes_from_json)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Presign session {presign_id} is not in Completed state. \
                 The presign may still be processing."
            )
        })?;
    Ok(presign_bytes)
}

/// Extract byte array from Sui JSON representation.
///
/// Sui encodes `vector<u8>` as either a JSON array of numbers or a base64 string.
/// Hex strings are supported only with an explicit `0x` prefix.
fn extract_bytes_from_json(value: &serde_json::Value) -> Option<Vec<u8>> {
    match value {
        // Array of numbers: [1, 2, 3, ...]
        serde_json::Value::Array(arr) => arr.iter().map(|v| v.as_u64().map(|n| n as u8)).collect(),
        // String: Sui uses base64 for vector<u8> fields.
        // Only treat as hex if explicitly prefixed with "0x".
        serde_json::Value::String(s) => {
            if let Some(hex_str) = s.strip_prefix("0x") {
                return hex::decode(hex_str).ok();
            }
            // Sui's default encoding for byte vectors is base64
            use base64::{Engine, engine::general_purpose::STANDARD};
            STANDARD.decode(s).ok()
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------

impl IkaDWalletCommand {
    pub async fn execute(
        self,
        context: &mut WalletContext,
        json: bool,
        quiet: bool,
        global_ika_config: Option<PathBuf>,
        global_gas_budget: Option<u64>,
    ) -> Result<()> {
        let response = match self {
            IkaDWalletCommand::Create {
                curve,
                output_secret,
                public_share,
                sign_message: _,
                hash_scheme: _,
                payment,
                seed,
                tx,
            } => {
                let (gas_budget, config_path, config) = resolve_config!(
                    tx.gas_budget,
                    tx.ika_config,
                    global_gas_budget,
                    global_ika_config,
                    context
                );
                let curve_id = curve_name_to_id(&curve)?;
                let coins = resolve_payment_coins(context, &config, &payment).await?;

                // 1. Get network key and derive protocol parameters
                let network_key_info =
                    get_network_key_info(context, &config_path, curve_id).await?;
                let protocol_pp = network_key_info.protocol_public_parameters.clone();

                // 2. Generate session identifier
                let session_id_random_bytes = random_bytes();
                let sender = context.active_address()?;
                let session_id = SessionIdentifier::new(
                    ika_types::messages_dwallet_mpc::SessionType::User,
                    on_chain_session_preimage(&sender, &session_id_random_bytes),
                )
                .to_vec();

                // 3. Generate centralized DKG output (local crypto)
                let dkg_result = create_dkg_output_by_curve_v2(
                    curve_id,
                    protocol_pp.clone(),
                    session_id.clone(),
                )
                .context("DKG output generation failed")?;

                // 4. Derive encryption keys from seed
                let seed_bytes = resolve_seed(context, seed.seed_file, seed.address, seed.index)?;
                let (encryption_key, _decryption_key, signing_keypair) =
                    derive_encryption_keys(curve_id, seed_bytes, seed.legacy_hash)?;
                let signer_public_key = signing_keypair.public().as_bytes().to_vec();
                let encryption_key_address: SuiAddress = signing_keypair.public().into();

                // 5. Save user secret share (only if --output-secret was provided)
                if let Some(ref path) = output_secret {
                    std::fs::write(path, &dkg_result.centralized_secret_output)
                        .context("Failed to save secret share")?;
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
                    }
                }

                // 6. Submit DKG transaction
                let public_key_hex = hex::encode(&dkg_result.public_key_share_and_proof);

                let response = if public_share {
                    ika_dwallet_transactions::request_dwallet_dkg_with_public_share(
                        context,
                        config.packages.ika_dwallet_2pc_mpc_package_id,
                        config.objects.ika_dwallet_coordinator_object_id,
                        network_key_info.network_encryption_key_id,
                        curve_id,
                        dkg_result.public_key_share_and_proof,
                        dkg_result.public_output,
                        dkg_result.centralized_secret_output.clone(),
                        session_id_random_bytes.to_vec(),
                        coins,
                        None, // sign_during_dkg
                        gas_budget,
                    )
                    .await?
                } else {
                    let encrypted_secret_share = encrypt_secret_key_share_and_prove_v2(
                        curve_id,
                        dkg_result.centralized_secret_output.clone(),
                        encryption_key.clone(),
                        protocol_pp,
                    )
                    .context("Failed to encrypt secret share")?;

                    ika_dwallet_transactions::request_dwallet_dkg(
                        context,
                        config.packages.ika_dwallet_2pc_mpc_package_id,
                        config.objects.ika_dwallet_coordinator_object_id,
                        network_key_info.network_encryption_key_id,
                        curve_id,
                        dkg_result.public_key_share_and_proof,
                        encrypted_secret_share,
                        encryption_key_address,
                        dkg_result.public_output,
                        signer_public_key,
                        session_id_random_bytes.to_vec(),
                        coins,
                        None, // sign_during_dkg
                        gas_budget,
                    )
                    .await?
                };

                // 7. Extract created object IDs from transaction events
                let (digest, _status) = tx_digest_and_status(&response);
                let events = fetch_tx_events(context, &digest).await;
                let event_list = events.as_deref().unwrap_or(&[]);
                let dwallet_id =
                    extract_event_field(event_list, "DWalletDKGRequestEvent", "dwallet_id")
                        .and_then(|s| s.parse::<ObjectID>().ok());
                let dwallet_cap_id =
                    extract_event_field(event_list, "DWalletDKGRequestEvent", "dwallet_cap_id")
                        .and_then(|s| s.parse::<ObjectID>().ok());
                // encrypted_user_secret_key_share_id is nested inside
                // event_data.user_secret_key_share (an enum variant: Encrypted { ... })
                let encrypted_share_id = extract_nested_event_field(
                    event_list,
                    "DWalletDKGRequestEvent",
                    &[
                        "user_secret_key_share",
                        "encrypted_user_secret_key_share_id",
                    ],
                )
                .and_then(|s| s.parse::<ObjectID>().ok());

                // 8. Auto-accept: poll for AwaitingKeyHolderSignature, sign public_output,
                //    call accept_encrypted_user_share, then poll for Active state.
                if let (Some(did), Some(esid)) = (dwallet_id, encrypted_share_id) {
                    if !quiet {
                        eprintln!("DKG transaction submitted. Waiting for network to process...");
                    }

                    let sdk_client = create_sdk_client(context).await?;

                    // Poll until DKG completes (public_output appears, up to 5 minutes)
                    let fields = poll_dwallet_until_dkg_complete(&sdk_client, did, 300)
                        .await
                        .context(
                            "Failed waiting for DKG completion. \
                             Check the dWallet state with: ika dwallet get --dwallet-id",
                        )?;

                    // Extract public_output from state
                    let public_output_bytes = fields
                        .get("state")
                        .and_then(|state| state.get("fields"))
                        .and_then(|f| f.get("public_output"))
                        .and_then(extract_bytes_from_json)
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "Could not extract public_output from \
                                 AwaitingKeyHolderSignature state"
                            )
                        })?;

                    if !quiet {
                        eprintln!(
                            "DKG complete. Signing public output to accept encrypted share..."
                        );
                    }

                    // Sign public_output with the signer keypair
                    let signature: fastcrypto::ed25519::Ed25519Signature =
                        signing_keypair.sign(&public_output_bytes);
                    let signature_bytes = signature.as_ref().to_vec();

                    // Submit accept_encrypted_user_share transaction
                    ika_dwallet_transactions::accept_encrypted_user_share(
                        context,
                        config.packages.ika_dwallet_2pc_mpc_package_id,
                        config.objects.ika_dwallet_coordinator_object_id,
                        did,
                        esid,
                        signature_bytes,
                        gas_budget,
                    )
                    .await
                    .context("Failed to accept encrypted user share")?;

                    if !quiet {
                        eprintln!("dWallet accepted. It is now Active.");
                    }
                }

                let (secret_share_hex, secret_share_path) = match output_secret {
                    Some(ref path) => (None, Some(path.display().to_string())),
                    None => (
                        Some(hex::encode(&dkg_result.centralized_secret_output)),
                        None,
                    ),
                };

                IkaDWalletCommandResponse::Create {
                    dwallet_id: dwallet_id
                        .map(|id| id.to_string())
                        .unwrap_or_else(|| "pending (check transaction)".to_string()),
                    dwallet_cap_id: dwallet_cap_id
                        .map(|id| id.to_string())
                        .unwrap_or_else(|| "pending (check transaction)".to_string()),
                    public_key: public_key_hex,
                    encrypted_share_id: encrypted_share_id.map(|id| id.to_string()),
                    secret_share: secret_share_hex,
                    secret_share_path,
                }
            }

            IkaDWalletCommand::Sign {
                dwallet_cap_id,
                message,
                signature_algorithm,
                hash_scheme,
                presign_cap_id,
                secret_share,
                secret_share_hex,
                presign_output,
                dwallet_id,
                curve,
                dkg_output,
                payment,
                seed,
                tx,
                wait,
            } => {
                let (gas_budget, config_path, config) = resolve_config!(
                    tx.gas_budget,
                    tx.ika_config,
                    global_gas_budget,
                    global_ika_config,
                    context
                );
                let coins = resolve_payment_coins(context, &config, &payment).await?;
                let message_bytes = hex_decode(&message)?;

                // Resolve presign output: from flag or auto-fetch from presign cap
                let presign_output_bytes =
                    resolve_presign_output(context, presign_output, presign_cap_id).await?;

                // Resolve curve, DKG output, and dWallet metadata from chain
                let metadata = match dwallet_id {
                    Some(id) => Some(fetch_dwallet_metadata(context, id).await?),
                    None => None,
                };

                let curve_id = match curve {
                    Some(c) => curve_name_to_id(&c)?,
                    None => metadata.as_ref().map(|m| m.curve).ok_or_else(|| {
                        anyhow::anyhow!(
                            "Curve is required. Provide --curve or --dwallet-id to auto-detect."
                        )
                    })?,
                };

                let signature_algorithm =
                    signature_algorithm_name_to_id(curve_id, &signature_algorithm)?;
                let hash_scheme =
                    hash_scheme_name_to_id(curve_id, signature_algorithm, &hash_scheme)?;

                let dkg_output_bytes = match dkg_output {
                    Some(hex) => hex_decode(&hex)?,
                    None => metadata
                        .as_ref()
                        .and_then(|m| m.dkg_output.clone())
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "DKG output not available. The dWallet may not be in Active state."
                            )
                        })?,
                };

                let is_imported_key = metadata
                    .as_ref()
                    .map(|m| m.is_imported_key_dwallet)
                    .unwrap_or(false);

                // Use the dWallet's specific network encryption key for protocol parameters
                let dwallet_network_key_id =
                    metadata.as_ref().and_then(|m| m.network_encryption_key_id);

                // Auto-detect if presign cap needs verification
                let needs_verification = !is_presign_cap_verified(context, presign_cap_id).await?;
                if needs_verification && !quiet {
                    eprintln!(
                        "Presign cap is unverified. Will auto-verify in the sign transaction."
                    );
                }

                let network_key_info = get_network_key_info_for(
                    context,
                    &config_path,
                    dwallet_network_key_id,
                    curve_id,
                )
                .await?;
                let protocol_pp = network_key_info.protocol_public_parameters;

                // Resolve the user secret share from file, hex, or on-chain decryption
                let secret_share_bytes = resolve_secret_share(
                    context,
                    secret_share,
                    secret_share_hex,
                    dwallet_id,
                    curve_id,
                    &dkg_output_bytes,
                    &protocol_pp,
                    &seed,
                    quiet,
                )
                .await?;

                let centralized_signature = advance_centralized_sign_party(
                    protocol_pp,
                    dkg_output_bytes,
                    secret_share_bytes,
                    presign_output_bytes,
                    message_bytes.clone(),
                    curve_id,
                    signature_algorithm,
                    hash_scheme,
                )
                .context("Failed to generate centralized signature")?;

                let session_id_preimage = random_bytes();

                let response = if is_imported_key {
                    if !quiet {
                        eprintln!("Detected imported key dWallet. Using imported key sign flow.");
                    }
                    ika_dwallet_transactions::request_imported_key_sign_tx(
                        context,
                        config.packages.ika_dwallet_2pc_mpc_package_id,
                        config.objects.ika_dwallet_coordinator_object_id,
                        dwallet_cap_id,
                        signature_algorithm,
                        hash_scheme,
                        message_bytes,
                        centralized_signature,
                        presign_cap_id,
                        session_id_preimage.to_vec(),
                        coins,
                        gas_budget,
                        needs_verification,
                    )
                    .await?
                } else {
                    ika_dwallet_transactions::request_sign_tx(
                        context,
                        config.packages.ika_dwallet_2pc_mpc_package_id,
                        config.objects.ika_dwallet_coordinator_object_id,
                        dwallet_cap_id,
                        signature_algorithm,
                        hash_scheme,
                        message_bytes,
                        centralized_signature,
                        presign_cap_id,
                        session_id_preimage.to_vec(),
                        coins,
                        gas_budget,
                        needs_verification,
                    )
                    .await?
                };
                let (digest, status) = tx_digest_and_status(&response);

                // Find the sign session ID from transaction events
                let sign_session_id = find_sign_session_id(context, &digest).await;

                // If --wait, poll until sign completes
                let signature = if wait {
                    if let Some(ref session_id) = sign_session_id {
                        let session_oid: ObjectID =
                            session_id.parse().context("Invalid sign session ID")?;
                        if !quiet {
                            eprintln!("Waiting for sign session {session_id} to complete...");
                        }
                        match poll_sign_session(context, session_oid).await? {
                            SignSessionResult::Completed { signature } => Some(signature),
                            SignSessionResult::Rejected => {
                                anyhow::bail!("Sign session was rejected by the network");
                            }
                        }
                    } else {
                        eprintln!("Warning: Could not find sign session ID to wait on.");
                        None
                    }
                } else {
                    None
                };

                IkaDWalletCommandResponse::Sign {
                    digest,
                    status,
                    sign_session_id,
                    signature,
                }
            }

            IkaDWalletCommand::FutureSign { cmd } => match cmd {
                IkaDWalletFutureSignCommand::Create {
                    dwallet_id,
                    message,
                    hash_scheme,
                    presign_cap_id,
                    secret_share,
                    secret_share_hex,
                    presign_output,
                    signature_algorithm,
                    curve,
                    dkg_output,
                    payment,
                    seed,
                    tx,
                } => {
                    let (gas_budget, config_path, config) = resolve_config!(
                        tx.gas_budget,
                        tx.ika_config,
                        global_gas_budget,
                        global_ika_config,
                        context
                    );
                    let coins = resolve_payment_coins(context, &config, &payment).await?;
                    let message_bytes = hex_decode(&message)?;

                    let presign_output_bytes =
                        resolve_presign_output(context, presign_output, presign_cap_id).await?;

                    let metadata = fetch_dwallet_metadata(context, dwallet_id).await?;

                    let curve_id = match curve {
                        Some(c) => curve_name_to_id(&c)?,
                        None => metadata.curve,
                    };

                    let signature_algorithm =
                        signature_algorithm_name_to_id(curve_id, &signature_algorithm)?;
                    let hash_scheme =
                        hash_scheme_name_to_id(curve_id, signature_algorithm, &hash_scheme)?;

                    let dkg_output_bytes = match dkg_output {
                        Some(hex) => hex_decode(&hex)?,
                        None => metadata.dkg_output.ok_or_else(|| {
                            anyhow::anyhow!(
                                "DKG output not available. The dWallet may not be in Active state."
                            )
                        })?,
                    };

                    let network_key_info = get_network_key_info_for(
                        context,
                        &config_path,
                        metadata.network_encryption_key_id,
                        curve_id,
                    )
                    .await?;
                    let protocol_pp = network_key_info.protocol_public_parameters;

                    let secret_share_bytes = resolve_secret_share(
                        context,
                        secret_share,
                        secret_share_hex,
                        Some(dwallet_id),
                        curve_id,
                        &dkg_output_bytes,
                        &protocol_pp,
                        &seed,
                        quiet,
                    )
                    .await?;

                    let centralized_signature = advance_centralized_sign_party(
                        protocol_pp,
                        dkg_output_bytes,
                        secret_share_bytes,
                        presign_output_bytes,
                        message_bytes.clone(),
                        curve_id,
                        signature_algorithm,
                        hash_scheme,
                    )
                    .context("Failed to generate centralized signature")?;

                    let session_id_preimage = random_bytes();

                    let needs_verification =
                        !is_presign_cap_verified(context, presign_cap_id).await?;
                    if needs_verification && !quiet {
                        eprintln!(
                            "Presign cap is unverified. Will auto-verify in the sign transaction."
                        );
                    }

                    let response = ika_dwallet_transactions::request_future_sign_tx(
                        context,
                        config.packages.ika_dwallet_2pc_mpc_package_id,
                        config.objects.ika_dwallet_coordinator_object_id,
                        dwallet_id,
                        presign_cap_id,
                        message_bytes,
                        hash_scheme,
                        centralized_signature,
                        session_id_preimage.to_vec(),
                        coins,
                        gas_budget,
                        needs_verification,
                    )
                    .await?;
                    let (digest, status) = tx_digest_and_status(&response);
                    let sign_session_id = find_sign_session_id(context, &digest).await;
                    IkaDWalletCommandResponse::Sign {
                        digest,
                        status,
                        sign_session_id,
                        signature: None,
                    }
                }
                IkaDWalletFutureSignCommand::Fulfill {
                    partial_cap_id,
                    dwallet_cap_id,
                    dwallet_id,
                    message,
                    signature_algorithm,
                    hash_scheme,
                    payment,
                    tx,
                    wait,
                } => {
                    let (gas_budget, _config_path, config) = resolve_config!(
                        tx.gas_budget,
                        tx.ika_config,
                        global_gas_budget,
                        global_ika_config,
                        context
                    );
                    let coins = resolve_payment_coins(context, &config, &payment).await?;
                    let message_bytes = hex_decode(&message)?;
                    let session_id_preimage = random_bytes();

                    let metadata = fetch_dwallet_metadata(context, dwallet_id).await?;
                    let signature_algorithm =
                        signature_algorithm_name_to_id(metadata.curve, &signature_algorithm)?;
                    let hash_scheme =
                        hash_scheme_name_to_id(metadata.curve, signature_algorithm, &hash_scheme)?;

                    let response = ika_dwallet_transactions::request_future_sign_fulfill_tx(
                        context,
                        config.packages.ika_dwallet_2pc_mpc_package_id,
                        config.objects.ika_dwallet_coordinator_object_id,
                        partial_cap_id,
                        dwallet_cap_id,
                        signature_algorithm,
                        hash_scheme,
                        message_bytes,
                        session_id_preimage.to_vec(),
                        coins,
                        gas_budget,
                    )
                    .await?;
                    let (digest, status) = tx_digest_and_status(&response);
                    let sign_session_id = find_sign_session_id(context, &digest).await;

                    let signature = if wait {
                        if let Some(ref session_id) = sign_session_id {
                            let session_oid: ObjectID =
                                session_id.parse().context("Invalid sign session ID")?;
                            if !quiet {
                                eprintln!("Waiting for sign session {session_id} to complete...");
                            }
                            match poll_sign_session(context, session_oid).await? {
                                SignSessionResult::Completed { signature } => Some(signature),
                                SignSessionResult::Rejected => {
                                    anyhow::bail!("Sign session was rejected by the network");
                                }
                            }
                        } else {
                            eprintln!("Warning: Could not find sign session ID to wait on.");
                            None
                        }
                    } else {
                        None
                    };

                    IkaDWalletCommandResponse::Sign {
                        digest,
                        status,
                        sign_session_id,
                        signature,
                    }
                }
            },

            IkaDWalletCommand::Presign {
                dwallet_id,
                signature_algorithm,
                count,
                payment,
                tx,
                wait,
            } => {
                let (gas_budget, config_path, config) = resolve_config!(
                    tx.gas_budget,
                    tx.ika_config,
                    global_gas_budget,
                    global_ika_config,
                    context
                );

                let metadata = fetch_dwallet_metadata(context, dwallet_id).await?;
                let signature_algorithm =
                    signature_algorithm_name_to_id(metadata.curve, &signature_algorithm)?;

                let session_ids: Vec<Vec<u8>> =
                    (0..count).map(|_| random_bytes().to_vec()).collect();

                // Try per-dWallet presign first; fall back to global if needed
                let coins = resolve_payment_coins(context, &config, &payment).await?;
                let result = if count == 1 {
                    ika_dwallet_transactions::request_presign_tx(
                        context,
                        config.packages.ika_dwallet_2pc_mpc_package_id,
                        config.objects.ika_dwallet_coordinator_object_id,
                        dwallet_id,
                        signature_algorithm,
                        session_ids[0].clone(),
                        coins,
                        gas_budget,
                    )
                    .await
                } else {
                    ika_dwallet_transactions::request_batch_presign_tx(
                        context,
                        config.packages.ika_dwallet_2pc_mpc_package_id,
                        config.objects.ika_dwallet_coordinator_object_id,
                        dwallet_id,
                        signature_algorithm,
                        session_ids.clone(),
                        coins,
                        gas_budget,
                    )
                    .await
                };

                let response = match result {
                    Ok(resp) => resp,
                    Err(e)
                        if e.to_string().contains("MoveAbort")
                            && e.to_string().contains(", 31)") =>
                    {
                        if !quiet {
                            eprintln!(
                                "Per-dWallet presign not allowed for this curve/algorithm. \
                                 Using global presign..."
                            );
                        }
                        let coins = resolve_payment_coins(context, &config, &payment).await?;
                        let network_key_info =
                            get_network_key_info(context, &config_path, metadata.curve).await?;
                        if count == 1 {
                            ika_dwallet_transactions::request_global_presign_tx(
                                context,
                                config.packages.ika_dwallet_2pc_mpc_package_id,
                                config.objects.ika_dwallet_coordinator_object_id,
                                network_key_info.network_encryption_key_id,
                                metadata.curve,
                                signature_algorithm,
                                session_ids[0].clone(),
                                coins,
                                gas_budget,
                            )
                            .await?
                        } else {
                            ika_dwallet_transactions::request_batch_global_presign_tx(
                                context,
                                config.packages.ika_dwallet_2pc_mpc_package_id,
                                config.objects.ika_dwallet_coordinator_object_id,
                                network_key_info.network_encryption_key_id,
                                metadata.curve,
                                signature_algorithm,
                                session_ids,
                                coins,
                                gas_budget,
                            )
                            .await?
                        }
                    }
                    Err(e) => return Err(e),
                };

                let (digest, status) = tx_digest_and_status(&response);

                // For batch: find all created PresignCap objects
                let effects = response.effects.as_ref();
                let created_ids: Vec<ObjectID> = effects
                    .map(|e| e.created().iter().map(|o| o.reference.object_id).collect())
                    .unwrap_or_default();

                // Identify presign caps among created objects
                let mut presign_cap_ids = Vec::new();
                let mut grpc_client = context.grpc_client()?;
                for obj_id in &created_ids {
                    if let Ok(obj) = grpc_client.get_object(*obj_id).await
                        && let Some(move_obj) = obj.data.try_as_move()
                    {
                        let type_str = move_obj.type_().to_string();
                        if type_str.contains("PresignCap") && !type_str.contains("dynamic_field") {
                            presign_cap_ids.push(*obj_id);
                        }
                    }
                }

                // Extract presign IDs from events
                let events = fetch_tx_events(context, &digest).await;
                let event_list = events.as_deref().unwrap_or(&[]);
                let presign_ids: Vec<String> = event_list
                    .iter()
                    .filter(|e| e.type_.to_string().contains("PresignRequestEvent"))
                    .filter_map(|e| {
                        e.parsed_json
                            .get("event_data")
                            .or(Some(&e.parsed_json))
                            .and_then(|d| d.get("presign_id"))
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string())
                    })
                    .collect();

                // For single presign, use the first IDs
                let presign_id = presign_ids.first().cloned();
                let presign_cap_id = presign_cap_ids.first().map(|id| id.to_string());

                // Wait + verify if requested
                let verified_presign_cap_id = if wait && !presign_ids.is_empty() {
                    if !quiet && count > 1 {
                        eprintln!("Waiting for {count} presigns to complete and verifying...");
                    }
                    let mut verified_ids = Vec::new();
                    for (pid_str, &cap_oid) in presign_ids.iter().zip(presign_cap_ids.iter()) {
                        let pid: ObjectID = pid_str.parse().context("Invalid presign ID")?;
                        let vcid = wait_and_verify_presign(
                            context, &config, pid, cap_oid, gas_budget, quiet,
                        )
                        .await?;
                        verified_ids.push(vcid.to_string());
                    }
                    verified_ids.first().cloned()
                } else {
                    None
                };

                if count > 1 && !quiet {
                    eprintln!(
                        "Created {count} presigns ({} caps found).",
                        presign_cap_ids.len()
                    );
                }

                IkaDWalletCommandResponse::Presign {
                    digest,
                    status,
                    presign_id,
                    presign_cap_id,
                    verified_presign_cap_id,
                }
            }

            IkaDWalletCommand::GlobalPresign {
                curve,
                signature_algorithm,
                payment,
                tx,
                wait,
            } => {
                let (gas_budget, config_path, config) = resolve_config!(
                    tx.gas_budget,
                    tx.ika_config,
                    global_gas_budget,
                    global_ika_config,
                    context
                );
                let curve_id = curve_name_to_id(&curve)?;
                let signature_algorithm =
                    signature_algorithm_name_to_id(curve_id, &signature_algorithm)?;
                let coins = resolve_payment_coins(context, &config, &payment).await?;
                let session_id = random_bytes().to_vec();
                let network_key_info =
                    get_network_key_info(context, &config_path, curve_id).await?;

                let response = ika_dwallet_transactions::request_global_presign_tx(
                    context,
                    config.packages.ika_dwallet_2pc_mpc_package_id,
                    config.objects.ika_dwallet_coordinator_object_id,
                    network_key_info.network_encryption_key_id,
                    curve_id,
                    signature_algorithm,
                    session_id,
                    coins,
                    gas_budget,
                )
                .await?;
                let (digest, status) = tx_digest_and_status(&response);
                let presign_cap_oid =
                    find_created_object_by_type(context, &response, "PresignCap").await;
                let presign_cap_id = presign_cap_oid.map(|id| id.to_string());
                let presign_id =
                    fetch_tx_events(context, &digest)
                        .await
                        .as_deref()
                        .and_then(|evts| {
                            extract_event_field(evts, "PresignRequestEvent", "presign_id")
                        });

                let verified_presign_cap_id = if wait {
                    if let (Some(pid_str), Some(cap_oid)) = (&presign_id, presign_cap_oid) {
                        let pid: ObjectID = pid_str.parse().context("Invalid presign ID")?;
                        let vcid = wait_and_verify_presign(
                            context, &config, pid, cap_oid, gas_budget, quiet,
                        )
                        .await?;
                        Some(vcid.to_string())
                    } else {
                        eprintln!("Warning: Could not find presign/cap IDs to wait on.");
                        None
                    }
                } else {
                    None
                };

                IkaDWalletCommandResponse::Presign {
                    digest,
                    status,
                    presign_id,
                    presign_cap_id,
                    verified_presign_cap_id,
                }
            }

            IkaDWalletCommand::Import {
                curve,
                secret_key,
                output_secret,
                payment,
                seed,
                tx,
            } => {
                let (gas_budget, config_path, config) = resolve_config!(
                    tx.gas_budget,
                    tx.ika_config,
                    global_gas_budget,
                    global_ika_config,
                    context
                );
                let curve_id = curve_name_to_id(&curve)?;
                let coins = resolve_payment_coins(context, &config, &payment).await?;

                let secret_key =
                    std::fs::read(&secret_key).context("Failed to read secret key file")?;

                let network_key_info =
                    get_network_key_info(context, &config_path, curve_id).await?;
                let protocol_pp = network_key_info.protocol_public_parameters.clone();

                let session_id_random_bytes = random_bytes();
                let sender = context.active_address()?;
                let session_id = SessionIdentifier::new(
                    ika_types::messages_dwallet_mpc::SessionType::User,
                    on_chain_session_preimage(&sender, &session_id_random_bytes),
                )
                .to_vec();

                let (user_secret_share, user_public_output, centralized_party_message) =
                    create_imported_dwallet_centralized_step_inner_v2(
                        curve_id,
                        &protocol_pp,
                        &session_id,
                        &secret_key,
                    )
                    .context("Failed to run imported key centralized step")?;

                // Derive encryption keys from seed
                let seed_bytes = resolve_seed(context, seed.seed_file, seed.address, seed.index)?;
                let (encryption_key, _decryption_key, signing_keypair) =
                    derive_encryption_keys(curve_id, seed_bytes, seed.legacy_hash)?;
                let signer_public_key = signing_keypair.public().as_bytes().to_vec();
                let encryption_key_address: SuiAddress = signing_keypair.public().into();

                let encrypted_secret_share = encrypt_secret_key_share_and_prove_v2(
                    curve_id,
                    user_secret_share.clone(),
                    encryption_key,
                    protocol_pp,
                )
                .context("Failed to encrypt secret share")?;

                if let Some(ref path) = output_secret {
                    std::fs::write(path, &user_secret_share)
                        .context("Failed to save secret share")?;
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
                    }
                }

                let response = ika_dwallet_transactions::request_imported_key_dwallet_verification(
                    context,
                    config.packages.ika_dwallet_2pc_mpc_package_id,
                    config.objects.ika_dwallet_coordinator_object_id,
                    network_key_info.network_encryption_key_id,
                    curve_id,
                    centralized_party_message,
                    encrypted_secret_share,
                    encryption_key_address,
                    user_public_output,
                    signer_public_key,
                    session_id_random_bytes.to_vec(),
                    coins,
                    gas_budget,
                )
                .await?;

                // Extract IDs from events (import event type)
                let (import_digest, _) = tx_digest_and_status(&response);
                let import_events = fetch_tx_events(context, &import_digest).await;
                let import_event_list = import_events.as_deref().unwrap_or(&[]);
                let dwallet_id = extract_event_field(
                    import_event_list,
                    "DWalletImportedKeyVerificationRequestEvent",
                    "dwallet_id",
                )
                .and_then(|s| s.parse::<ObjectID>().ok());
                let dwallet_cap_id = extract_event_field(
                    import_event_list,
                    "DWalletImportedKeyVerificationRequestEvent",
                    "dwallet_cap_id",
                )
                .and_then(|s| s.parse::<ObjectID>().ok());
                let encrypted_share_id = extract_event_field(
                    import_event_list,
                    "DWalletImportedKeyVerificationRequestEvent",
                    "encrypted_user_secret_key_share_id",
                )
                .and_then(|s| s.parse::<ObjectID>().ok());
                if let (Some(did), Some(esid)) = (dwallet_id, encrypted_share_id) {
                    if !quiet {
                        eprintln!(
                            "Import verification submitted. Waiting for network to process..."
                        );
                    }

                    let sdk_client = create_sdk_client(context).await?;
                    let fields = poll_dwallet_until_dkg_complete(&sdk_client, did, 300)
                        .await
                        .context("Failed waiting for imported key verification")?;

                    let public_output_bytes = fields
                        .get("state")
                        .and_then(|state| state.get("fields"))
                        .and_then(|f| f.get("public_output"))
                        .and_then(extract_bytes_from_json)
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "Could not extract public_output from imported dWallet state"
                            )
                        })?;

                    if !quiet {
                        eprintln!("Verification complete. Accepting encrypted share...");
                    }

                    let signature: fastcrypto::ed25519::Ed25519Signature =
                        signing_keypair.sign(&public_output_bytes);
                    let signature_bytes = signature.as_ref().to_vec();

                    ika_dwallet_transactions::accept_encrypted_user_share(
                        context,
                        config.packages.ika_dwallet_2pc_mpc_package_id,
                        config.objects.ika_dwallet_coordinator_object_id,
                        did,
                        esid,
                        signature_bytes,
                        gas_budget,
                    )
                    .await
                    .context("Failed to accept encrypted user share for imported dWallet")?;

                    if !quiet {
                        eprintln!("Imported dWallet is now Active.");
                    }

                    let (secret_share_hex, secret_share_path) = match output_secret {
                        Some(ref path) => (None, Some(path.display().to_string())),
                        None => (Some(hex::encode(&user_secret_share)), None),
                    };

                    IkaDWalletCommandResponse::Create {
                        dwallet_id: did.to_string(),
                        dwallet_cap_id: dwallet_cap_id
                            .map(|id| id.to_string())
                            .unwrap_or_else(|| "pending".to_string()),
                        public_key: String::new(),
                        encrypted_share_id: encrypted_share_id.map(|id| id.to_string()),
                        secret_share: secret_share_hex,
                        secret_share_path,
                    }
                } else {
                    tx_response_to_output(&response)
                }
            }

            IkaDWalletCommand::RegisterEncryptionKey { curve, seed, tx } => {
                let (gas_budget, _config_path, config) = resolve_config!(
                    tx.gas_budget,
                    tx.ika_config,
                    global_gas_budget,
                    global_ika_config,
                    context
                );
                let curve_id = curve_name_to_id(&curve)?;

                let seed_bytes = resolve_seed(context, seed.seed_file, seed.address, seed.index)?;

                let (encryption_key, _decryption_key, signing_keypair) =
                    derive_encryption_keys(curve_id, seed_bytes, seed.legacy_hash)?;

                let sig: fastcrypto::ed25519::Ed25519Signature =
                    signing_keypair.sign(&encryption_key);
                let encryption_key_signature: Vec<u8> = sig.as_ref().to_vec();
                let signer_public_key = signing_keypair.public().as_bytes().to_vec();

                let response = ika_dwallet_transactions::register_encryption_key(
                    context,
                    config.packages.ika_dwallet_2pc_mpc_package_id,
                    config.objects.ika_dwallet_coordinator_object_id,
                    curve_id,
                    encryption_key.clone(),
                    encryption_key_signature,
                    signer_public_key.clone(),
                    gas_budget,
                )
                .await?;
                let (digest, status) = tx_digest_and_status(&response);
                let encryption_key_id = fetch_tx_events(context, &digest)
                    .await
                    .as_deref()
                    .and_then(|evts| {
                        extract_event_field(evts, "CreatedEncryptionKeyEvent", "encryption_key_id")
                    })
                    .and_then(|s| s.parse::<ObjectID>().ok());

                IkaDWalletCommandResponse::RegisterEncryptionKeyResponse {
                    encryption_key_id: encryption_key_id
                        .map(|id| id.to_string())
                        .unwrap_or_else(|| "pending (check transaction)".to_string()),
                    digest,
                    status,
                }
            }

            IkaDWalletCommand::VerifyPresign { presign_cap_id, tx } => {
                let (gas_budget, _config_path, config) = resolve_config!(
                    tx.gas_budget,
                    tx.ika_config,
                    global_gas_budget,
                    global_ika_config,
                    context
                );

                let response = ika_dwallet_transactions::verify_presign_cap(
                    context,
                    config.packages.ika_dwallet_2pc_mpc_package_id,
                    config.objects.ika_dwallet_coordinator_object_id,
                    presign_cap_id,
                    gas_budget,
                )
                .await?;
                let (digest, status) = tx_digest_and_status(&response);
                let verified_cap_id =
                    find_created_object_by_type(context, &response, "VerifiedPresignCap")
                        .await
                        .map(|id| id.to_string());
                IkaDWalletCommandResponse::VerifyPresign {
                    digest,
                    status,
                    verified_presign_cap_id: verified_cap_id,
                }
            }

            IkaDWalletCommand::GetEncryptionKey {
                encryption_key_id,
                tx: _,
            } => {
                let sdk_client = create_sdk_client(context).await?;
                let fields = fetch_object_fields(&sdk_client, encryption_key_id).await?;
                IkaDWalletCommandResponse::Get {
                    dwallet: serde_json::json!({
                        "encryption_key_id": encryption_key_id.to_string(),
                        "encryption_key": fields,
                    }),
                }
            }

            IkaDWalletCommand::Get { dwallet_id, tx: _ } => {
                let sdk_client = create_sdk_client(context).await?;

                let object_response = sdk_client
                    .read_api()
                    .get_object_with_options(dwallet_id, SuiObjectDataOptions::full_content())
                    .await?;

                let data = object_response
                    .data
                    .ok_or_else(|| anyhow::anyhow!("dWallet object not found: {dwallet_id}"))?;

                let content = data.content.ok_or_else(|| {
                    anyhow::anyhow!("No content for dWallet object: {dwallet_id}")
                })?;

                let json_value = serde_json::to_value(&content)?;

                IkaDWalletCommandResponse::Get {
                    dwallet: json_value,
                }
            }

            IkaDWalletCommand::Pricing { tx } => {
                let config_path = tx
                    .ika_config
                    .or(global_ika_config.clone())
                    .unwrap_or(ika_config_dir()?.join(IKA_SUI_CONFIG));
                let client = create_sui_client(context, &config_path).await?;
                let (_, coordinator_inner) = client.must_get_dwallet_coordinator_inner().await;
                let pricing_info = client.get_pricing_info(coordinator_inner).await;
                let pricing = serde_json::to_value(&pricing_info)?;
                IkaDWalletCommandResponse::Pricing { pricing }
            }

            IkaDWalletCommand::GenerateKeypair { curve, seed } => {
                let curve_id = curve_name_to_id(&curve)?;
                let seed_bytes = resolve_seed(context, seed.seed_file, seed.address, seed.index)?;
                let (encryption_key, decryption_key, signing_keypair) =
                    derive_encryption_keys(curve_id, seed_bytes, seed.legacy_hash)?;

                IkaDWalletCommandResponse::Keypair {
                    encryption_key: hex::encode(&encryption_key),
                    decryption_key: hex::encode(&decryption_key),
                    signer_public_key: hex::encode(signing_keypair.public().as_bytes()),
                    seed: hex::encode(seed_bytes),
                }
            }

            IkaDWalletCommand::List { tx: _ } => {
                let sdk_client = create_sdk_client(context).await?;
                let owner = context.active_address()?;

                // Query all owned objects of type DWalletCap
                let mut dwallets = Vec::new();
                let mut cursor = None;
                loop {
                    let page = sdk_client
                        .read_api()
                        .get_owned_objects(
                            owner,
                            Some(sui_json_rpc_types::SuiObjectResponseQuery {
                                filter: None,
                                options: Some(SuiObjectDataOptions::full_content()),
                            }),
                            cursor,
                            Some(50),
                        )
                        .await
                        .context("Failed to query owned objects")?;

                    for obj_resp in &page.data {
                        let Some(data) = &obj_resp.data else {
                            continue;
                        };
                        let Some(type_) = &data.type_ else { continue };
                        let type_str = type_.to_string();
                        if !type_str.contains("DWalletCap") {
                            continue;
                        }
                        let content = data
                            .content
                            .as_ref()
                            .map(|c| serde_json::to_value(c).unwrap_or_default());
                        let fields = content
                            .as_ref()
                            .and_then(|c| c.get("fields"))
                            .and_then(|f| {
                                if f.get("type").is_some() {
                                    f.get("fields")
                                } else {
                                    Some(f)
                                }
                            });
                        let dwallet_id = fields
                            .and_then(|f| f.get("dwallet_id"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown");
                        dwallets.push(serde_json::json!({
                            "cap_id": data.object_id.to_string(),
                            "dwallet_id": dwallet_id,
                        }));
                    }

                    if !page.has_next_page {
                        break;
                    }
                    cursor = page.next_cursor;
                }

                IkaDWalletCommandResponse::List { dwallets }
            }

            IkaDWalletCommand::ListPresigns { tx: _ } => {
                let sdk_client = create_sdk_client(context).await?;
                let owner = context.active_address()?;

                let mut verified = Vec::new();
                let mut unverified = Vec::new();
                let mut cursor = None;

                loop {
                    let page = sdk_client
                        .read_api()
                        .get_owned_objects(
                            owner,
                            Some(sui_json_rpc_types::SuiObjectResponseQuery {
                                filter: None,
                                options: Some(SuiObjectDataOptions::full_content()),
                            }),
                            cursor,
                            Some(50),
                        )
                        .await
                        .context("Failed to query owned objects")?;

                    for obj_resp in &page.data {
                        let Some(data) = &obj_resp.data else {
                            continue;
                        };
                        let Some(type_) = &data.type_ else { continue };
                        let type_str = type_.to_string();

                        let is_verified = type_str.contains("VerifiedPresignCap");
                        let is_unverified =
                            !is_verified && type_str.contains("UnverifiedPresignCap");
                        if !is_verified && !is_unverified {
                            continue;
                        }

                        let content = data
                            .content
                            .as_ref()
                            .map(|c| serde_json::to_value(c).unwrap_or_default());
                        let fields = content
                            .as_ref()
                            .and_then(|c| c.get("fields"))
                            .and_then(|f| {
                                if f.get("type").is_some() {
                                    f.get("fields")
                                } else {
                                    Some(f)
                                }
                            });

                        let presign_id = fields
                            .and_then(|f| f.get("presign_id"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown");
                        let dwallet_id = fields
                            .and_then(|f| f.get("dwallet_id"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("global");

                        // Fetch curve from presign session
                        let curve_name = if let Ok(pid) = presign_id.parse::<ObjectID>() {
                            fetch_object_fields(&sdk_client, pid)
                                .await
                                .ok()
                                .and_then(|f| f.get("curve").and_then(|v| v.as_u64()))
                                .and_then(|c| curve_id_to_name(c as u32).ok())
                                .unwrap_or("unknown")
                        } else {
                            "unknown"
                        };

                        let entry = serde_json::json!({
                            "cap_id": data.object_id.to_string(),
                            "presign_id": presign_id,
                            "dwallet_id": dwallet_id,
                            "curve": curve_name,
                        });

                        if is_verified {
                            verified.push(entry);
                        } else {
                            unverified.push(entry);
                        }
                    }

                    if !page.has_next_page {
                        break;
                    }
                    cursor = page.next_cursor;
                }

                // Sort by curve for readability
                verified.sort_by(|a, b| {
                    a.get("curve")
                        .and_then(|v| v.as_str())
                        .cmp(&b.get("curve").and_then(|v| v.as_str()))
                });
                unverified.sort_by(|a, b| {
                    a.get("curve")
                        .and_then(|v| v.as_str())
                        .cmp(&b.get("curve").and_then(|v| v.as_str()))
                });

                IkaDWalletCommandResponse::ListPresigns {
                    verified,
                    unverified,
                }
            }

            IkaDWalletCommand::PublicKey { dwallet_id, tx: _ } => {
                let metadata = fetch_dwallet_metadata(context, dwallet_id).await?;
                let dkg_output = metadata.dkg_output.ok_or_else(|| {
                    anyhow::anyhow!("dWallet not in Active state — cannot extract public key")
                })?;

                let curve =
                    dwallet_mpc_types::mpc_protocol_configuration::try_into_curve(metadata.curve)
                        .map_err(|e| anyhow::anyhow!("Invalid curve: {e:?}"))?;
                let public_key =
                    dwallet_mpc::public_key_from_dwallet_output_by_curve(curve, &dkg_output)
                        .context("Failed to extract public key from dWallet output")?;

                IkaDWalletCommandResponse::PublicKey {
                    dwallet_id: dwallet_id.to_string(),
                    public_key: hex::encode(&public_key),
                }
            }

            IkaDWalletCommand::Decrypt {
                dwallet_id,
                output_secret,
                seed,
                tx,
            } => {
                let (_, config_path, _) = resolve_config!(
                    tx.gas_budget,
                    tx.ika_config,
                    global_gas_budget,
                    global_ika_config,
                    context
                );
                let metadata = fetch_dwallet_metadata(context, dwallet_id).await?;
                let dkg_output = metadata.dkg_output.ok_or_else(|| {
                    anyhow::anyhow!("dWallet not in Active state — DKG output unavailable")
                })?;

                let network_key_info = get_network_key_info_for(
                    context,
                    &config_path,
                    metadata.network_encryption_key_id,
                    metadata.curve,
                )
                .await?;
                let protocol_pp = network_key_info.protocol_public_parameters;

                let sdk_client = create_sdk_client(context).await?;
                let encrypted_share = fetch_encrypted_share_for_dwallet(
                    &sdk_client,
                    context,
                    dwallet_id,
                    metadata.curve,
                    &seed,
                )
                .await?;

                let seed_bytes = resolve_seed(context, seed.seed_file, seed.address, seed.index)?;
                let (_enc_key, decryption_key, _signing_kp) =
                    derive_encryption_keys(metadata.curve, seed_bytes, seed.legacy_hash)?;

                let secret_share = decrypt_user_share_v2(
                    metadata.curve,
                    decryption_key,
                    dkg_output,
                    encrypted_share,
                    protocol_pp,
                )
                .context("Failed to decrypt user share")?;

                let secret_share_path = if let Some(ref path) = output_secret {
                    std::fs::write(path, &secret_share).context("Failed to save secret share")?;
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
                    }
                    Some(path.display().to_string())
                } else {
                    None
                };

                IkaDWalletCommandResponse::DecryptShare {
                    dwallet_id: dwallet_id.to_string(),
                    secret_share: hex::encode(&secret_share),
                    secret_share_path,
                }
            }

            IkaDWalletCommand::Epoch { tx } => {
                let config_path = tx
                    .ika_config
                    .or(global_ika_config.clone())
                    .unwrap_or(ika_config_dir()?.join(IKA_SUI_CONFIG));
                let client = create_sui_client(context, &config_path).await?;
                let (_, coordinator_inner) = client.must_get_dwallet_coordinator_inner().await;
                let epoch = match &coordinator_inner {
                    ika_types::sui::DWalletCoordinatorInner::V1(inner) => inner.current_epoch,
                };
                IkaDWalletCommandResponse::Epoch { epoch }
            }

            IkaDWalletCommand::Share { cmd } => match cmd {
                IkaDWalletShareCommand::MakePublic {
                    dwallet_id,
                    secret_share,
                    secret_share_hex,
                    seed: share_seed,
                    payment,
                    tx,
                } => {
                    let (gas_budget, config_path, config) = resolve_config!(
                        tx.gas_budget,
                        tx.ika_config,
                        global_gas_budget,
                        global_ika_config,
                        context
                    );
                    let coins = resolve_payment_coins(context, &config, &payment).await?;

                    // Fetch metadata for on-chain decryption if needed
                    let metadata = fetch_dwallet_metadata(context, dwallet_id).await?;
                    let dkg_output_bytes = metadata.dkg_output.ok_or_else(|| {
                        anyhow::anyhow!("dWallet not in Active state — DKG output unavailable")
                    })?;
                    let network_key_info = get_network_key_info_for(
                        context,
                        &config_path,
                        metadata.network_encryption_key_id,
                        metadata.curve,
                    )
                    .await?;
                    let protocol_pp = network_key_info.protocol_public_parameters;

                    let share_bytes = resolve_secret_share(
                        context,
                        secret_share,
                        secret_share_hex,
                        Some(dwallet_id),
                        metadata.curve,
                        &dkg_output_bytes,
                        &protocol_pp,
                        &share_seed,
                        quiet,
                    )
                    .await?;
                    let session_id = random_bytes().to_vec();

                    let response = ika_dwallet_transactions::request_make_shares_public(
                        context,
                        config.packages.ika_dwallet_2pc_mpc_package_id,
                        config.objects.ika_dwallet_coordinator_object_id,
                        dwallet_id,
                        share_bytes,
                        session_id,
                        coins,
                        gas_budget,
                    )
                    .await?;
                    tx_response_to_output(&response)
                }
                IkaDWalletShareCommand::ReEncrypt {
                    dwallet_id,
                    destination_address,
                    secret_share,
                    secret_share_hex,
                    source_encrypted_share_id,
                    destination_encryption_key,
                    curve,
                    seed: share_seed,
                    payment,
                    tx,
                } => {
                    let (gas_budget, config_path, config) = resolve_config!(
                        tx.gas_budget,
                        tx.ika_config,
                        global_gas_budget,
                        global_ika_config,
                        context
                    );
                    let curve_id = curve_name_to_id(&curve)?;
                    let coins = resolve_payment_coins(context, &config, &payment).await?;
                    let dest_encryption_key = hex_decode(&destination_encryption_key)?;

                    // Use the dWallet's specific network key for protocol parameters
                    let dwallet_metadata = fetch_dwallet_metadata(context, dwallet_id).await?;
                    let dkg_output_bytes = dwallet_metadata.dkg_output.ok_or_else(|| {
                        anyhow::anyhow!("dWallet not in Active state — DKG output unavailable")
                    })?;
                    let network_key_info = get_network_key_info_for(
                        context,
                        &config_path,
                        dwallet_metadata.network_encryption_key_id,
                        curve_id,
                    )
                    .await?;
                    let protocol_pp = network_key_info.protocol_public_parameters;

                    let share_bytes = resolve_secret_share(
                        context,
                        secret_share,
                        secret_share_hex,
                        Some(dwallet_id),
                        curve_id,
                        &dkg_output_bytes,
                        &protocol_pp,
                        &share_seed,
                        quiet,
                    )
                    .await?;

                    let encrypted_share_and_proof = encrypt_secret_key_share_and_prove_v2(
                        curve_id,
                        share_bytes,
                        dest_encryption_key,
                        protocol_pp,
                    )
                    .context("Failed to re-encrypt secret share")?;

                    let session_id = random_bytes().to_vec();

                    let response = ika_dwallet_transactions::request_re_encrypt_user_share(
                        context,
                        config.packages.ika_dwallet_2pc_mpc_package_id,
                        config.objects.ika_dwallet_coordinator_object_id,
                        dwallet_id,
                        destination_address,
                        encrypted_share_and_proof,
                        source_encrypted_share_id,
                        session_id,
                        coins,
                        gas_budget,
                    )
                    .await?;
                    tx_response_to_output(&response)
                }
                IkaDWalletShareCommand::Accept {
                    dwallet_id,
                    encrypted_share_id,
                    user_output_signature,
                    tx,
                } => {
                    let (gas_budget, _config_path, config) = resolve_config!(
                        tx.gas_budget,
                        tx.ika_config,
                        global_gas_budget,
                        global_ika_config,
                        context
                    );
                    let sig_bytes = hex_decode(&user_output_signature)?;

                    let response = ika_dwallet_transactions::accept_encrypted_user_share(
                        context,
                        config.packages.ika_dwallet_2pc_mpc_package_id,
                        config.objects.ika_dwallet_coordinator_object_id,
                        dwallet_id,
                        encrypted_share_id,
                        sig_bytes,
                        gas_budget,
                    )
                    .await?;
                    tx_response_to_output(&response)
                }
            },
        };

        if !quiet || json {
            response.print(json);
        }
        Ok(())
    }
}

/// Poll a presign session until it reaches Completed state.
async fn poll_presign_until_complete(
    context: &WalletContext,
    presign_id: ObjectID,
    timeout_secs: u64,
) -> Result<()> {
    let sdk_client = create_sdk_client(context).await?;
    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(timeout_secs);
    let mut interval_ms = 2000u64;
    let max_interval_ms = 5000u64;

    loop {
        if start.elapsed() > timeout {
            anyhow::bail!(
                "Timeout waiting for presign {presign_id} to complete ({}s)",
                timeout_secs
            );
        }

        if let Ok(fields) = fetch_object_fields(&sdk_client, presign_id).await
            && let Some(state) = fields.get("state")
        {
            let variant = state.get("variant").and_then(|v| v.as_str()).unwrap_or("");
            match variant {
                "Completed" => return Ok(()),
                "NetworkRejected" => {
                    anyhow::bail!("Presign {presign_id} was rejected by the network");
                }
                _ => {} // Still processing
            }
            // Also check for presign field (non-enum state representation)
            let has_presign = state.get("fields").and_then(|f| f.get("presign")).is_some();
            if has_presign {
                return Ok(());
            }
        }

        tokio::time::sleep(std::time::Duration::from_millis(interval_ms)).await;
        interval_ms = (interval_ms * 3 / 2).min(max_interval_ms);
    }
}

/// Wait for a presign to complete, then verify the cap. Returns the verified cap ID.
async fn wait_and_verify_presign(
    context: &mut WalletContext,
    config: &IkaNetworkConfig,
    presign_id: ObjectID,
    unverified_cap_id: ObjectID,
    gas_budget: u64,
    quiet: bool,
) -> Result<ObjectID> {
    if !quiet {
        eprintln!("Waiting for presign to complete...");
    }
    poll_presign_until_complete(context, presign_id, 300).await?;

    if !quiet {
        eprintln!("Presign complete. Verifying cap...");
    }
    let response = ika_dwallet_transactions::verify_presign_cap(
        context,
        config.packages.ika_dwallet_2pc_mpc_package_id,
        config.objects.ika_dwallet_coordinator_object_id,
        unverified_cap_id,
        gas_budget,
    )
    .await?;

    let verified_cap_id = find_created_object_by_type(context, &response, "VerifiedPresignCap")
        .await
        .ok_or_else(|| anyhow::anyhow!("Failed to find VerifiedPresignCap in verify response"))?;

    if !quiet {
        eprintln!("Presign verified: {verified_cap_id}");
    }
    Ok(verified_cap_id)
}

/// Resolve the user secret share from one of three sources (in priority order):
/// 1. `--secret-share <file>` — read raw bytes from a local file
/// 2. `--secret-share-hex <hex>` — decode a hex string
/// 3. On-chain decryption — fetch the encrypted share from the dWallet object, derive the
///    decryption key from the user's Sui keystore, and decrypt locally.
async fn resolve_secret_share(
    context: &mut WalletContext,
    secret_share_file: Option<PathBuf>,
    secret_share_hex: Option<String>,
    dwallet_id: Option<ObjectID>,
    curve_id: u32,
    dkg_output_bytes: &[u8],
    protocol_pp: &[u8],
    seed: &SeedArgs,
    quiet: bool,
) -> Result<Vec<u8>> {
    // Priority 1: file on disk
    if let Some(path) = secret_share_file {
        return std::fs::read(&path).context("Failed to read secret share file");
    }

    // Priority 2: hex string
    if let Some(hex) = secret_share_hex {
        return hex_decode(&hex);
    }

    // Priority 3: on-chain decryption
    let dwallet_id = dwallet_id.ok_or_else(|| {
        anyhow::anyhow!(
            "No secret share provided. Either pass --secret-share <file>, \
             --secret-share-hex <hex>, or provide --dwallet-id so the CLI can \
             fetch and decrypt the on-chain encrypted share."
        )
    })?;

    if !quiet {
        eprintln!("No secret share provided. Decrypting from on-chain encrypted share...");
    }

    let sdk_client = create_sdk_client(context).await?;
    let encrypted_share_and_proof =
        fetch_encrypted_share_for_dwallet(&sdk_client, context, dwallet_id, curve_id, seed).await?;

    let seed_bytes = resolve_seed(context, seed.seed_file.clone(), seed.address, seed.index)?;
    let (_encryption_key, decryption_key, _signing_keypair) =
        derive_encryption_keys(curve_id, seed_bytes, seed.legacy_hash)?;

    decrypt_user_share_v2(
        curve_id,
        decryption_key,
        dkg_output_bytes.to_vec(),
        encrypted_share_and_proof,
        protocol_pp.to_vec(),
    )
    .context("Failed to decrypt on-chain secret share. Is your keystore seed correct?")
}

/// Fetch the encrypted secret share for a dWallet from its on-chain `ObjectTable`.
///
/// The dWallet stores encrypted shares in `encrypted_user_secret_key_shares: ObjectTable`.
/// We enumerate its dynamic fields (DynamicObject entries) and find the one whose
/// `encryption_key_address` matches the user's derived encryption key address.
///
/// `encryption_key_address` is an `address` field derived from the Ed25519 signing keypair
/// (not the Sui wallet address), so we compute it from seed args.
async fn fetch_encrypted_share_for_dwallet(
    sdk_client: &sui_sdk::SuiClient,
    context: &mut WalletContext,
    dwallet_id: ObjectID,
    curve_id: u32,
    seed: &SeedArgs,
) -> Result<Vec<u8>> {
    // Compute the encryption_key_address from the user's seed
    let seed_bytes = resolve_seed(context, seed.seed_file.clone(), seed.address, seed.index)?;
    let (_encryption_key, _decryption_key, signing_keypair) =
        derive_encryption_keys(curve_id, seed_bytes, seed.legacy_hash)?;
    let encryption_key_address: SuiAddress = signing_keypair.public().into();

    // 1. Get the dWallet object to find the ObjectTable ID
    let dwallet_fields = fetch_object_fields(sdk_client, dwallet_id).await?;
    let table_id = dwallet_fields
        .get("encrypted_user_secret_key_shares")
        .and_then(|v| v.get("fields"))
        .and_then(|f| f.get("id"))
        .and_then(|id| id.get("id"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Could not find encrypted_user_secret_key_shares table on dWallet {dwallet_id}"
            )
        })?;
    let table_oid: ObjectID = table_id
        .parse()
        .context("Invalid ObjectTable ID for encrypted shares")?;

    // 2. Enumerate dynamic fields of the ObjectTable.
    //    These are DynamicObject entries — each field_info.object_id IS the
    //    EncryptedUserSecretKeyShare object directly (no Field wrapper).
    let mut cursor = None;
    loop {
        let page = sdk_client
            .read_api()
            .get_dynamic_fields(table_oid, cursor, Some(50))
            .await
            .context("Failed to query encrypted share dynamic fields")?;

        for field_info in &page.data {
            let share_fields = fetch_object_fields(sdk_client, field_info.object_id).await?;

            // Check if this share belongs to the current user's encryption key
            let key_address = share_fields
                .get("encryption_key_address")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if key_address != encryption_key_address.to_string() {
                continue;
            }

            // Found our share — extract the encrypted bytes
            let encrypted_bytes = share_fields
                .get("encrypted_centralized_secret_share_and_proof")
                .and_then(extract_bytes_from_json)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "Found EncryptedUserSecretKeyShare for dWallet {dwallet_id} \
                         but could not extract encrypted bytes"
                    )
                })?;
            return Ok(encrypted_bytes);
        }

        if !page.has_next_page {
            break;
        }
        cursor = page.next_cursor;
    }

    anyhow::bail!(
        "No EncryptedUserSecretKeyShare found for dWallet {dwallet_id} \
         with encryption key address {encryption_key_address}. \
         Was the dWallet created with this keystore address and seed index?"
    )
}

/// Resolve presign output: use provided hex string or auto-fetch from the presign cap on chain.
async fn resolve_presign_output(
    context: &WalletContext,
    presign_output: Option<String>,
    presign_cap_id: ObjectID,
) -> Result<Vec<u8>> {
    match presign_output {
        Some(hex) => hex_decode(&hex),
        None => fetch_presign_output(context, presign_cap_id).await,
    }
}

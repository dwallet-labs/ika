// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::*;
use dwallet_mpc_centralized_party::{
    advance_centralized_sign_party, create_dkg_output_by_curve_v2,
    create_imported_dwallet_centralized_step_inner_v2, encrypt_secret_key_share_and_prove_v2,
    generate_cg_keypair_from_seed, network_dkg_public_output_to_protocol_pp_inner,
};
use fastcrypto::ed25519::Ed25519KeyPair;
use fastcrypto::traits::{KeyPair, Signer, ToFromBytes};
use ika_config::{IKA_SUI_CONFIG, ika_config_dir};
use ika_sui_client::SuiConnectorClient;
use ika_sui_client::ika_dwallet_transactions;
use ika_sui_client::metrics::SuiClientMetrics;
use ika_types::messages_dwallet_mpc::{IkaNetworkConfig, SessionIdentifier};
use serde::{Deserialize, Serialize};
use sui_json_rpc_types::{SuiObjectDataOptions, SuiTransactionBlockEffectsAPI};
use sui_sdk::wallet_context::WalletContext;
use sui_types::base_types::{ObjectID, SuiAddress};

use crate::output::CommandOutput;
use crate::read_ika_sui_config_yaml;

const DEFAULT_GAS_BUDGET: u64 = 200_000_000; // 0.2 SUI
const ENCRYPTION_KEYS_DIR: &str = "encryption_keys";

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
        /// Path to the user secret share file.
        #[clap(long)]
        secret_share: PathBuf,
        /// IKA coin object ID for payment. Auto-detected from wallet if omitted.
        #[clap(long)]
        ika_coin_id: Option<ObjectID>,
        /// SUI coin object ID for payment. Auto-detected from wallet if omitted.
        #[clap(long)]
        sui_coin_id: Option<ObjectID>,
        #[clap(long)]
        gas_budget: Option<u64>,
        #[clap(long)]
        ika_sui_config: Option<PathBuf>,
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
        /// Path to the user secret share file.
        #[clap(long)]
        secret_share: PathBuf,
        /// The source encrypted user secret key share ID.
        #[clap(long)]
        source_encrypted_share_id: ObjectID,
        /// The destination user's encryption key value (hex-encoded).
        #[clap(long)]
        destination_encryption_key: String,
        /// The curve used for this dWallet.
        #[clap(long, value_parser = ["secp256k1", "secp256r1", "ed25519", "ristretto"])]
        curve: String,
        /// IKA coin object ID for payment. Auto-detected from wallet if omitted.
        #[clap(long)]
        ika_coin_id: Option<ObjectID>,
        /// SUI coin object ID for payment. Auto-detected from wallet if omitted.
        #[clap(long)]
        sui_coin_id: Option<ObjectID>,
        #[clap(long)]
        gas_budget: Option<u64>,
        #[clap(long)]
        ika_sui_config: Option<PathBuf>,
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
        #[clap(long)]
        gas_budget: Option<u64>,
        #[clap(long)]
        ika_sui_config: Option<PathBuf>,
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
        /// The network encryption key object ID.
        #[clap(long)]
        encryption_key_id: ObjectID,
        /// Where to save the user secret share.
        #[clap(long, default_value = "dwallet_secret_share.bin")]
        output_secret: PathBuf,
        /// Use public user secret key share variant (shared dWallet).
        #[clap(long)]
        public_share: bool,
        /// Optional message to sign during DKG (hex-encoded).
        #[clap(long)]
        sign_message: Option<String>,
        /// Hash scheme for sign-during-DKG (required if --sign-message is set).
        #[clap(long)]
        hash_scheme: Option<u32>,
        /// IKA coin object ID for payment. Auto-detected from wallet if omitted.
        #[clap(long)]
        ika_coin_id: Option<ObjectID>,
        /// SUI coin object ID for payment. Auto-detected from wallet if omitted.
        #[clap(long)]
        sui_coin_id: Option<ObjectID>,
        /// Seed for encryption key derivation (hex-encoded, 32 bytes). Random if omitted.
        #[clap(long)]
        encryption_seed: Option<String>,
        #[clap(long)]
        gas_budget: Option<u64>,
        #[clap(long)]
        ika_sui_config: Option<PathBuf>,
    },

    /// Request a signature from a dWallet.
    ///
    /// Pass --dwallet-id to auto-fetch curve and DKG output from chain.
    /// Or provide --curve and --dkg-output manually for offline use.
    #[clap(name = "sign")]
    Sign {
        /// The dWallet capability object ID.
        #[clap(long)]
        dwallet_cap_id: ObjectID,
        /// The message to sign (hex-encoded).
        #[clap(long)]
        message: String,
        /// The signature algorithm to use.
        #[clap(long)]
        signature_algorithm: u32,
        /// The hash scheme to use.
        #[clap(long)]
        hash_scheme: u32,
        /// Pre-existing verified presign cap ID.
        #[clap(long)]
        presign_cap_id: ObjectID,
        /// Path to the user secret share file.
        #[clap(long)]
        secret_share: PathBuf,
        /// The presign output (hex-encoded). Auto-fetched from --presign-cap-id if omitted.
        #[clap(long)]
        presign_output: Option<String>,
        /// The dWallet object ID. When provided, curve and DKG output are fetched from chain.
        #[clap(long)]
        dwallet_id: Option<ObjectID>,
        /// The curve used by the dWallet. Auto-detected if --dwallet-id is provided.
        #[clap(long, value_parser = ["secp256k1", "secp256r1", "ed25519", "ristretto"])]
        curve: Option<String>,
        /// The dWallet's decentralized DKG public output (hex-encoded).
        /// Auto-fetched if --dwallet-id is provided.
        #[clap(long)]
        dkg_output: Option<String>,
        /// IKA coin object ID for payment. Auto-detected from wallet if omitted.
        #[clap(long)]
        ika_coin_id: Option<ObjectID>,
        /// SUI coin object ID for payment. Auto-detected from wallet if omitted.
        #[clap(long)]
        sui_coin_id: Option<ObjectID>,
        #[clap(long)]
        gas_budget: Option<u64>,
        #[clap(long)]
        ika_sui_config: Option<PathBuf>,
    },

    /// Request a future/conditional signature.
    ///
    /// Pass --dwallet-id to auto-fetch curve and DKG output from chain.
    #[clap(name = "future-sign")]
    FutureSign {
        /// The dWallet ID.
        #[clap(long)]
        dwallet_id: ObjectID,
        /// The message to sign (hex-encoded).
        #[clap(long)]
        message: String,
        /// The hash scheme to use.
        #[clap(long)]
        hash_scheme: u32,
        /// The verified presign cap ID.
        #[clap(long)]
        presign_cap_id: ObjectID,
        /// Path to the user secret share file.
        #[clap(long)]
        secret_share: PathBuf,
        /// The presign output (hex-encoded). Auto-fetched from --presign-cap-id if omitted.
        #[clap(long)]
        presign_output: Option<String>,
        /// The signature algorithm to use.
        #[clap(long)]
        signature_algorithm: u32,
        /// The curve used by the dWallet. Auto-detected from --dwallet-id if omitted.
        #[clap(long, value_parser = ["secp256k1", "secp256r1", "ed25519", "ristretto"])]
        curve: Option<String>,
        /// The dWallet's decentralized DKG public output (hex-encoded).
        /// Auto-fetched from --dwallet-id if omitted.
        #[clap(long)]
        dkg_output: Option<String>,
        /// IKA coin object ID for payment. Auto-detected from wallet if omitted.
        #[clap(long)]
        ika_coin_id: Option<ObjectID>,
        /// SUI coin object ID for payment. Auto-detected from wallet if omitted.
        #[clap(long)]
        sui_coin_id: Option<ObjectID>,
        #[clap(long)]
        gas_budget: Option<u64>,
        #[clap(long)]
        ika_sui_config: Option<PathBuf>,
    },

    /// Request a presign for a dWallet.
    #[clap(name = "presign")]
    Presign {
        /// The dWallet ID.
        #[clap(long)]
        dwallet_id: ObjectID,
        /// The signature algorithm to use.
        #[clap(long)]
        signature_algorithm: u32,
        /// IKA coin object ID for payment. Auto-detected from wallet if omitted.
        #[clap(long)]
        ika_coin_id: Option<ObjectID>,
        /// SUI coin object ID for payment. Auto-detected from wallet if omitted.
        #[clap(long)]
        sui_coin_id: Option<ObjectID>,
        #[clap(long)]
        gas_budget: Option<u64>,
        #[clap(long)]
        ika_sui_config: Option<PathBuf>,
    },

    /// Request a global presign using network encryption key.
    #[clap(name = "global-presign")]
    GlobalPresign {
        /// The curve.
        #[clap(long)]
        curve: u32,
        /// The signature algorithm.
        #[clap(long)]
        signature_algorithm: u32,
        /// IKA coin object ID for payment. Auto-detected from wallet if omitted.
        #[clap(long)]
        ika_coin_id: Option<ObjectID>,
        /// SUI coin object ID for payment. Auto-detected from wallet if omitted.
        #[clap(long)]
        sui_coin_id: Option<ObjectID>,
        #[clap(long)]
        gas_budget: Option<u64>,
        #[clap(long)]
        ika_sui_config: Option<PathBuf>,
    },

    /// Import an external key as a dWallet.
    #[clap(name = "import")]
    Import {
        /// The curve.
        #[clap(long, value_parser = ["secp256k1", "secp256r1", "ed25519", "ristretto"])]
        curve: String,
        /// Path to the secret key file to import.
        #[clap(long)]
        centralized_message: PathBuf,
        /// The network encryption key object ID.
        #[clap(long)]
        encryption_key_id: ObjectID,
        /// Where to save the user secret share.
        #[clap(long, default_value = "imported_dwallet_secret_share.bin")]
        output_secret: PathBuf,
        /// IKA coin object ID for payment. Auto-detected from wallet if omitted.
        #[clap(long)]
        ika_coin_id: Option<ObjectID>,
        /// SUI coin object ID for payment. Auto-detected from wallet if omitted.
        #[clap(long)]
        sui_coin_id: Option<ObjectID>,
        #[clap(long)]
        gas_budget: Option<u64>,
        #[clap(long)]
        ika_sui_config: Option<PathBuf>,
    },

    /// Register a user encryption key for dWallet operations.
    #[clap(name = "register-encryption-key")]
    RegisterEncryptionKey {
        /// The curve for which to register the encryption key.
        #[clap(long, value_parser = ["secp256k1", "secp256r1", "ed25519", "ristretto"])]
        curve: String,
        /// Seed for key derivation (hex-encoded, 32 bytes). Random if omitted.
        #[clap(long)]
        seed: Option<String>,
        #[clap(long)]
        gas_budget: Option<u64>,
        #[clap(long)]
        ika_sui_config: Option<PathBuf>,
    },

    /// Get an encryption key by its object ID (returned from register-encryption-key).
    #[clap(name = "get-encryption-key")]
    GetEncryptionKey {
        /// The encryption key object ID (returned from register-encryption-key).
        #[clap(long)]
        encryption_key_id: ObjectID,
        #[clap(long)]
        ika_sui_config: Option<PathBuf>,
    },

    /// Verify a presign capability.
    #[clap(name = "verify-presign")]
    VerifyPresign {
        /// The unverified presign cap ID.
        #[clap(long)]
        presign_cap_id: ObjectID,
        #[clap(long)]
        gas_budget: Option<u64>,
        #[clap(long)]
        ika_sui_config: Option<PathBuf>,
    },

    /// Query dWallet information.
    #[clap(name = "get")]
    Get {
        /// The dWallet ID to query.
        #[clap(long)]
        dwallet_id: ObjectID,
        #[clap(long)]
        ika_sui_config: Option<PathBuf>,
    },

    /// Query current pricing information.
    #[clap(name = "pricing")]
    Pricing {
        #[clap(long)]
        ika_sui_config: Option<PathBuf>,
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
        /// Seed for derivation (hex-encoded, 32 bytes). Random if omitted.
        #[clap(long)]
        seed: Option<String>,
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
        secret_share_path: String,
    },
    #[serde(rename = "sign")]
    Sign { digest: String, status: String },
    #[serde(rename = "presign")]
    Presign { digest: String, status: String },
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
                secret_share_path,
            } => {
                println!("dWallet created successfully.");
                println!("  dWallet ID: {dwallet_id}");
                println!("  Cap ID:     {dwallet_cap_id}");
                println!("  Public Key: {public_key}");
                println!("  Secret share saved to: {secret_share_path}");
            }
            Self::Sign { digest, status } => {
                println!("Sign request submitted.");
                println!("  Transaction: {digest}");
                println!("  Status:      {status}");
            }
            Self::Presign { digest, status } => {
                println!("Presign request submitted.");
                println!("  Transaction: {digest}");
                println!("  Status:      {status}");
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
        if let Ok(obj) = grpc_client.get_object(obj_id).await {
            if let Some(move_obj) = obj.data.try_as_move() {
                let type_str = move_obj.type_().to_string();
                if type_str.contains(type_substr) {
                    return Some(obj_id);
                }
            }
        }
    }
    None
}

/// Extract dWallet ID and DWalletCap ID from created objects.
struct CreatedDWalletIds {
    dwallet_id: Option<ObjectID>,
    dwallet_cap_id: Option<ObjectID>,
    encrypted_share_id: Option<ObjectID>,
}

async fn extract_created_dwallet_ids(
    context: &mut WalletContext,
    response: &sui_json_rpc_types::SuiTransactionBlockResponse,
) -> CreatedDWalletIds {
    let effects = match response.effects.as_ref() {
        Some(e) => e,
        None => {
            return CreatedDWalletIds {
                dwallet_id: None,
                dwallet_cap_id: None,
                encrypted_share_id: None,
            };
        }
    };

    let created_ids: Vec<ObjectID> = effects
        .created()
        .iter()
        .map(|o| o.reference.object_id)
        .collect();

    let mut dwallet_cap_id = None;
    let mut encrypted_share_id = None;

    let mut grpc_client = match context.grpc_client() {
        Ok(c) => c,
        Err(_) => {
            return CreatedDWalletIds {
                dwallet_id: None,
                dwallet_cap_id: None,
                encrypted_share_id: None,
            };
        }
    };

    for obj_id in &created_ids {
        if let Ok(obj) = grpc_client.get_object(*obj_id).await {
            if let Some(move_obj) = obj.data.try_as_move() {
                let type_str = move_obj.type_().to_string();
                if type_str.contains("DWalletCap") {
                    dwallet_cap_id = Some(*obj_id);
                } else if type_str.contains("EncryptedUserSecretKeyShare") {
                    encrypted_share_id = Some(*obj_id);
                }
            }
        }
    }

    // Get the dWallet ID from the DWalletCap's `dwallet_id` field — this is the
    // authoritative source. Direct type matching on created objects can pick up
    // wrong objects (e.g. DWalletNetworkEncryptionKey also contains "DWallet").
    let dwallet_id = if let Some(cap_id) = dwallet_cap_id {
        let sdk_client = create_sdk_client(context).await.ok();
        if let Some(client) = sdk_client {
            fetch_object_fields(&client, cap_id)
                .await
                .ok()
                .and_then(|fields| {
                    fields
                        .get("dwallet_id")
                        .and_then(|v| v.as_str())
                        .and_then(|s| s.parse::<ObjectID>().ok())
                })
        } else {
            None
        }
    } else {
        None
    };

    CreatedDWalletIds {
        dwallet_id,
        dwallet_cap_id,
        encrypted_share_id,
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

        if let Ok(fields) = fetch_object_fields(sdk_client, dwallet_id).await {
            if let Some(state) = fields.get("state") {
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

/// Compute the session identifier preimage as it would be computed on-chain by
/// `register_session_identifier`: `keccak256(sender_address || user_bytes)`.
/// This must match the on-chain computation so the MPC network sees the correct session ID.
fn on_chain_session_preimage(sender: &SuiAddress, user_bytes: &[u8]) -> [u8; 32] {
    use fastcrypto::hash::{HashFunction, Keccak256};
    let mut hasher = Keccak256::default();
    hasher.update(&sender.to_vec());
    hasher.update(user_bytes);
    let digest = hasher.finalize();
    let mut preimage = [0u8; 32];
    preimage.copy_from_slice(digest.as_ref());
    preimage
}

/// Derive encryption keys from a seed: (encryption_key, decryption_key, signing_keypair).
fn derive_encryption_keys(
    curve: u32,
    seed: [u8; 32],
) -> Result<(Vec<u8>, Vec<u8>, Ed25519KeyPair)> {
    let cg_seed = {
        use fastcrypto::hash::{HashFunction, Keccak256};
        let mut hasher = Keccak256::default();
        hasher.update(b"CLASS_GROUPS_DECRYPTION_KEY_V1");
        hasher.update(&seed);
        hasher.update(&curve.to_le_bytes());
        let digest = hasher.finalize();
        let mut cg_seed = [0u8; 32];
        cg_seed.copy_from_slice(digest.as_ref());
        cg_seed
    };

    let signing_seed = {
        use fastcrypto::hash::{HashFunction, Keccak256};
        let mut hasher = Keccak256::default();
        hasher.update(b"ED25519_SIGNING_KEY_V1");
        hasher.update(&seed);
        hasher.update(&curve.to_le_bytes());
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

// ---------------------------------------------------------------------------
// Local encryption key storage
// ---------------------------------------------------------------------------

/// Locally stored encryption keypair for reuse across dWallet operations.
#[derive(Serialize, Deserialize)]
struct StoredEncryptionKey {
    encryption_key_id: String,
    curve: String,
    encryption_key: String,
    decryption_key: String,
    signer_public_key: String,
    signer_address: String,
    seed: String,
}

/// Directory for stored encryption keys: `~/.ika/ika_config/encryption_keys/`.
fn encryption_keys_dir() -> Result<PathBuf> {
    let dir = ika_config_dir()?.join(ENCRYPTION_KEYS_DIR);
    std::fs::create_dir_all(&dir).context("Failed to create encryption_keys directory")?;
    Ok(dir)
}

/// Save an encryption keypair locally after registration.
fn save_encryption_key(
    encryption_key_id: &str,
    curve: &str,
    encryption_key: &[u8],
    decryption_key: &[u8],
    signer_public_key: &[u8],
    signer_address: &str,
    seed: &[u8; 32],
) -> Result<PathBuf> {
    let stored = StoredEncryptionKey {
        encryption_key_id: encryption_key_id.to_string(),
        curve: curve.to_string(),
        encryption_key: hex::encode(encryption_key),
        decryption_key: hex::encode(decryption_key),
        signer_public_key: hex::encode(signer_public_key),
        signer_address: signer_address.to_string(),
        seed: hex::encode(seed),
    };
    let dir = encryption_keys_dir()?;
    let path = dir.join(format!("{encryption_key_id}.json"));
    let json = serde_json::to_string_pretty(&stored)?;
    std::fs::write(&path, &json).context("Failed to write encryption key file")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(path)
}

/// Load a stored encryption keypair by encryption key ID.
fn load_encryption_key(encryption_key_id: &ObjectID) -> Result<Option<StoredEncryptionKey>> {
    let dir = match encryption_keys_dir() {
        Ok(d) => d,
        Err(_) => return Ok(None),
    };
    let path = dir.join(format!("{encryption_key_id}.json"));
    if !path.exists() {
        return Ok(None);
    }
    let json = std::fs::read_to_string(&path).context("Failed to read encryption key file")?;
    let stored: StoredEncryptionKey =
        serde_json::from_str(&json).context("Failed to parse encryption key file")?;
    Ok(Some(stored))
}

/// Load a stored encryption key and derive the full keypair from the stored seed.
fn load_encryption_keypair(
    encryption_key_id: &ObjectID,
    curve_id: u32,
) -> Result<Option<(Vec<u8>, Vec<u8>, Ed25519KeyPair)>> {
    let stored = match load_encryption_key(encryption_key_id)? {
        Some(s) => s,
        None => return Ok(None),
    };
    let seed_bytes = hex_decode(&stored.seed)?;
    anyhow::ensure!(seed_bytes.len() == 32, "Stored seed must be 32 bytes");
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes);
    let (enc_key, dec_key, keypair) = derive_encryption_keys(curve_id, seed)?;
    Ok(Some((enc_key, dec_key, keypair)))
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
    network_dkg_public_output: Vec<u8>,
}

async fn get_network_key_info(
    context: &WalletContext,
    config_path: &PathBuf,
) -> Result<NetworkKeyInfo> {
    let client = create_sui_client(context, config_path).await?;
    let (_, coordinator_inner) = client.must_get_dwallet_coordinator_inner().await;
    let network_keys = client
        .get_dwallet_mpc_network_keys(&coordinator_inner)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get network encryption keys: {e}"))?;

    let (id, key) = network_keys
        .iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("No network encryption keys found"))?;

    let epoch = match &coordinator_inner {
        ika_types::sui::DWalletCoordinatorInner::V1(inner) => inner.current_epoch,
    };

    let key_data = client
        .get_network_encryption_key_with_full_data_by_epoch(key, epoch)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get network key data: {e}"))?;

    Ok(NetworkKeyInfo {
        network_encryption_key_id: *id,
        network_dkg_public_output: key_data.network_dkg_public_output,
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

/// Auto-find a SUI coin owned by the active address for use as the payment coin.
/// Returns the coin with the smallest balance to minimize conflict with gas coin selection,
/// which typically picks the coin with the largest balance.
async fn find_sui_coin(sdk_client: &sui_sdk::SuiClient, owner: SuiAddress) -> Result<ObjectID> {
    let coins = sdk_client
        .coin_read_api()
        .get_coins(owner, Some("0x2::sui::SUI".to_string()), None, Some(10))
        .await
        .context("Failed to query SUI coins")?;
    // Pick the coin with the smallest balance to avoid conflict with gas coin
    // (gas selection typically picks a coin with sufficient balance).
    let coin = coins
        .data
        .into_iter()
        .min_by_key(|c| c.balance)
        .ok_or_else(|| anyhow::anyhow!("No SUI coins found for {owner}"))?;
    Ok(coin.coin_object_id)
}

/// Resolve IKA and SUI coin IDs: use provided values or auto-detect from wallet.
/// When no IKA coins exist (common on localnet with zero fees), creates a zero-value IKA coin.
async fn resolve_coins(
    context: &mut WalletContext,
    config: &IkaNetworkConfig,
    ika_coin_id: Option<ObjectID>,
    sui_coin_id: Option<ObjectID>,
) -> Result<(ObjectID, ObjectID)> {
    let owner = context.active_address()?;
    let sdk_client = if ika_coin_id.is_none() || sui_coin_id.is_none() {
        Some(create_sdk_client(context).await?)
    } else {
        None
    };

    let ika = match ika_coin_id {
        Some(id) => id,
        None => match find_ika_coin(sdk_client.as_ref().unwrap(), owner, config).await {
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
                        anyhow::anyhow!("Failed to find created IKA coin in transaction response")
                    })?
            }
        },
    };
    let sui = match sui_coin_id {
        Some(id) => id,
        None => find_sui_coin(sdk_client.as_ref().unwrap(), owner).await?,
    };
    Ok((ika, sui))
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
    json.get("fields")
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("No fields in object: {object_id}"))
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

    Ok(DWalletMetadata {
        curve,
        dkg_output,
        is_imported_key_dwallet,
    })
}

struct DWalletMetadata {
    curve: u32,
    /// The DKG public output bytes, if the dWallet is in Active state.
    dkg_output: Option<Vec<u8>>,
    /// Whether this dWallet was created from an imported key.
    is_imported_key_dwallet: bool,
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
/// Sui encodes `vector<u8>` as either a JSON array of numbers or a base64/hex string.
fn extract_bytes_from_json(value: &serde_json::Value) -> Option<Vec<u8>> {
    match value {
        // Array of numbers: [1, 2, 3, ...]
        serde_json::Value::Array(arr) => arr.iter().map(|v| v.as_u64().map(|n| n as u8)).collect(),
        // String: could be hex or base64
        serde_json::Value::String(s) => {
            // Try hex first (with or without 0x prefix)
            let stripped = s.strip_prefix("0x").unwrap_or(s);
            if let Ok(bytes) = hex::decode(stripped) {
                return Some(bytes);
            }
            // Try base64
            use base64::{Engine, engine::general_purpose::STANDARD};
            STANDARD.decode(s).ok()
        }
        _ => None,
    }
}

/// Parse a seed from hex string or generate random.
fn parse_or_random_seed(seed_hex: Option<String>) -> Result<[u8; 32]> {
    match seed_hex {
        Some(hex_seed) => {
            let bytes = hex_decode(&hex_seed)?;
            anyhow::ensure!(bytes.len() == 32, "Seed must be 32 bytes");
            let mut s = [0u8; 32];
            s.copy_from_slice(&bytes);
            Ok(s)
        }
        None => Ok(random_bytes()),
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
                encryption_key_id,
                output_secret,
                public_share,
                sign_message: _,
                hash_scheme: _,
                ika_coin_id,
                sui_coin_id,
                encryption_seed,
                gas_budget,
                ika_sui_config,
            } => {
                let gas_budget = gas_budget
                    .or(global_gas_budget)
                    .unwrap_or(DEFAULT_GAS_BUDGET);
                let config_path = ika_sui_config
                    .or(global_ika_config.clone())
                    .unwrap_or(ika_config_dir()?.join(IKA_SUI_CONFIG));
                let config = read_ika_sui_config_yaml(context, &config_path)?;
                let curve_id = curve_name_to_id(&curve)?;
                let (ika_coin, sui_coin) =
                    resolve_coins(context, &config, ika_coin_id, sui_coin_id).await?;

                // 1. Get network DKG public output and derive protocol parameters
                let network_key_info = get_network_key_info(context, &config_path).await?;
                let protocol_pp = network_dkg_public_output_to_protocol_pp_inner(
                    curve_id,
                    network_key_info.network_dkg_public_output,
                )
                .context("Failed to derive protocol parameters")?;

                // 2. Generate session identifier
                // The on-chain register_session_identifier hashes sender || bytes
                // to get the preimage, so we must match that for the crypto computation.
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

                // 4. Load stored encryption key or derive from seed
                let (encryption_key, _decryption_key, signing_keypair) =
                    match load_encryption_keypair(&encryption_key_id, curve_id)? {
                        Some(keys) => keys,
                        None => {
                            let seed = parse_or_random_seed(encryption_seed)?;
                            derive_encryption_keys(curve_id, seed)?
                        }
                    };
                let signer_public_key = signing_keypair.public().as_bytes().to_vec();
                let encryption_key_address: SuiAddress = signing_keypair.public().into();

                // 5. Save user secret share
                std::fs::write(&output_secret, &dkg_result.centralized_secret_output)
                    .context("Failed to save secret share")?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(
                        &output_secret,
                        std::fs::Permissions::from_mode(0o600),
                    )?;
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
                        ika_coin,
                        sui_coin,
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
                        ika_coin,
                        sui_coin,
                        None, // sign_during_dkg
                        gas_budget,
                    )
                    .await?
                };

                // 7. Extract created object IDs from transaction effects
                let created = extract_created_dwallet_ids(context, &response).await;

                let dwallet_id = created.dwallet_id;
                let dwallet_cap_id = created.dwallet_cap_id;
                let encrypted_share_id = created.encrypted_share_id;

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

                IkaDWalletCommandResponse::Create {
                    dwallet_id: dwallet_id
                        .map(|id| id.to_string())
                        .unwrap_or_else(|| "pending (check transaction)".to_string()),
                    dwallet_cap_id: dwallet_cap_id
                        .map(|id| id.to_string())
                        .unwrap_or_else(|| "pending (check transaction)".to_string()),
                    public_key: public_key_hex,
                    secret_share_path: output_secret.display().to_string(),
                }
            }

            IkaDWalletCommand::Sign {
                dwallet_cap_id,
                message,
                signature_algorithm,
                hash_scheme,
                presign_cap_id,
                secret_share,
                presign_output,
                dwallet_id,
                curve,
                dkg_output,
                ika_coin_id,
                sui_coin_id,
                gas_budget,
                ika_sui_config,
            } => {
                let gas_budget = gas_budget
                    .or(global_gas_budget)
                    .unwrap_or(DEFAULT_GAS_BUDGET);
                let config_path = ika_sui_config
                    .or(global_ika_config.clone())
                    .unwrap_or(ika_config_dir()?.join(IKA_SUI_CONFIG));
                let config = read_ika_sui_config_yaml(context, &config_path)?;
                let (ika_coin, sui_coin) =
                    resolve_coins(context, &config, ika_coin_id, sui_coin_id).await?;
                let message_bytes = hex_decode(&message)?;

                // Resolve presign output: from flag or auto-fetch from presign cap
                let presign_output_bytes =
                    resolve_presign_output(context, presign_output, presign_cap_id).await?;

                // Resolve curve and DKG output: from chain if dwallet_id given, else from flags
                let (curve_id, dkg_output_bytes) =
                    resolve_dwallet_sign_params(context, dwallet_id, curve, dkg_output).await?;

                // Check if this is an imported key dWallet
                let is_imported_key = if let Some(did) = dwallet_id {
                    let metadata = fetch_dwallet_metadata(context, did).await?;
                    metadata.is_imported_key_dwallet
                } else {
                    false
                };

                let secret_share_bytes =
                    std::fs::read(&secret_share).context("Failed to read secret share file")?;

                let network_dkg_output = get_network_key_info(context, &config_path)
                    .await?
                    .network_dkg_public_output;
                let protocol_pp =
                    network_dkg_public_output_to_protocol_pp_inner(curve_id, network_dkg_output)
                        .context("Failed to derive protocol parameters")?;

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
                        ika_coin,
                        sui_coin,
                        gas_budget,
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
                        ika_coin,
                        sui_coin,
                        gas_budget,
                    )
                    .await?
                };
                let (digest, status) = tx_digest_and_status(&response);
                IkaDWalletCommandResponse::Sign { digest, status }
            }

            IkaDWalletCommand::FutureSign {
                dwallet_id,
                message,
                hash_scheme,
                presign_cap_id,
                secret_share,
                presign_output,
                signature_algorithm,
                curve,
                dkg_output,
                ika_coin_id,
                sui_coin_id,
                gas_budget,
                ika_sui_config,
            } => {
                let gas_budget = gas_budget
                    .or(global_gas_budget)
                    .unwrap_or(DEFAULT_GAS_BUDGET);
                let config_path = ika_sui_config
                    .or(global_ika_config.clone())
                    .unwrap_or(ika_config_dir()?.join(IKA_SUI_CONFIG));
                let config = read_ika_sui_config_yaml(context, &config_path)?;
                let (ika_coin, sui_coin) =
                    resolve_coins(context, &config, ika_coin_id, sui_coin_id).await?;
                let message_bytes = hex_decode(&message)?;

                // Resolve presign output: from flag or auto-fetch from presign cap
                let presign_output_bytes =
                    resolve_presign_output(context, presign_output, presign_cap_id).await?;

                // Resolve curve and DKG output from dwallet-id
                let (curve_id, dkg_output_bytes) =
                    resolve_dwallet_sign_params(context, Some(dwallet_id), curve, dkg_output)
                        .await?;

                let secret_share_bytes =
                    std::fs::read(&secret_share).context("Failed to read secret share file")?;

                let network_dkg_output = get_network_key_info(context, &config_path)
                    .await?
                    .network_dkg_public_output;
                let protocol_pp =
                    network_dkg_public_output_to_protocol_pp_inner(curve_id, network_dkg_output)
                        .context("Failed to derive protocol parameters")?;

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
                    ika_coin,
                    sui_coin,
                    gas_budget,
                )
                .await?;
                let (digest, status) = tx_digest_and_status(&response);
                IkaDWalletCommandResponse::Sign { digest, status }
            }

            IkaDWalletCommand::Presign {
                dwallet_id,
                signature_algorithm,
                ika_coin_id,
                sui_coin_id,
                gas_budget,
                ika_sui_config,
            } => {
                let gas_budget = gas_budget
                    .or(global_gas_budget)
                    .unwrap_or(DEFAULT_GAS_BUDGET);
                let config_path = ika_sui_config
                    .or(global_ika_config.clone())
                    .unwrap_or(ika_config_dir()?.join(IKA_SUI_CONFIG));
                let config = read_ika_sui_config_yaml(context, &config_path)?;
                let (ika_coin, sui_coin) =
                    resolve_coins(context, &config, ika_coin_id, sui_coin_id).await?;
                let session_id = random_bytes().to_vec();

                // Try per-dWallet presign first; if the protocol requires global presign
                // (EOnlyGlobalPresignAllowed, abort code 31), automatically fall back.
                let result = ika_dwallet_transactions::request_presign_tx(
                    context,
                    config.packages.ika_dwallet_2pc_mpc_package_id,
                    config.objects.ika_dwallet_coordinator_object_id,
                    dwallet_id,
                    signature_algorithm,
                    session_id,
                    ika_coin,
                    sui_coin,
                    gas_budget,
                )
                .await;

                let response = match result {
                    Ok(resp) => resp,
                    Err(e)
                        if e.to_string().contains("MoveAbort")
                            && e.to_string().contains(", 31)") =>
                    {
                        // Fall back to global presign
                        if !quiet {
                            eprintln!(
                                "Per-dWallet presign not allowed for this curve/algorithm. \
                                 Using global presign..."
                            );
                        }
                        let metadata = fetch_dwallet_metadata(context, dwallet_id).await?;
                        let (ika_coin, sui_coin) =
                            resolve_coins(context, &config, ika_coin_id, sui_coin_id).await?;
                        let network_key_info = get_network_key_info(context, &config_path).await?;
                        let session_id = random_bytes().to_vec();
                        ika_dwallet_transactions::request_global_presign_tx(
                            context,
                            config.packages.ika_dwallet_2pc_mpc_package_id,
                            config.objects.ika_dwallet_coordinator_object_id,
                            network_key_info.network_encryption_key_id,
                            metadata.curve,
                            signature_algorithm,
                            session_id,
                            ika_coin,
                            sui_coin,
                            gas_budget,
                        )
                        .await?
                    }
                    Err(e) => return Err(e.into()),
                };
                let (digest, status) = tx_digest_and_status(&response);
                IkaDWalletCommandResponse::Presign { digest, status }
            }

            IkaDWalletCommand::GlobalPresign {
                curve,
                signature_algorithm,
                ika_coin_id,
                sui_coin_id,
                gas_budget,
                ika_sui_config,
            } => {
                let gas_budget = gas_budget
                    .or(global_gas_budget)
                    .unwrap_or(DEFAULT_GAS_BUDGET);
                let config_path = ika_sui_config
                    .or(global_ika_config.clone())
                    .unwrap_or(ika_config_dir()?.join(IKA_SUI_CONFIG));
                let config = read_ika_sui_config_yaml(context, &config_path)?;
                let (ika_coin, sui_coin) =
                    resolve_coins(context, &config, ika_coin_id, sui_coin_id).await?;
                let session_id = random_bytes().to_vec();
                let network_key_info = get_network_key_info(context, &config_path).await?;

                let response = ika_dwallet_transactions::request_global_presign_tx(
                    context,
                    config.packages.ika_dwallet_2pc_mpc_package_id,
                    config.objects.ika_dwallet_coordinator_object_id,
                    network_key_info.network_encryption_key_id,
                    curve,
                    signature_algorithm,
                    session_id,
                    ika_coin,
                    sui_coin,
                    gas_budget,
                )
                .await?;
                let (digest, status) = tx_digest_and_status(&response);
                IkaDWalletCommandResponse::Presign { digest, status }
            }

            IkaDWalletCommand::Import {
                curve,
                centralized_message,
                encryption_key_id,
                output_secret,
                ika_coin_id,
                sui_coin_id,
                gas_budget,
                ika_sui_config,
            } => {
                let gas_budget = gas_budget
                    .or(global_gas_budget)
                    .unwrap_or(DEFAULT_GAS_BUDGET);
                let config_path = ika_sui_config
                    .or(global_ika_config.clone())
                    .unwrap_or(ika_config_dir()?.join(IKA_SUI_CONFIG));
                let config = read_ika_sui_config_yaml(context, &config_path)?;
                let curve_id = curve_name_to_id(&curve)?;
                let (ika_coin, sui_coin) =
                    resolve_coins(context, &config, ika_coin_id, sui_coin_id).await?;

                let secret_key = std::fs::read(&centralized_message)
                    .context("Failed to read secret key file")?;

                let network_key_info = get_network_key_info(context, &config_path).await?;
                let protocol_pp = network_dkg_public_output_to_protocol_pp_inner(
                    curve_id,
                    network_key_info.network_dkg_public_output.clone(),
                )
                .context("Failed to derive protocol parameters")?;

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

                // Load stored encryption key or derive from seed
                let (encryption_key, _decryption_key, signing_keypair) =
                    match load_encryption_keypair(&encryption_key_id, curve_id)? {
                        Some(keys) => keys,
                        None => {
                            anyhow::bail!(
                                "No stored encryption key found for {encryption_key_id}. \
                                 Register one first with: ika dwallet register-encryption-key"
                            );
                        }
                    };
                let signer_public_key = signing_keypair.public().as_bytes().to_vec();
                let encryption_key_address: SuiAddress = signing_keypair.public().into();

                let encrypted_secret_share = encrypt_secret_key_share_and_prove_v2(
                    curve_id,
                    user_secret_share.clone(),
                    encryption_key,
                    protocol_pp,
                )
                .context("Failed to encrypt secret share")?;

                std::fs::write(&output_secret, &user_secret_share)
                    .context("Failed to save secret share")?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(
                        &output_secret,
                        std::fs::Permissions::from_mode(0o600),
                    )?;
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
                    ika_coin,
                    sui_coin,
                    gas_budget,
                )
                .await?;

                // Extract created IDs and auto-accept (same flow as create)
                let created = extract_created_dwallet_ids(context, &response).await;
                if let (Some(did), Some(esid)) = (created.dwallet_id, created.encrypted_share_id) {
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

                    IkaDWalletCommandResponse::Create {
                        dwallet_id: did.to_string(),
                        dwallet_cap_id: created
                            .dwallet_cap_id
                            .map(|id| id.to_string())
                            .unwrap_or_else(|| "pending".to_string()),
                        public_key: String::new(),
                        secret_share_path: output_secret.display().to_string(),
                    }
                } else {
                    tx_response_to_output(&response)
                }
            }

            IkaDWalletCommand::RegisterEncryptionKey {
                curve,
                seed,
                gas_budget,
                ika_sui_config,
            } => {
                let gas_budget = gas_budget
                    .or(global_gas_budget)
                    .unwrap_or(DEFAULT_GAS_BUDGET);
                let config_path = ika_sui_config
                    .or(global_ika_config.clone())
                    .unwrap_or(ika_config_dir()?.join(IKA_SUI_CONFIG));
                let config = read_ika_sui_config_yaml(context, &config_path)?;
                let curve_id = curve_name_to_id(&curve)?;

                let seed = parse_or_random_seed(seed)?;

                let (encryption_key, decryption_key, signing_keypair) =
                    derive_encryption_keys(curve_id, seed)?;

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
                let enc_key_id =
                    find_created_object_by_type(context, &response, "EncryptionKey").await;

                // Save the encryption keypair locally for reuse.
                if let Some(id) = enc_key_id {
                    let signer_address: SuiAddress = signing_keypair.public().into();
                    if let Err(e) = save_encryption_key(
                        &id.to_string(),
                        &curve,
                        &encryption_key,
                        &decryption_key,
                        &signer_public_key,
                        &signer_address.to_string(),
                        &seed,
                    ) {
                        eprintln!("Warning: failed to save encryption key locally: {e}");
                    }
                }

                IkaDWalletCommandResponse::RegisterEncryptionKeyResponse {
                    encryption_key_id: enc_key_id
                        .map(|id| id.to_string())
                        .unwrap_or_else(|| "pending (check transaction)".to_string()),
                    digest,
                    status,
                }
            }

            IkaDWalletCommand::VerifyPresign {
                presign_cap_id,
                gas_budget,
                ika_sui_config,
            } => {
                let gas_budget = gas_budget
                    .or(global_gas_budget)
                    .unwrap_or(DEFAULT_GAS_BUDGET);
                let config_path = ika_sui_config
                    .or(global_ika_config.clone())
                    .unwrap_or(ika_config_dir()?.join(IKA_SUI_CONFIG));
                let config = read_ika_sui_config_yaml(context, &config_path)?;

                let response = ika_dwallet_transactions::verify_presign_cap(
                    context,
                    config.packages.ika_dwallet_2pc_mpc_package_id,
                    config.objects.ika_dwallet_coordinator_object_id,
                    presign_cap_id,
                    gas_budget,
                )
                .await?;
                tx_response_to_output(&response)
            }

            IkaDWalletCommand::GetEncryptionKey {
                encryption_key_id,
                ika_sui_config: _,
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

            IkaDWalletCommand::Get {
                dwallet_id,
                ika_sui_config: _,
            } => {
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

            IkaDWalletCommand::Pricing { ika_sui_config } => {
                let config_path = ika_sui_config
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
                let seed = parse_or_random_seed(seed)?;
                let (encryption_key, decryption_key, signing_keypair) =
                    derive_encryption_keys(curve_id, seed)?;

                IkaDWalletCommandResponse::Keypair {
                    encryption_key: hex::encode(&encryption_key),
                    decryption_key: hex::encode(&decryption_key),
                    signer_public_key: hex::encode(signing_keypair.public().as_bytes()),
                    seed: hex::encode(seed),
                }
            }

            IkaDWalletCommand::Share { cmd } => match cmd {
                IkaDWalletShareCommand::MakePublic {
                    dwallet_id,
                    secret_share,
                    ika_coin_id,
                    sui_coin_id,
                    gas_budget,
                    ika_sui_config,
                } => {
                    let gas_budget = gas_budget
                        .or(global_gas_budget)
                        .unwrap_or(DEFAULT_GAS_BUDGET);
                    let config_path = ika_sui_config
                        .or(global_ika_config.clone())
                        .unwrap_or(ika_config_dir()?.join(IKA_SUI_CONFIG));
                    let config = read_ika_sui_config_yaml(context, &config_path)?;
                    let (ika_coin, sui_coin) =
                        resolve_coins(context, &config, ika_coin_id, sui_coin_id).await?;
                    let share_bytes = std::fs::read(&secret_share)?;
                    let session_id = random_bytes().to_vec();

                    let response = ika_dwallet_transactions::request_make_shares_public(
                        context,
                        config.packages.ika_dwallet_2pc_mpc_package_id,
                        config.objects.ika_dwallet_coordinator_object_id,
                        dwallet_id,
                        share_bytes,
                        session_id,
                        ika_coin,
                        sui_coin,
                        gas_budget,
                    )
                    .await?;
                    tx_response_to_output(&response)
                }
                IkaDWalletShareCommand::ReEncrypt {
                    dwallet_id,
                    destination_address,
                    secret_share,
                    source_encrypted_share_id,
                    destination_encryption_key,
                    curve,
                    ika_coin_id,
                    sui_coin_id,
                    gas_budget,
                    ika_sui_config,
                } => {
                    let gas_budget = gas_budget
                        .or(global_gas_budget)
                        .unwrap_or(DEFAULT_GAS_BUDGET);
                    let config_path = ika_sui_config
                        .or(global_ika_config.clone())
                        .unwrap_or(ika_config_dir()?.join(IKA_SUI_CONFIG));
                    let config = read_ika_sui_config_yaml(context, &config_path)?;
                    let curve_id = curve_name_to_id(&curve)?;
                    let (ika_coin, sui_coin) =
                        resolve_coins(context, &config, ika_coin_id, sui_coin_id).await?;

                    let share_bytes =
                        std::fs::read(&secret_share).context("Failed to read secret share file")?;
                    let dest_enc_key = hex_decode(&destination_encryption_key)?;

                    let network_dkg_output = get_network_key_info(context, &config_path)
                        .await?
                        .network_dkg_public_output;
                    let protocol_pp = network_dkg_public_output_to_protocol_pp_inner(
                        curve_id,
                        network_dkg_output,
                    )
                    .context("Failed to derive protocol parameters")?;

                    let encrypted_share_and_proof = encrypt_secret_key_share_and_prove_v2(
                        curve_id,
                        share_bytes,
                        dest_enc_key,
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
                        ika_coin,
                        sui_coin,
                        gas_budget,
                    )
                    .await?;
                    tx_response_to_output(&response)
                }
                IkaDWalletShareCommand::Accept {
                    dwallet_id,
                    encrypted_share_id,
                    user_output_signature,
                    gas_budget,
                    ika_sui_config,
                } => {
                    let gas_budget = gas_budget
                        .or(global_gas_budget)
                        .unwrap_or(DEFAULT_GAS_BUDGET);
                    let config_path = ika_sui_config
                        .or(global_ika_config.clone())
                        .unwrap_or(ika_config_dir()?.join(IKA_SUI_CONFIG));
                    let config = read_ika_sui_config_yaml(context, &config_path)?;
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

/// Resolve curve and DKG output for sign commands.
///
/// If `dwallet_id` is provided, fetches the curve and DKG output from chain.
/// Explicit `--curve` and `--dkg-output` flags take precedence over auto-fetched values.
async fn resolve_dwallet_sign_params(
    context: &WalletContext,
    dwallet_id: Option<ObjectID>,
    curve: Option<String>,
    dkg_output: Option<String>,
) -> Result<(u32, Vec<u8>)> {
    // If dwallet_id is provided, fetch metadata (curve + DKG output) from chain
    let metadata = match dwallet_id {
        Some(id) if curve.is_none() || dkg_output.is_none() => {
            Some(fetch_dwallet_metadata(context, id).await?)
        }
        _ => None,
    };

    let curve_id = match curve {
        Some(c) => curve_name_to_id(&c)?,
        None => metadata.as_ref().map(|m| m.curve).ok_or_else(|| {
            anyhow::anyhow!(
                "Curve is required. Provide --curve <CURVE> or --dwallet-id <ID> to auto-detect."
            )
        })?,
    };

    let dkg_output_bytes = match dkg_output {
        Some(hex) => hex_decode(&hex)?,
        None => metadata
            .as_ref()
            .and_then(|m| m.dkg_output.clone())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "DKG output not available. The dWallet may not be in Active state yet.\n\
                     Provide --dkg-output <HEX> manually, or wait for DKG to complete."
                )
            })?,
    };

    Ok((curve_id, dkg_output_bytes))
}

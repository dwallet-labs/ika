// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! User encryption-key derivation and on-chain encrypted-share lookup.

use anyhow::{Context, Result};
use dwallet_mpc_centralized_party::generate_cg_keypair_from_seed;
use fastcrypto::ed25519::{Ed25519KeyPair, Ed25519PrivateKey};
use fastcrypto::traits::ToFromBytes;
use sui_types::base_types::{ObjectID, SuiAddress};

use super::common::{extract_bytes_from_json, fetch_object_fields};

/// Derive encryption keys from a seed: `(encryption_key, decryption_key, signing_keypair)`.
///
/// Hash matches the TS SDK `UserShareEncryptionKeys.hash()`:
///   `keccak256(ASCII(domain_separator) || curve_byte || seed)`
///
/// By default uses the numeric curve byte (matching TS SDK V2 hash).
/// With `legacy_hash = true`, uses 0x00 as curve byte (matching TS SDK V1 bug).
pub fn derive_encryption_keys(
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
        let private_key = Ed25519PrivateKey::from_bytes(&signing_seed)
            .map_err(|e| anyhow::anyhow!("Failed to derive Ed25519 private key: {e}"))?;
        Ed25519KeyPair::from(private_key)
    };

    Ok((encryption_key, decryption_key, signing_keypair))
}

/// Fetch the encrypted secret share for a dWallet from its on-chain `ObjectTable`.
///
/// The dWallet stores encrypted shares in `encrypted_user_secret_key_shares: ObjectTable`.
/// This enumerates dynamic-field entries and returns the one whose `encryption_key_address`
/// matches the supplied address. Compute that address by deriving keys from the user's seed
/// (see [`derive_encryption_keys`]) and taking `signing_keypair.public()`.
pub async fn fetch_encrypted_share_for_dwallet(
    sdk_client: &sui_sdk::SuiClient,
    dwallet_id: ObjectID,
    encryption_key_address: SuiAddress,
) -> Result<Vec<u8>> {
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

    let mut cursor = None;
    loop {
        let page = sdk_client
            .read_api()
            .get_dynamic_fields(table_oid, cursor, Some(50))
            .await
            .context("Failed to query encrypted share dynamic fields")?;

        for field_info in &page.data {
            let share_fields = fetch_object_fields(sdk_client, field_info.object_id).await?;

            let key_address = share_fields
                .get("encryption_key_address")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if key_address != encryption_key_address.to_string() {
                continue;
            }

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
         with encryption key address {encryption_key_address}"
    )
}

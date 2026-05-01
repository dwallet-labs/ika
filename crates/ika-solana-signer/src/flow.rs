// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Sign-flow orchestration: presign → centralized sign → submit → poll.

use std::time::Duration;

use anyhow::Context;
use dwallet_mpc_centralized_party::advance_centralized_sign_party;
use ika_sui_client::dwallet_signer::{
    DWalletMetadata, SignSessionResult, fetch_encrypted_share_for_dwallet, fetch_presign_output,
    find_sign_session_id, is_presign_cap_verified, poll_sign_session, tx,
};
use ika_sui_client::ika_dwallet_transactions::PaymentCoinArgs;
use rand::RngCore;
use sui_rpc_api::Client as RpcClient;
use sui_types::{
    base_types::{ObjectID, SuiAddress},
    crypto::SuiKeyPair,
};

use crate::config::{IkaSignerConfig, PresignMode, SecretShareSource};
use crate::error::IkaSignerError;
use crate::pubkey::ed25519_curve_id;

/// Package ID to address Move calls at.
///
/// The dWallet coordinator object carries a `version` field that must match
/// the `VERSION` constant of whichever package it's called through. When the
/// network has upgraded the coordinator (e.g. to V2 on testnet), V1 calls
/// abort with `EWrongInnerVersion` inside `coordinator::inner_mut`. Always
/// use V2 if the network config exposes it; fall back to V1 only when the
/// network hasn't been upgraded.
fn dwallet_package_id(cfg: &IkaSignerConfig) -> ObjectID {
    cfg.ika_network_config
        .packages
        .ika_dwallet_2pc_mpc_package_id_v2
        .unwrap_or(cfg.ika_network_config.packages.ika_dwallet_2pc_mpc_package_id)
}

/// Solana-specific algorithm identifiers used in every sign call.
const EDDSA_SIG_ALGORITHM: u32 = 0;
const SHA512_HASH_SCHEME: u32 = 0;

/// Cached state captured from the dWallet at signer construction time.
pub(crate) struct DWalletState {
    pub metadata: DWalletMetadata,
    pub dkg_output: Vec<u8>,
    pub protocol_pp: Vec<u8>,
    pub network_encryption_key_id: ObjectID,
}

/// Run the centralized sign step against an explicit presign output + cap.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn sign_with_presign(
    rpc: &mut RpcClient,
    sui_client: &sui_sdk::SuiClient,
    keypair: &SuiKeyPair,
    sender: SuiAddress,
    cfg: &IkaSignerConfig,
    state: &DWalletState,
    secret_share: &[u8],
    presign_cap_id: ObjectID,
    presign_output: Vec<u8>,
    needs_verification: bool,
    message: Vec<u8>,
) -> Result<[u8; 64], IkaSignerError> {
    let centralized_signature = advance_centralized_sign_party(
        state.protocol_pp.clone(),
        state.dkg_output.clone(),
        secret_share.to_vec(),
        presign_output,
        message.clone(),
        ed25519_curve_id(),
        EDDSA_SIG_ALGORITHM,
        SHA512_HASH_SCHEME,
    )
    .map_err(|e| IkaSignerError::Crypto(format!("{e}")))?;

    let session_identifier_bytes = random_bytes().to_vec();

    let coins = PaymentCoinArgs {
        ika_coin_id: cfg.ika_coin_id,
        sui_coin_id: cfg.sui_coin_id,
    };

    let package_id = dwallet_package_id(cfg);
    let response = if state.metadata.is_imported_key_dwallet {
        tx::request_imported_key_sign_tx_with_signer(
            rpc,
            keypair,
            sender,
            package_id,
            cfg.ika_network_config
                .objects
                .ika_dwallet_coordinator_object_id,
            cfg.dwallet_cap_id,
            EDDSA_SIG_ALGORITHM,
            SHA512_HASH_SCHEME,
            message,
            centralized_signature,
            presign_cap_id,
            session_identifier_bytes,
            coins,
            cfg.gas_budget,
            needs_verification,
        )
        .await?
    } else {
        tx::request_sign_tx_with_signer(
            rpc,
            keypair,
            sender,
            package_id,
            cfg.ika_network_config
                .objects
                .ika_dwallet_coordinator_object_id,
            cfg.dwallet_cap_id,
            EDDSA_SIG_ALGORITHM,
            SHA512_HASH_SCHEME,
            message,
            centralized_signature,
            presign_cap_id,
            session_identifier_bytes,
            coins,
            cfg.gas_budget,
            needs_verification,
        )
        .await?
    };

    let digest = response
        .effects
        .as_ref()
        .map(|e| {
            use sui_json_rpc_types::SuiTransactionBlockEffectsAPI;
            e.transaction_digest().to_string()
        })
        .ok_or_else(|| anyhow::anyhow!("sign tx returned no effects"))?;

    let session_id_str = find_sign_session_id(sui_client, &digest)
        .await
        .ok_or_else(|| anyhow::anyhow!("could not locate sign session id from tx events"))?;
    let session_id: ObjectID = session_id_str.parse().context("invalid sign session id")?;

    let result = poll_sign_session(
        sui_client,
        session_id,
        cfg.poll_interval,
        cfg.poll_timeout.or(Some(Duration::from_secs(300))),
    )
    .await?;

    let sig_hex = match result {
        SignSessionResult::Completed { signature } => signature,
        SignSessionResult::Rejected => return Err(IkaSignerError::SignRejected),
    };

    let sig_bytes = hex::decode(&sig_hex)
        .map_err(|e| anyhow::anyhow!("invalid signature hex from sign session: {e}"))?;
    if sig_bytes.len() != 64 {
        return Err(anyhow::anyhow!(
            "expected 64-byte ed25519 signature, got {} bytes",
            sig_bytes.len()
        )
        .into());
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(&sig_bytes);
    Ok(out)
}

/// Resolve the secret share source into raw bytes (decrypting from chain if needed).
pub(crate) async fn resolve_secret_share(
    sui_client: &sui_sdk::SuiClient,
    cfg: &IkaSignerConfig,
    state: &DWalletState,
) -> Result<Vec<u8>, IkaSignerError> {
    match &cfg.share_source {
        SecretShareSource::Bytes(b) => Ok(b.clone()),
        SecretShareSource::OnChainEncrypted {
            decryption_key,
            encryption_key_address,
        } => {
            let encrypted = fetch_encrypted_share_for_dwallet(
                sui_client,
                cfg.dwallet_id,
                *encryption_key_address,
            )
            .await?;
            let decrypted = dwallet_mpc_centralized_party::decrypt_user_share_v2(
                ed25519_curve_id(),
                decryption_key.clone(),
                state.dkg_output.clone(),
                encrypted,
                state.protocol_pp.clone(),
            )
            .map_err(|e| IkaSignerError::Crypto(format!("decrypt failed: {e}")))?;
            Ok(decrypted)
        }
    }
}

/// Issue a fresh global presign and wait for it to complete.
/// Returns `(presign_cap_id, presign_output_bytes, needs_verification = true)`.
pub(crate) async fn fresh_global_presign(
    rpc: &mut RpcClient,
    sui_client: &sui_sdk::SuiClient,
    keypair: &SuiKeyPair,
    sender: SuiAddress,
    cfg: &IkaSignerConfig,
    state: &DWalletState,
) -> Result<(ObjectID, Vec<u8>, bool), IkaSignerError> {
    let session_identifier_bytes = random_bytes().to_vec();
    let coins = PaymentCoinArgs {
        ika_coin_id: cfg.ika_coin_id,
        sui_coin_id: cfg.sui_coin_id,
    };

    let response = tx::request_global_presign_tx_with_signer(
        rpc,
        keypair,
        sender,
        dwallet_package_id(cfg),
        cfg.ika_network_config
            .objects
            .ika_dwallet_coordinator_object_id,
        state.network_encryption_key_id,
        ed25519_curve_id(),
        EDDSA_SIG_ALGORITHM,
        session_identifier_bytes,
        coins,
        cfg.gas_budget,
    )
    .await?;

    let presign_cap_id = extract_presign_cap_from_response(&response)
        .ok_or_else(|| anyhow::anyhow!("could not locate presign cap in tx events"))?;

    // Poll the presign session for completion via `fetch_presign_output` retries.
    let timeout = cfg.poll_timeout.unwrap_or(Duration::from_secs(300));
    let interval = cfg.poll_interval.unwrap_or(Duration::from_secs(3));
    let start = std::time::Instant::now();
    let presign_output = loop {
        if start.elapsed() > timeout {
            return Err(anyhow::anyhow!(
                "timeout waiting for presign {presign_cap_id} to complete"
            )
            .into());
        }
        match fetch_presign_output(sui_client, presign_cap_id).await {
            Ok(bytes) => break bytes,
            Err(_) => tokio::time::sleep(interval).await,
        }
    };

    Ok((presign_cap_id, presign_output, true))
}

/// Resolve a caller-provided presign cap into `(cap_id, presign_output, needs_verification)`.
pub(crate) async fn use_provided_presign(
    sui_client: &sui_sdk::SuiClient,
    presign_cap_id: ObjectID,
) -> Result<(ObjectID, Vec<u8>, bool), IkaSignerError> {
    let already_verified = is_presign_cap_verified(sui_client, presign_cap_id).await?;
    let presign_output = fetch_presign_output(sui_client, presign_cap_id).await?;
    Ok((presign_cap_id, presign_output, !already_verified))
}

fn extract_presign_cap_from_response(
    response: &sui_json_rpc_types::SuiTransactionBlockResponse,
) -> Option<ObjectID> {
    use sui_json_rpc_types::SuiTransactionBlockEffectsAPI;
    let effects = response.effects.as_ref()?;
    // The PTB transfers the new presign cap to the sender. Find the first
    // created object owned by an address.
    effects
        .created()
        .iter()
        .find(|c| matches!(c.owner, sui_types::object::Owner::AddressOwner(_)))
        .map(|c| c.reference.object_id)
}

/// Determine the presign source for this `sign_message` call.
pub(crate) async fn resolve_presign(
    rpc: &mut RpcClient,
    sui_client: &sui_sdk::SuiClient,
    keypair: &SuiKeyPair,
    sender: SuiAddress,
    cfg: &IkaSignerConfig,
    state: &DWalletState,
    consumed_provided_cap: bool,
) -> Result<(ObjectID, Vec<u8>, bool), IkaSignerError> {
    match &cfg.presign_mode {
        PresignMode::PerSignGlobal => {
            fresh_global_presign(rpc, sui_client, keypair, sender, cfg, state).await
        }
        PresignMode::SingleProvided(cap_id) => {
            if consumed_provided_cap {
                return Err(IkaSignerError::PresignCapConsumed);
            }
            use_provided_presign(sui_client, *cap_id).await
        }
    }
}

fn random_bytes() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    bytes
}

// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use std::sync::Arc;

use ika_sui_client::SuiConnectorClient;
use ika_sui_client::dwallet_signer::{fetch_dwallet_metadata, get_network_key_info_for};
use ika_sui_client::metrics::SuiClientMetrics;
use sui_rpc_api::Client as RpcClient;
use sui_sdk::SuiClientBuilder;
use sui_types::base_types::SuiAddress;
use tokio::sync::Mutex;

use crate::config::{IkaSignerConfig, PresignMode};
use crate::error::IkaSignerError;
use crate::flow::{DWalletState, resolve_presign, resolve_secret_share, sign_with_presign};
use crate::pubkey::{ed25519_curve_id, extract_ed25519_pubkey};

/// Signer for Solana Ed25519 messages backed by an Ika dWallet.
///
/// Construct with [`IkaSigner::create`]. Sign with [`IkaSigner::sign_message`].
pub struct IkaSigner {
    cfg: IkaSignerConfig,
    sender: SuiAddress,
    pubkey: [u8; 32],
    state: DWalletState,
    /// Cached resolved secret share. Resolved once at construction time so that
    /// hot-path signing doesn't re-decrypt on every call.
    secret_share: Vec<u8>,
    /// Persistent SDK client (read-only RPC).
    sui_client: sui_sdk::SuiClient,
    /// Persistent gRPC client (used for object refs and tx execution).
    /// Mutable because `sui_rpc_api::Client::get_object` takes `&mut self`.
    rpc: Arc<Mutex<RpcClient>>,
    /// Tracks whether a `SingleProvided` presign cap has already been consumed.
    consumed_provided_cap: Arc<Mutex<bool>>,
}

impl IkaSigner {
    /// Build a signer against an existing ed25519 dWallet.
    ///
    /// Validates that the dWallet is in `Active` state and uses the ed25519 curve,
    /// fetches the network key parameters needed for centralized signing, resolves
    /// the secret share, and caches everything for fast `sign_message`.
    pub async fn create(cfg: IkaSignerConfig) -> Result<Self, IkaSignerError> {
        let sui_client = SuiClientBuilder::default()
            .build(&cfg.sui_rpc_url)
            .await
            .map_err(|e| anyhow::anyhow!("failed to build Sui SDK client: {e}"))?;

        let metadata = fetch_dwallet_metadata(&sui_client, cfg.dwallet_id).await?;

        if metadata.curve != ed25519_curve_id() {
            return Err(IkaSignerError::UnsupportedCurve {
                dwallet_id: cfg.dwallet_id.to_string(),
                actual: metadata.curve,
                expected: ed25519_curve_id(),
            });
        }

        let dkg_output = metadata
            .dkg_output
            .clone()
            .ok_or_else(|| IkaSignerError::DWalletNotActive(cfg.dwallet_id.to_string()))?;

        let network_encryption_key_id = metadata
            .network_encryption_key_id
            .ok_or_else(|| IkaSignerError::DWalletNotActive(cfg.dwallet_id.to_string()))?;

        let connector = SuiConnectorClient::new(
            &cfg.sui_rpc_url,
            SuiClientMetrics::new_for_testing(),
            cfg.ika_network_config.clone(),
        )
        .await
        .map_err(|e| anyhow::anyhow!("failed to build SuiConnectorClient: {e}"))?;

        let net_key = get_network_key_info_for(
            &connector,
            Some(network_encryption_key_id),
            ed25519_curve_id(),
        )
        .await?;

        let state = DWalletState {
            metadata,
            dkg_output,
            protocol_pp: net_key.protocol_public_parameters,
            network_encryption_key_id,
        };

        let pubkey = extract_ed25519_pubkey(&cfg.dwallet_id.to_string(), &state.dkg_output)?;

        let secret_share = resolve_secret_share(&sui_client, &cfg, &state).await?;

        let sender: SuiAddress = (&cfg.payer.public()).into();
        let rpc = RpcClient::new(&cfg.sui_rpc_url)
            .map_err(|e| anyhow::anyhow!("failed to build Sui gRPC client: {e}"))?;

        Ok(Self {
            cfg,
            sender,
            pubkey,
            state,
            secret_share,
            sui_client,
            rpc: Arc::new(Mutex::new(rpc)),
            consumed_provided_cap: Arc::new(Mutex::new(false)),
        })
    }

    /// 32-byte Ed25519 public key (Solana address).
    pub fn pubkey(&self) -> [u8; 32] {
        self.pubkey
    }

    /// Run the MPC sign flow against the Ika network and return a 64-byte
    /// Ed25519 signature.
    pub async fn sign_message(&self, message: &[u8]) -> Result<[u8; 64], IkaSignerError> {
        let mut rpc = self.rpc.lock().await;
        let mut consumed = self.consumed_provided_cap.lock().await;

        let (presign_cap_id, presign_output, needs_verification) = resolve_presign(
            &mut rpc,
            &self.sui_client,
            &self.cfg.payer,
            self.sender,
            &self.cfg,
            &self.state,
            *consumed,
        )
        .await?;

        if matches!(self.cfg.presign_mode, PresignMode::SingleProvided(_)) {
            *consumed = true;
        }

        sign_with_presign(
            &mut rpc,
            &self.sui_client,
            &self.cfg.payer,
            self.sender,
            &self.cfg,
            &self.state,
            &self.secret_share,
            presign_cap_id,
            presign_output,
            needs_verification,
            message.to_vec(),
        )
        .await
    }

    /// Lightweight reachability check: confirms the Sui RPC is up and the
    /// dWallet is still in `Active` state.
    pub async fn is_available(&self) -> bool {
        match fetch_dwallet_metadata(&self.sui_client, self.cfg.dwallet_id).await {
            Ok(m) => m.dkg_output.is_some(),
            Err(_) => false,
        }
    }
}

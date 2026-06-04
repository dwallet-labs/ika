// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Continuous dWallet workload driver.
//!
//! A dependency state machine (not a fire-and-forget loop): a Sign needs a
//! completed DKG + Presign first, and that chain must survive the epoch
//! boundary the harness is deliberately perturbing. Requests are built with
//! `ika-sui-client::ika_dwallet_transactions` and submitted as Sui txns to the
//! coordinator contract (there is no gRPC submission surface); user-side 2PC
//! inputs come from `dwallet-mpc-centralized-party`. Each issued session is
//! tracked to one terminal bucket; an orphan (neither completed nor cleanly
//! rejected by end of run) is the bug this asserts against.
//!
//! The DKG recipe mirrors the in-process integration tests
//! (`ika-core/.../integration_tests/create_dwallet.rs`): derive protocol public
//! parameters from the network key's DKG output, run the centralized party, and
//! submit. Curve25519 (EdDSA) uses the public-share variant (no class-groups
//! encryption), which is also the fastest to drive.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use dwallet_mpc_centralized_party::{
    create_dkg_output_by_curve_v2, network_dkg_public_output_to_protocol_pp_inner,
};
use ika_config::Config;
use ika_sui_client::SuiClient as IkaClient;
use ika_sui_client::ika_dwallet_transactions::{
    PaymentCoinArgs, request_dwallet_dkg_with_public_share,
};
use ika_sui_client::metrics::SuiClientMetrics;
use ika_types::messages_dwallet_mpc::{IkaNetworkConfig, SessionIdentifier, SessionType};
use ika_types::sui::{DWalletCoordinatorInner, SystemInner};
use rand::RngCore;
use rand::rngs::OsRng;
use sui_keys::keystore::{AccountKeystore, InMemKeystore, Keystore};
use sui_sdk::sui_client_config::{SuiClientConfig, SuiEnv};
use sui_sdk::wallet_context::WalletContext;
use sui_sdk::{SuiClient as SuiSdkClient, SuiClientBuilder};
use sui_types::base_types::{ObjectID, SuiAddress};
use sui_types::crypto::SuiKeyPair;

/// Curve25519 / EdDSA — the public-share DKG path, fastest to drive.
const CURVE25519: u32 = 2;

const DEFAULT_GAS_BUDGET: u64 = 1_000_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionKind {
    Dkg,
    Presign,
    Sign,
}

/// Terminal classification of an issued session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TerminalState {
    /// Reached its completed state on-chain.
    Completed,
    /// Rejected for a documented reason (e.g. started in epoch N, ran past the
    /// boundary, rejected with `epoch != current`).
    RejectedWithDocumentedReason(String),
    /// Neither completed nor cleanly rejected by end of run — the bug.
    OrphanedAfterTimeout,
}

#[derive(Clone, Debug)]
pub struct InFlightSession {
    pub session_id: ObjectID,
    pub kind: SessionKind,
    pub started_epoch: u64,
}

/// Summary returned when the workload is stopped.
#[derive(Clone, Debug, Default)]
pub struct WorkloadReport {
    pub completed: usize,
    pub rejected: Vec<(String, String)>,
    pub orphaned: Vec<String>,
}

impl WorkloadReport {
    /// The assertion the cross-binary scenario makes: nothing orphaned.
    pub fn assert_no_silent_drops(&self) -> Result<()> {
        if self.orphaned.is_empty() {
            Ok(())
        } else {
            bail!(
                "{} session(s) orphaned (no terminal state): {:?}",
                self.orphaned.len(),
                self.orphaned,
            )
        }
    }
}

/// Drives dWallet traffic against the cluster's Sui RPC using the funded
/// publisher key as the user.
pub struct WorkloadDriver {
    rpc_url: String,
    network_config: IkaNetworkConfig,
    /// Keeps the wallet's on-disk config alive for the driver's lifetime.
    _config_dir: tempfile::TempDir,
    context: WalletContext,
    user_address: SuiAddress,
}

impl WorkloadDriver {
    pub async fn new(
        rpc_url: String,
        network_config: IkaNetworkConfig,
        user_keypair: SuiKeyPair,
    ) -> Result<Self> {
        let user_address: SuiAddress = (&user_keypair.public()).into();
        let (context, config_dir) =
            build_wallet_context(&rpc_url, user_keypair, user_address).await?;
        Ok(Self {
            rpc_url,
            network_config,
            _config_dir: config_dir,
            context,
            user_address,
        })
    }

    fn ika_package_id(&self) -> ObjectID {
        self.network_config.packages.ika_package_id
    }

    fn coordinator_object_id(&self) -> ObjectID {
        self.network_config
            .objects
            .ika_dwallet_coordinator_object_id
    }

    fn dwallet_2pc_mpc_package_id(&self) -> ObjectID {
        self.network_config.packages.ika_dwallet_2pc_mpc_package_id
    }

    pub async fn ika_client(&self) -> Result<IkaClient<SuiSdkClient>> {
        IkaClient::new(
            &self.rpc_url,
            SuiClientMetrics::new_for_testing(),
            self.network_config.clone(),
        )
        .await
        .context("construct ika client for workload")
    }

    /// `(started, completed)` user-session counts from the coordinator. These
    /// are the on-chain truth for whether sessions are draining — used to
    /// confirm completion without per-dwallet Move decoding (no Rust type for
    /// the dWallet state object exists).
    async fn user_session_counts(&self, ika: &IkaClient<SuiSdkClient>) -> Result<(u64, u64)> {
        let (_, DWalletCoordinatorInner::V1(inner)) = ika
            .get_dwallet_coordinator_inner()
            .await
            .map_err(|e| anyhow::anyhow!("get_dwallet_coordinator_inner: {e}"))?;
        let keeper = inner.sessions_manager.user_sessions_keeper;
        Ok((
            keeper.started_sessions_count,
            keeper.completed_sessions_count,
        ))
    }

    /// Issue one DKG and block until the coordinator's completed-session count
    /// rises (a real on-chain completion) or `timeout` elapses (orphaned). This
    /// is aggregate, not per-session: it proves the committee is draining user
    /// sessions, which is the load-bearing invariant across an upgrade.
    pub async fn issue_dkg_and_confirm(
        &mut self,
        ika: &IkaClient<SuiSdkClient>,
        timeout: Duration,
    ) -> Result<TerminalState> {
        let (_, completed_before) = self.user_session_counts(ika).await?;
        let session_id = self.issue_dkg(ika).await?;
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let (_, completed_now) = self.user_session_counts(ika).await?;
            if completed_now > completed_before {
                tracing::info!(%session_id, completed_now, "DKG session completed on-chain");
                return Ok(TerminalState::Completed);
            }
            if tokio::time::Instant::now() >= deadline {
                tracing::warn!(%session_id, "DKG session not completed within timeout");
                return Ok(TerminalState::OrphanedAfterTimeout);
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    /// Wait until the network key's DKG output is published on-chain and return
    /// `(network_key_id, protocol_public_parameters)` for `curve`.
    async fn protocol_public_parameters(
        &self,
        ika: &IkaClient<SuiSdkClient>,
        curve: u32,
        timeout: Duration,
    ) -> Result<(ObjectID, Vec<u8>)> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if let Some((id, pp)) = self.try_protocol_pp(ika, curve).await? {
                return Ok((id, pp));
            }
            if tokio::time::Instant::now() >= deadline {
                bail!("network key DKG output not available within {timeout:?}");
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    async fn try_protocol_pp(
        &self,
        ika: &IkaClient<SuiSdkClient>,
        curve: u32,
    ) -> Result<Option<(ObjectID, Vec<u8>)>> {
        let (_, coordinator_inner) = ika
            .get_dwallet_coordinator_inner()
            .await
            .map_err(|e| anyhow::anyhow!("get_dwallet_coordinator_inner: {e}"))?;
        let keys = ika
            .get_dwallet_mpc_network_keys(&coordinator_inner)
            .await
            .map_err(|e| anyhow::anyhow!("get_dwallet_mpc_network_keys: {e}"))?;
        let Some((id, key)) = keys.into_iter().next() else {
            return Ok(None);
        };
        // The key stores its DKG output as an on-chain `TableVec`; the full-data
        // fetch assembles it into bytes. Read at the current epoch.
        let (_, SystemInner::V1(system)) = ika
            .get_system_inner()
            .await
            .map_err(|e| anyhow::anyhow!("get_system_inner: {e}"))?;
        let data = ika
            .get_network_encryption_key_with_full_data_by_epoch(&key, system.epoch)
            .await
            .map_err(|e| anyhow::anyhow!("get_network_encryption_key_with_full_data: {e}"))?;
        if data.network_dkg_public_output.is_empty() {
            return Ok(None);
        }
        let pp =
            network_dkg_public_output_to_protocol_pp_inner(curve, data.network_dkg_public_output)
                .context("derive protocol public parameters")?;
        Ok(Some((id, pp)))
    }

    /// Find an IKA coin owned by the user to pay session fees.
    async fn find_ika_coin(&self) -> Result<ObjectID> {
        let client: SuiSdkClient = SuiClientBuilder::default().build(&self.rpc_url).await?;
        let ika_coin_type = format!("{}::ika::IKA", self.ika_package_id());
        let coins = client
            .coin_read_api()
            .get_coins(
                self.user_address,
                Some(ika_coin_type.clone()),
                None,
                Some(1),
            )
            .await
            .context("list IKA coins")?;
        let coin = coins
            .data
            .into_iter()
            .next()
            .with_context(|| format!("user {} owns no {ika_coin_type}", self.user_address))?;
        Ok(coin.coin_object_id)
    }

    /// Issue one Curve25519 DKG (public-share variant) and return the created
    /// dWallet's object id.
    pub async fn issue_dkg(&mut self, ika: &IkaClient<SuiSdkClient>) -> Result<ObjectID> {
        let curve = CURVE25519;
        let (network_key_id, protocol_pp) = self
            .protocol_public_parameters(ika, curve, Duration::from_secs(300))
            .await?;

        let mut preimage = [0u8; 32];
        OsRng.fill_bytes(&mut preimage);
        let session_identifier_bytes = SessionIdentifier::new(SessionType::User, preimage).to_vec();

        let centralized =
            create_dkg_output_by_curve_v2(curve, protocol_pp, session_identifier_bytes.clone())
                .context("centralized DKG")?;

        let ika_coin_id = self.find_ika_coin().await?;
        let coins = PaymentCoinArgs {
            ika_coin_id,
            sui_coin_id: None,
        };

        // Bind the immutable reads before the mutable `self.context` borrow.
        let dwallet_2pc_mpc_package_id = self.dwallet_2pc_mpc_package_id();
        let coordinator_object_id = self.coordinator_object_id();
        let response = request_dwallet_dkg_with_public_share(
            &mut self.context,
            dwallet_2pc_mpc_package_id,
            coordinator_object_id,
            network_key_id,
            curve,
            centralized.public_key_share_and_proof,
            centralized.public_output,
            centralized.centralized_secret_output,
            session_identifier_bytes,
            coins,
            None,
            DEFAULT_GAS_BUDGET,
        )
        .await
        .map_err(|e| anyhow::anyhow!("request_dwallet_dkg_with_public_share: {e}"))?;

        let dwallet_id = created_dwallet_id(&response)
            .context("extract created dWallet id from DKG response")?;
        tracing::info!(%dwallet_id, "issued DKG");
        Ok(dwallet_id)
    }
}

/// Build an in-memory `WalletContext` for `address`, persisted to a temp dir.
/// Mirrors the publisher-wallet setup in `ika_swarm_config::sui_client`.
async fn build_wallet_context(
    rpc_url: &str,
    keypair: SuiKeyPair,
    address: SuiAddress,
) -> Result<(WalletContext, tempfile::TempDir)> {
    let dir = tempfile::tempdir()?;
    let config_path = dir.path().join("client.yaml");
    let mut keystore = Keystore::InMem(InMemKeystore::default());
    keystore
        .import(Some("workload-user".to_string()), keypair)
        .await
        .context("import workload key")?;
    SuiClientConfig {
        keystore,
        external_keys: None,
        envs: vec![SuiEnv {
            alias: "localnet".to_string(),
            rpc: rpc_url.to_string(),
            ws: None,
            basic_auth: None,
            chain_id: None,
        }],
        active_address: Some(address),
        active_env: Some("localnet".to_string()),
    }
    .persisted(&config_path)
    .save()?;
    let context = WalletContext::new(&config_path)?;
    Ok((context, dir))
}

/// Pull the created dWallet object id out of a DKG transaction response.
fn created_dwallet_id(
    response: &sui_sdk::rpc_types::SuiTransactionBlockResponse,
) -> Result<ObjectID> {
    let changes = response
        .object_changes
        .as_ref()
        .context("response has no object_changes (request full content)")?;
    for change in changes {
        if let sui_sdk::rpc_types::ObjectChange::Created {
            object_type,
            object_id,
            ..
        } = change
            && (object_type.name.as_str().contains("DWallet")
                || object_type.module.as_str().contains("dwallet"))
        {
            return Ok(*object_id);
        }
    }
    bail!("no created DWallet object in response")
}

// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! dWallet workload driver — runs a full **DKG → Presign → Sign** lifecycle
//! against the cluster's Sui RPC and confirms each step completes on-chain.
//!
//! Rather than re-derive the ~500-line user-side 2PC flow (encryption-key
//! derivation, centralized DKG, encrypt-and-prove, accept-encrypted-share,
//! presign-cap verification, centralized sign), the driver orchestrates the
//! canonical `ika` CLI (`crates/ika`, `dwallet create | presign | sign`) as a
//! subprocess. That CLI *is* the tested Rust client built on
//! `dwallet-mpc-centralized-party` + `ika-sui-client`; driving it gives a real,
//! end-to-end dWallet lifecycle that completes on-chain — which is exactly the
//! session-lifecycle invariant the upgrade harness needs (sessions started in
//! an epoch complete, no silent drops). The driver funds a dedicated user,
//! writes a file-based keystore and `ika_sui_config.yaml`, then chains
//! create → presign → sign, parsing each `--json` result.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use ika_config::Config;
use ika_types::messages_dwallet_mpc::IkaNetworkConfig;
use rand::rngs::OsRng;
use serde::Serialize;
use shared_crypto::intent::{Intent, IntentMessage};
use sui_keys::keystore::{AccountKeystore, FileBasedKeystore, Keystore};
use sui_sdk::SuiClientBuilder;
use sui_sdk::sui_client_config::{SuiClientConfig, SuiEnv};
use sui_types::base_types::SuiAddress;
use sui_types::crypto::{Signature, SuiKeyPair, get_key_pair_from_rng};
use sui_types::transaction::Transaction;

const ENV_ALIAS: &str = "localnet";
const FUND_GAS_BUDGET: u64 = 100_000_000;

/// The `ika dwallet ...` config-file wrapper: `{ envs: { <alias>: IkaNetworkConfig } }`.
#[derive(Serialize)]
struct IkaConfigFile {
    envs: HashMap<String, IkaNetworkConfig>,
}

/// Result of a full DKG → Presign → Sign lifecycle (each step confirmed
/// on-chain). `sign_digest` is the sign transaction's digest; the sign's
/// completion is confirmed via the coordinator's user completed-session count.
#[derive(Clone, Debug)]
pub struct LifecycleOutcome {
    pub dwallet_id: String,
    pub verified_presign_cap_id: String,
    pub sign_digest: String,
}

/// Drives dWallet traffic by orchestrating the `ika` CLI against the cluster,
/// using a dedicated, separately-funded user.
pub struct WorkloadDriver {
    ika_binary: PathBuf,
    client_config: PathBuf,
    ika_config: PathBuf,
    rpc_url: String,
    network_config: IkaNetworkConfig,
    /// Holds the keystore + configs + secret-share file for the driver's life.
    work_dir: tempfile::TempDir,
    user_address: SuiAddress,
}

impl WorkloadDriver {
    /// Set up a **dedicated** workload user (its own SUI gas + IKA coin) so it
    /// never contends with the notifier, which submits from the publisher key.
    /// Generates a fresh key, faucet-funds it, and transfers one IKA coin from
    /// the publisher; then writes the user's keystore + Sui `client.yaml` +
    /// `ika_sui_config.yaml`.
    pub async fn new(
        ika_binary: PathBuf,
        rpc_url: String,
        faucet_url: String,
        network_config: IkaNetworkConfig,
        publisher_keypair: SuiKeyPair,
    ) -> Result<Self> {
        let work_dir = tempfile::tempdir()?;

        // Fresh user key, isolated from the publisher/notifier.
        let (user_address, user_ed): (SuiAddress, fastcrypto::ed25519::Ed25519KeyPair) =
            get_key_pair_from_rng(&mut OsRng);
        let user_keypair = SuiKeyPair::Ed25519(user_ed);

        faucet_sui(&faucet_url, user_address).await?;
        transfer_one_ika(&rpc_url, &publisher_keypair, &network_config, user_address)
            .await
            .context("fund workload user with IKA")?;

        let keystore_path = work_dir.path().join("ika.keystore");
        let mut file_keystore =
            FileBasedKeystore::load_or_create(&keystore_path).context("create keystore")?;
        file_keystore
            .import(Some("workload-user".to_string()), user_keypair)
            .await
            .context("add user key to keystore")?;
        let keystore = Keystore::File(file_keystore);

        let client_config = work_dir.path().join("client.yaml");
        SuiClientConfig {
            keystore,
            external_keys: None,
            envs: vec![SuiEnv {
                alias: ENV_ALIAS.to_string(),
                rpc: rpc_url.clone(),
                ws: None,
                basic_auth: None,
                chain_id: None,
            }],
            active_address: Some(user_address),
            active_env: Some(ENV_ALIAS.to_string()),
        }
        .persisted(&client_config)
        .save()
        .context("write client.yaml")?;

        let ika_config = work_dir.path().join("ika_sui_config.yaml");
        let file = IkaConfigFile {
            envs: HashMap::from([(ENV_ALIAS.to_string(), network_config.clone())]),
        };
        std::fs::write(
            &ika_config,
            serde_yaml::to_string(&file).context("serialize ika config")?,
        )
        .context("write ika_sui_config.yaml")?;

        Ok(Self {
            ika_binary,
            client_config,
            ika_config,
            rpc_url,
            network_config,
            work_dir,
            user_address,
        })
    }

    /// User `completed_sessions_count` from the coordinator — the on-chain truth
    /// for whether a user session (e.g. a sign) has finished.
    async fn user_completed_count(&self) -> Result<u64> {
        use ika_sui_client::SuiClient as IkaClient;
        use ika_sui_client::metrics::SuiClientMetrics;
        use ika_types::sui::DWalletCoordinatorInner;

        let ika = IkaClient::new(
            &self.rpc_url,
            SuiClientMetrics::new_for_testing(),
            self.network_config.clone(),
        )
        .await
        .context("construct ika client")?;
        let (_, DWalletCoordinatorInner::V1(inner)) = ika
            .get_dwallet_coordinator_inner()
            .await
            .map_err(|e| anyhow::anyhow!("get_dwallet_coordinator_inner: {e}"))?;
        Ok(inner
            .sessions_manager
            .user_sessions_keeper
            .completed_sessions_count)
    }

    pub fn user_address(&self) -> SuiAddress {
        self.user_address
    }

    pub fn client_config_path(&self) -> &std::path::Path {
        &self.client_config
    }

    pub fn ika_config_path(&self) -> &std::path::Path {
        &self.ika_config
    }

    /// Run `ika --json --client.config .. --ika-config .. dwallet <args...>` and
    /// return the parsed JSON object (the CLI's structured response).
    async fn run_dwallet(&self, args: &[&str]) -> Result<serde_json::Value> {
        let output = tokio::process::Command::new(&self.ika_binary)
            .arg("--json")
            .arg("--client.config")
            .arg(&self.client_config)
            .arg("--ika-config")
            .arg(&self.ika_config)
            .arg("dwallet")
            .args(args)
            .output()
            .await
            .with_context(|| format!("spawn ika dwallet {args:?}"))?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        if !output.status.success() {
            bail!(
                "ika dwallet {args:?} failed ({}):\nstdout: {stdout}\nstderr: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr),
            );
        }
        serde_json::from_str(stdout.trim())
            .with_context(|| format!("parse ika dwallet {args:?} json output: {stdout}"))
    }

    /// Like `run_dwallet`, but retries on transient conditions, up to `attempts`
    /// times: the network DKG output still assembling ("unexpected end of
    /// input"), or shared/owned-object version contention at the epoch-busy
    /// localnet ("unavailable for consumption" / "needs to be rebuilt").
    async fn run_dwallet_with_retry(
        &self,
        args: &[&str],
        attempts: usize,
    ) -> Result<serde_json::Value> {
        let mut last_err = None;
        for attempt in 0..attempts {
            match self.run_dwallet(args).await {
                Ok(v) => return Ok(v),
                Err(e) if is_transient(&e) => {
                    tracing::debug!(attempt, error = %e, "transient, retrying ika dwallet call");
                    last_err = Some(e);
                    tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                }
                Err(e) => return Err(e),
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("run_dwallet_with_retry exhausted")))
    }

    /// Full lifecycle: create a Secp256k1 dWallet (DKG + auto-accept → Active),
    /// request a presign (auto-verified), then sign a message — each step blocks
    /// until it completes on-chain.
    pub async fn run_dwallet_lifecycle(&self) -> Result<LifecycleOutcome> {
        let secret_path = self.work_dir.path().join("user-secret.bin");
        let secret_path_str = secret_path.to_string_lossy().to_string();

        // The encrypted DKG borrows the user's encryption key from the
        // coordinator (`self.encryption_keys.borrow(address)`), so it must be
        // registered first (the TS SDK does the same before `requestDWalletDKG`).
        tracing::info!(user = %self.user_address, "workload: register encryption key");
        let _ = self
            .run_dwallet(&["register-encryption-key", "--curve", "secp256k1"])
            .await?;

        tracing::info!(user = %self.user_address, "workload: dWallet create (DKG)");
        // Just after the network key is created at an epoch boundary, its DKG
        // output `TableVec` can still be assembling on-chain, so deriving
        // protocol parameters fails with "unexpected end of input". This is
        // transient — retry the create until the output is fully readable.
        let create = self
            .run_dwallet_with_retry(
                &[
                    "create",
                    "--curve",
                    "secp256k1",
                    "--output-secret",
                    &secret_path_str,
                ],
                12,
            )
            .await?;
        let dwallet_id = json_str(&create, "dwallet_id")?;
        let dwallet_cap_id = json_str(&create, "dwallet_cap_id")?;
        tracing::info!(%dwallet_id, "workload: dWallet Active; requesting presign");

        // Retry on a presign-pool wait timeout (each request is independent and
        // contention-free with the dedicated user); eventually the pool has one.
        let presign = self
            .run_dwallet_with_retry(
                &[
                    "presign",
                    "--dwallet-id",
                    &dwallet_id,
                    "--signature-algorithm",
                    "ecdsa",
                    "--wait",
                ],
                4,
            )
            .await?;
        let verified_presign_cap_id = json_str(&presign, "verified_presign_cap_id")?;
        tracing::info!(%verified_presign_cap_id, "workload: presign verified; signing");

        // Message bytes (hex). The hash scheme is applied by the protocol.
        let message_hex = hex::encode(b"ika-upgrade-test workload message");

        // Submit the sign WITHOUT `--wait`: the network signs reliably, but the
        // CLI's `--wait` polls an ephemeral sign-session object that is removed
        // on completion ("Object not found"), so it races and times out even
        // when the sign succeeds. Sign is also not idempotent (consumes the
        // single-use presign cap), so it must not be retried. Instead, confirm
        // completion via the coordinator's on-chain user completed-session count.
        let completed_before = self.user_completed_count().await?;
        let sign = self
            .run_dwallet(&[
                "sign",
                "--dwallet-cap-id",
                &dwallet_cap_id,
                "--dwallet-id",
                &dwallet_id,
                "--message",
                &message_hex,
                "--signature-algorithm",
                "ecdsa",
                "--hash-scheme",
                "keccak256",
                "--presign-cap-id",
                &verified_presign_cap_id,
                "--secret-share",
                &secret_path_str,
            ])
            .await?;
        let sign_digest = json_str(&sign, "digest")?;

        let deadline = tokio::time::Instant::now() + Duration::from_secs(180);
        loop {
            if self.user_completed_count().await? > completed_before {
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                bail!("sign session did not complete on-chain (completed count did not rise)");
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
        tracing::info!(%dwallet_id, %sign_digest, "workload: sign completed on-chain");

        Ok(LifecycleOutcome {
            dwallet_id,
            verified_presign_cap_id,
            sign_digest,
        })
    }
}

/// Whether an `ika dwallet` error is a transient localnet condition worth
/// retrying (output still assembling, or object-version contention).
fn is_transient(e: &anyhow::Error) -> bool {
    // With a dedicated, uncontended user the remaining transients are: the
    // network DKG output still assembling ("unexpected end of input", a read
    // before any submission), and a global-presign request out-waiting the
    // on-chain presign pool ("Timeout waiting for presign", run-to-run
    // variable). Both are safe to retry. Submission/lock errors are NOT.
    let s = e.to_string();
    s.contains("unexpected end of input") || s.contains("Timeout waiting for presign")
}

fn json_str(value: &serde_json::Value, field: &str) -> Result<String> {
    value
        .get(field)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .with_context(|| format!("response missing string field `{field}`: {value}"))
}

/// Request SUI gas for `recipient` from the localnet faucet. The localnet
/// faucet sometimes returns a 200 with an error-shaped body; treat that as OK.
async fn faucet_sui(faucet_url: &str, recipient: SuiAddress) -> Result<()> {
    let body = serde_json::json!({ "FixedAmountRequest": { "recipient": recipient.to_string() } });
    match reqwest::Client::new()
        .post(faucet_url)
        .json(&body)
        .send()
        .await
    {
        Ok(_) => {}
        Err(e) if e.to_string().contains("200 OK") => {}
        Err(e) => return Err(e).context("faucet request"),
    }
    // Give the faucet a moment to deliver the gas object.
    tokio::time::sleep(Duration::from_secs(3)).await;
    Ok(())
}

/// Transfer one of the publisher's IKA coins to `recipient` so the workload user
/// can pay dWallet session fees from its own (uncontended) coin. Retries a few
/// times since this single setup txn shares the publisher's gas with the
/// notifier.
async fn transfer_one_ika(
    rpc_url: &str,
    publisher: &SuiKeyPair,
    network_config: &IkaNetworkConfig,
    recipient: SuiAddress,
) -> Result<()> {
    use sui_sdk::rpc_types::SuiTransactionBlockResponseOptions;
    use sui_types::transaction_driver_types::ExecuteTransactionRequestType;

    let publisher_address: SuiAddress = (&publisher.public()).into();
    let client = SuiClientBuilder::default().build(rpc_url).await?;
    let ika_type = format!("{}::ika::IKA", network_config.packages.ika_package_id);

    let mut last_err = None;
    for _ in 0..8 {
        let coins = client
            .coin_read_api()
            .get_coins(publisher_address, Some(ika_type.clone()), None, Some(1))
            .await?;
        let ika_coin = match coins.data.into_iter().next() {
            Some(c) => c.coin_object_id,
            None => bail!("publisher {publisher_address} owns no {ika_type}"),
        };
        let tx_data = client
            .transaction_builder()
            .transfer_object(
                publisher_address,
                ika_coin,
                None,
                FUND_GAS_BUDGET,
                recipient,
            )
            .await?;
        let signature = Signature::new_secure(
            &IntentMessage::new(Intent::sui_transaction(), &tx_data),
            publisher,
        );
        match client
            .quorum_driver_api()
            .execute_transaction_block(
                Transaction::from_data(tx_data, vec![signature]),
                SuiTransactionBlockResponseOptions::new().with_effects(),
                Some(ExecuteTransactionRequestType::WaitForLocalExecution),
            )
            .await
        {
            Ok(resp) => {
                if resp.status_ok() == Some(true) {
                    return Ok(());
                }
                last_err = Some(anyhow::anyhow!("IKA transfer effects: {:?}", resp.effects));
            }
            Err(e) => last_err = Some(e.into()),
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("IKA transfer exhausted")))
}

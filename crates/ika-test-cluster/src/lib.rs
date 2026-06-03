// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! In-process Ika test cluster: spins up Sui via `test_cluster::TestCluster`,
//! publishes the four Ika Move packages, initializes the on-chain system, and
//! launches an in-memory Ika [`Swarm`] pointed at the in-process Sui RPC.

use anyhow::{Context, Result};
use dwallet_mpc_centralized_party::{
    create_dkg_output_by_curve_v2, encrypt_secret_key_share_and_prove_v2,
    generate_cg_keypair_from_seed, network_dkg_public_output_to_protocol_pp_inner,
};
use fastcrypto::ed25519::{Ed25519KeyPair, Ed25519PrivateKey};
use fastcrypto::hash::{HashFunction, Keccak256};
use fastcrypto::traits::{KeyPair as _, Signer, ToFromBytes};
use ika_config::initiation::InitiationParameters;
use ika_node::IkaNodeHandle;
use ika_protocol_config::ProtocolVersion;
use ika_sui_client::SuiConnectorClient;
use ika_sui_client::ika_dwallet_transactions::{
    PaymentCoinArgs, register_encryption_key, request_dwallet_dkg,
};
use ika_sui_client::metrics::SuiClientMetrics;
use ika_swarm::memory::{Swarm, SwarmBuilder};
use ika_swarm_config::network_config::NetworkConfig;
use ika_swarm_config::node_config_builder::{FullnodeConfigBuilder, ValidatorConfigBuilder};
use ika_swarm_config::sui_client::{
    ContractPaths, InitializedIkaSystem, PublishedIkaPackages,
    ika_system_request_dwallet_network_encryption_key_dkg_by_cap, initialize_ika_system,
    publish_ika_packages, request_add_validator, request_add_validator_candidate,
    request_remove_validator, stake_ika,
};
use ika_swarm_config::validator_initialization_config::{
    ValidatorInitializationConfig, ValidatorInitializationConfigBuilder,
};
use ika_types::crypto::AuthorityPublicKeyBytes;
use ika_types::messages_dwallet_mpc::{IkaNetworkConfig, SessionIdentifier, SessionType};
use ika_types::supported_protocol_versions::SupportedProtocolVersions;
use rand::rngs::OsRng;
use sui_json_rpc_types::SuiTransactionBlockEffectsAPI;
use sui_keys::key_derive::generate_new_key;
use sui_sdk::SuiClientBuilder;
use sui_types::base_types::{ObjectID, SuiAddress};
use sui_types::crypto::SignatureScheme;
use test_cluster::{TestCluster, TestClusterBuilder};

#[cfg(not(msim))]
use ika_protocol_config::Chain;
#[cfg(not(msim))]
use ika_swarm_config::sui_client::setup_contract_paths;

#[cfg(msim)]
use ika_swarm_config::sui_client::setup_contract_paths_for_simtest;

const DEFAULT_NUM_VALIDATORS: usize = 4;
/// SUI sent from publisher to each validator address so the validator can pay
/// gas for its own `request_add_validator_candidate` transaction. The amount is
/// orders of magnitude over what's needed; faucet calls fund similarly.
const VALIDATOR_FUNDING_MIST: u64 = 100_000_000_000;

pub struct IkaTestCluster {
    pub test_cluster: TestCluster,
    pub swarm: Swarm,
    /// State captured from the bootstrap so post-build helpers (joiner /
    /// remove flows) can compose new on-chain transactions without
    /// re-publishing or re-initializing.
    pub packages: PublishedIkaPackages,
    pub system: InitializedIkaSystem,
    pub sui_rpc_url: String,
    pub publisher_address: SuiAddress,
    /// Validator protocol public keys in the configured order. The i-th name
    /// is the authority name of the validator built from
    /// `validator_initialization_configs[i]`. Used by index-based test helpers
    /// (e.g. `upgrade_validator_supported_protocol_versions`) because the
    /// swarm stores nodes in a HashMap and `validator_nodes()` order is
    /// otherwise unspecified.
    pub validator_names: Vec<ika_types::crypto::AuthorityName>,
}

/// Handle to a validator that joined the network after the initial
/// bootstrap via [`IkaTestCluster::add_joiner_validator`].
pub struct JoinerHandle {
    pub address: SuiAddress,
    pub validator_id: ObjectID,
    pub validator_cap_id: ObjectID,
    pub node_handle: IkaNodeHandle,
    pub init_config: ValidatorInitializationConfig,
}

impl JoinerHandle {
    /// BLS authority name (committee identity) for this joiner.
    pub fn authority_name(&self) -> AuthorityPublicKeyBytes {
        self.init_config.key_pair.public().into()
    }
}

/// Retry a transaction-submitting expression on transient Sui
/// object-version contention.
///
/// During the churn test the owned objects the joiner-add path consumes
/// advance version continuously under concurrent submission — the IKA
/// supply coin (`stake_ika` splits from it, and the per-cycle user DKG
/// also pays from it) and the freshly-resolved validator cap. A tx built
/// against a just-superseded version is rejected by Sui as
/// "non-retriable" for that exact version even though rebuilding against
/// the current version succeeds, so each retry re-evaluates `$submit`,
/// which re-resolves its object refs via `get_object_ref`. Same
/// retriable conditions and backoff as the inline retry in
/// `register_user_encryption_key` / `request_user_dwallet_dkg`.
macro_rules! retry_on_object_contention {
    ($label:expr, $submit:expr) => {{
        let mut last_err: Option<anyhow::Error> = None;
        let mut out = None;
        for attempt in 0..10 {
            match $submit {
                Ok(value) => {
                    out = Some(value);
                    break;
                }
                Err(e) => {
                    let msg = e.to_string();
                    let is_retriable_contention = msg.contains("unavailable for consumption")
                        || msg.contains("Transaction needs to be rebuilt")
                        || msg.contains("already locked by a different transaction");
                    tracing::warn!(
                        attempt,
                        is_retriable_contention,
                        "{} tx failed: {e}",
                        $label
                    );
                    if !is_retriable_contention {
                        return Err(anyhow::anyhow!("{} tx failed: {e}", $label));
                    }
                    last_err = Some(anyhow::anyhow!("{} tx failed: {e}", $label));
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                }
            }
        }
        out.ok_or_else(|| {
            last_err.unwrap_or_else(|| anyhow::anyhow!("{}: out of retries", $label))
        })?
    }};
}

impl IkaTestCluster {
    pub fn builder() -> IkaTestClusterBuilder {
        IkaTestClusterBuilder::new()
    }

    /// Block until at least one validator node reports an in-memory epoch
    /// greater than or equal to `target_epoch`. Polls every 250ms.
    pub async fn wait_for_epoch(&self, target_epoch: u64) {
        let handle = self
            .swarm
            .validator_node_handles()
            .into_iter()
            .next()
            .expect("swarm must have at least one validator node");
        wait_for_node_epoch(&handle, target_epoch).await;
    }

    /// Current in-memory epoch reported by an arbitrary validator
    /// node in the swarm. Read from a node-handle's
    /// `current_epoch_for_testing` rather than chain so tests don't
    /// have to spin up a fresh `SuiClient` for a single value.
    pub async fn current_epoch_from_chain(&self) -> anyhow::Result<u64> {
        let handle = self
            .swarm
            .validator_node_handles()
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("swarm has no validator nodes"))?;
        Ok(handle.with(|node| node.current_epoch_for_testing()))
    }

    /// Generate a fresh validator config, run the full candidate →
    /// staked → active flow on-chain, then spawn the joiner's in-memory
    /// `IkaNode` and attach it to the swarm. The returned [`JoinerHandle`]
    /// exposes the validator's identity + node handle so callers can
    /// wait for it to reach the next epoch or inspect committee state.
    ///
    /// The joiner becomes part of the active set at the next epoch
    /// boundary (the same lifecycle the bootstrap path drives for the
    /// initial set). Caller is responsible for `wait_for_epoch` after.
    pub async fn add_joiner_validator(&mut self) -> Result<JoinerHandle> {
        let mut rng = OsRng;
        let mut joiner_init = ValidatorInitializationConfigBuilder::new().build(&mut rng);
        joiner_init.name = Some(format!(
            "joiner-{}",
            self.swarm.validator_node_handles().len()
        ));
        let joiner_address: SuiAddress = (&joiner_init.account_key_pair.public()).into();

        // Add the joiner's account key to the wallet so the publisher's
        // `WalletContext` can sign transactions sent from the joiner.
        self.test_cluster
            .wallet_mut()
            .add_account(
                joiner_init.name.clone(),
                joiner_init.account_key_pair.copy(),
            )
            .await;

        // Fund the joiner address from the publisher — joiner needs SUI
        // gas to pay for its own candidate-registration tx.
        let tx_data = self
            .test_cluster
            .test_transaction_builder_with_sender(self.publisher_address)
            .await
            .transfer_sui(Some(VALIDATOR_FUNDING_MIST), joiner_address)
            .build();
        self.test_cluster
            .sign_and_execute_transaction(&tx_data)
            .await;

        let metadata = joiner_init.to_validator_info();
        let (validator_id, validator_cap_id) = retry_on_object_contention!(
            "request_add_validator_candidate",
            request_add_validator_candidate(
                joiner_address,
                self.test_cluster.wallet_mut(),
                &metadata,
                self.packages.ika_system_package_id,
                self.packages.ika_common_package_id,
                self.system.ika_system_object_id,
                self.system.init_system_shared_version,
            )
            .await
        );

        // Publisher stakes `MIN_VALIDATOR_JOINING_STAKE_INKU` into the
        // joiner's pool so `request_add_validator` doesn't abort with
        // insufficient-stake.
        retry_on_object_contention!(
            "stake_ika",
            stake_ika(
                self.publisher_address,
                self.test_cluster.wallet_mut(),
                self.packages.ika_system_package_id,
                self.system.ika_system_object_id,
                self.system.init_system_shared_version,
                self.packages.ika_supply_id,
                vec![validator_id],
            )
            .await
        );

        let client = SuiClientBuilder::default().build(&self.sui_rpc_url).await?;
        retry_on_object_contention!(
            "request_add_validator",
            request_add_validator(
                joiner_address,
                self.test_cluster.wallet_mut(),
                client.clone(),
                self.packages.ika_system_package_id,
                self.system.ika_system_object_id,
                self.system.init_system_shared_version,
                validator_cap_id,
            )
            .await
        );

        let validator_config = ValidatorConfigBuilder::new().build(
            &joiner_init,
            self.sui_rpc_url.clone(),
            self.packages.ika_package_id,
            self.packages.ika_common_package_id,
            self.packages.ika_dwallet_2pc_mpc_package_id,
            self.packages.ika_system_package_id,
            self.system.ika_system_object_id,
            self.system.ika_dwallet_coordinator_object_id,
        );
        let node_handle = self.swarm.spawn_new_node(validator_config).await;

        Ok(JoinerHandle {
            address: joiner_address,
            validator_id,
            validator_cap_id,
            node_handle,
            init_config: joiner_init,
        })
    }

    /// Submit `system::request_remove_validator` as the validator at
    /// `validator_idx` in the initial bootstrap order. The validator
    /// stays in the active set until the next epoch boundary; the
    /// on-chain logic moves it out at the next reconfiguration.
    /// Caller drives `wait_for_epoch(next_epoch)` to observe the
    /// committee change.
    ///
    /// Indexes into the bootstrap's validator set (0..num_validators).
    /// The corresponding `ValidatorCap` ObjectID is read from
    /// `system.validator_cap_ids`.
    pub async fn remove_validator(&mut self, validator_idx: usize) -> Result<()> {
        let validator_cap_id = self.system.validator_cap_ids[validator_idx];
        let validator_address = SuiAddress::from(
            &self.swarm.config().validator_initialization_configs[validator_idx]
                .account_key_pair
                .public(),
        );
        let client = SuiClientBuilder::default().build(&self.sui_rpc_url).await?;
        retry_on_object_contention!(
            "request_remove_validator",
            request_remove_validator(
                validator_address,
                self.test_cluster.wallet_mut(),
                client.clone(),
                self.packages.ika_system_package_id,
                self.system.ika_system_object_id,
                self.system.init_system_shared_version,
                validator_cap_id,
            )
            .await
        );
        Ok(())
    }

    /// Poll the chain until at least one `DWalletNetworkEncryptionKey`
    /// has its initial network DKG output published, then return its
    /// id + the public-output bytes. The bytes are the
    /// `network_dkg_public_output` blob from
    /// `DWalletNetworkEncryptionKeyData`, suitable for feeding into
    /// `network_dkg_public_output_to_protocol_pp_inner` to build the
    /// protocol public parameters for user-side dWallet DKG.
    pub async fn wait_for_network_key(&self) -> Result<(ObjectID, Vec<u8>)> {
        let client = self.sui_connector_client().await?;
        loop {
            let (_, inner) = client.must_get_dwallet_coordinator_inner().await;
            let keys = client.get_dwallet_mpc_network_keys(&inner).await?;
            for (key_id, key) in keys {
                if !matches!(
                    key.state,
                    ika_types::messages_dwallet_mpc::DWalletNetworkEncryptionKeyState::AwaitingNetworkDKG
                ) {
                    let data = client
                        .get_network_encryption_key_with_full_data_by_epoch(&key, key.dkg_at_epoch)
                        .await?;
                    if !data.network_dkg_public_output.is_empty() {
                        return Ok((key_id, data.network_dkg_public_output));
                    }
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    }

    /// Submit an on-chain `request_dwallet_network_encryption_key_dkg_by_cap`
    /// call so the network spins up a NEW `DWalletNetworkEncryptionKey`
    /// in addition to the one created at cluster bootstrap. The chain
    /// transition is synchronous (this returns once the tx executes);
    /// the actual MPC takes another epoch boundary to settle —
    /// callers typically pair this with `wait_for_new_network_key`.
    pub async fn request_network_key_dkg(&mut self) -> Result<()> {
        let client = SuiClientBuilder::default().build(&self.sui_rpc_url).await?;
        ika_system_request_dwallet_network_encryption_key_dkg_by_cap(
            self.publisher_address,
            self.test_cluster.wallet_mut(),
            client,
            self.packages.ika_system_package_id,
            self.packages.ika_dwallet_2pc_mpc_package_id,
            self.system.ika_system_object_id,
            self.system.init_system_shared_version,
            self.system.ika_dwallet_coordinator_object_id,
            self.system
                .dwallet_2pc_mpc_coordinator_initial_shared_version,
            self.system.protocol_cap_id,
        )
        .await
    }

    /// Poll until a `DWalletNetworkEncryptionKey` whose id is NOT in
    /// `known_key_ids` has finished its initial network DKG. Returns
    /// `(new_key_id, dkg_public_output_bytes)`.
    ///
    /// Used after `request_network_key_dkg` to observe completion of
    /// the freshly-requested key without confusing it with the
    /// bootstrap key (or any earlier keys requested in this test).
    pub async fn wait_for_new_network_key(
        &self,
        known_key_ids: &[ObjectID],
        timeout: std::time::Duration,
    ) -> Result<(ObjectID, Vec<u8>)> {
        let client = self.sui_connector_client().await?;
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if tokio::time::Instant::now() >= deadline {
                anyhow::bail!(
                    "timeout waiting for a new DWalletNetworkEncryptionKey \
                     beyond known_key_ids ({known_key_ids:?})"
                );
            }
            let (_, inner) = client.must_get_dwallet_coordinator_inner().await;
            let keys = client.get_dwallet_mpc_network_keys(&inner).await?;
            for (key_id, key) in keys {
                if known_key_ids.contains(&key_id) {
                    continue;
                }
                if matches!(
                    key.state,
                    ika_types::messages_dwallet_mpc::DWalletNetworkEncryptionKeyState::AwaitingNetworkDKG
                ) {
                    continue;
                }
                let data = client
                    .get_network_encryption_key_with_full_data_by_epoch(&key, key.dkg_at_epoch)
                    .await?;
                if !data.network_dkg_public_output.is_empty() {
                    return Ok((key_id, data.network_dkg_public_output));
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    }

    /// Snapshot of all `DWalletNetworkEncryptionKey` object ids on
    /// chain right now, used by `wait_for_new_network_key`.
    pub async fn current_network_key_ids(&self) -> Result<Vec<ObjectID>> {
        let client = self.sui_connector_client().await?;
        let (_, inner) = client.must_get_dwallet_coordinator_inner().await;
        let keys = client.get_dwallet_mpc_network_keys(&inner).await?;
        Ok(keys.into_keys().collect())
    }

    /// Build an `IkaSuiClient` pointed at this cluster's in-process Sui
    /// chain. Used by test helpers that need to query chain state via
    /// the ika-typed API (e.g. `get_dwallet_mpc_network_keys`,
    /// `get_dwallet_coordinator_inner`) rather than dropping down to
    /// the raw Sui SDK and re-implementing dynamic-field traversal.
    pub async fn sui_connector_client(&self) -> Result<SuiConnectorClient> {
        let ika_network_config = IkaNetworkConfig::new(
            self.packages.ika_package_id,
            self.packages.ika_common_package_id,
            self.packages.ika_dwallet_2pc_mpc_package_id,
            None,
            self.packages.ika_system_package_id,
            self.system.ika_system_object_id,
            self.system.ika_dwallet_coordinator_object_id,
        );
        SuiConnectorClient::new(
            &self.sui_rpc_url,
            SuiClientMetrics::new_for_testing(),
            ika_network_config,
        )
        .await
    }

    /// Derive a deterministic class-groups + Ed25519 keypair from a
    /// 32-byte seed and register the class-groups encryption key on
    /// chain. Returns the user-side material (kept locally) + the
    /// chain-side `encryption_key_id` extracted from the
    /// `CreatedEncryptionKeyEvent`.
    ///
    /// The seed-derivation logic mirrors `ika::dwallet_commands`'
    /// `derive_encryption_keys` so future SDK-side changes there
    /// stay aligned with what tests expect.
    pub async fn register_user_encryption_key(
        &mut self,
        curve: u32,
        seed: [u8; 32],
    ) -> Result<UserEncryptionKey> {
        let curve_byte = u8::try_from(curve)
            .map_err(|_| anyhow::anyhow!("curve {curve} does not fit in a single byte"))?;

        let cg_seed = {
            let mut hasher = Keccak256::default();
            hasher.update(b"CLASS_GROUPS_DECRYPTION_KEY_V1");
            hasher.update([curve_byte]);
            hasher.update(seed);
            let digest = hasher.finalize();
            let mut buf = [0u8; 32];
            buf.copy_from_slice(digest.as_ref());
            buf
        };
        let signing_seed = {
            let mut hasher = Keccak256::default();
            hasher.update(b"ED25519_SIGNING_KEY_V1");
            hasher.update([curve_byte]);
            hasher.update(seed);
            let digest = hasher.finalize();
            let mut buf = [0u8; 32];
            buf.copy_from_slice(digest.as_ref());
            buf
        };

        let (encryption_key, decryption_key) = generate_cg_keypair_from_seed(curve, cg_seed)
            .context("generate_cg_keypair_from_seed failed")?;
        let signing_keypair = {
            let private_key = Ed25519PrivateKey::from_bytes(&signing_seed)
                .map_err(|e| anyhow::anyhow!("Ed25519PrivateKey::from_bytes failed: {e}"))?;
            Ed25519KeyPair::from(private_key)
        };

        let sig: fastcrypto::ed25519::Ed25519Signature = signing_keypair.sign(&encryption_key);
        let encryption_key_signature = sig.as_ref().to_vec();
        let signer_public_key = signing_keypair.public().as_bytes().to_vec();

        // Retry on Sui object-contention errors. Background presign
        // tasks + parallel txs can lock the publisher's gas SUI
        // coin or other owned objects between our resolve and
        // submit; same retriable conditions as
        // `request_user_dwallet_dkg`.
        let mut register_last_err: Option<anyhow::Error> = None;
        let mut response = None;
        for attempt in 0..10 {
            match register_encryption_key(
                self.test_cluster.wallet_mut(),
                self.packages.ika_dwallet_2pc_mpc_package_id,
                self.system.ika_dwallet_coordinator_object_id,
                curve,
                encryption_key.clone(),
                encryption_key_signature.clone(),
                signer_public_key.clone(),
                DEFAULT_DWALLET_TX_GAS_BUDGET,
            )
            .await
            {
                Ok(resp) => {
                    response = Some(resp);
                    break;
                }
                Err(e) => {
                    let msg = e.to_string();
                    let is_retriable_contention = msg.contains("unavailable for consumption")
                        || msg.contains("Transaction needs to be rebuilt")
                        || msg.contains("already locked by a different transaction");
                    tracing::warn!(
                        attempt,
                        is_retriable_contention,
                        "register_encryption_key tx failed: {e}"
                    );
                    register_last_err =
                        Some(anyhow::anyhow!("register_encryption_key tx failed: {e}"));
                    if !is_retriable_contention {
                        return Err(register_last_err.unwrap());
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                }
            }
        }
        let response = response.ok_or_else(|| {
            register_last_err
                .unwrap_or_else(|| anyhow::anyhow!("register_encryption_key: out of retries"))
        })?;

        let digest = *response
            .effects
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("register_encryption_key tx has no effects"))?
            .transaction_digest();
        let encryption_key_id_str = fetch_event_field(
            &self.sui_rpc_url,
            &digest,
            "CreatedEncryptionKeyEvent",
            "encryption_key_id",
        )
        .await
        .ok_or_else(|| {
            anyhow::anyhow!("CreatedEncryptionKeyEvent not found in tx {digest} events")
        })?;
        let encryption_key_id: ObjectID = encryption_key_id_str.parse().map_err(|e| {
            anyhow::anyhow!("failed to parse encryption_key_id {encryption_key_id_str}: {e}")
        })?;

        // The on-chain coordinator indexes user encryption keys by the
        // SuiAddress derived from the signer's Ed25519 public key (not
        // by the tx sender's address). Mirror that so
        // `request_user_dwallet_dkg` later can look it up.
        let encryption_key_address: SuiAddress = signing_keypair.public().into();
        Ok(UserEncryptionKey {
            curve,
            encryption_key,
            decryption_key,
            signing_keypair,
            signer_public_key,
            encryption_key_id,
            encryption_key_address,
        })
    }

    /// Drive a user-initiated dWallet DKG end-to-end on-chain.
    ///
    /// Runs the centralized half of the 2PC-MPC DKG locally
    /// (`create_dkg_output_by_curve_v2`), encrypts the user's secret
    /// share against `user_key.encryption_key`, then submits
    /// `coordinator::request_dwallet_dkg`. The decentralized half is
    /// run asynchronously by the validators; this call returns as
    /// soon as the on-chain request lands.
    ///
    /// Returns the dWallet's chain id + the random session
    /// identifier so callers can wait for completion via
    /// `wait_for_dwallet_dkg_complete`.
    pub async fn request_user_dwallet_dkg(
        &mut self,
        curve: u32,
        network_key_id: ObjectID,
        network_dkg_public_output: Vec<u8>,
        user_key: &UserEncryptionKey,
        ika_coin_id: ObjectID,
    ) -> Result<DwalletDkgHandle> {
        let protocol_pp =
            network_dkg_public_output_to_protocol_pp_inner(curve, network_dkg_public_output)
                .map_err(|e| {
                    anyhow::anyhow!("network_dkg_public_output_to_protocol_pp_inner: {e}")
                })?;

        // Two session-id values are in play:
        //   - `session_id_random_bytes`: 32 random bytes that
        //     `request_dwallet_dkg` accepts directly.
        //   - `centralized_session_id`: BCS-encoded `SessionIdentifier`
        //     wrapping `keccak256(sender || session_id_random_bytes)` —
        //     the preimage form that the centralized DKG expects.
        // Mirroring `ika::dwallet_commands::on_chain_session_preimage`.
        let session_id_random_bytes: [u8; 32] = rand::random();
        let preimage: [u8; 32] = {
            let mut hasher = Keccak256::default();
            hasher.update(self.publisher_address.to_vec());
            hasher.update(session_id_random_bytes);
            let digest = hasher.finalize();
            let mut buf = [0u8; 32];
            buf.copy_from_slice(digest.as_ref());
            buf
        };
        let centralized_session_id = SessionIdentifier::new(SessionType::User, preimage).to_vec();

        let centralized_result =
            create_dkg_output_by_curve_v2(curve, protocol_pp.clone(), centralized_session_id)
                .map_err(|e| anyhow::anyhow!("create_dkg_output_by_curve_v2: {e}"))?;

        let encrypted_centralized_secret_share_and_proof = encrypt_secret_key_share_and_prove_v2(
            curve,
            centralized_result.centralized_secret_output,
            user_key.encryption_key.clone(),
            protocol_pp,
        )
        .map_err(|e| anyhow::anyhow!("encrypt_secret_key_share_and_prove_v2: {e}"))?;

        // Retry on Sui object-contention errors. Two patterns
        // surface in this setup:
        // 1. `"object ... version N is unavailable for consumption,
        //    current version: N+1"` — the IKA payment coin moved
        //    between our `get_object_ref` resolve and tx
        //    submission (e.g., a parallel staking split). Each
        //    retry re-resolves through `PaymentCoinArgs`.
        // 2. `"already locked by a different transaction:
        //    TransactionDigest(...)"` — Sui's shared-object /
        //    owned-object lock conflict; the prior tx will commit
        //    or fail soon, releasing the lock. Re-attempt clears
        //    once that resolves.
        let mut last_err: Option<anyhow::Error> = None;
        let mut response = None;
        for attempt in 0..10 {
            match request_dwallet_dkg(
                self.test_cluster.wallet_mut(),
                self.packages.ika_dwallet_2pc_mpc_package_id,
                self.system.ika_dwallet_coordinator_object_id,
                network_key_id,
                curve,
                centralized_result.public_key_share_and_proof.clone(),
                encrypted_centralized_secret_share_and_proof.clone(),
                user_key.encryption_key_address,
                centralized_result.public_output.clone(),
                user_key.signer_public_key.clone(),
                session_id_random_bytes.to_vec(),
                PaymentCoinArgs {
                    ika_coin_id,
                    sui_coin_id: None,
                },
                None,
                DEFAULT_DWALLET_TX_GAS_BUDGET,
            )
            .await
            {
                Ok(resp) => {
                    response = Some(resp);
                    break;
                }
                Err(e) => {
                    let msg = e.to_string();
                    let is_retriable_contention = msg.contains("unavailable for consumption")
                        || msg.contains("Transaction needs to be rebuilt")
                        || msg.contains("already locked by a different transaction");
                    tracing::warn!(
                        attempt,
                        is_retriable_contention,
                        "request_dwallet_dkg tx failed: {e}"
                    );
                    last_err = Some(anyhow::anyhow!("request_dwallet_dkg tx failed: {e}"));
                    if !is_retriable_contention {
                        return Err(last_err.unwrap());
                    }
                    // Backoff long enough for the contending tx to
                    // either commit or fail (Sui's tx finalization
                    // is typically sub-second on the in-process
                    // chain, but checkpoint settle adds ~1s).
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                }
            }
        }
        let response = response.ok_or_else(|| {
            last_err.unwrap_or_else(|| anyhow::anyhow!("request_dwallet_dkg: out of retries"))
        })?;

        let digest = *response
            .effects
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("request_dwallet_dkg tx has no effects"))?
            .transaction_digest();
        let dwallet_id_str = fetch_event_field(
            &self.sui_rpc_url,
            &digest,
            "DWalletDKGRequestEvent",
            "dwallet_id",
        )
        .await
        .ok_or_else(|| anyhow::anyhow!("DWalletDKGRequestEvent not found in tx {digest} events"))?;
        let dwallet_id: ObjectID = dwallet_id_str
            .parse()
            .map_err(|e| anyhow::anyhow!("failed to parse dwallet_id {dwallet_id_str}: {e}"))?;

        Ok(DwalletDkgHandle {
            dwallet_id,
            session_identifier: session_id_random_bytes,
        })
    }

    /// Poll the chain until the `DWallet` at `dwallet_id` transitions
    /// out of the in-flight DKG states (`DKGRequested`,
    /// `AwaitingNetworkDKGVerification`, etc.) into a terminal one
    /// (`Active` / equivalent on success, `NetworkRejected*` on
    /// failure). Returns `Ok` on success terminal state, `Err` on
    /// rejection or timeout.
    ///
    /// Events-based detection (`DWalletSessionResultEvent` emitted
    /// by `sessions_manager`) doesn't surface reliably through the
    /// Sui SDK's `MoveEventModule` / `MoveModule` filters in this
    /// Return the set of epochs for which the given node has a
    /// persisted `CertifiedHandoffAttestation` in its perpetual
    /// tables. Use this to verify the off-chain handoff pipeline
    /// is actually generating + storing certs (and, indirectly,
    /// that the joiner-announcement broadcast / signature
    /// aggregation through consensus all worked).
    pub fn handoff_cert_epochs_for_node(
        &self,
        node_handle: &IkaNodeHandle,
    ) -> Vec<ika_types::committee::EpochId> {
        node_handle.with(|node| {
            let perpetual = node.state().perpetual_tables();
            perpetual
                .iter_certified_handoff_attestations()
                .filter_map(|res| res.ok().map(|(epoch, _)| epoch))
                .collect()
        })
    }

    /// in-process setup, so we query the on-chain object state
    /// instead. The `DWalletCoordinator` stores each dWallet as a
    /// dynamic object field of its `dwallets: ObjectTable<ID,
    /// DWallet>`, which means the dwallet has its own ObjectID and
    /// can be fetched directly via `get_object`.
    pub async fn wait_for_dwallet_dkg_complete(
        &self,
        dwallet_id: ObjectID,
        timeout: std::time::Duration,
    ) -> Result<()> {
        use sui_json_rpc_types::SuiObjectDataOptions;
        let client = sui_sdk::SuiClientBuilder::default()
            .build(&self.sui_rpc_url)
            .await?;
        let deadline = tokio::time::Instant::now() + timeout;
        let mut last_observed_state = String::from("(no get_object response yet)");
        loop {
            if tokio::time::Instant::now() >= deadline {
                anyhow::bail!(
                    "timeout waiting for dWallet {dwallet_id} to reach terminal DKG state; last observed: {last_observed_state}"
                );
            }
            let resp = client
                .read_api()
                .get_object_with_options(dwallet_id, SuiObjectDataOptions::full_content())
                .await?;
            if let Some(data) = resp.data
                && let Some(content) = data.content
            {
                let state_str = format!("{content:?}");
                last_observed_state = state_str.clone();
                // The `state` field encodes the DKG progression
                // enum. The decentralized half-DKG terminates at
                // `AwaitingKeyHolderSignature { public_output }`;
                // the further transition to `Active { public_output }`
                // requires a separate user `accept_dwallet` call —
                // both carry a `public_output` field. Pre-completion
                // variants (`DKGRequested`,
                // `AwaitingNetworkDKGVerification`) have no fields,
                // so the SuiParsedData dump won't contain
                // `"public_output"` until the network produces the
                // DKG output and the on-chain pipeline lands it.
                //
                // Sui's parsed-JSON formatter drops the variant tag
                // for enum variants (only the inhabited fields show
                // up), so we can't string-match the variant name —
                // matching on the presence of the field name is the
                // reliable signal.
                if state_str.contains("\"public_output\"") {
                    return Ok(());
                }
                if state_str.contains("NetworkRejected") {
                    anyhow::bail!("dwallet DKG rejected for {dwallet_id}: state={state_str}");
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    }

    /// Current ika protocol version, read from the first validator's in-memory
    /// epoch store. Updated when the network reconfigures into a new epoch.
    pub fn current_protocol_version(&self) -> ProtocolVersion {
        let handle = self
            .swarm
            .validator_node_handles()
            .into_iter()
            .next()
            .expect("swarm must have at least one validator node");
        handle.with(|node| node.current_protocol_version_for_testing())
    }

    /// Simulate an in-place validator upgrade: stop the validator, mutate its
    /// `NodeConfig.supported_protocol_versions`, and restart it. The next
    /// `AuthorityCapabilitiesV1` notification (sent at the start of the next
    /// epoch the validator observes) carries the new range, which the
    /// end-of-epoch quorum vote uses to pick the next protocol version.
    ///
    /// Index is into `validator_names` (insertion order at build time).
    pub async fn upgrade_validator_supported_protocol_versions(
        &self,
        validator_index: usize,
        new_versions: SupportedProtocolVersions,
    ) -> Result<()> {
        let name = *self
            .validator_names
            .get(validator_index)
            .expect("validator_index out of range");
        let node = self
            .swarm
            .node(&name)
            .expect("validator node exists for the configured name");
        tracing::info!(
            ?validator_index,
            ?new_versions,
            "upgrading validator: stop -> mutate config -> start",
        );
        node.stop();
        node.config().supported_protocol_versions = Some(new_versions);
        node.start().await?;
        Ok(())
    }
}

/// User-side material produced by `register_user_encryption_key`. The
/// `decryption_key` and `signing_keypair` stay local — the test
/// retains them so it could in principle decrypt or sign later,
/// though the current `test_sessions_complete_across_epoch_switch`
/// only exercises the DKG completion path.
pub struct UserEncryptionKey {
    pub curve: u32,
    pub encryption_key: Vec<u8>,
    pub decryption_key: Vec<u8>,
    pub signing_keypair: Ed25519KeyPair,
    pub signer_public_key: Vec<u8>,
    pub encryption_key_id: ObjectID,
    pub encryption_key_address: SuiAddress,
}

/// Handle returned by `request_user_dwallet_dkg` — captures both the
/// chain dwallet id (for state queries) and the random session
/// identifier the centralized party used (for event correlation).
pub struct DwalletDkgHandle {
    pub dwallet_id: ObjectID,
    pub session_identifier: [u8; 32],
}

/// Gas budget large enough to cover even the heaviest dWallet
/// coordinator transactions (DKG with payment + session id +
/// encryption key Move calls).
const DEFAULT_DWALLET_TX_GAS_BUDGET: u64 = 1_000_000_000;

/// Fetch the events emitted by `tx_digest` and return the first
/// `field_name` value found in an event whose Move type contains
/// `event_type_substr`. Looks at the event's `parsed_json` first,
/// then falls back to nested `event_data` (for events wrapped in a
/// `DWalletSessionEvent`).
///
/// `execute_transaction` in `ika-sui-client` builds a
/// `SuiTransactionBlockResponse` with only `effects` populated — events
/// have to be fetched separately via the SDK's `event_api`.
async fn fetch_event_field(
    sui_rpc_url: &str,
    tx_digest: &sui_types::digests::TransactionDigest,
    event_type_substr: &str,
    field_name: &str,
) -> Option<String> {
    let client = sui_sdk::SuiClientBuilder::default()
        .build(sui_rpc_url)
        .await
        .ok()?;
    let events = client.event_api().get_events(*tx_digest).await.ok()?;
    for event in &events {
        let type_str = event.type_.to_string();
        if type_str.contains(event_type_substr) {
            if let Some(val) = event.parsed_json.get(field_name).and_then(|v| v.as_str()) {
                return Some(val.to_string());
            }
            if let Some(val) = event
                .parsed_json
                .get("event_data")
                .and_then(|d| d.get(field_name))
                .and_then(|v| v.as_str())
            {
                return Some(val.to_string());
            }
        }
    }
    None
}

/// Block until `node_handle`'s in-memory epoch reaches `target_epoch`.
/// Polls every 250ms — same cadence as `IkaTestCluster::wait_for_epoch`.
pub async fn wait_for_node_epoch(node_handle: &IkaNodeHandle, target_epoch: u64) {
    loop {
        let current = node_handle.with(|node| node.current_epoch_for_testing());
        if current >= target_epoch {
            tracing::info!(current, target_epoch, "wait_for_node_epoch reached target");
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
}

pub struct IkaTestClusterBuilder {
    num_validators: usize,
    epoch_duration_ms: Option<u64>,
    protocol_version: Option<ProtocolVersion>,
    /// Per-validator `SupportedProtocolVersions` overrides (indexed). When
    /// `None`, every validator uses `SupportedProtocolVersions::SYSTEM_DEFAULT`.
    /// `Some(v)` must have length `num_validators`.
    per_validator_supported_protocol_versions: Option<Vec<SupportedProtocolVersions>>,
}

impl IkaTestClusterBuilder {
    pub fn new() -> Self {
        Self {
            num_validators: DEFAULT_NUM_VALIDATORS,
            epoch_duration_ms: None,
            protocol_version: None,
            per_validator_supported_protocol_versions: None,
        }
    }

    pub fn with_num_validators(mut self, num_validators: usize) -> Self {
        self.num_validators = num_validators;
        self
    }

    pub fn with_epoch_duration_ms(mut self, epoch_duration_ms: u64) -> Self {
        self.epoch_duration_ms = Some(epoch_duration_ms);
        self
    }

    /// Genesis protocol version. Defaults to `ProtocolVersion::MAX`. Use this
    /// to boot the cluster at an older version (e.g. v3) so an epoch
    /// transition will exercise the capability vote and advance to a newer
    /// version (e.g. v4) supported by `SupportedProtocolVersions::SYSTEM_DEFAULT`.
    pub fn with_protocol_version(mut self, protocol_version: ProtocolVersion) -> Self {
        self.protocol_version = Some(protocol_version);
        self
    }

    /// Per-validator `SupportedProtocolVersions` overrides — vector length must
    /// equal `num_validators`. Use this to model a gradual upgrade scenario
    /// where some validators support a newer max than others. When unset,
    /// every validator gets `SupportedProtocolVersions::SYSTEM_DEFAULT`.
    pub fn with_per_validator_supported_protocol_versions(
        mut self,
        per_validator_versions: Vec<SupportedProtocolVersions>,
    ) -> Self {
        self.per_validator_supported_protocol_versions = Some(per_validator_versions);
        self
    }

    pub async fn build(self) -> Result<IkaTestCluster> {
        let mut test_cluster = TestClusterBuilder::new()
            .with_num_validators(self.num_validators)
            .build()
            .await;

        let sui_rpc_url = test_cluster.rpc_url().to_string();
        let publisher_address = test_cluster.get_address_0();

        let mut rng = OsRng;
        let validator_initialization_configs: Vec<ValidatorInitializationConfig> = (0..self
            .num_validators)
            .map(|i| {
                let mut cfg = ValidatorInitializationConfigBuilder::new().build(&mut rng);
                cfg.name = Some(format!("validator-{i}"));
                cfg
            })
            .collect();

        let mut validator_addresses = Vec::with_capacity(self.num_validators);
        for validator in &validator_initialization_configs {
            let address: SuiAddress = (&validator.account_key_pair.public()).into();
            test_cluster
                .wallet_mut()
                .add_account(validator.name.clone(), validator.account_key_pair.copy())
                .await;
            validator_addresses.push(address);
        }

        // Fund validator addresses from the publisher. `init_ika_on_sui` does this
        // via the Sui faucet; the in-process test cluster has no faucet, so we
        // transfer directly from a publisher gas object instead.
        for validator_address in &validator_addresses {
            let tx_data = test_cluster
                .test_transaction_builder_with_sender(publisher_address)
                .await
                .transfer_sui(Some(VALIDATOR_FUNDING_MIST), *validator_address)
                .build();
            test_cluster.sign_and_execute_transaction(&tx_data).await;
        }

        let contract_paths = build_contract_paths()?;
        let cwd = contract_paths.current_working_dir.clone();

        // Sui's publish flow writes `Pub.<env>.toml` to whatever cwd is when it
        // finishes; entries reference absolute paths to the unpacked package
        // dirs. The file is read on the next publish to resolve transitive
        // package addresses. If it lands in the workspace, stale entries from
        // a previous test run point to deleted temp dirs and break the next
        // run's publish with `InvalidEphemeralPath`. Park cwd inside the
        // contracts temp dir so the pubfile lives and dies with that TempDir.
        std::env::set_current_dir(contract_paths.contracts_dir.path())?;

        let client = SuiClientBuilder::default().build(&sui_rpc_url).await?;

        let packages = publish_ika_packages(
            test_cluster.wallet_mut(),
            client.clone(),
            publisher_address,
            &contract_paths,
        )
        .await?;

        let mut initiation_parameters = InitiationParameters::new();
        if let Some(epoch_duration_ms) = self.epoch_duration_ms {
            initiation_parameters.epoch_duration_ms = epoch_duration_ms;
        }
        if let Some(protocol_version) = self.protocol_version {
            initiation_parameters.protocol_version = protocol_version.as_u64();
        }

        let system = initialize_ika_system(
            test_cluster.wallet_mut(),
            client,
            publisher_address,
            &packages,
            &validator_initialization_configs,
            &validator_addresses,
            &initiation_parameters,
        )
        .await?;

        // `sui move build` inside publish_*_to_sui chdirs into the contract temp
        // dir; restore cwd so the caller's process state isn't mutated.
        std::env::set_current_dir(&cwd)?;

        // Validators must declare which protocol versions they support so they
        // send `AuthorityCapabilitiesV1` notifications — that's what the
        // end-of-epoch quorum vote reads to pick the next protocol version.
        // Without an override every validator gets `SYSTEM_DEFAULT`
        // (`ProtocolVersion::MIN..=MAX`); the per-validator override lets
        // tests model heterogeneous / gradual upgrade scenarios.
        if let Some(per_validator) = self.per_validator_supported_protocol_versions.as_ref() {
            anyhow::ensure!(
                per_validator.len() == validator_initialization_configs.len(),
                "per_validator_supported_protocol_versions has {} entries but cluster has {} validators",
                per_validator.len(),
                validator_initialization_configs.len(),
            );
        }
        let validator_configs: Vec<_> = validator_initialization_configs
            .iter()
            .enumerate()
            .map(|(i, v)| {
                let supported_versions = self
                    .per_validator_supported_protocol_versions
                    .as_ref()
                    .map(|per_validator| per_validator[i])
                    .unwrap_or(SupportedProtocolVersions::SYSTEM_DEFAULT);
                ValidatorConfigBuilder::new()
                    .with_supported_protocol_versions(supported_versions)
                    .build(
                        v,
                        sui_rpc_url.clone(),
                        packages.ika_package_id,
                        packages.ika_common_package_id,
                        packages.ika_dwallet_2pc_mpc_package_id,
                        packages.ika_system_package_id,
                        system.ika_system_object_id,
                        system.ika_dwallet_coordinator_object_id,
                    )
            })
            .collect();
        // Record the validators' protocol public keys in their configured
        // order so test helpers (e.g. `upgrade_validator_supported_protocol_versions`)
        // can address a specific validator by index.
        let validator_names: Vec<_> = validator_configs
            .iter()
            .map(|c| c.protocol_public_key())
            .collect();
        // The ika epoch only advances when a Notifier node submits the
        // `process_mid_epoch` / `request_advance_epoch` transactions to Sui (the
        // validators never do — `run_epoch_switch` is gated on a notifier key).
        // Without one the network is frozen at its genesis epoch, so any test that
        // calls `wait_for_epoch` hangs. Run one notifier (a fullnode carrying the
        // publisher's Sui key) so reconfiguration actually progresses.
        // Give the notifier its OWN funded Sui key rather than reusing the
        // publisher's. Sharing the publisher gas coin makes the notifier's
        // cached gas ref go stale whenever the test wallet spends from the same
        // address (validator management, funding, faucet, presign drivers), and
        // the in-process notifier fullnode lags the validators too far behind to
        // recover the current version — the rejected-version re-fetch loops and
        // wedges epoch advance. Production notifiers run a dedicated key, so a
        // dedicated, publisher-funded key here matches reality and removes the
        // cross-actor gas contention.
        let (notifier_address, notifier_keypair, _scheme, _phrase) =
            generate_new_key(SignatureScheme::ED25519, None, None)?;
        let fund_notifier_tx_data = test_cluster
            .test_transaction_builder_with_sender(publisher_address)
            .await
            .transfer_sui(Some(VALIDATOR_FUNDING_MIST), notifier_address)
            .build();
        test_cluster
            .sign_and_execute_transaction(&fund_notifier_tx_data)
            .await;
        let mut notifier_rng = OsRng;
        let notifier_config = FullnodeConfigBuilder::new().build(
            &mut notifier_rng,
            &validator_initialization_configs,
            sui_rpc_url.clone(),
            packages.ika_package_id,
            packages.ika_common_package_id,
            packages.ika_dwallet_2pc_mpc_package_id,
            packages.ika_system_package_id,
            system.ika_system_object_id,
            system.ika_dwallet_coordinator_object_id,
            Some(notifier_keypair),
        );

        let network_config = NetworkConfig {
            validator_configs,
            fullnode_configs: vec![notifier_config],
            validator_initialization_configs,
            ika_package_id: packages.ika_package_id,
            ika_common_package_id: packages.ika_common_package_id,
            ika_dwallet_2pc_mpc_package_id: packages.ika_dwallet_2pc_mpc_package_id,
            ika_system_package_id: packages.ika_system_package_id,
            ika_system_object_id: system.ika_system_object_id,
            ika_dwallet_coordinator_object_id: system.ika_dwallet_coordinator_object_id,
        };

        let mut swarm = SwarmBuilder::new()
            .with_network_config(network_config)
            .build()
            .await?;
        swarm.launch().await?;

        Ok(IkaTestCluster {
            test_cluster,
            swarm,
            packages,
            system,
            sui_rpc_url,
            publisher_address,
            validator_names,
        })
    }
}

impl Default for IkaTestClusterBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(not(msim))]
fn build_contract_paths() -> Result<ContractPaths> {
    setup_contract_paths(Chain::Devnet)
}

#[cfg(msim)]
fn build_contract_paths() -> Result<ContractPaths> {
    let (sui_framework, move_stdlib) = locate_sui_framework_and_move_stdlib()?;
    setup_contract_paths_for_simtest(&sui_framework, &move_stdlib)
}

/// Find the on-disk Move sources for `sui-framework` and `move-stdlib` so we can
/// rewrite ika `Move.toml` files to use local-path deps (msim cannot fetch via
/// git). We resolve the `sui-framework` Rust crate's manifest_path via
/// `cargo metadata`, then walk to its sibling Move-package layout
/// (`crates/sui-framework/packages/sui-framework` and `.../move-stdlib`).
#[cfg(msim)]
fn locate_sui_framework_and_move_stdlib() -> Result<(std::path::PathBuf, std::path::PathBuf)> {
    let metadata = cargo_metadata::MetadataCommand::new()
        .manifest_path(metadata_workspace_manifest()?)
        .exec()
        .map_err(|e| anyhow::anyhow!("cargo metadata failed: {e}"))?;

    let sui_framework_pkg = metadata
        .packages
        .iter()
        .find(|p| p.name.as_str() == "sui-framework")
        .ok_or_else(|| anyhow::anyhow!("sui-framework not found in cargo metadata"))?;
    // sui-framework's manifest sits at .../crates/sui-framework/Cargo.toml; the
    // Move package is its sibling at .../crates/sui-framework/packages/sui-framework.
    let sui_crate_dir = std::path::PathBuf::from(
        sui_framework_pkg
            .manifest_path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("sui-framework manifest_path has no parent"))?,
    );
    let sui_framework_move = sui_crate_dir.join("packages").join("sui-framework");
    let move_stdlib_move = sui_crate_dir.join("packages").join("move-stdlib");
    if !sui_framework_move.join("Move.toml").is_file() {
        anyhow::bail!(
            "sui-framework Move package not found at {}",
            sui_framework_move.display()
        );
    }
    if !move_stdlib_move.join("Move.toml").is_file() {
        anyhow::bail!(
            "move-stdlib Move package not found at {}",
            move_stdlib_move.display()
        );
    }
    Ok((sui_framework_move, move_stdlib_move))
}

#[cfg(msim)]
fn metadata_workspace_manifest() -> Result<std::path::PathBuf> {
    // Walk up from this crate's manifest dir to find the workspace root Cargo.toml.
    let start = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for ancestor in start.ancestors() {
        let candidate = ancestor.join("Cargo.toml");
        if candidate.is_file()
            && std::fs::read_to_string(&candidate)
                .map(|s| s.contains("[workspace]"))
                .unwrap_or(false)
        {
            return Ok(candidate);
        }
    }
    anyhow::bail!("workspace Cargo.toml not found above {}", start.display())
}

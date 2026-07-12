// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! User-flow drivers for cluster tests: sign (dedicated or global presign),
//! future-sign, imported-key dwallet, make-share-public, and
//! transfer (re-encrypt to another key) — the Rust-native equivalents of the
//! TypeScript SDK flows, driveable under both `#[tokio::test]` and
//! `#[sim_test]` because `dwallet-mpc-centralized-party` forwards the
//! `dwallet-mpc-unsafe-mock` feature (both 2PC halves agree under test).
//!
//! Shapes mirror the battle-tested CLI (`ika` binary `dwallet_commands`):
//! transaction builders from `ika_sui_client::ika_dwallet_transactions`,
//! user-side crypto from `dwallet_mpc_centralized_party`, and completion by
//! polling object state through the fullnode RPC.

use anyhow::{Context, Result, anyhow};
use dwallet_mpc_centralized_party::{
    advance_centralized_sign_party, create_imported_dwallet_centralized_step_inner_v2,
    encrypt_secret_key_share_and_prove_v2, network_dkg_public_output_to_protocol_pp_inner,
    sample_dwallet_keypair_inner,
};
use fastcrypto::traits::Signer as _;
use ika_sui_client::ika_dwallet_transactions::{
    self, PaymentCoinArgs, request_future_sign_fulfill_tx, request_future_sign_tx,
    request_presign_tx, request_sign_tx,
};
use ika_types::messages_dwallet_mpc::{SessionIdentifier, SessionType};
use sui_json_rpc_types::{SuiObjectDataOptions, SuiTransactionBlockEffectsAPI as _};
use sui_types::base_types::ObjectID;

use crate::{
    DEFAULT_DWALLET_TX_GAS_BUDGET, DwalletDkgHandle, IkaTestCluster, UserEncryptionKey,
    fetch_event_field,
};

/// Handle for a requested dedicated presign: the (unverified) cap the sign
/// transaction consumes, and the presign session whose completion carries
/// the presign bytes.
pub struct PresignHandle {
    pub presign_cap_id: ObjectID,
    pub presign_id: ObjectID,
}

/// Handle for an imported-key dwallet: like [`DwalletDkgHandle`] plus the
/// encrypted-share id the acceptance step finalizes.
pub struct ImportedKeyHandle {
    pub dwallet_id: ObjectID,
    pub dwallet_cap_id: ObjectID,
    pub user_secret_key_share: Vec<u8>,
    pub curve: u32,
}

/// The signer-side view of a dwallet — what the sign / future-sign /
/// make-public flows need, common to DKG-created ([`DwalletDkgHandle`])
/// and imported-key ([`ImportedKeyHandle`]) dwallets.
pub struct DwalletSigner<'a> {
    pub dwallet_id: ObjectID,
    pub dwallet_cap_id: ObjectID,
    pub user_secret_key_share: &'a [u8],
    pub curve: u32,
}

impl DwalletDkgHandle {
    pub fn signer(&self) -> DwalletSigner<'_> {
        DwalletSigner {
            dwallet_id: self.dwallet_id,
            dwallet_cap_id: self.dwallet_cap_id,
            user_secret_key_share: &self.user_secret_key_share,
            curve: self.curve,
        }
    }
}

impl ImportedKeyHandle {
    pub fn signer(&self) -> DwalletSigner<'_> {
        DwalletSigner {
            dwallet_id: self.dwallet_id,
            dwallet_cap_id: self.dwallet_cap_id,
            user_secret_key_share: &self.user_secret_key_share,
            curve: self.curve,
        }
    }
}

async fn sdk_client(sui_rpc_url: &str) -> Result<sui_sdk::SuiClient> {
    Ok(sui_sdk::SuiClientBuilder::default()
        .build(sui_rpc_url)
        .await?)
}

/// Object fields as JSON, unwrapping the `WithTypes` `{type, fields}`
/// wrapper Sui applies to nested Move structs.
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
        .ok_or_else(|| anyhow!("object not found: {object_id}"))?;
    let content = data
        .content
        .ok_or_else(|| anyhow!("no content for object: {object_id}"))?;
    let json = serde_json::to_value(&content)?;
    let fields = json
        .get("fields")
        .cloned()
        .ok_or_else(|| anyhow!("no fields in object: {object_id}"))?;
    if fields.get("type").is_some()
        && let Some(inner) = fields.get("fields")
    {
        return Ok(inner.clone());
    }
    Ok(fields)
}

/// `vector<u8>` from Sui JSON: array-of-numbers, base64 string, or
/// 0x-prefixed hex.
fn extract_bytes_from_json(value: &serde_json::Value) -> Option<Vec<u8>> {
    match value {
        serde_json::Value::Array(arr) => arr.iter().map(|v| v.as_u64().map(|n| n as u8)).collect(),
        serde_json::Value::String(s) => {
            if let Some(hex_str) = s.strip_prefix("0x") {
                return hex::decode(hex_str).ok();
            }
            use base64::{Engine, engine::general_purpose::STANDARD};
            STANDARD.decode(s).ok()
        }
        _ => None,
    }
}

/// First created object of the transaction whose Move type contains
/// `type_substr` (skipping dynamic-field wrappers).
pub(crate) async fn find_created_object_by_type(
    sui_rpc_url: &str,
    response: &sui_json_rpc_types::SuiTransactionBlockResponse,
    type_substr: &str,
) -> Result<ObjectID> {
    let effects = response
        .effects
        .as_ref()
        .ok_or_else(|| anyhow!("tx has no effects"))?;
    let client = sdk_client(sui_rpc_url).await?;
    for created in effects.created() {
        let object_id = created.reference.object_id;
        let Ok(resp) = client
            .read_api()
            .get_object_with_options(object_id, SuiObjectDataOptions::new().with_type())
            .await
        else {
            continue;
        };
        let Some(type_str) = resp.data.and_then(|d| d.type_).map(|t| t.to_string()) else {
            continue;
        };
        if type_str.contains("dynamic_field") || type_str.contains("dynamic_object_field") {
            continue;
        }
        if type_str.contains(type_substr) {
            return Ok(object_id);
        }
    }
    Err(anyhow!(
        "no created object of type containing {type_substr:?} in tx"
    ))
}

/// A nested field from a matching event, traversing Move enum variant
/// serialization (`{variant, fields}`) along `path` — starting from the
/// `DWalletSessionEvent` wrapper's `event_data` when present. Mirrors the
/// CLI's `extract_nested_event_field`.
pub(crate) async fn fetch_nested_event_field(
    sui_rpc_url: &str,
    tx_digest: &sui_types::digests::TransactionDigest,
    event_type_substr: &str,
    path: &[&str],
) -> Option<String> {
    let client = sdk_client(sui_rpc_url).await.ok()?;
    let events = client.event_api().get_events(*tx_digest).await.ok()?;
    for event in &events {
        let type_str = event.type_.to_string();
        if !type_str.contains(event_type_substr) {
            continue;
        }
        let root = event
            .parsed_json
            .get("event_data")
            .unwrap_or(&event.parsed_json);
        let mut current = root;
        for (i, key) in path.iter().enumerate() {
            let next = current
                .get(key)
                .or_else(|| current.get("fields").and_then(|f| f.get(key)));
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

/// Poll `object_id` until its session state carries `bytes_field` and
/// return those bytes.
///
/// Completion is detected by FIELD PRESENCE, not by the state enum's
/// variant name: the pinned Sui renders Move enum values as
/// `{"type": ..., "fields": {...}}` WITHOUT a variant tag (the same quirk
/// `wait_for_dwallet_dkg_complete` documents), so only the inhabited
/// variant's fields are observable. `Completed` is the only variant
/// carrying the output bytes, which makes the field decisive. Where a
/// node DOES render a variant tag, `NetworkRejected` is surfaced as an
/// error; without one, a rejected session is indistinguishable from a
/// pending one and surfaces as this poll's timeout (whose message carries
/// the last observed state for diagnosis).
async fn poll_session_until_completed(
    sui_rpc_url: &str,
    object_id: ObjectID,
    bytes_field: &str,
    timeout: std::time::Duration,
) -> Result<Vec<u8>> {
    let client = sdk_client(sui_rpc_url).await?;
    let start = tokio::time::Instant::now();
    let mut last_observed = String::from("(no fetch yet)");
    let mut poll_count: u64 = 0;
    loop {
        if start.elapsed() > timeout {
            anyhow::bail!(
                "timeout ({timeout:?}) waiting for session {object_id} to complete; \
                 polls={poll_count} last_observed={last_observed}"
            );
        }
        match fetch_object_fields(&client, object_id).await {
            Ok(fields) => {
                let state = fields.get("state");
                if let Some(bytes) = state
                    .and_then(|state| state.get("fields"))
                    .and_then(|f| f.get(bytes_field))
                    .and_then(extract_bytes_from_json)
                {
                    return Ok(bytes);
                }
                if let Some("NetworkRejected") = state
                    .and_then(|state| state.get("variant"))
                    .and_then(|v| v.as_str())
                {
                    anyhow::bail!("session {object_id} was rejected by the network");
                }
                last_observed = state
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| format!("no state field in {fields}"));
            }
            Err(e) => last_observed = format!("fetch error: {e}"),
        }
        poll_count += 1;
        if poll_count.is_multiple_of(40) {
            tracing::info!(
                %object_id,
                poll_count,
                last_observed,
                "still polling session for completion"
            );
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

impl IkaTestCluster {
    fn payment_coins(&self) -> PaymentCoinArgs {
        PaymentCoinArgs {
            ika_coin_id: self.packages.ika_supply_id,
            sui_coin_id: None,
        }
    }

    /// The dwallet's decentralized DKG public output from chain state
    /// (`state.fields.public_output` of an Active dwallet).
    pub async fn dwallet_public_output(&self, dwallet_id: ObjectID) -> Result<Vec<u8>> {
        let client = sdk_client(&self.sui_rpc_url).await?;
        let fields = fetch_object_fields(&client, dwallet_id).await?;
        fields
            .get("state")
            .and_then(|state| state.get("fields"))
            .and_then(|f| f.get("public_output"))
            .and_then(extract_bytes_from_json)
            .ok_or_else(|| anyhow!("dwallet {dwallet_id} has no public_output (not Active?)"))
    }

    /// Requests a dedicated (per-dwallet) presign. Returns once the
    /// request transaction lands; completion is awaited separately with
    /// [`Self::wait_for_presign`].
    ///
    /// Only valid where the on-chain global-presign config does NOT route
    /// the (curve, algorithm) pair to global presigns — under the `Full`
    /// (mainnet-shape) genesis config the test cluster boots with, that
    /// means imported-key dwallets with secp256k1-ECDSA; DKG dwallets must
    /// use [`Self::request_global_presign`].
    pub async fn request_dedicated_presign(
        &mut self,
        signer: &DwalletSigner<'_>,
        signature_algorithm: u32,
    ) -> Result<PresignHandle> {
        let session_identifier_bytes: [u8; 32] = rand::random();
        let coins = self.payment_coins();
        let response = request_presign_tx(
            self.test_cluster.wallet_mut(),
            self.packages.ika_dwallet_2pc_mpc_package_id,
            self.system.ika_dwallet_coordinator_object_id,
            signer.dwallet_id,
            signature_algorithm,
            session_identifier_bytes.to_vec(),
            coins,
            DEFAULT_DWALLET_TX_GAS_BUDGET,
        )
        .await
        .context("request_presign_tx failed")?;
        let presign_cap_id =
            find_created_object_by_type(&self.sui_rpc_url, &response, "PresignCap").await?;
        let client = sdk_client(&self.sui_rpc_url).await?;
        let cap_fields = fetch_object_fields(&client, presign_cap_id).await?;
        let presign_id: ObjectID = cap_fields
            .get("presign_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("presign cap {presign_cap_id} has no presign_id"))?
            .parse()?;
        Ok(PresignHandle {
            presign_cap_id,
            presign_id,
        })
    }

    /// Requests a global (dwallet-independent) presign — the production
    /// path for DKG-created dwallets under the `Full` genesis config.
    pub async fn request_global_presign(
        &mut self,
        network_key_id: ObjectID,
        curve: u32,
        signature_algorithm: u32,
    ) -> Result<PresignHandle> {
        let session_identifier_bytes: [u8; 32] = rand::random();
        let coins = self.payment_coins();
        let response = ika_dwallet_transactions::request_global_presign_tx(
            self.test_cluster.wallet_mut(),
            self.packages.ika_dwallet_2pc_mpc_package_id,
            self.system.ika_dwallet_coordinator_object_id,
            network_key_id,
            curve,
            signature_algorithm,
            session_identifier_bytes.to_vec(),
            coins,
            DEFAULT_DWALLET_TX_GAS_BUDGET,
        )
        .await
        .context("request_global_presign_tx failed")?;
        let presign_cap_id =
            find_created_object_by_type(&self.sui_rpc_url, &response, "PresignCap").await?;
        let client = sdk_client(&self.sui_rpc_url).await?;
        let cap_fields = fetch_object_fields(&client, presign_cap_id).await?;
        let presign_id: ObjectID = cap_fields
            .get("presign_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("presign cap {presign_cap_id} has no presign_id"))?
            .parse()?;
        Ok(PresignHandle {
            presign_cap_id,
            presign_id,
        })
    }

    /// Waits for the presign session to complete and returns the presign
    /// bytes the centralized signer consumes.
    pub async fn wait_for_presign(
        &self,
        presign: &PresignHandle,
        timeout: std::time::Duration,
    ) -> Result<Vec<u8>> {
        poll_session_until_completed(&self.sui_rpc_url, presign.presign_id, "presign", timeout)
            .await
    }

    /// Full sign leg against an Active dwallet and a completed dedicated
    /// presign: computes the centralized (user) signature share, submits
    /// the sign request (verifying the presign cap in the same PTB), and
    /// waits for the network signature.
    pub async fn sign(
        &mut self,
        signer: &DwalletSigner<'_>,
        presign: &PresignHandle,
        presign_bytes: Vec<u8>,
        network_dkg_public_output: Vec<u8>,
        message: Vec<u8>,
        signature_algorithm: u32,
        hash_scheme: u32,
        timeout: std::time::Duration,
    ) -> Result<Vec<u8>> {
        let protocol_pp =
            network_dkg_public_output_to_protocol_pp_inner(signer.curve, network_dkg_public_output)
                .map_err(|e| anyhow!("network_dkg_public_output_to_protocol_pp_inner: {e}"))?;
        let dwallet_public_output = self.dwallet_public_output(signer.dwallet_id).await?;
        let message_centralized_signature = advance_centralized_sign_party(
            protocol_pp,
            dwallet_public_output,
            signer.user_secret_key_share.to_vec(),
            presign_bytes,
            message.clone(),
            signer.curve,
            signature_algorithm,
            hash_scheme,
        )
        .map_err(|e| anyhow!("advance_centralized_sign_party: {e}"))?;

        let session_identifier_bytes: [u8; 32] = rand::random();
        let coins = self.payment_coins();
        let response = request_sign_tx(
            self.test_cluster.wallet_mut(),
            self.packages.ika_dwallet_2pc_mpc_package_id,
            self.system.ika_dwallet_coordinator_object_id,
            signer.dwallet_cap_id,
            signature_algorithm,
            hash_scheme,
            message,
            message_centralized_signature,
            presign.presign_cap_id,
            session_identifier_bytes.to_vec(),
            coins,
            DEFAULT_DWALLET_TX_GAS_BUDGET,
            true,
        )
        .await
        .context("request_sign_tx failed")?;
        self.wait_for_sign_session(&response, timeout).await
    }

    /// Future-sign, step 1: pre-commit the user's signature share for
    /// `message` against a completed presign. Returns the partial-user-
    /// signature cap consumed by [`Self::future_sign_fulfill`].
    pub async fn future_sign(
        &mut self,
        signer: &DwalletSigner<'_>,
        presign: &PresignHandle,
        presign_bytes: Vec<u8>,
        network_dkg_public_output: Vec<u8>,
        message: Vec<u8>,
        signature_algorithm: u32,
        hash_scheme: u32,
    ) -> Result<ObjectID> {
        let protocol_pp =
            network_dkg_public_output_to_protocol_pp_inner(signer.curve, network_dkg_public_output)
                .map_err(|e| anyhow!("network_dkg_public_output_to_protocol_pp_inner: {e}"))?;
        let dwallet_public_output = self.dwallet_public_output(signer.dwallet_id).await?;
        let message_centralized_signature = advance_centralized_sign_party(
            protocol_pp,
            dwallet_public_output,
            signer.user_secret_key_share.to_vec(),
            presign_bytes,
            message.clone(),
            signer.curve,
            signature_algorithm,
            hash_scheme,
        )
        .map_err(|e| anyhow!("advance_centralized_sign_party: {e}"))?;

        let session_identifier_bytes: [u8; 32] = rand::random();
        let coins = self.payment_coins();
        let response = request_future_sign_tx(
            self.test_cluster.wallet_mut(),
            self.packages.ika_dwallet_2pc_mpc_package_id,
            self.system.ika_dwallet_coordinator_object_id,
            signer.dwallet_id,
            presign.presign_cap_id,
            message,
            hash_scheme,
            message_centralized_signature,
            session_identifier_bytes.to_vec(),
            coins,
            DEFAULT_DWALLET_TX_GAS_BUDGET,
            true,
        )
        .await
        .context("request_future_sign_tx failed")?;
        find_created_object_by_type(&self.sui_rpc_url, &response, "PartialUserSignatureCap").await
    }

    /// Waits until every user-initiated session the coordinator has
    /// started is completed on-chain (`user_sessions_keeper` started ==
    /// completed), reading the coordinator via BCS (immune to the JSON
    /// enum-rendering quirk). In a single-actor test this is both the
    /// end-of-flow invariant (no session silently lost) and the barrier
    /// for waits whose target state is a fieldless enum variant and thus
    /// unobservable through object JSON — e.g. the future-sign partial
    /// signature's `NetworkVerificationCompleted`.
    pub async fn wait_for_user_sessions_drained(&self, timeout: std::time::Duration) -> Result<()> {
        let sui_client = self.sui_connector_client().await?;
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let (_, inner) = sui_client.must_get_dwallet_coordinator_inner().await;
            let ika_types::sui::DWalletCoordinatorInner::V1(inner) = inner;
            let started = inner
                .sessions_manager
                .user_sessions_keeper
                .started_sessions_count;
            let completed = inner
                .sessions_manager
                .user_sessions_keeper
                .completed_sessions_count;
            if started == completed {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                anyhow::bail!(
                    "user sessions never drained within {timeout:?}: \
                     started={started} completed={completed}"
                );
            }
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
    }

    /// Future-sign, step 2: fulfill the pre-committed signature for the
    /// same message and wait for the network signature. The fulfill
    /// transaction aborts on-chain while the partial signature is still
    /// awaiting network verification (a fieldless state, unobservable
    /// through object JSON), so pending verification is handled by
    /// retrying the transaction until it lands.
    pub async fn future_sign_fulfill(
        &mut self,
        signer: &DwalletSigner<'_>,
        partial_user_signature_cap_id: ObjectID,
        message: Vec<u8>,
        signature_algorithm: u32,
        hash_scheme: u32,
        timeout: std::time::Duration,
    ) -> Result<Vec<u8>> {
        let deadline = tokio::time::Instant::now() + timeout;
        let response = loop {
            let session_identifier_bytes: [u8; 32] = rand::random();
            let coins = self.payment_coins();
            match request_future_sign_fulfill_tx(
                self.test_cluster.wallet_mut(),
                self.packages.ika_dwallet_2pc_mpc_package_id,
                self.system.ika_dwallet_coordinator_object_id,
                partial_user_signature_cap_id,
                signer.dwallet_cap_id,
                signature_algorithm,
                hash_scheme,
                message.clone(),
                session_identifier_bytes.to_vec(),
                coins,
                DEFAULT_DWALLET_TX_GAS_BUDGET,
            )
            .await
            {
                Ok(response) => break response,
                Err(e) => {
                    if tokio::time::Instant::now() >= deadline {
                        return Err(e).context(
                            "request_future_sign_fulfill_tx kept failing until the deadline",
                        );
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                }
            }
        };
        self.wait_for_sign_session(&response, timeout).await
    }

    /// Creates an imported-key dwallet from a freshly sampled secp256k1
    /// keypair, waits for network verification, and accepts the encrypted
    /// share (signing the on-chain public output with the user's Ed25519
    /// key) — after which the dwallet is Active and signable. The secret
    /// is sampled internally because the centralized step consumes a
    /// BCS-encoded curve scalar, and `sample_dwallet_keypair_inner` is the
    /// only sampler with that encoding (secp256k1-only, hence the guard).
    pub async fn import_key_dwallet(
        &mut self,
        network_key_id: ObjectID,
        network_dkg_public_output: Vec<u8>,
        user_key: &UserEncryptionKey,
        timeout: std::time::Duration,
    ) -> Result<ImportedKeyHandle> {
        let curve = user_key.curve;
        anyhow::ensure!(
            curve == 0,
            "import_key_dwallet samples secp256k1 keys only (curve 0), got curve {curve}"
        );
        let protocol_pp =
            network_dkg_public_output_to_protocol_pp_inner(curve, network_dkg_public_output)
                .map_err(|e| anyhow!("network_dkg_public_output_to_protocol_pp_inner: {e}"))?;
        let (secret_key, _public_key) = sample_dwallet_keypair_inner(protocol_pp.clone())
            .map_err(|e| anyhow!("sample_dwallet_keypair_inner: {e}"))?;

        let session_id_random_bytes: [u8; 32] = rand::random();
        let sender = self.publisher_address;
        let preimage = crate::on_chain_session_preimage(&sender, &session_id_random_bytes);
        let session_id = SessionIdentifier::new(SessionType::User, preimage).to_vec();

        let (user_secret_share, user_public_output, centralized_party_message) =
            create_imported_dwallet_centralized_step_inner_v2(
                curve,
                &protocol_pp,
                &session_id,
                &secret_key,
            )
            .map_err(|e| anyhow!("create_imported_dwallet_centralized_step_inner_v2: {e}"))?;
        let encrypted_secret_share = encrypt_secret_key_share_and_prove_v2(
            curve,
            user_secret_share.clone(),
            user_key.encryption_key.clone(),
            protocol_pp,
        )
        .map_err(|e| anyhow!("encrypt_secret_key_share_and_prove_v2: {e}"))?;

        let coins = self.payment_coins();
        let response = ika_dwallet_transactions::request_imported_key_dwallet_verification(
            self.test_cluster.wallet_mut(),
            self.packages.ika_dwallet_2pc_mpc_package_id,
            self.system.ika_dwallet_coordinator_object_id,
            network_key_id,
            curve,
            centralized_party_message,
            encrypted_secret_share,
            user_key.encryption_key_address,
            user_public_output,
            user_key.signer_public_key.clone(),
            session_id_random_bytes.to_vec(),
            coins,
            DEFAULT_DWALLET_TX_GAS_BUDGET,
        )
        .await
        .context("request_imported_key_dwallet_verification failed")?;

        let digest = *response
            .effects
            .as_ref()
            .ok_or_else(|| anyhow!("import verification tx has no effects"))?
            .transaction_digest();
        let event = "DWalletImportedKeyVerificationRequestEvent";
        let dwallet_id: ObjectID =
            fetch_event_field(&self.sui_rpc_url, &digest, event, "dwallet_id")
                .await
                .ok_or_else(|| anyhow!("{event} missing dwallet_id"))?
                .parse()?;
        let dwallet_cap_id: ObjectID =
            fetch_event_field(&self.sui_rpc_url, &digest, event, "dwallet_cap_id")
                .await
                .ok_or_else(|| anyhow!("{event} missing dwallet_cap_id"))?
                .parse()?;
        let encrypted_share_id: ObjectID = fetch_event_field(
            &self.sui_rpc_url,
            &digest,
            event,
            "encrypted_user_secret_key_share_id",
        )
        .await
        .ok_or_else(|| anyhow!("{event} missing encrypted_user_secret_key_share_id"))?
        .parse()?;

        self.wait_for_dwallet_dkg_complete(dwallet_id, timeout)
            .await
            .context("imported-key verification never completed")?;
        self.accept_encrypted_share(dwallet_id, encrypted_share_id, user_key, timeout)
            .await?;

        Ok(ImportedKeyHandle {
            dwallet_id,
            dwallet_cap_id,
            user_secret_key_share: user_secret_share,
            curve,
        })
    }

    /// Publishes the user's secret share on-chain, making the dwallet
    /// share-public (trustless signing without the user round-trip).
    pub async fn make_share_public(&mut self, signer: &DwalletSigner<'_>) -> Result<()> {
        let session_identifier_bytes: [u8; 32] = rand::random();
        let coins = self.payment_coins();
        ika_dwallet_transactions::request_make_shares_public(
            self.test_cluster.wallet_mut(),
            self.packages.ika_dwallet_2pc_mpc_package_id,
            self.system.ika_dwallet_coordinator_object_id,
            signer.dwallet_id,
            signer.user_secret_key_share.to_vec(),
            session_identifier_bytes.to_vec(),
            coins,
            DEFAULT_DWALLET_TX_GAS_BUDGET,
        )
        .await
        .context("request_make_shares_public failed")?;
        Ok(())
    }

    /// Waits until the dwallet's on-chain state carries the public user
    /// share (make-share-public completed network-side).
    pub async fn wait_for_public_share(
        &self,
        dwallet_id: ObjectID,
        timeout: std::time::Duration,
    ) -> Result<()> {
        let client = sdk_client(&self.sui_rpc_url).await?;
        let start = tokio::time::Instant::now();
        loop {
            if start.elapsed() > timeout {
                anyhow::bail!("timeout waiting for dwallet {dwallet_id} public share");
            }
            if let Ok(fields) = fetch_object_fields(&client, dwallet_id).await {
                let has_public_share = fields
                    .get("public_user_secret_key_share")
                    .map(|v| !v.is_null())
                    .unwrap_or(false);
                if has_public_share {
                    return Ok(());
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    }

    /// Transfers (re-encrypts) the user share of `dkg` to `destination`,
    /// waits for the network to verify the new encrypted share, and
    /// accepts it with the destination's key — after which both keys hold
    /// a share of the same dwallet.
    pub async fn transfer_share(
        &mut self,
        dkg: &DwalletDkgHandle,
        network_dkg_public_output: Vec<u8>,
        destination: &UserEncryptionKey,
        timeout: std::time::Duration,
    ) -> Result<ObjectID> {
        let protocol_pp =
            network_dkg_public_output_to_protocol_pp_inner(dkg.curve, network_dkg_public_output)
                .map_err(|e| anyhow!("network_dkg_public_output_to_protocol_pp_inner: {e}"))?;
        let encrypted_for_destination = encrypt_secret_key_share_and_prove_v2(
            dkg.curve,
            dkg.user_secret_key_share.clone(),
            destination.encryption_key.clone(),
            protocol_pp,
        )
        .map_err(|e| anyhow!("encrypt_secret_key_share_and_prove_v2: {e}"))?;

        let source_share_id = dkg
            .encrypted_user_secret_key_share_id
            .ok_or_else(|| anyhow!("DKG handle carries no encrypted share id — cannot transfer"))?;
        let session_identifier_bytes: [u8; 32] = rand::random();
        let coins = self.payment_coins();
        let response = ika_dwallet_transactions::request_re_encrypt_user_share(
            self.test_cluster.wallet_mut(),
            self.packages.ika_dwallet_2pc_mpc_package_id,
            self.system.ika_dwallet_coordinator_object_id,
            dkg.dwallet_id,
            destination.encryption_key_address,
            encrypted_for_destination,
            source_share_id,
            session_identifier_bytes.to_vec(),
            coins,
            DEFAULT_DWALLET_TX_GAS_BUDGET,
        )
        .await
        .context("request_re_encrypt_user_share failed")?;

        let digest = *response
            .effects
            .as_ref()
            .ok_or_else(|| anyhow!("re-encrypt tx has no effects"))?
            .transaction_digest();
        let new_share_id: ObjectID = fetch_event_field(
            &self.sui_rpc_url,
            &digest,
            "EncryptedShareVerificationRequestEvent",
            "encrypted_user_secret_key_share_id",
        )
        .await
        .ok_or_else(|| anyhow!("re-encrypt event missing encrypted_user_secret_key_share_id"))?
        .parse()?;

        // The network verifies the re-encrypted share asynchronously; the
        // verified state is a fieldless enum variant (unobservable through
        // object JSON), so pending verification is handled inside
        // `accept_encrypted_share`, which retries the acceptance
        // transaction until it stops aborting.
        self.accept_encrypted_share(dkg.dwallet_id, new_share_id, destination, timeout)
            .await?;
        Ok(new_share_id)
    }

    /// Accepts the DKG-created encrypted user share, activating the
    /// dwallet (`AwaitingKeyHolderSignature` -> `Active`) — signing
    /// requires an Active dwallet.
    pub async fn accept_dwallet_share(
        &mut self,
        dkg: &DwalletDkgHandle,
        user_key: &UserEncryptionKey,
    ) -> Result<()> {
        let share_id = dkg
            .encrypted_user_secret_key_share_id
            .ok_or_else(|| anyhow!("DKG handle carries no encrypted share id — cannot accept"))?;
        self.accept_encrypted_share(
            dkg.dwallet_id,
            share_id,
            user_key,
            std::time::Duration::from_secs(120),
        )
        .await
    }

    /// Signs the dwallet's on-chain public output with the key-holder's
    /// Ed25519 key and accepts the encrypted share (imported-key and
    /// transfer-destination finalization). Acceptance aborts on-chain
    /// while the share still awaits network verification, so the
    /// transaction is retried until it lands or the deadline passes.
    async fn accept_encrypted_share(
        &mut self,
        dwallet_id: ObjectID,
        encrypted_share_id: ObjectID,
        key_holder: &UserEncryptionKey,
        timeout: std::time::Duration,
    ) -> Result<()> {
        let public_output = self.dwallet_public_output(dwallet_id).await?;
        let signature: fastcrypto::ed25519::Ed25519Signature =
            key_holder.signing_keypair.sign(&public_output);
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            match ika_dwallet_transactions::accept_encrypted_user_share(
                self.test_cluster.wallet_mut(),
                self.packages.ika_dwallet_2pc_mpc_package_id,
                self.system.ika_dwallet_coordinator_object_id,
                dwallet_id,
                encrypted_share_id,
                signature.as_ref().to_vec(),
                DEFAULT_DWALLET_TX_GAS_BUDGET,
            )
            .await
            {
                Ok(_) => return Ok(()),
                Err(e) => {
                    if tokio::time::Instant::now() >= deadline {
                        return Err(e).context(
                            "accept_encrypted_user_share kept failing until the deadline",
                        );
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                }
            }
        }
    }

    /// Waits for the sign session created by `response` (any of the sign
    /// request forms) to complete, returning the network signature bytes.
    ///
    /// Polls the `SignSession` object behind the event's `sign_id` — NOT
    /// the wrapper's `session_object_id`, which names the bookkeeping
    /// `DWalletSession` object that Move deletes on completion (polling it
    /// reads "object not found" precisely when the sign succeeds).
    async fn wait_for_sign_session(
        &self,
        response: &sui_json_rpc_types::SuiTransactionBlockResponse,
        timeout: std::time::Duration,
    ) -> Result<Vec<u8>> {
        let digest = *response
            .effects
            .as_ref()
            .ok_or_else(|| anyhow!("sign tx has no effects"))?
            .transaction_digest();
        let sign_id: ObjectID =
            fetch_event_field(&self.sui_rpc_url, &digest, "SignRequestEvent", "sign_id")
                .await
                .ok_or_else(|| anyhow!("SignRequestEvent missing sign_id"))?
                .parse()?;
        poll_session_until_completed(&self.sui_rpc_url, sign_id, "signature", timeout).await
    }
}

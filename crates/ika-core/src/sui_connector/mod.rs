// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::dwallet_checkpoints::DWalletCheckpointStore;
use crate::dwallet_session_request::DWalletSessionRequest;
use crate::sui_connector::bag_event_pump::BagEventPump;
use crate::sui_connector::metrics::SuiConnectorMetrics;
use crate::sui_connector::sui_executor::{StopReason, SuiExecutor};
use crate::sui_connector::sui_syncer::SuiSyncer;
use crate::sui_connector::verified_reader::OcsVerifiedReader;
use crate::system_checkpoints::SystemCheckpointStore;
use anyhow::anyhow;
use async_trait::async_trait;
use ika_config::node::{NodeMode, RunWithRange, SuiChainIdentifier, SuiConnectorConfig};
use ika_sui_client::{SuiBackend, SuiClient, SuiClientInner};
use ika_types::committee::{Committee, CommitteeMembership, EpochId};
use ika_types::error::IkaResult;
use ika_types::messages_consensus::MovePackageDigest;
use ika_types::messages_dwallet_mpc::DWalletNetworkEncryptionKeyData;
use ika_types::sui::{
    DWalletCoordinator, DWalletCoordinatorInner, System, SystemInner, SystemInnerTrait,
};
use move_core_types::ident_str;
use shared_crypto::intent::{Intent, IntentMessage};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use sui_types::SUI_FRAMEWORK_PACKAGE_ID;
use sui_types::base_types::{ObjectID, ObjectRef, SuiAddress};
use sui_types::crypto::{Signature, SuiKeyPair};
use sui_types::digests::{
    ChainIdentifier as SuiNetworkChainIdentifier, get_mainnet_chain_identifier,
    get_testnet_chain_identifier,
};
use sui_types::effects::TransactionEffectsAPI;
use sui_types::execution_status::ExecutionStatus;
use sui_types::gas_coin::GAS;
use sui_types::programmable_transaction_builder::ProgrammableTransactionBuilder;
use sui_types::transaction::{
    Argument, Command, GasData, ProgrammableTransaction, Transaction, TransactionData,
    TransactionDataV1, TransactionExpiration, TransactionKind,
};
use tokio::sync::watch;
use tokio::sync::watch::{Receiver, Sender};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

pub mod bag_event_pump;
pub mod changeset_receiver;
pub mod committee_follower;
pub mod committee_store;
pub mod fallback_transport;
pub mod metrics;
pub mod ocs_currency;
pub mod ocs_metrics;
pub mod ocs_verifier;
pub mod pubkey_provider_updater;
pub mod push_worker;
pub mod retained_transport;
pub mod setup;
mod sui_event_into_request;
pub mod sui_executor;
pub mod sui_syncer;
pub mod trusted_peer_updater;
pub mod verified_reader;
pub mod verified_state_cache;
pub mod verified_transport;

pub struct SuiNotifier {
    sui_key: SuiKeyPair,
    sui_address: SuiAddress,
    /// The chain's full genesis-rooted identifier, resolved once at boot.
    /// `ValidDuring` embeds it and validators compare the full identifier.
    sui_network_chain_identifier: SuiNetworkChainIdentifier,
}

impl SuiNotifier {
    pub(crate) fn sui_address(&self) -> SuiAddress {
        self.sui_address
    }
}

pub struct SuiConnectorService {
    sui_client: Arc<SuiClient<SuiBackend>>,
    sui_executor: SuiExecutor<SuiBackend>,
    network_keys_receiver: Receiver<Arc<HashMap<ObjectID, DWalletNetworkEncryptionKeyData>>>,
    // todo(zeev): this needs a refactor.
    #[allow(dead_code)]
    task_handles: Vec<JoinHandle<()>>,
    /// Late-bindable handle the network-keys sync task reads on each
    /// fetch. Lets ika-node install (and replace, per epoch) the
    /// off-chain `NetworkKeyBlobSource` used to overlay locally-
    /// cached DKG/reconfig output blobs onto the chain copy. `None`
    /// here disables the overlay; chain bytes flow through unchanged.
    network_key_blob_source:
        Arc<arc_swap::ArcSwapOption<Box<dyn crate::validator_metadata::NetworkKeyBlobSource>>>,
    /// Late-bindable off-chain validator-mpc_data assembler. When
    /// installed and `Complete` for the next-epoch committee,
    /// `sync_next_committee` builds the `Committee` from this
    /// instead of from the on-chain mpc_data. `Incomplete` /
    /// `None` paths fall through to the existing chain-read.
    off_chain_mpc_data_source: Arc<
        arc_swap::ArcSwapOption<Box<dyn crate::validator_metadata::OffChainCommitteeMpcDataSource>>,
    >,
}

impl SuiConnectorService {
    pub async fn new(
        checkpoint_store: Arc<DWalletCheckpointStore>,
        system_checkpoint_store: Arc<SystemCheckpointStore>,
        sui_client: Arc<SuiClient<SuiBackend>>,
        sui_connector_config: SuiConnectorConfig,
        sui_connector_metrics: Arc<SuiConnectorMetrics>,
        mode: NodeMode,
        next_epoch_committee_sender: Sender<Committee>,
        chain_next_committee_sender: Sender<CommitteeMembership>,
        current_epoch_mpc_keys_sender: Sender<
            Option<(EpochId, crate::validator_metadata::OffChainCommitteeBundles)>,
        >,
        next_epoch_mpc_keys_sender: Sender<
            Option<(EpochId, crate::validator_metadata::OffChainCommitteeBundles)>,
        >,
        new_requests_sender: tokio::sync::broadcast::Sender<Vec<DWalletSessionRequest>>,
        end_of_publish_sender: Sender<Option<u64>>,
        last_session_to_complete_in_current_epoch_sender: Sender<(EpochId, u64)>,
        uncompleted_requests_sender: Sender<(Vec<DWalletSessionRequest>, EpochId)>,
        noa_checkpoints_finalized: Arc<dyn Fn() -> bool + Send + Sync>,
        // Shared set of network keys the MPC manager flagged as stranded by a
        // mid-epoch restart. Created once at the node seam and shared with the
        // MPC manager (the writer); the network-keys sync task reads it to
        // decide, per key, whether to serve the off-chain reconfiguration
        // output (healthy) or source the current-epoch output from chain
        // (stranded recovery).
        stranded_network_keys: Arc<arc_swap::ArcSwap<HashSet<ObjectID>>>,
        // OCS verified-read surface. Validators require it for BagEventPump;
        // notifier/fullnode roles may omit it because they run no MPC sessions.
        reader: Option<Arc<OcsVerifiedReader>>,
        ocs_metrics: Arc<crate::sui_connector::ocs_metrics::OcsMetrics>,
        // Feed of the chain's processed checkpoint cursors into p2p state
        // sync (its pull-mode sync floor; `None` until the first successful
        // chain read). Created in ika-node because state sync is built
        // before this service; this service is the writer.
        on_chain_dwallet_checkpoint_cursor_sender: watch::Sender<Option<u64>>,
        on_chain_system_checkpoint_cursor_sender: watch::Sender<Option<u64>>,
    ) -> anyhow::Result<(
        Arc<Self>,
        watch::Receiver<Arc<HashMap<ObjectID, DWalletNetworkEncryptionKeyData>>>,
    )> {
        let (network_keys_sender, network_keys_receiver) = watch::channel(Default::default());
        let (system_object_sender, system_object_receiver) = watch::channel(Default::default());
        let (dwallet_coordinator_object_sender, dwallet_coordinator_receiver) =
            watch::channel(Default::default());

        tokio::spawn(Self::forward_on_chain_checkpoint_cursors(
            system_object_receiver.clone(),
            dwallet_coordinator_receiver.clone(),
            on_chain_dwallet_checkpoint_cursor_sender,
            on_chain_system_checkpoint_cursor_sender,
        ));

        let sui_notifier = Self::prepare_for_sui(
            sui_connector_config.clone(),
            sui_client.clone(),
            sui_connector_metrics.clone(),
        )
        .await?;

        let sui_executor = SuiExecutor::new(
            system_object_sender,
            dwallet_coordinator_object_sender,
            checkpoint_store.clone(),
            system_checkpoint_store.clone(),
            sui_notifier,
            sui_client.clone(),
            reader.clone(),
            sui_connector_metrics.clone(),
        );

        let network_key_blob_source: Arc<
            arc_swap::ArcSwapOption<Box<dyn crate::validator_metadata::NetworkKeyBlobSource>>,
        > = Arc::new(arc_swap::ArcSwapOption::empty());
        let off_chain_mpc_data_source: Arc<
            arc_swap::ArcSwapOption<
                Box<dyn crate::validator_metadata::OffChainCommitteeMpcDataSource>,
            >,
        > = Arc::new(arc_swap::ArcSwapOption::empty());

        let task_handles = SuiSyncer::new(sui_client.clone(), sui_connector_metrics.clone())
            .run(
                next_epoch_committee_sender,
                chain_next_committee_sender,
                current_epoch_mpc_keys_sender,
                next_epoch_mpc_keys_sender,
                mode,
                system_object_receiver,
                dwallet_coordinator_receiver.clone(),
                network_keys_sender,
                end_of_publish_sender,
                checkpoint_store,
                last_session_to_complete_in_current_epoch_sender,
                noa_checkpoints_finalized,
                network_key_blob_source.clone(),
                stranded_network_keys,
                off_chain_mpc_data_source.clone(),
            )
            .await
            .map_err(|e| anyhow::anyhow!("Failed to start sui syncer: {e}"))?;

        // Validators feed the MPC engine from the OCS-verified bag walker.
        // Fullnodes/notifiers run no MPC sessions and do not need the pump.
        if mode.is_validator() {
            let reader = reader.ok_or_else(|| {
                anyhow!("Validator requires OcsVerifiedReader for MPC event ingestion")
            })?;
            let pump = BagEventPump::new(
                reader,
                sui_client.ika_network_config.clone(),
                dwallet_coordinator_receiver,
                new_requests_sender,
                uncompleted_requests_sender,
                ocs_metrics,
                sui_connector_metrics.clone(),
                // 50 ms tick. Bandwidth dropped ~3 orders of magnitude when
                // we moved from full-checkpoint shipping to inclusion proofs,
                // so the relay can absorb 20 Hz polling cleanly. Drives MPC
                // session-start latency down from ~1 s to ~50 ms worst-case.
                Duration::from_millis(50),
            );
            tokio::spawn(pump.run());
        } else {
            drop((new_requests_sender, uncompleted_requests_sender));
        }

        Ok((
            Arc::new(Self {
                sui_client,
                sui_executor,
                network_keys_receiver: network_keys_receiver.clone(),
                task_handles,
                network_key_blob_source,
                off_chain_mpc_data_source,
            }),
            network_keys_receiver,
        ))
    }

    /// Installs the off-chain `NetworkKeyBlobSource` the network-
    /// keys sync task uses to overlay cached DKG / reconfig output
    /// blobs onto the chain copy. Called once per epoch by ika-node
    /// after the per-epoch store is up.
    pub fn install_network_key_blob_source(
        &self,
        source: Box<dyn crate::validator_metadata::NetworkKeyBlobSource>,
    ) {
        self.network_key_blob_source.store(Some(Arc::new(source)));
    }

    /// Installs the off-chain validator-mpc_data assembler the
    /// next-committee sync uses before falling back to the chain
    /// `get_mpc_data_from_validators_pool` path.
    pub fn install_mpc_data_source(
        &self,
        source: Box<dyn crate::validator_metadata::OffChainCommitteeMpcDataSource>,
    ) {
        self.off_chain_mpc_data_source.store(Some(Arc::new(source)));
    }

    pub async fn run_epoch(
        &self,
        epoch_id: EpochId,
        run_with_range: Option<RunWithRange>,
    ) -> StopReason {
        self.sui_executor
            .run_epoch(epoch_id, run_with_range, self.network_keys_receiver.clone())
            .await
    }

    /// Forward the chain's processed checkpoint cursors — the coordinator's
    /// and system object's `last_processed_checkpoint_sequence_number` — into
    /// the watch channels p2p state sync uses as its pull-mode sync floor.
    /// Values only move forward: a stale read (e.g. a lagging fullnode view)
    /// must never drag the floor backwards.
    async fn forward_on_chain_checkpoint_cursors(
        mut system_object_receiver: Receiver<Option<(System, SystemInner)>>,
        mut dwallet_coordinator_receiver: Receiver<
            Option<(DWalletCoordinator, DWalletCoordinatorInner)>,
        >,
        dwallet_cursor_sender: watch::Sender<Option<u64>>,
        system_cursor_sender: watch::Sender<Option<u64>>,
    ) {
        loop {
            tokio::select! {
                changed = dwallet_coordinator_receiver.changed() => {
                    if changed.is_err() {
                        return;
                    }
                    let cursor = dwallet_coordinator_receiver.borrow_and_update().as_ref().map(
                        |(_, inner)| {
                            let DWalletCoordinatorInner::V1(inner) = inner;
                            inner.last_processed_checkpoint_sequence_number
                        },
                    );
                    if let Some(cursor) = cursor {
                        let advanced = Some(cursor) > *dwallet_cursor_sender.borrow();
                        if advanced {
                            // First reading at info (the cold-start unblock signal);
                            // steady-state advances at debug — one per processed
                            // checkpoint, far too chatty for info.
                            if dwallet_cursor_sender.borrow().is_none() {
                                info!(
                                    cursor,
                                    "on-chain dwallet checkpoint cursor known (state-sync floor active)"
                                );
                            } else {
                                debug!(cursor, "on-chain dwallet checkpoint cursor advanced");
                            }
                            if dwallet_cursor_sender.send(Some(cursor)).is_err() {
                                return;
                            }
                        }
                    }
                }
                changed = system_object_receiver.changed() => {
                    if changed.is_err() {
                        return;
                    }
                    let cursor = system_object_receiver
                        .borrow_and_update()
                        .as_ref()
                        .map(|(_, inner)| inner.last_processed_checkpoint_sequence_number());
                    if let Some(cursor) = cursor {
                        let advanced = Some(cursor) > *system_cursor_sender.borrow();
                        if advanced && system_cursor_sender.send(Some(cursor)).is_err() {
                            return;
                        }
                    }
                }
            }
        }
    }

    async fn prepare_for_sui(
        sui_connector_config: SuiConnectorConfig,
        sui_client: Arc<SuiClient<SuiBackend>>,
        sui_connector_metrics: Arc<SuiConnectorMetrics>,
    ) -> anyhow::Result<Option<SuiNotifier>> {
        let Some(sui_key_path) = sui_connector_config.notifier_client_key_pair else {
            return Ok(None);
        };

        let sui_key = sui_key_path.keypair().copy();

        // If sui chain id is Mainnet or Testnet, we expect to see chain
        // identifier to match accordingly.
        let sui_identifier = sui_client
            .get_chain_identifier()
            .await
            .map_err(|e| anyhow!("Error getting chain identifier from Sui: {:?}", e))?;

        if sui_connector_config.sui_chain_identifier == SuiChainIdentifier::Mainnet
            && sui_identifier != get_mainnet_chain_identifier().to_string()
        {
            anyhow::bail!(
                "Expected the sui chain {}, but connected to {}",
                sui_connector_config.sui_chain_identifier,
                sui_identifier
            );
        }
        if sui_connector_config.sui_chain_identifier == SuiChainIdentifier::Testnet
            && sui_identifier != get_testnet_chain_identifier().to_string()
        {
            anyhow::bail!(
                "Expected the sui chain {}, but connected to {}",
                sui_connector_config.sui_chain_identifier,
                sui_identifier
            );
        }
        info!(
            "Connected sui chain {}, sui identifier: {}",
            sui_connector_config.sui_chain_identifier, sui_identifier
        );

        let sui_address = SuiAddress::from(&sui_key.public());

        // Resolve the chain's FULL identifier once
        // (a `ValidDuring` expiration embeds it verbatim). Fail the boot
        // loudly if it can't be resolved — a writer silently unable to build
        // transactions is exactly the failure shape issue #1892 is about.
        let sui_network_chain_identifier =
            sui_client.get_sui_chain_identifier().await.map_err(|e| {
                anyhow!(
                    "the chain identifier could not be resolved (required for ValidDuring \
                     expirations): {e}"
                )
            })?;

        // Preflight the ADDRESS BALANCE (not coin objects — plain coin
        // transfers don't fund it). An underfunded balance would
        // otherwise surface as an hour of failed submissions followed by
        // a panic, with the network's epoch close blocked the whole time
        // — the issue-#1892 outage shape. Refuse to boot with the exact
        // remediation instead: a writer that cannot pay must not run.
        let funds = sui_client.get_sui_funds(sui_address).await.map_err(|e| {
            anyhow!(
                "the funds of {sui_address} could not be read (does the target Sui network \
                 have accumulators/address-balance gas enabled?): {e}"
            )
        })?;

        // Migration sweep: an existing notifier may still hold its funds as
        // coin objects, which address-balance gas cannot spend. Deposit them
        // into the address balance automatically (split off the sweep tx's
        // own gas, then `coin::send_funds`). Best-effort: a failed sweep only warns —
        // the preflight below still decides whether the writer can run.
        let mut address_balance = funds.in_address_balance;
        if funds.in_coin_objects >= SWEEP_MIN_COIN_TOTAL {
            match sweep_gas_coins_into_address_balance(
                &sui_client,
                &sui_key,
                sui_address,
                funds.in_coin_objects,
            )
            .await
            {
                Ok(swept) => {
                    info!(
                        swept,
                        "Swept gas-coin objects into the notifier's address balance"
                    );
                    // Count the swept funds directly instead of re-reading:
                    // the read goes through a fullnode view that can lag
                    // the just-finalized sweep and would flunk the
                    // preflight spuriously.
                    address_balance = address_balance.saturating_add(swept);
                }
                Err(e) => warn!(
                    error = ?e,
                    in_coin_objects = funds.in_coin_objects,
                    "failed to sweep gas coins into the address balance; \
                     continuing to the balance preflight without them"
                ),
            }
        }
        if address_balance < NOTIFIER_GAS_BUDGET {
            anyhow::bail!(
                "{sui_address} holds only {address_balance} MIST in its ADDRESS BALANCE — \
                 below one gas budget ({} MIST). Deposit SUI into the address balance; \
                 coin-object transfers do not fund it.",
                NOTIFIER_GAS_BUDGET,
            );
        }
        sui_connector_metrics
            .gas_coin_balance
            .set(i64::try_from(address_balance).unwrap_or(i64::MAX));
        info!(
            ?sui_network_chain_identifier,
            address_balance, "Notifier pays gas from its SUI address balance (SIP-58)"
        );

        // Keep the writer-funds gauge live by refreshing the address balance
        // once a minute. Funds exhaustion is otherwise invisible until
        // submissions start failing, so the gauge is the alert surface for
        // topping up the balance.
        let balance_sui_client = sui_client.clone();
        let balance_metrics = sui_connector_metrics.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                if let Ok(funds) = balance_sui_client.get_sui_funds(sui_address).await {
                    balance_metrics
                        .gas_coin_balance
                        .set(i64::try_from(funds.in_address_balance).unwrap_or(i64::MAX));
                }
            }
        });

        Ok(Some(SuiNotifier {
            sui_key,
            sui_address,
            sui_network_chain_identifier,
        }))
    }

    pub async fn get_available_move_packages(
        &self,
    ) -> anyhow::Result<Vec<(ObjectID, MovePackageDigest)>> {
        self.sui_client
            .get_available_move_packages()
            .await
            .map_err(|e| anyhow!("Cannot get available move packages: {:?}", e))
    }
}

#[async_trait]
pub trait CheckpointMessageSuiNotify: Sync + Send + 'static {
    async fn notify_certified_checkpoint_message(
        &self,
        signature: Vec<u8>,
        signers: Vec<u16>,
        message: Vec<u8>,
    ) -> IkaResult;
}

#[async_trait]
impl CheckpointMessageSuiNotify for SuiConnectorService {
    async fn notify_certified_checkpoint_message(
        &self,
        _signature: Vec<u8>,
        _signers: Vec<u16>,
        _message: Vec<u8>,
    ) -> IkaResult {
        Ok(())
    }
}

/// Gas budget for the one-shot boot sweep that deposits coin objects into
/// the address balance. The unswept remainder (this budget minus actual
/// fees) is left behind as a small coin.
const SWEEP_GAS_BUDGET: u64 = 200_000_000;

/// Don't bother sweeping coin totals below this (1 SUI): repeatedly
/// re-depositing sweep-fee dust on every boot is churn, not funding.
const SWEEP_MIN_COIN_TOTAL: u64 = 1_000_000_000;

/// A sweep pays gas with the very coins it sweeps; Sui caps gas payments at
/// 256 objects per transaction.
const SWEEP_MAX_GAS_COINS: usize = 256;

/// Deposit the notifier's gas-coin objects into its SIP-58 address balance.
/// Returns the amount deposited (MIST). The sweep transaction uses ALL owned
/// gas coins as its own gas payment (Sui merges them into the first), splits
/// off everything above the sweep's own gas budget, and deposits the split
/// via `coin::send_funds` — the gas coin itself cannot be passed by value to
/// a Move call, hence split-then-deposit rather than depositing the coin.
async fn sweep_gas_coins_into_address_balance<C: SuiClientInner>(
    sui_client: &Arc<SuiClient<C>>,
    sui_key: &SuiKeyPair,
    sui_address: SuiAddress,
    coin_total: u64,
) -> anyhow::Result<u64> {
    let gas_coins = sui_client.get_gas_objects(sui_address).await;
    if gas_coins.is_empty() {
        anyhow::bail!("coin balance is {coin_total} MIST but no gas-coin objects were listed");
    }
    if gas_coins.len() >= SWEEP_MAX_GAS_COINS {
        // The subset's value is unknown, so a correct split amount can't be
        // computed. This does not happen to a writer address in practice.
        //
        // `>=`, not `>`: the lister truncates at the same cap, so a returned
        // set of exactly this length may be a truncation of a larger holding.
        // `coin_total` still counts every coin, so proceeding would smash a
        // 256-coin payment while splitting the full balance, and the
        // SplitCoins would abort on chain instead of bailing here.
        anyhow::bail!(
            "{} gas coins exceed the {SWEEP_MAX_GAS_COINS}-object gas payment cap;              consolidate them manually",
            gas_coins.len()
        );
    }
    let sweep_amount = coin_total.saturating_sub(SWEEP_GAS_BUDGET);
    if sweep_amount == 0 {
        anyhow::bail!("coin balance {coin_total} MIST does not exceed the sweep gas budget");
    }
    let computation_price = sui_client.get_reference_gas_price_until_success().await;
    let tx_data = sweep_transaction_data(sui_address, gas_coins, sweep_amount, computation_price)?;
    let signature = Signature::new_secure(
        &IntentMessage::new(Intent::sui_transaction(), &tx_data),
        sui_key,
    );
    let transaction = Transaction::from_data(tx_data, vec![signature]);
    let response = sui_client
        .execute_transaction_block_with_effects(transaction)
        .await
        .map_err(|e| anyhow!("sweep submission failed: {e}"))?;
    if let ExecutionStatus::Failure(failure) = response.effects.status() {
        anyhow::bail!(
            "sweep transaction executed but aborted: {:?}",
            failure.error
        );
    }
    Ok(sweep_amount)
}

/// The sweep transaction: all owned gas coins as payment (merged into the
/// first by the protocol), `SplitCoins(GasCoin, [sweep_amount])`, and
/// `coin::send_funds<SUI>(split, sender)` to deposit into the sender's own
/// address balance. Ordinary gas-coin payment — the sweep exists precisely
/// because the address balance may be empty.
fn sweep_transaction_data(
    sender: SuiAddress,
    gas_coins: Vec<ObjectRef>,
    sweep_amount: u64,
    computation_price: u64,
) -> anyhow::Result<TransactionData> {
    let mut ptb = ProgrammableTransactionBuilder::new();
    let amount_arg = ptb.pure(sweep_amount)?;
    let deposit_coin = ptb.command(Command::SplitCoins(Argument::GasCoin, vec![amount_arg]));
    let recipient_arg = ptb.pure(sender)?;
    ptb.programmable_move_call(
        SUI_FRAMEWORK_PACKAGE_ID,
        ident_str!("coin").into(),
        ident_str!("send_funds").into(),
        vec![GAS::type_tag()],
        vec![deposit_coin, recipient_arg],
    );
    Ok(TransactionData::new_programmable(
        sender,
        gas_coins,
        ptb.finish(),
        SWEEP_GAS_BUDGET,
        computation_price,
    ))
}

/// The writer's fixed gas budget. Under address-balance gas the full budget
/// is reserved from the balance for the transaction's validity window, so the
/// balance must comfortably cover `budget x in-flight transactions` (the
/// writer submits serially: one).
const NOTIFIER_GAS_BUDGET: u64 = 10_000_000_000;

pub(crate) async fn build_sui_transaction<C: SuiClientInner>(
    sui_notifier: &SuiNotifier,
    pt: ProgrammableTransaction,
    sui_client: &Arc<SuiClient<C>>,
) -> Transaction {
    let computation_price = sui_client.get_reference_gas_price_until_success().await;
    let sui_epoch = sui_client.get_sui_epoch_until_success().await;
    let tx_data = balance_gas_transaction_data(
        sui_notifier.sui_address,
        pt,
        computation_price,
        sui_epoch,
        sui_notifier.sui_network_chain_identifier,
        rand::random(),
    );

    let signature = Signature::new_secure(
        &IntentMessage::new(Intent::sui_transaction(), &tx_data),
        &sui_notifier.sui_key,
    );

    Transaction::from_data(tx_data, vec![signature])
}

/// SIP-58 address-balance-gas transaction: an EMPTY gas payment is the
/// protocol-level trigger for paying from the sender's address balance, and
/// the `ValidDuring` expiration supplies the replay protection that gas-coin
/// version bumps used to provide. The window is `[current, current + 1]`:
/// a submission built just before a Sui epoch boundary stays valid into the
/// next epoch instead of expiring mid-flight and costing a rebuild-retry.
/// The one-epoch extension is the maximum `is_replay_protected` allows, and
/// multi-epoch expiration is enabled from Sui protocol 105 — strictly below
/// every network's address-balance-gas enablement, so wherever this
/// transaction is legal at all, the window is too. Cost: an abandoned
/// signed-but-never-executed transaction can hold its balance reservation
/// for up to two epochs instead of one (irrelevant to a serial writer with
/// normal float).
fn balance_gas_transaction_data(
    sender: SuiAddress,
    pt: ProgrammableTransaction,
    computation_price: u64,
    sui_epoch: u64,
    chain_identifier: SuiNetworkChainIdentifier,
    nonce: u32,
) -> TransactionData {
    TransactionData::V1(TransactionDataV1 {
        kind: TransactionKind::ProgrammableTransaction(pt),
        sender,
        gas_data: GasData {
            payment: vec![],
            owner: sender,
            price: computation_price,
            budget: NOTIFIER_GAS_BUDGET,
        },
        expiration: TransactionExpiration::ValidDuring {
            min_epoch: Some(sui_epoch),
            max_epoch: Some(sui_epoch.saturating_add(1)),
            min_timestamp: None,
            max_timestamp: None,
            chain: chain_identifier,
            nonce,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ika_sui_client::retry_with_max_elapsed_time;
    use std::time::Duration;
    use tracing::warn;

    async fn example_func_ok() -> anyhow::Result<()> {
        Ok(())
    }

    async fn example_func_err() -> anyhow::Result<()> {
        info!("example_func_err");
        Err(anyhow::anyhow!(""))
    }

    #[test]
    fn balance_gas_transaction_has_no_gas_objects_and_is_replay_protected() {
        let sender = SuiAddress::random_for_testing_only();
        let pt = sui_types::programmable_transaction_builder::ProgrammableTransactionBuilder::new()
            .finish();
        let tx_data =
            balance_gas_transaction_data(sender, pt, 750, 42, get_testnet_chain_identifier(), 7);

        let v1 = tx_data.as_v1();
        // An empty gas payment on a programmable transaction IS the SIP-58
        // trigger for paying gas from the sender's address balance.
        assert!(sui_types::transaction::is_gas_paid_from_address_balance(
            &v1.gas_data,
            &v1.kind
        ));
        assert_eq!(v1.sender, sender);
        assert_eq!(v1.gas_data.owner, sender);
        assert_eq!(v1.gas_data.price, 750);
        assert_eq!(v1.gas_data.budget, NOTIFIER_GAS_BUDGET);
        // The [current, current+1] window survives a Sui epoch boundary and
        // is the maximum extension is_replay_protected allows (validators
        // retain executed digests across the expiry range).
        assert!(v1.expiration.is_replay_protected());
        assert!(matches!(
            v1.expiration,
            TransactionExpiration::ValidDuring {
                min_epoch: Some(42),
                max_epoch: Some(43),
                min_timestamp: None,
                max_timestamp: None,
                nonce: 7,
                ..
            }
        ));
    }

    #[test]
    fn sweep_transaction_splits_gas_and_deposits_to_sender_balance() {
        let sender = SuiAddress::random_for_testing_only();
        let gas_coins = vec![sui_types::base_types::random_object_ref()];
        let tx_data = sweep_transaction_data(sender, gas_coins.clone(), 5_000, 750).unwrap();

        let v1 = tx_data.as_v1();
        assert_eq!(v1.sender, sender);
        // Ordinary gas-coin payment: the sweep runs precisely when the
        // address balance may be empty.
        assert_eq!(v1.gas_data.payment, gas_coins);
        assert_eq!(v1.gas_data.budget, SWEEP_GAS_BUDGET);
        assert_eq!(v1.expiration, TransactionExpiration::None);

        let TransactionKind::ProgrammableTransaction(pt) = &v1.kind else {
            panic!("sweep must be a programmable transaction");
        };
        // SplitCoins off the (merged) gas coin, then coin::send_funds<SUI>.
        assert!(matches!(
            &pt.commands[0],
            Command::SplitCoins(Argument::GasCoin, amounts) if amounts.len() == 1
        ));
        let Command::MoveCall(call) = &pt.commands[1] else {
            panic!("second command must be the send_funds deposit");
        };
        assert_eq!(call.package, SUI_FRAMEWORK_PACKAGE_ID);
        assert_eq!(call.module.as_str(), "coin");
        assert_eq!(call.function.as_str(), "send_funds");
        assert_eq!(
            call.type_arguments,
            vec![sui_types::type_input::TypeInput::from(GAS::type_tag())]
        );
    }

    #[tokio::test]
    async fn test_retry_with_max_elapsed_time() {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        // No retry is needed, should return immediately. We give it a very small
        // max_elapsed_time and it should still finish in time.
        let max_elapsed_time = Duration::from_millis(20);
        retry_with_max_elapsed_time!(example_func_ok(), max_elapsed_time)
            .unwrap()
            .unwrap();

        // Now call a function that always errors and expect it to return before max_elapsed_time runs out.
        let max_elapsed_time = Duration::from_secs(10);
        let instant = std::time::Instant::now();
        retry_with_max_elapsed_time!(example_func_err(), max_elapsed_time).unwrap_err();
        assert!(instant.elapsed() < max_elapsed_time);
    }
}

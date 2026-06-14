// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Per-epoch task that installs a consensus-pubkey provider on the
//! current `AuthorityPerEpochStore`, mapping each committee member's
//! `AuthorityName` to its Ed25519 consensus pubkey (fetched from the
//! members' on-chain `StakingPool.validator_info`).
//!
//! Two flavors share this machinery — they differ only in which
//! committee they read and which provider slot they install into:
//!
//! - **Active committee** (`new_for_active_committee`): feeds
//!   `ConsensusPubkeyProvider`, used by handoff-signature verification
//!   (`process_handoff_signature`) to look up the current committee's
//!   signers.
//! - **Next-epoch committee** (`new_for_next_epoch_committee`): feeds
//!   `JoinerPubkeyProvider`, used by the relay path
//!   (`verify_joiner_announcement`) to verify a joiner's signature.
//!
//! The consensus pubkey is fixed at validator registration, but the
//! *membership* (esp. the next-epoch committee) changes mid-epoch at
//! reconfiguration, and the provider must reflect a newly-published
//! next committee promptly — otherwise a joiner's relayed announcement
//! is rejected as `UnregisteredJoiner` until the next poll. So the
//! fetch cadence is modest (5s) and the task retries on transport
//! failure rather than aborting. Without a provider installed, the
//! corresponding verification drops every message (handoff sigs as
//! `UnknownSigner`; relayed announcements as `UnregisteredJoiner`).

use crate::authority::authority_per_epoch_store::AuthorityPerEpochStore;
use crate::validator_metadata::{StaticConsensusPubkeyProvider, StaticJoinerPubkeyProvider};
use fastcrypto::ed25519::Ed25519PublicKey;
use ika_sui_client::{SuiClient, SuiClientInner};
use ika_types::committee::{Committee, EpochId, StakeUnit};
use ika_types::crypto::AuthorityName;
use ika_types::sui::{SystemInner, SystemInnerTrait, SystemInnerV1};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Weak};
use std::time::Duration;
use sui_types::base_types::ObjectID;
use tracing::{debug, info, warn};

/// Selects the validator-ids whose consensus pubkeys to install. An
/// empty result means "nothing to install yet" (e.g. the next-epoch
/// committee hasn't been selected).
type MemberSelector = fn(&SystemInnerV1) -> Vec<ObjectID>;

/// Installs the assembled `AuthorityName -> consensus pubkey` map on
/// the epoch store, behind the appropriate provider slot.
type ProviderInstaller = fn(&AuthorityPerEpochStore, Vec<(AuthorityName, Ed25519PublicKey)>);

fn select_active_committee(system_inner: &SystemInnerV1) -> Vec<ObjectID> {
    system_inner
        .validator_set
        .active_committee
        .members
        .iter()
        .map(|m| m.validator_id)
        .collect()
}

fn select_next_epoch_committee(system_inner: &SystemInnerV1) -> Vec<ObjectID> {
    system_inner
        .validator_set
        .next_epoch_committee
        .as_ref()
        .map(|c| c.members.iter().map(|m| m.validator_id).collect())
        .unwrap_or_default()
}

/// Fetches the **previous** committee's `AuthorityName -> Ed25519
/// consensus pubkey` pairs from chain.
///
/// Reads the prior-committee member ids from
/// `validator_set.previous_committee` and resolves each member's
/// `StakingPool.validator_info` by object id. Resolving by object id is
/// what lets this recover signers that have *departed* the active set
/// since they signed the handoff cert: their StakingPool object still
/// exists on chain (only the active-committee membership dropped them),
/// so a bootstrapping validator can verify their handoff signatures even
/// though the current active-validator set no longer carries their keys.
pub async fn fetch_previous_committee_consensus_pubkeys<C: SuiClientInner>(
    sui_client: &SuiClient<C>,
) -> anyhow::Result<Vec<(AuthorityName, Ed25519PublicKey)>> {
    let (_, system_inner) = sui_client
        .get_system_inner()
        .await
        .map_err(|e| anyhow::anyhow!("get_system_inner failed: {e}"))?;
    let SystemInner::V1(system_inner) = system_inner;
    let validator_ids: Vec<ObjectID> = system_inner
        .validator_set
        .previous_committee
        .members
        .iter()
        .map(|m| m.validator_id)
        .collect();
    if validator_ids.is_empty() {
        return Ok(Vec::new());
    }
    let staking_pools = sui_client.get_validators_info_by_ids(validator_ids).await?;
    staking_pools
        .iter()
        .map(|pool| {
            let verified = pool
                .validator_info
                .verify()
                .map_err(|code| anyhow::anyhow!("validator info verify failed: code {code}"))?;
            let name: AuthorityName = (&verified.protocol_pubkey).into();
            Ok((name, verified.consensus_pubkey.clone()))
        })
        .collect()
}

/// Chain-reads the **previous** committee as a quorum-checkable
/// `Committee`, for a joiner that never locally observed/persisted that
/// epoch (so its `committee_store` has no entry for it). The source is
/// `validator_set.previous_committee` — the same field
/// `fetch_previous_committee_consensus_pubkeys` reads — and the membership
/// is decoded with `read_bls_committee`. The class-groups / PVSS maps are
/// left empty: handoff-cert verification (`verify_certified_handoff_attestation`)
/// only needs membership, voting power, and the quorum threshold.
///
/// `previous_committee` is implicitly the committee of `on_chain_epoch -
/// 1`. This returns it **only** when that equals `expected_prior_epoch`,
/// so an advanced on-chain view can't hand back a wrong-epoch committee —
/// which would make a valid handoff cert fail to verify and (via
/// `BootstrapOutcome::Rejected`) fail-closed-halt the node.
pub async fn fetch_previous_committee<C: SuiClientInner>(
    sui_client: &SuiClient<C>,
    expected_prior_epoch: EpochId,
) -> anyhow::Result<Committee> {
    let (_, system_inner) = sui_client
        .get_system_inner()
        .await
        .map_err(|e| anyhow::anyhow!("get_system_inner failed: {e}"))?;
    let SystemInner::V1(system_inner) = system_inner;
    let on_chain_epoch = system_inner.epoch();
    if on_chain_epoch != expected_prior_epoch + 1 {
        anyhow::bail!(
            "on-chain epoch {on_chain_epoch} does not equal expected prior epoch \
             {expected_prior_epoch} + 1; refusing to use validator_set.previous_committee \
             as a possibly-wrong-epoch bootstrap anchor"
        );
    }
    let bls_committee = &system_inner.validator_set.previous_committee;
    let voting_rights: Vec<(AuthorityName, StakeUnit)> = system_inner
        .read_bls_committee(bls_committee)
        .into_iter()
        .map(|(_, (name, stake))| (name, stake))
        .collect();
    if voting_rights.is_empty() {
        anyhow::bail!("validator_set.previous_committee is empty");
    }
    Ok(Committee::new(
        expected_prior_epoch,
        voting_rights,
        HashMap::new(),
        HashMap::new(),
        HashMap::new(),
        HashMap::new(),
        bls_committee.quorum_threshold,
        bls_committee.validity_threshold,
    ))
}

fn install_consensus_provider(
    epoch_store: &AuthorityPerEpochStore,
    entries: Vec<(AuthorityName, Ed25519PublicKey)>,
) {
    epoch_store.install_consensus_pubkey_provider(Box::new(
        StaticConsensusPubkeyProvider::from_iter(entries),
    ));
}

fn install_joiner_provider(
    epoch_store: &AuthorityPerEpochStore,
    entries: Vec<(AuthorityName, Ed25519PublicKey)>,
) {
    epoch_store
        .install_joiner_pubkey_provider(Box::new(StaticJoinerPubkeyProvider::from_iter(entries)));
}

pub struct PubkeyProviderUpdater<C> {
    epoch_store: Weak<AuthorityPerEpochStore>,
    epoch_id: EpochId,
    sui_client: Arc<SuiClient<C>>,
    select_members: MemberSelector,
    install: ProviderInstaller,
    label: &'static str,
    /// Cache of the last-installed `AuthorityName -> consensus_pubkey`
    /// map so we don't reinstall when the source committee hasn't
    /// changed.
    last_installed: parking_lot::Mutex<Option<BTreeMap<AuthorityName, Ed25519PublicKey>>>,
}

impl<C> PubkeyProviderUpdater<C>
where
    C: SuiClientInner + 'static,
{
    /// Installs a `ConsensusPubkeyProvider` from the current
    /// (active) committee — for handoff-signature verification.
    pub fn new_for_active_committee(
        epoch_store: Weak<AuthorityPerEpochStore>,
        epoch_id: EpochId,
        sui_client: Arc<SuiClient<C>>,
    ) -> Self {
        Self::new(
            epoch_store,
            epoch_id,
            sui_client,
            select_active_committee,
            install_consensus_provider,
            "ConsensusPubkeyProvider (active committee)",
        )
    }

    /// Installs a `JoinerPubkeyProvider` from the next-epoch
    /// committee — for joiner-announcement relay verification.
    pub fn new_for_next_epoch_committee(
        epoch_store: Weak<AuthorityPerEpochStore>,
        epoch_id: EpochId,
        sui_client: Arc<SuiClient<C>>,
    ) -> Self {
        Self::new(
            epoch_store,
            epoch_id,
            sui_client,
            select_next_epoch_committee,
            install_joiner_provider,
            "JoinerPubkeyProvider (next-epoch committee)",
        )
    }

    fn new(
        epoch_store: Weak<AuthorityPerEpochStore>,
        epoch_id: EpochId,
        sui_client: Arc<SuiClient<C>>,
        select_members: MemberSelector,
        install: ProviderInstaller,
        label: &'static str,
    ) -> Self {
        Self {
            epoch_store,
            epoch_id,
            sui_client,
            select_members,
            install,
            label,
            last_installed: parking_lot::Mutex::new(None),
        }
    }

    pub async fn run(self: Arc<Self>) {
        use ika_types::sui::epoch_start_system::EpochStartSystemTrait;
        let mut poll_interval = Duration::from_secs(5);
        if let Some(epoch_store) = self.epoch_store.upgrade() {
            if !epoch_store
                .protocol_config()
                .off_chain_validator_metadata_enabled()
            {
                info!(
                    epoch = self.epoch_id,
                    label = self.label,
                    "off-chain validator metadata disabled; pubkey updater exiting"
                );
                return;
            }
            poll_interval = crate::validator_metadata::epoch_scaled_poll_interval(
                epoch_store.epoch_start_state().epoch_duration_ms(),
                poll_interval,
            );
        }
        // Throttle the failure-path warn: a fullnode RPC outage would
        // otherwise repeat the identical line every poll tick for the
        // outage's duration (two updater instances run per epoch). Warn
        // on the first failure and every 12th thereafter (~1/minute at
        // the 5s production cadence), debug in between, and log recovery
        // once so the outage's end is visible.
        let mut consecutive_refresh_failures: u64 = 0;
        loop {
            // Exit once the epoch store this updater serves has been
            // dropped (the epoch advanced) — otherwise the task would
            // spin forever re-polling for a store that no longer exists.
            if self.epoch_store.upgrade().is_none() {
                info!(
                    epoch = self.epoch_id,
                    label = self.label,
                    "epoch store dropped; pubkey updater exiting"
                );
                return;
            }
            match self.refresh().await {
                Ok(()) => {
                    if consecutive_refresh_failures > 0 {
                        info!(
                            label = self.label,
                            consecutive_failures = consecutive_refresh_failures,
                            "pubkey provider refresh recovered"
                        );
                    }
                    consecutive_refresh_failures = 0;
                }
                Err(err) => {
                    if consecutive_refresh_failures.is_multiple_of(12) {
                        warn!(
                            error=?err,
                            label = self.label,
                            consecutive_failures = consecutive_refresh_failures,
                            "pubkey provider refresh failed; will retry"
                        );
                    } else {
                        debug!(
                            error=?err,
                            label = self.label,
                            consecutive_failures = consecutive_refresh_failures,
                            "pubkey provider refresh failed; will retry"
                        );
                    }
                    consecutive_refresh_failures += 1;
                }
            }
            tokio::time::sleep(poll_interval).await;
        }
    }

    async fn refresh(&self) -> anyhow::Result<()> {
        let Some(epoch_store) = self.epoch_store.upgrade() else {
            return Ok(());
        };
        let (_, system_inner) = self
            .sui_client
            .get_system_inner()
            .await
            .map_err(|e| anyhow::anyhow!("get_system_inner failed: {e}"))?;
        let SystemInner::V1(system_inner) = system_inner;
        // This updater serves a single epoch (`self.epoch_id`). If the
        // chain has already advanced past it — the epoch store hasn't
        // dropped yet, so the `Weak` upgrade above still succeeded — the
        // committees read here belong to a later epoch; installing them
        // onto this epoch's store would clobber it with the wrong keys.
        // Skip; the next epoch's own updater installs its committees.
        if system_inner.epoch != self.epoch_id {
            return Ok(());
        }
        let validator_ids = (self.select_members)(&system_inner);
        if validator_ids.is_empty() {
            // Nothing to install yet (e.g. next-epoch committee not
            // selected). Leave whatever's installed (empty by default).
            return Ok(());
        }
        let staking_pools = self
            .sui_client
            .get_validators_info_by_ids(validator_ids)
            .await?;

        let mut consensus_keys_by_name: BTreeMap<AuthorityName, Ed25519PublicKey> = BTreeMap::new();
        for pool in &staking_pools {
            let verified = pool
                .validator_info
                .verify()
                .map_err(|code| anyhow::anyhow!("validator info verify failed: code {code}"))?;
            let name: AuthorityName = (&verified.protocol_pubkey).into();
            consensus_keys_by_name.insert(name, verified.consensus_pubkey.clone());
        }

        {
            let last = self.last_installed.lock();
            if last.as_ref() == Some(&consensus_keys_by_name) {
                return Ok(());
            }
        }

        let entries: Vec<(AuthorityName, Ed25519PublicKey)> =
            consensus_keys_by_name.clone().into_iter().collect();
        let entry_count = entries.len();
        (self.install)(&epoch_store, entries);
        *self.last_installed.lock() = Some(consensus_keys_by_name);
        info!(
            epoch = self.epoch_id,
            label = self.label,
            members = entry_count,
            "installed pubkey provider"
        );
        Ok(())
    }
}

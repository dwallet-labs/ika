// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Per-epoch task that installs a `JoinerPubkeyProvider` on the current
//! `AuthorityPerEpochStore`, mapping each next-epoch committee member's
//! `AuthorityName` to its Ed25519 consensus pubkey (fetched from the
//! members' on-chain `StakingPool.validator_info`).
//!
//! It feeds `JoinerPubkeyProvider`, used by the relay path
//! (`verify_joiner_announcement`) to verify a joiner's signature. Joiners
//! aren't in the active committee yet, so — unlike handoff-signature
//! verification, which reads consensus keys straight off the `Committee` —
//! their keys can't come from the committee and need this side channel.
//!
//! The consensus pubkey is fixed at validator registration, but the
//! next-epoch *membership* changes mid-epoch at reconfiguration, and the
//! provider must reflect a newly-published next committee promptly —
//! otherwise a joiner's relayed announcement is rejected as
//! `UnregisteredJoiner` until the next poll. So the fetch cadence is
//! modest (5s) and the task retries on transport failure rather than
//! aborting. Without a provider installed, relayed announcements drop as
//! `UnregisteredJoiner`.

use crate::authority::authority_per_epoch_store::AuthorityPerEpochStore;
use crate::validator_metadata::StaticJoinerPubkeyProvider;
use fastcrypto::ed25519::Ed25519PublicKey;
use ika_sui_client::{SuiClient, SuiClientInner};
use ika_types::committee::{Committee, EpochId, StakeUnit};
use ika_types::crypto::AuthorityName;
use ika_types::sui::epoch_start_system::{
    EpochStartSystemTrait, consensus_key_identity_for_version,
};
use ika_types::sui::{SystemInner, SystemInnerTrait, SystemInnerV1};
use std::collections::{BTreeMap, HashMap, HashSet};
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

fn select_next_epoch_committee(system_inner: &SystemInnerV1) -> Vec<ObjectID> {
    system_inner
        .validator_set
        .next_epoch_committee
        .as_ref()
        .map(|c| c.members.iter().map(|m| m.validator_id).collect())
        .unwrap_or_default()
}

/// Chain-reads the **previous** committee as a quorum-checkable
/// `Committee`, for a joiner that never locally observed/persisted that
/// epoch (so its `committee_store` has no entry for it). The membership
/// is decoded with `read_bls_committee_lossy`; each member's consensus key
/// is fetched and carried on the committee so its prior-epoch handoff
/// signatures verify by name (best-effort per member: one whose
/// validator_info fails to decode is skipped and only its signatures are
/// lost, never the whole committee). The class-groups / PVSS maps are left empty:
/// handoff-cert verification (`verify_certified_handoff_attestation`) only
/// needs membership, voting power, the quorum threshold, and the consensus
/// keys.
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
    // The identity basis of the PRIOR epoch's committee — the name space its
    // members signed their handoff attestations under. Version-gated on the
    // CURRENT on-chain version (the prior epoch's own version is no longer
    // on chain): correct everywhere except when the flag activated exactly
    // at the current epoch, where the prior committee was still BLS-named —
    // the single-boundary limitation shared by the whole version-gated flip.
    let consensus_key_identity =
        consensus_key_identity_for_version(system_inner.protocol_version());
    if on_chain_epoch != expected_prior_epoch + 1 {
        anyhow::bail!(
            "on-chain epoch {on_chain_epoch} does not equal expected prior epoch \
             {expected_prior_epoch} + 1; refusing to use validator_set.previous_committee \
             as a possibly-wrong-epoch bootstrap anchor"
        );
    }
    let bls_committee = &system_inner.validator_set.previous_committee;
    if bls_committee.members.is_empty() {
        anyhow::bail!("validator_set.previous_committee is empty");
    }
    // Resolving by object id is what lets this recover signers that have
    // *departed* the active set since they signed the handoff cert: their
    // StakingPool object still exists on chain, so a bootstrapping
    // validator can verify their handoff signatures even though the
    // current active-validator set no longer carries their keys.
    let validator_ids: Vec<ObjectID> = bls_committee
        .members
        .iter()
        .map(|m| m.validator_id)
        .collect();
    let staking_pools = sui_client.get_validators_info_by_ids(validator_ids).await?;
    // Both name-keyed maps on the returned `Committee` must use the SAME name
    // space, and it must be the PRIOR-epoch snapshot's — that is the name each
    // member signed its handoff attestation under. `voting_rights` already
    // comes from the frozen `previous_committee` snapshot; the consensus-key
    // map must too. Keying the consensus map by the member's CURRENT on-chain
    // protocol_pubkey (from which `AuthorityName` is derived) would diverge
    // for any validator that rotated its protocol key at the boundary — its
    // handoff signatures, signed under the old name, would then fail to
    // resolve a consensus key and drop, silently dropping its stake from the
    // cert quorum. Resolve each fetched pool to its snapshot name by
    // validator id (StakingPool.id == BlsCommitteeMember.validator_id).
    // Lossy: a departed prior-committee member with an unparseable protocol
    // pubkey is skipped, not fatal — bootstrap must not crash-loop on one bad
    // record. NOTE: the skip is NOT graceful quorum degradation. The skipped
    // member is absent from `voting_rights`, and cert verification
    // HARD-REJECTS a certificate carrying a weight-0 signer's signature —
    // and since that member's own node runs fine, its signature is in every
    // aggregated cert, so every served cert fails verification and bootstrap
    // surfaces `Rejected`. The warn below makes that outcome attributable to
    // the corrupt prior-committee record instead of the Rejected log's
    // default "wrong prior-committee view / wrong peers" guidance. (Trigger
    // requires registration-validated snapshot bytes to fail BLS parse —
    // near-unreachable; the pre-lossy behavior was a panic crash-loop.)
    let bls_members = system_inner.read_bls_committee_lossy(bls_committee);
    if bls_members.len() < bls_committee.members.len() {
        let parsed_ids: HashSet<ObjectID> = bls_members.iter().map(|(id, _)| *id).collect();
        let dropped: Vec<ObjectID> = bls_committee
            .members
            .iter()
            .map(|member| member.validator_id)
            .filter(|id| !parsed_ids.contains(id))
            .collect();
        warn!(
            ?dropped,
            "prior-committee members dropped by the lossy read (unparseable protocol \
             pubkey in the frozen snapshot): any handoff cert carrying their signatures \
             will FAIL verification (weight-0 signer) — a subsequent Rejected outcome \
             means a corrupt prior-committee record, not wrong peers"
        );
    }
    let snapshot_name_by_id: HashMap<ObjectID, AuthorityName> = if consensus_key_identity {
        // Consensus-basis prior epoch: the snapshot name derives from the
        // consensus key, whose VALUE is fixed at registration — so the
        // current on-chain value IS the snapshot value. A member whose
        // validator_info fails verify has no resolvable name and drops out
        // (the verify-failure warn below attributes it).
        staking_pools
            .iter()
            .filter_map(|pool| {
                let verified = pool.validator_info.verify().ok()?;
                Some((
                    pool.id,
                    AuthorityName::from_consensus_key(&verified.consensus_pubkey),
                ))
            })
            .collect()
    } else {
        bls_members
            .iter()
            .map(|(id, (name, _))| (*id, *name))
            .collect()
    };
    // Tolerate a member whose validator_info fails to decode: `verify()`
    // rejects on ANY malformed metadata field (addresses, next-epoch keys),
    // not just the consensus key needed here, and the member may have
    // departed the active set with no one left to fix its stale record.
    // Skipping costs only that member's handoff signature (it drops as
    // unverifiable — same as a byzantine signer); failing the whole fetch
    // would block joiner bootstrap on a deterministic error forever, since
    // the cert only needs a quorum of the members that DO verify.
    let mut consensus_keys: HashMap<AuthorityName, Ed25519PublicKey> = HashMap::new();
    for pool in &staking_pools {
        let verified = match pool.validator_info.verify() {
            Ok(verified) => verified,
            Err(code) => {
                warn!(
                    code,
                    validator_id = ?pool.id,
                    "prior-committee member validator_info failed verify; skipping — \
                     its handoff signatures won't count toward the cert quorum"
                );
                continue;
            }
        };
        // The consensus pubkey VALUE is fixed at registration, so reading the
        // current one is correct; only the map KEY must be the snapshot name.
        let Some(name) = snapshot_name_by_id.get(&pool.id).copied() else {
            warn!(
                validator_id = ?pool.id,
                "prior-committee staking pool absent from the previous_committee \
                 snapshot; skipping"
            );
            continue;
        };
        consensus_keys.insert(name, verified.consensus_pubkey.clone());
    }
    let voting_rights: Vec<(AuthorityName, StakeUnit)> = bls_members
        .into_iter()
        .filter_map(|(id, (_, stake))| Some((*snapshot_name_by_id.get(&id)?, stake)))
        .collect();
    Ok(Committee::new(
        expected_prior_epoch,
        voting_rights,
        // class-groups left empty: handoff-cert verification only needs
        // membership, voting power, and the quorum threshold. The off-chain
        // PVSS / VSS keys are not on `Committee` at all.
        HashMap::new(),
        consensus_keys,
        bls_committee.quorum_threshold,
        bls_committee.validity_threshold,
    ))
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
        // outage's duration. Warn on the first failure and every 12th
        // thereafter (~1/minute at the 5s production cadence), debug in
        // between, and log recovery once so the outage's end is visible.
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
        let consensus_key_identity = epoch_store.epoch_start_state().consensus_key_identity();
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

        // Tolerate a member whose validator_info fails to decode, exactly as
        // `fetch_previous_committee` does: `verify()` rejects on ANY malformed
        // metadata field, not just the consensus key needed here. Failing the
        // whole refresh on one bad record would return Err every 5s forever
        // and install NO provider — suppressing joiner-announcement relay for
        // the entire epoch on a single deterministic error. Skipping costs
        // only that member's relayed announcements (its own direct
        // announcements still reach peers), and cert verification needs only a
        // quorum of the members that DO verify.
        let mut consensus_keys_by_name: BTreeMap<AuthorityName, Ed25519PublicKey> = BTreeMap::new();
        // Collect skips silently here; the warns are emitted AFTER the
        // `last_installed` dedup below, so a deterministically-bad record
        // warns once per actual map change instead of twice per 5s poll
        // tick for the rest of the epoch (~34k lines/day).
        let mut skipped_members: Vec<(ObjectID, u64)> = Vec::new();
        for pool in &staking_pools {
            let verified = match pool.validator_info.verify() {
                Ok(verified) => verified,
                Err(code) => {
                    skipped_members.push((pool.id, code));
                    continue;
                }
            };
            // Key by the name space announcements use in THIS epoch's store:
            // an announcer names itself under its epoch's identity basis, so
            // the provider must key the same way (consensus-basis past the
            // authority-name flip epoch, BLS before it).
            let name = if consensus_key_identity {
                AuthorityName::from_consensus_key(&verified.consensus_pubkey)
            } else {
                (&verified.protocol_pubkey).into()
            };
            consensus_keys_by_name.insert(name, verified.consensus_pubkey.clone());
        }

        {
            let last = self.last_installed.lock();
            if last.as_ref() == Some(&consensus_keys_by_name) {
                return Ok(());
            }
        }

        if !skipped_members.is_empty() {
            warn!(
                epoch = self.epoch_id,
                label = self.label,
                skipped = ?skipped_members,
                installed = consensus_keys_by_name.len(),
                "installing pubkey provider with an incomplete member set \
                 (validator_info failed verify; (validator_id, code) pairs listed); \
                 relayed announcements from the skipped members will be dropped"
            );
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

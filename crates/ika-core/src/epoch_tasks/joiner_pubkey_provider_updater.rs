// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Per-epoch task that installs a `JoinerPubkeyProvider` on the
//! current `AuthorityPerEpochStore`, mapping each next-epoch
//! committee member's `AuthorityName` to its Ed25519 **consensus**
//! pubkey.
//!
//! The relay path (`verify_joiner_announcement`) reads the installed
//! provider to look up a joiner's consensus pubkey and verify the
//! joiner's signature over its `ValidatorMpcDataAnnouncement`.
//! Without a provider installed, every relayed announcement is
//! dropped — current-committee self-announcements still work (they
//! don't go through this provider).
//!
//! The consensus pubkey is fixed at validator registration, so the
//! fetch cadence is slow (15s) and the task retries on transport
//! failure rather than aborting. Mirrors
//! `consensus_pubkey_provider_updater`, but reads the *next-epoch*
//! committee instead of the active one.

use crate::authority::authority_per_epoch_store::AuthorityPerEpochStore;
use crate::validator_metadata::StaticJoinerPubkeyProvider;
use fastcrypto::ed25519::Ed25519PublicKey;
use ika_sui_client::{SuiClient, SuiClientInner};
use ika_types::committee::EpochId;
use ika_types::crypto::AuthorityName;
use ika_types::sui::SystemInner;
use std::collections::BTreeMap;
use std::sync::{Arc, Weak};
use std::time::Duration;
use tracing::{info, warn};

pub struct JoinerPubkeyProviderUpdater<C> {
    epoch_store: Weak<AuthorityPerEpochStore>,
    epoch_id: EpochId,
    sui_client: Arc<SuiClient<C>>,
    /// Cache of the last-installed `AuthorityName -> consensus_pubkey`
    /// map (compared by serialized form) so we don't reinstall when
    /// the next-epoch committee hasn't changed.
    last_installed: parking_lot::Mutex<Option<BTreeMap<AuthorityName, Vec<u8>>>>,
}

impl<C> JoinerPubkeyProviderUpdater<C>
where
    C: SuiClientInner + 'static,
{
    pub fn new(
        epoch_store: Weak<AuthorityPerEpochStore>,
        epoch_id: EpochId,
        sui_client: Arc<SuiClient<C>>,
    ) -> Self {
        Self {
            epoch_store,
            epoch_id,
            sui_client,
            last_installed: parking_lot::Mutex::new(None),
        }
    }

    pub async fn run(self: Arc<Self>) {
        if let Some(epoch_store) = self.epoch_store.upgrade()
            && !epoch_store
                .protocol_config()
                .off_chain_validator_metadata_enabled()
        {
            info!(
                epoch = self.epoch_id,
                "off-chain validator metadata disabled; joiner pubkey updater exiting"
            );
            return;
        }
        loop {
            if let Err(err) = self.refresh().await {
                warn!(error=?err, "joiner pubkey provider refresh failed; will retry");
            }
            tokio::time::sleep(Duration::from_secs(15)).await;
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
        // Next-epoch committee members are the eligible joiners.
        // Until Sui has selected the next committee there's nothing
        // to install — leave whatever's there (empty by default).
        let Some(next_committee) = system_inner.validator_set.next_epoch_committee.as_ref() else {
            return Ok(());
        };
        let validator_ids: Vec<_> = next_committee
            .members
            .iter()
            .map(|m| m.validator_id)
            .collect();
        if validator_ids.is_empty() {
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

        let serialized: BTreeMap<AuthorityName, Vec<u8>> = consensus_keys_by_name
            .iter()
            .map(|(name, pk)| {
                use fastcrypto::traits::EncodeDecodeBase64;
                (*name, pk.encode_base64().into_bytes())
            })
            .collect();
        {
            let last = self.last_installed.lock();
            if last.as_ref() == Some(&serialized) {
                return Ok(());
            }
        }

        let entries: Vec<(AuthorityName, Ed25519PublicKey)> =
            consensus_keys_by_name.into_iter().collect();
        let entry_count = entries.len();
        let provider = StaticJoinerPubkeyProvider::from_iter(entries);
        epoch_store.install_joiner_pubkey_provider(Box::new(provider));
        *self.last_installed.lock() = Some(serialized);
        info!(
            epoch = self.epoch_id,
            members = entry_count,
            "installed JoinerPubkeyProvider from next-epoch committee"
        );
        Ok(())
    }
}

// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Per-epoch task that installs a `JoinerPubkeyProvider` on the
//! current `AuthorityPerEpochStore`, derived from the next-epoch
//! committee snapshot the sui_syncer keeps live.
//!
//! Step 6's verification path (`verify_joiner_announcement`) reads
//! the installed provider to decide whether a next-epoch
//! `ValidatorMpcDataAnnouncement` came from a registered joiner.
//! Without a provider installed, every next-epoch announcement is
//! silently dropped — which is the previous default. This task
//! lights up the joiner path by treating every authority in
//! `next_epoch_committee_receiver.borrow()` as a valid joiner (the
//! authority *is* the BLS pubkey via `AuthorityName ==
//! AuthorityPublicKeyBytes`, so a sig verify against the authority
//! is sufficient).
//!
//! Using V_{e+1} as the eligible set instead of reading
//! `PendingActiveSet` directly is a simplification: joiners can
//! only announce after they're in V_{e+1}, not earlier. For full
//! "early announcement" the task would need to plumb
//! PendingActiveSet contents via a Sui dynamic-field read; not
//! wired here.

use crate::authority::authority_per_epoch_store::AuthorityPerEpochStore;
use crate::validator_metadata::StaticJoinerPubkeyProvider;
use ika_types::committee::{Committee, EpochId};
use ika_types::crypto::AuthorityName;
use std::collections::HashSet;
use std::sync::{Arc, Weak};
use std::time::Duration;
use tokio::sync::watch::Receiver;
use tracing::info;

pub struct JoinerPubkeyProviderUpdater {
    epoch_store: Weak<AuthorityPerEpochStore>,
    epoch_id: EpochId,
    next_epoch_committee_receiver: Receiver<Committee>,
    /// Last installed set; we skip re-installation when the
    /// underlying authority list hasn't changed.
    last_installed: parking_lot::Mutex<Option<HashSet<AuthorityName>>>,
}

impl JoinerPubkeyProviderUpdater {
    pub fn new(
        epoch_store: Weak<AuthorityPerEpochStore>,
        epoch_id: EpochId,
        next_epoch_committee_receiver: Receiver<Committee>,
    ) -> Self {
        Self {
            epoch_store,
            epoch_id,
            next_epoch_committee_receiver,
            last_installed: parking_lot::Mutex::new(None),
        }
    }

    pub async fn run(self: Arc<Self>) {
        // Poll-based update: the watch channel may already hold a
        // value at task spawn time, so we read on each tick rather
        // than only on changes.
        loop {
            self.maybe_install();
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }

    fn maybe_install(&self) {
        let Some(epoch_store) = self.epoch_store.upgrade() else {
            return;
        };
        let next_committee = self.next_epoch_committee_receiver.borrow().clone();
        if next_committee.epoch() != self.epoch_id + 1 {
            // Either no next-epoch committee yet, or the receiver
            // is showing some other epoch's committee. Skip.
            return;
        }
        let new_set: HashSet<AuthorityName> = next_committee
            .voting_rights
            .iter()
            .map(|(name, _)| *name)
            .collect();
        {
            let last = self.last_installed.lock();
            if last.as_ref() == Some(&new_set) {
                return;
            }
        }
        let provider = StaticJoinerPubkeyProvider::from_iter(new_set.iter().copied());
        epoch_store.install_joiner_pubkey_provider(Box::new(provider));
        *self.last_installed.lock() = Some(new_set);
        info!(
            epoch = self.epoch_id,
            "installed JoinerPubkeyProvider from next-epoch committee"
        );
    }
}

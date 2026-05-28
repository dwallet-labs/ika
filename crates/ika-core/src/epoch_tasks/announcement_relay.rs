// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Concrete `AnnouncementRelay` impl for the Anemo
//! `SubmitMpcDataAnnouncement` RPC.
//!
//! Joiners who aren't in the consensus committee yet can't submit
//! their own `ValidatorMpcDataAnnouncement` to consensus directly.
//! They fan out the signed announcement to every current-committee
//! validator over the new RPC; whichever validator accepts it
//! forwards it as a `ConsensusTransaction`. One honest relayer per
//! announcement is sufficient.
//!
//! This impl runs:
//! 1. Cheap envelope checks (sig epoch == announcement epoch,
//!    announcement.validator == sig.authority).
//! 2. The pure verifier
//!    `verify_joiner_announcement` against the currently-installed
//!    `JoinerPubkeyProvider`. Rejection here stops spam from
//!    abusing us as a one-way pipe.
//! 3. Consensus submission of the wrapped
//!    `ConsensusTransaction::new_validator_mpc_data_announcement`.

use crate::authority::authority_per_epoch_store::AuthorityPerEpochStore;
use crate::consensus_adapter::SubmitToConsensus;
use crate::validator_metadata::{JoinerAnnouncementVerdict, verify_joiner_announcement};
use ika_network::mpc_artifacts::AnnouncementRelay;
use ika_types::messages_consensus::ConsensusTransaction;
use ika_types::validator_metadata::SignedValidatorMpcDataAnnouncement;
use std::sync::{Arc, Weak};

pub struct ConsensusBackedAnnouncementRelay {
    epoch_store: Weak<AuthorityPerEpochStore>,
    consensus_adapter: Arc<dyn SubmitToConsensus>,
}

impl ConsensusBackedAnnouncementRelay {
    pub fn new(
        epoch_store: Weak<AuthorityPerEpochStore>,
        consensus_adapter: Arc<dyn SubmitToConsensus>,
    ) -> Self {
        Self {
            epoch_store,
            consensus_adapter,
        }
    }
}

#[async_trait::async_trait]
impl AnnouncementRelay for ConsensusBackedAnnouncementRelay {
    async fn relay(&self, announcement: SignedValidatorMpcDataAnnouncement) -> Result<(), String> {
        let Some(epoch_store) = self.epoch_store.upgrade() else {
            return Err("epoch ended".to_string());
        };
        let current_epoch = epoch_store.epoch();
        let next_epoch = current_epoch.saturating_add(1);
        // Joiner announcements target `next_epoch`. Current-epoch
        // announcements would come from validators that are
        // already in the committee and can submit themselves —
        // refuse to relay those.
        if announcement.announcement.epoch != next_epoch {
            return Err(format!(
                "announcement epoch {} is not next_epoch {next_epoch}",
                announcement.announcement.epoch
            ));
        }
        let Some(provider) = epoch_store.joiner_pubkey_provider() else {
            return Err("joiner pubkey provider not installed".to_string());
        };
        match verify_joiner_announcement(&announcement, provider.as_ref().as_ref(), next_epoch) {
            JoinerAnnouncementVerdict::Accept => {}
            verdict => {
                return Err(format!("joiner verify rejected: {verdict:?}"));
            }
        }
        let tx = ConsensusTransaction::new_relayed_validator_mpc_data_announcement(announcement);
        self.consensus_adapter
            .submit_to_consensus(&[tx], &epoch_store)
            .await
            .map_err(|e| format!("consensus submit failed: {e}"))?;
        Ok(())
    }
}

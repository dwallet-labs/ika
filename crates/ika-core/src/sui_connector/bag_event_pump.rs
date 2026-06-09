// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Single-source-of-truth event feeder for the MPC engine.
//!
//! Each tick reads the two `session_events` bag IDs out of the current
//! `DWalletCoordinatorInner`, walks them through
//! [`OcsVerifiedReader::verified_bag_page`] (every entry comes back with
//! an OCS inclusion proof we verify against `CommitteeStore`), diffs
//! against the previous tick's set of bag-entry `ObjectID`s, and emits:
//!
//! - new entries on `new_requests_sender` (broadcast — live MPC start);
//! - the full set on `uncompleted_requests_sender` (watch — recovery
//!   snapshot the engine consumes on epoch turn / restart).
//!
//! Trade-offs (carried over from the design discussion):
//! - **Latency**: caller-supplied poll interval; ika-node runs it at ~50ms
//!   (20 Hz), so session-start latency is ~50ms worst-case.
//! - **Transient entries**: a session whose bag entry is added and
//!   removed within a single ~50ms tick is invisible. Consensus catches up
//!   any locally-missed session.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use ika_types::committee::EpochId;
use ika_types::messages_dwallet_mpc::{DBSuiEvent, IkaNetworkConfig};
use ika_types::sui::{DWalletCoordinator, DWalletCoordinatorInner};
use sui_types::TypeTag;
use sui_types::base_types::ObjectID;
use sui_types::object::Object;
use tokio::sync::{broadcast, watch};
use tracing::{debug, error, info, warn};

use crate::dwallet_session_request::DWalletSessionRequest;
use crate::sui_connector::ocs_metrics::OcsMetrics;
use crate::sui_connector::sui_event_into_request::sui_event_into_session_request;
use crate::sui_connector::verified_reader::{OcsVerifiedReader, VerifiedObject};

pub struct BagEventPump {
    reader: Arc<OcsVerifiedReader>,
    network_config: IkaNetworkConfig,
    coordinator_rx: watch::Receiver<Option<(DWalletCoordinator, DWalletCoordinatorInner)>>,
    new_requests_sender: broadcast::Sender<Vec<DWalletSessionRequest>>,
    uncompleted_requests_sender: watch::Sender<(Vec<DWalletSessionRequest>, EpochId)>,
    metrics: Arc<OcsMetrics>,
    poll_interval: Duration,
    seen: HashSet<ObjectID>,
    /// Police `Bag.size`-vs-listed-children omission. Only meaningful when
    /// bag pages come from an untrusted relay (sui-state-mirrored). On
    /// sui-state-direct the pages are trusted-local and the `Bag.size`
    /// comes from a cache-first (lagging) parent read, so the check would
    /// false-positive on every session completion — disabled there.
    detect_omission: bool,
}

impl BagEventPump {
    pub fn new(
        reader: Arc<OcsVerifiedReader>,
        network_config: IkaNetworkConfig,
        coordinator_rx: watch::Receiver<Option<(DWalletCoordinator, DWalletCoordinatorInner)>>,
        new_requests_sender: broadcast::Sender<Vec<DWalletSessionRequest>>,
        uncompleted_requests_sender: watch::Sender<(Vec<DWalletSessionRequest>, EpochId)>,
        metrics: Arc<OcsMetrics>,
        poll_interval: Duration,
    ) -> Self {
        let detect_omission = reader.bag_source_is_untrusted();
        Self {
            reader,
            network_config,
            coordinator_rx,
            new_requests_sender,
            uncompleted_requests_sender,
            metrics,
            poll_interval,
            seen: HashSet::new(),
            detect_omission,
        }
    }

    pub async fn run(mut self) {
        info!(
            poll_interval_ms = self.poll_interval.as_millis() as u64,
            "BagEventPump starting"
        );
        let mut tick = tokio::time::interval(self.poll_interval);
        loop {
            tick.tick().await;
            if let Err(e) = self.advance().await {
                warn!(error = ?e, "BagEventPump tick failed; will retry");
            }
        }
    }

    async fn advance(&mut self) -> anyhow::Result<()> {
        let (user_bag, user_size, sys_bag, sys_size, epoch) =
            match self.coordinator_rx.borrow().as_ref() {
                Some((_, DWalletCoordinatorInner::V1(inner))) => {
                    let user = &inner.sessions_manager.user_sessions_keeper.session_events;
                    let sys = &inner.sessions_manager.system_sessions_keeper.session_events;
                    (
                        user.id.id.bytes,
                        user.size,
                        sys.id.id.bytes,
                        sys.size,
                        inner.current_epoch,
                    )
                }
                None => {
                    debug!("DWalletCoordinator not yet available; skipping tick");
                    return Ok(());
                }
            };

        let mut entries: Vec<(ObjectID, DBSuiEvent)> = Vec::new();
        self.collect_bag("user", user_bag, user_size, &mut entries)
            .await?;
        self.collect_bag("system", sys_bag, sys_size, &mut entries)
            .await?;

        let current_ids: HashSet<ObjectID> = entries.iter().map(|(id, _)| *id).collect();
        let new_ids: HashSet<ObjectID> = current_ids.difference(&self.seen).copied().collect();

        let mut delta_requests = Vec::new();
        let mut snapshot_requests = Vec::with_capacity(entries.len());
        for (id, ev) in entries {
            match sui_event_into_session_request(
                &self.network_config,
                ev.type_.clone(),
                &ev.contents,
                ev.pulled,
            ) {
                Ok(Some(req)) => {
                    if new_ids.contains(&id) {
                        delta_requests.push(req.clone());
                    }
                    snapshot_requests.push(req);
                }
                Ok(None) => {}
                Err(e) => error!(error=?e, event_type=?ev.type_, ?id, "failed to parse bag entry"),
            }
        }

        if !delta_requests.is_empty() {
            debug!(
                count = delta_requests.len(),
                epoch, "broadcasting new requests"
            );
            let _ = self.new_requests_sender.send(delta_requests);
        }
        if let Err(e) = self
            .uncompleted_requests_sender
            .send((snapshot_requests, epoch))
        {
            error!(error=?e, "failed to send uncompleted snapshot");
        }

        self.seen = current_ids;
        Ok(())
    }

    /// Walk one bag end-to-end (paginating), append `(child_id, DBSuiEvent)`
    /// per verified entry. Each page's proofs are verified against the
    /// committee inside the reader; we just consume the trusted output.
    ///
    /// Bag-omission detection: `expected_size` comes from the verified
    /// `DWalletCoordinatorInner.sessions_manager.*.session_events.size`
    /// field — i.e. an authenticated `Bag.size`. If the relay-listed
    /// children come up short, log a warn and bump
    /// `bag_omission_suspected_total{bag}`. We don't fail the tick: the
    /// size could legitimately drift during the walk (sessions complete
    /// and get removed), so a single short walk is just a hint, not a
    /// proof of misbehavior. Persistent suspicion is what to alert on.
    async fn collect_bag(
        &self,
        bag_label: &'static str,
        bag_id: ObjectID,
        expected_size: u64,
        out: &mut Vec<(ObjectID, DBSuiEvent)>,
    ) -> anyhow::Result<()> {
        let mut page_token = None;
        let mut listed: u64 = 0;
        loop {
            let page = self
                .reader
                .verified_bag_page(bag_id, Some(256), page_token)
                .await?;
            listed += page.entries.len() as u64;
            for verified in page.entries {
                if let Some(ev) = decode_session_event(&verified) {
                    out.push((verified.object.id(), ev));
                }
            }
            match page.next_page_token {
                Some(t) => page_token = Some(t),
                None => break,
            }
        }
        if self.detect_omission && listed < expected_size {
            warn!(
                bag = bag_label,
                listed,
                expected_size,
                "bag walk returned fewer children than verified parent claims; suspected omission \
                 (or a benign mid-walk removal)"
            );
            self.metrics
                .bag_omission_suspected_total
                .with_label_values(&[bag_label])
                .inc();
        }
        Ok(())
    }
}

/// Bag entries are dynamic-field children of type `Field<K, V>`. We
/// extract the event tag (the `V` type parameter) and the BCS contents
/// (the whole Move object, which decodes as `Field<K, V>`).
fn decode_session_event(verified: &VerifiedObject) -> Option<DBSuiEvent> {
    fn move_obj(o: &Object) -> Option<&sui_types::object::MoveObject> {
        o.data.try_as_move()
    }
    let move_obj = move_obj(&verified.object)?;
    let event_tag = match move_obj.type_().type_params().get(1) {
        Some(cow) => match cow.as_ref() {
            TypeTag::Struct(s) => (**s).clone(),
            _ => return None,
        },
        None => return None,
    };
    Some(DBSuiEvent {
        type_: event_tag,
        contents: move_obj.contents().to_vec(),
        // Bag entries are read out of the (OCS-verified) object state,
        // not delivered as a Sui event stream — so this is a "pulled" event.
        pulled: true,
    })
}

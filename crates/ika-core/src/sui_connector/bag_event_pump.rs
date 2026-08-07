// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Single-source-of-truth event feeder for the MPC engine.
//!
//! Each tick reads the two `session_events` bag IDs out of the current
//! `DWalletCoordinatorInner`, walks them through
//! [`OcsVerifiedReader::verified_dynamic_fields_page`] (every entry comes back with
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
//! - **`seen` is in-memory and self-bounding**: each tick *replaces* it with
//!   the bag's current entry ids, so completed sessions fall out and it never
//!   outgrows the live bag. The flip side: a restart starts from an empty set
//!   and re-broadcasts every live entry as "new". That is within the
//!   consumer's existing contract — the recovery snapshot on
//!   `uncompleted_requests_sender` re-delivers the same live set every tick,
//!   so the engine must already dedup by session identifier (and it does:
//!   in-flight sessions by id, completed ones against the perpetual store).

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
use crate::sui_connector::metrics::SuiConnectorMetrics;
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
    /// Connector-level metrics: the pump feeds the same
    /// `uncompleted_events_backlog` gauge the legacy (v≤3) syncer poller
    /// feeds, so the series name is path-independent.
    connector_metrics: Arc<SuiConnectorMetrics>,
    poll_interval: Duration,
    seen: HashSet<ObjectID>,
    /// Police `Bag.size`-vs-listed-children omission. Only meaningful when
    /// bag pages come from an untrusted relay (sui-state-mirrored). On
    /// sui-state-direct the pages are trusted-local and the `Bag.size`
    /// comes from a cache-first (lagging) parent read, so the check would
    /// false-positive on every session completion — disabled there.
    detect_omission: bool,
    /// Consecutive ticks (so far) on which omission was suspected; drives the
    /// warn→error escalation in [`Self::note_bag_omission`]. Reset to 0 on any
    /// clean tick.
    consecutive_omission_ticks: u32,
}

/// Backoff cap for a persistently-failing pump tick. Throttles the retry (and
/// the error log) during a relay/proof outage, but kept short — deliberately
/// well below the 30s the executor's `verified_read_retry_backoff` uses —
/// because this is a *live* MPC-session feeder: during a backoff the pump
/// suppresses both the new-event broadcast and the recovery snapshot, so after a
/// transient fullnode blip recovers, event delivery should resume within a few
/// seconds, not tens. Still cuts a ~20 Hz flood down to ~1 line / 5s.
const MAX_PUMP_BACKOFF: Duration = Duration::from_secs(5);
/// Consecutive `advance()` failures before the per-tick `warn!` escalates to a
/// single `error!` (after which the grown backoff throttles the rate anyway).
const PUMP_FAILURE_ESCALATION_TICKS: u32 = 5;
/// Consecutive omission-suspected ticks before escalating warn→error. At the
/// ika-node ~50ms cadence this is ~5s of *persistent* suspicion — long enough
/// to rule out a benign mid-walk `Bag.size` drift (a session completing during
/// the walk), short enough to flag a relay actually withholding entries.
const SUSTAINED_OMISSION_TICKS: u32 = 100;

/// Next backoff after a failed tick: double the current (floored at the poll
/// interval), capped. Pure for testability.
fn next_pump_backoff(current: Duration, poll_interval: Duration) -> Duration {
    (current.max(poll_interval) * 2).min(MAX_PUMP_BACKOFF)
}

/// What to log for an omission streak, given the previous streak length and
/// whether this tick suspected omission. Pure for testability — the caller logs
/// and stores the returned streak length.
#[derive(Debug, PartialEq, Eq)]
enum OmissionEscalation {
    /// Within a streak but not at a logging boundary (metric still ticks).
    Quiet,
    /// First tick of a fresh streak — a single `warn!`.
    FirstSuspected,
    /// Streak reached the sustained threshold — a single `error!`.
    Sustained,
    /// A clean tick ended a previously-sustained streak — an `info!` recovery.
    Cleared { after: u32 },
}

fn omission_escalation(
    prev_ticks: u32,
    suspected: bool,
    sustained_ticks: u32,
) -> (u32, OmissionEscalation) {
    if !suspected {
        let action = if prev_ticks >= sustained_ticks {
            OmissionEscalation::Cleared { after: prev_ticks }
        } else {
            OmissionEscalation::Quiet
        };
        return (0, action);
    }
    let n = prev_ticks.saturating_add(1);
    let action = if n == 1 {
        OmissionEscalation::FirstSuspected
    } else if n == sustained_ticks {
        OmissionEscalation::Sustained
    } else {
        OmissionEscalation::Quiet
    };
    (n, action)
}

impl BagEventPump {
    pub fn new(
        reader: Arc<OcsVerifiedReader>,
        network_config: IkaNetworkConfig,
        coordinator_rx: watch::Receiver<Option<(DWalletCoordinator, DWalletCoordinatorInner)>>,
        new_requests_sender: broadcast::Sender<Vec<DWalletSessionRequest>>,
        uncompleted_requests_sender: watch::Sender<(Vec<DWalletSessionRequest>, EpochId)>,
        metrics: Arc<OcsMetrics>,
        connector_metrics: Arc<SuiConnectorMetrics>,
        poll_interval: Duration,
    ) -> Self {
        let detect_omission = reader.relay_source_is_untrusted();
        Self {
            reader,
            network_config,
            coordinator_rx,
            new_requests_sender,
            uncompleted_requests_sender,
            metrics,
            connector_metrics,
            poll_interval,
            seen: HashSet::new(),
            detect_omission,
            consecutive_omission_ticks: 0,
        }
    }

    pub async fn run(mut self) {
        info!(
            poll_interval_ms = self.poll_interval.as_millis() as u64,
            "BagEventPump starting"
        );
        let mut tick = tokio::time::interval(self.poll_interval);
        // Don't let `sleep(backoff)` below make the interval burst-catch-up.
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut backoff = Duration::ZERO;
        let mut consecutive_failures: u32 = 0;
        loop {
            tick.tick().await;
            if !backoff.is_zero() {
                tokio::time::sleep(backoff).await;
            }
            match self.advance().await {
                Ok(()) => {
                    if consecutive_failures > 0 {
                        info!(
                            after_failures = consecutive_failures,
                            "BagEventPump recovered"
                        );
                    }
                    consecutive_failures = 0;
                    backoff = Duration::ZERO;
                }
                Err(e) => {
                    consecutive_failures += 1;
                    backoff = next_pump_backoff(backoff, self.poll_interval);
                    // Escalate to a single error once sustained; from then on the
                    // grown backoff throttles the rate to ~1 line / 30s, so a long
                    // outage no longer floods the log at the poll rate.
                    if consecutive_failures >= PUMP_FAILURE_ESCALATION_TICKS {
                        error!(
                            error = ?e,
                            consecutive_failures,
                            backoff_ms = backoff.as_millis() as u64,
                            "BagEventPump tick failing persistently (relay/proof outage?); backing off"
                        );
                    } else {
                        warn!(error = ?e, consecutive_failures, "BagEventPump tick failed; will retry with backoff");
                    }
                }
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
        let user_omitted = self
            .collect_bag("user", user_bag, user_size, &mut entries)
            .await?;
        let sys_omitted = self
            .collect_bag("system", sys_bag, sys_size, &mut entries)
            .await?;
        self.note_bag_omission(user_omitted || sys_omitted);

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
        // Same backlog gauge the legacy (v≤3) poller feeds: "chain has N
        // uncompleted sessions from this validator's perspective".
        self.connector_metrics
            .uncompleted_events_backlog
            .set(snapshot_requests.len() as i64);
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
    /// field — i.e. an authenticated `Bag.size`. If the relay-listed children
    /// come up short, bump `bag_omission_suspected_total{bag}`, debug-log the
    /// detail, and return `true` so the caller can escalate across ticks (see
    /// [`Self::note_bag_omission`]). We don't fail the tick: the size could
    /// legitimately drift during the walk (sessions complete and get removed),
    /// so a single short walk is just a hint, not a proof of misbehavior —
    /// *persistent* suspicion is what to alert on.
    async fn collect_bag(
        &self,
        bag_label: &'static str,
        bag_id: ObjectID,
        expected_size: u64,
        out: &mut Vec<(ObjectID, DBSuiEvent)>,
    ) -> anyhow::Result<bool> {
        let mut page_token = None;
        let mut listed: u64 = 0;
        loop {
            let page = self
                .reader
                .verified_dynamic_fields_page(bag_id, Some(256), page_token)
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
        let suspected = self.detect_omission && listed < expected_size;
        if suspected {
            self.metrics
                .bag_omission_suspected_total
                .with_label_values(&[bag_label])
                .inc();
            debug!(
                bag = bag_label,
                listed,
                expected_size,
                "bag walk returned fewer children than verified parent claims this tick"
            );
        }
        Ok(suspected)
    }

    /// Escalate the omission log by streak length: a single warn on the first
    /// suspected tick, a single error once suspicion is *sustained* (likely a
    /// relay withholding entries — rotate it / investigate), an info on
    /// recovery, and silence in between. The per-tick
    /// `bag_omission_suspected_total` metric ticks throughout regardless; this
    /// only governs the (rate-limited) log. Consensus catch-up backstops
    /// liveness, so this is an alerting signal, not a fail-stop.
    fn note_bag_omission(&mut self, suspected: bool) {
        let (n, action) = omission_escalation(
            self.consecutive_omission_ticks,
            suspected,
            SUSTAINED_OMISSION_TICKS,
        );
        self.consecutive_omission_ticks = n;
        match action {
            OmissionEscalation::Quiet => {}
            OmissionEscalation::FirstSuspected => warn!(
                "suspected session_events bag omission (or a benign mid-walk removal); \
                 watching for persistence"
            ),
            OmissionEscalation::Sustained => error!(
                consecutive_ticks = n,
                "session_events bag omission SUSTAINED — the serving relay is likely \
                 withholding entries; rotate the relay / investigate (consensus catch-up \
                 still backstops liveness)"
            ),
            OmissionEscalation::Cleared { after } => {
                info!(after_ticks = after, "session_events bag omission cleared")
            }
        }
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
    let event_tag = match move_obj.type_().type_params().get(1)?.as_ref() {
        TypeTag::Struct(s) => (**s).clone(),
        _ => return None,
    };
    Some(DBSuiEvent {
        type_: event_tag,
        contents: move_obj.contents().to_vec(),
        // Bag entries are read out of the (OCS-verified) object state,
        // not delivered as a Sui event stream — so this is a "pulled" event.
        pulled: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn omission_escalation_warns_once_errors_when_sustained_then_clears() {
        let sustained = 3;
        // First suspected tick → one warn.
        assert_eq!(
            omission_escalation(0, true, sustained),
            (1, OmissionEscalation::FirstSuspected)
        );
        // Inside the streak, before the threshold → quiet (no per-tick spam).
        assert_eq!(
            omission_escalation(1, true, sustained),
            (2, OmissionEscalation::Quiet)
        );
        // Reaching the threshold → exactly one error.
        assert_eq!(
            omission_escalation(2, true, sustained),
            (3, OmissionEscalation::Sustained)
        );
        // Past the threshold → quiet again; the error fires once, not every tick.
        assert_eq!(
            omission_escalation(3, true, sustained),
            (4, OmissionEscalation::Quiet)
        );
        // Clean tick after a sustained streak → an info recovery line.
        assert_eq!(
            omission_escalation(4, false, sustained),
            (0, OmissionEscalation::Cleared { after: 4 })
        );
        // Clean tick after a SHORT (sub-threshold) streak → quiet, no info spam.
        assert_eq!(
            omission_escalation(2, false, sustained),
            (0, OmissionEscalation::Quiet)
        );
        // Clean tick with no prior streak → quiet.
        assert_eq!(
            omission_escalation(0, false, sustained),
            (0, OmissionEscalation::Quiet)
        );
    }

    #[test]
    fn pump_backoff_grows_from_poll_interval_and_caps() {
        let poll = Duration::from_millis(50);
        // From zero, the first backoff is the poll interval, doubled.
        let b1 = next_pump_backoff(Duration::ZERO, poll);
        assert_eq!(b1, Duration::from_millis(100));
        // Exponential growth.
        assert_eq!(next_pump_backoff(b1, poll), Duration::from_millis(200));
        // Caps at MAX_PUMP_BACKOFF (20s * 2 = 40s → clamped to the 5s cap).
        assert_eq!(
            next_pump_backoff(Duration::from_secs(20), poll),
            MAX_PUMP_BACKOFF
        );
        assert_eq!(next_pump_backoff(MAX_PUMP_BACKOFF, poll), MAX_PUMP_BACKOFF);
    }
}

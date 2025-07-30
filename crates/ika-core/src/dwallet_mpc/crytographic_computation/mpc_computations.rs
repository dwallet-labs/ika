// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::dwallet_mpc::mpc_session::MPCRoundToMessagesHashMap;
use commitment::CommitmentSizedNumber;
use group::PartyID;
use ika_types::dwallet_mpc_error::DwalletMPCResult;
use itertools::Itertools;
use mpc::{
    AsynchronouslyAdvanceable, GuaranteedOutputDeliveryParty, GuaranteedOutputDeliveryRoundResult,
    WeightedThresholdAccessStructure,
};
use rand_chacha::ChaCha20Rng;
use std::collections::hash_map::Entry::Vacant;
use std::collections::{HashMap, HashSet};

pub(crate) mod dwallet_dkg;
pub(crate) mod network_dkg;
pub(crate) mod presign;
pub(crate) mod reconfiguration;
pub(crate) mod sign;

/// This function iterates over the messages from different parties sent for
/// different MPC rounds, ordered by the consensus round they were received.
///
/// It builds a list of messages to advance the current round `current_mpc_round`,
/// using all the messages from the first consensus round to the first that satisfies the
/// following conditions:
/// - a quorum of messages from the previous round `current_mpc_round — 1` must exist
///   (except for the first round, which is always ready to advance requiring no messages as input.)
/// - a minimum number of consensus rounds that was required to delay the execution
///   (to allow more messages to come in before advancing)
///   has passed since the first consensus round where we got a quorum for this round.
/// - This quorum must be "fresh", in the sense we never tried to advance with it before.
///   There is only one case in which we attempt to advance the same round twice:
///   when we get a threshold not reached error.
///   Therefore, if such an error occurred for a consensus round, we don't stop the search,
///   and wait for at least one new message to come in a later consensus round before returning
///   the messages to advance with.
///
/// Duplicate messages are ignored — the first message a party has sent for an MPC round
/// is always used.
pub(crate) fn build_messages_to_advance(
    current_mpc_round: u64,
    rounds_to_delay: u64,
    mpc_round_to_threshold_not_reached_consensus_rounds: HashMap<u64, HashSet<u64>>,
    mut messages_by_consensus_round: HashMap<u64, MPCRoundToMessagesHashMap>,
    access_structure: &WeightedThresholdAccessStructure,
) -> Option<(Option<u64>, MPCRoundToMessagesHashMap)> {
    // The first round needs no messages as input, and is always ready to advance.
    if current_mpc_round == 1 {
        return Some((None, HashMap::new()));
    }

    let threshold_not_reached_consensus_rounds_for_current_mpc_round =
        mpc_round_to_threshold_not_reached_consensus_rounds
            .get(&current_mpc_round)
            .cloned()
            .unwrap_or_default();
    let mut delayed_rounds = 0;
    let mut got_new_messages_since_last_threshold_not_reached = false;
    let mut messages_for_advance: MPCRoundToMessagesHashMap = HashMap::new();

    // Make sure the messages are consecutive by inserting the default value (i.e. empty message map) for missing rounds.
    // This is just an extra step, as we should update sessions in every consensus round even if no new message were received.
    // It is important for computing delay.
    if let Some(&first_consensus_round) = messages_by_consensus_round.keys().min() {
        if let Some(&last_consensus_round) = messages_by_consensus_round.keys().max() {
            for consensus_round in first_consensus_round..=last_consensus_round {
                messages_by_consensus_round
                    .entry(consensus_round)
                    .or_default();
            }
        }
    }

    let sorted_messages_by_consensus_round = messages_by_consensus_round
        .clone()
        .into_iter()
        .sorted_by(|(first_consensus_round, _), (second_consensus_round, _)| {
            first_consensus_round.cmp(second_consensus_round)
        });

    for (consensus_round, consensus_round_messages) in sorted_messages_by_consensus_round {
        // Update messages to advance the current round by joining the messages
        // received at the current consensus round
        // with the ones we collected so far, ignoring duplicates.
        for (mpc_round, mpc_round_messages) in consensus_round_messages {
            if mpc_round < current_mpc_round {
                for (sender_party_id, message) in mpc_round_messages {
                    let mpc_round_messages_map = messages_for_advance.entry(mpc_round).or_default();

                    if let Vacant(e) = mpc_round_messages_map.entry(sender_party_id) {
                        // Always take the first message sent in consensus by a
                        // particular party for a particular round.
                        e.insert(message);
                        got_new_messages_since_last_threshold_not_reached = true;
                    }
                }
            }
        }

        // Check if we have the threshold of messages for the previous round
        // to advance to the next round.
        let is_quorum_reached = if let Some(previous_round_messages) =
            messages_for_advance.get(&(current_mpc_round - 1))
        {
            let previous_round_message_senders: HashSet<PartyID> =
                previous_round_messages.keys().cloned().collect();

            access_structure
                .is_authorized_subset(&previous_round_message_senders)
                .is_ok()
        } else {
            false
        };

        if is_quorum_reached {
            if delayed_rounds != rounds_to_delay {
                // Wait for the delay.
                // We set the map of messages by consensus round at each consensus round for
                // each session, even if no messages were received, so this count is
                // accurate as iterating the messages by consensus round goes through all
                // consensus rounds to date.
                delayed_rounds += 1;
            } else if threshold_not_reached_consensus_rounds_for_current_mpc_round
                .contains(&consensus_round)
            {
                // We already tried executing this MPC round at the current consensus round, no point in trying again.
                // Wait for new messages in later rounds before retrying.
                got_new_messages_since_last_threshold_not_reached = false;
            } else if got_new_messages_since_last_threshold_not_reached {
                // We have a quorum of previous round messages,
                // we delayed the execution as and if required,
                // and we know we haven't tried to advance the current MPC round with this
                // set of messages, so we have a chance at advancing (and reaching threshold):
                // Let's try advancing with this set of messages!
                return Some((Some(consensus_round), messages_for_advance));
            }
        }
    }

    // If we reached here, we either got no quorum of previous round messages,
    // or we need to delay execution further,
    // or we need to wait for more messages before retrying after a threshold not reached has occurred.
    // This session is not ready to advance.
    None
}

/// Advances the state of an MPC party and serializes the result into bytes.
///
/// This helper function wraps around a party `P`'s `advance()` method,
/// converting its output into a serialized byte format.
/// This abstraction allows the system's generic components to operate uniformly on byte arrays,
/// rather than requiring generics to handle the different message and output types
/// for each MPC protocol.
///
/// By maintaining a structured transition between instantiated types, and their
/// serialized forms, this function ensures compatibility across various components.
pub(crate) fn advance<P: AsynchronouslyAdvanceable>(
    session_id: CommitmentSizedNumber,
    party_id: PartyID,
    access_structure: &WeightedThresholdAccessStructure,
    serialized_messages: MPCRoundToMessagesHashMap,
    public_input: &P::PublicInput,
    private_input: P::PrivateInput,
    mut rng: ChaCha20Rng,
) -> DwalletMPCResult<GuaranteedOutputDeliveryRoundResult> {
    // When a `ThresholdNotReached` error is received, the system now waits for additional messages
    // (including those from previous rounds) and retries.
    match P::advance_with_guaranteed_output(
        session_id,
        party_id,
        access_structure,
        serialized_messages.clone(),
        Some(private_input),
        public_input,
        &mut rng,
    ) {
        Ok(res) => Ok(res),
        Err(e) => match e.into() {
            mpc::Error::ThresholdNotReached => Err(mpc::Error::ThresholdNotReached)?,
            e => Err(e)?,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use group::OsCsRng;

    #[test]
    fn builds_empty_messages_for_round1() {
        let access_structure =
            WeightedThresholdAccessStructure::uniform(3, 4, 4, &mut OsCsRng).unwrap();

        let current_mpc_round = 1;
        let rounds_to_delay = 0;
        let mpc_round_to_threshold_not_reached_consensus_rounds = HashMap::new();
        let messages_by_consensus_round = HashMap::new();
        let messages = build_messages_to_advance(
            current_mpc_round,
            rounds_to_delay,
            mpc_round_to_threshold_not_reached_consensus_rounds.clone(),
            messages_by_consensus_round,
            &access_structure,
        );

        assert_eq!(messages, Some((None, HashMap::new())));

        let messages_by_consensus_round = HashMap::from([
            (
                3,
                HashMap::from([(1, HashMap::from([(1u16, vec![42u8]), (3, vec![42u8])]))]),
            ),
            (4, HashMap::new()),
        ]);
        let messages = build_messages_to_advance(
            current_mpc_round,
            rounds_to_delay,
            mpc_round_to_threshold_not_reached_consensus_rounds,
            messages_by_consensus_round,
            &access_structure,
        );

        assert_eq!(messages, Some((None, HashMap::new())));
    }

    #[test]
    fn builds_messages_for_round2() {
        let access_structure =
            WeightedThresholdAccessStructure::uniform(3, 4, 4, &mut OsCsRng).unwrap();

        let current_mpc_round = 2;
        let rounds_to_delay = 0;
        let mpc_round_to_threshold_not_reached_consensus_rounds = HashMap::new();
        let round1_messages = HashMap::from([
            (1u16, vec![42u8]),
            (2u16, vec![0u8, 42u8]),
            (3, vec![43u8]),
            (4u16, vec![42u8]),
        ]);
        let messages_by_consensus_round = HashMap::from([
            (
                3,
                HashMap::from([(
                    1,
                    HashMap::from([
                        (1, round1_messages.get(&1).unwrap().clone()),
                        (3, round1_messages.get(&3).unwrap().clone()),
                    ]),
                )]),
            ),
            (4, HashMap::new()),
            (
                5,
                HashMap::from([(
                    1,
                    HashMap::from([(4, round1_messages.get(&4).unwrap().clone())]),
                )]),
            ),
            (6, HashMap::new()),
            (
                7,
                HashMap::from([(
                    1,
                    HashMap::from([(2, round1_messages.get(&2).unwrap().clone())]),
                )]),
            ),
        ]);

        let messages = build_messages_to_advance(
            current_mpc_round,
            rounds_to_delay,
            mpc_round_to_threshold_not_reached_consensus_rounds,
            messages_by_consensus_round,
            &access_structure,
        );
        let expected_messages = HashMap::from([(
            1,
            round1_messages
                .clone()
                .into_iter()
                .filter(|(pid, _)| *pid != 2)
                .collect(),
        )]);

        assert_eq!(messages, Some((Some(5), expected_messages)));
    }

    #[test]
    fn doesnt_build_messages_for_round2_no_quorum() {
        let access_structure =
            WeightedThresholdAccessStructure::uniform(3, 4, 4, &mut OsCsRng).unwrap();

        let current_mpc_round = 2;
        let rounds_to_delay = 0;
        let mpc_round_to_threshold_not_reached_consensus_rounds = HashMap::new();
        let messages_by_consensus_round = HashMap::from([
            (
                3,
                HashMap::from([(1, HashMap::from([(1u16, vec![42u8]), (3, vec![42u8])]))]),
            ),
            (4, HashMap::new()),
        ]);
        let messages = build_messages_to_advance(
            current_mpc_round,
            rounds_to_delay,
            mpc_round_to_threshold_not_reached_consensus_rounds,
            messages_by_consensus_round,
            &access_structure,
        );

        assert_eq!(messages, None);
    }

    #[test]
    fn doesnt_build_messages_for_round2_insufficent_delay() {
        let access_structure =
            WeightedThresholdAccessStructure::uniform(3, 4, 4, &mut OsCsRng).unwrap();

        let current_mpc_round = 2;
        let rounds_to_delay = 3;
        let mpc_round_to_threshold_not_reached_consensus_rounds = HashMap::new();
        let round1_messages = HashMap::from([
            (1u16, vec![42u8]),
            (2u16, vec![0u8, 42u8]),
            (3, vec![43u8]),
            (4u16, vec![42u8]),
        ]);
        let messages_by_consensus_round = HashMap::from([
            (
                3,
                HashMap::from([(
                    1,
                    HashMap::from([
                        (1, round1_messages.get(&1).unwrap().clone()),
                        (3, round1_messages.get(&3).unwrap().clone()),
                    ]),
                )]),
            ),
            (4, HashMap::new()),
            (
                5,
                HashMap::from([(
                    1,
                    HashMap::from([(4, round1_messages.get(&4).unwrap().clone())]),
                )]),
            ),
            (6, HashMap::new()),
            (
                7,
                HashMap::from([(
                    1,
                    HashMap::from([(2, round1_messages.get(&2).unwrap().clone())]),
                )]),
            ),
        ]);

        let messages = build_messages_to_advance(
            current_mpc_round,
            rounds_to_delay,
            mpc_round_to_threshold_not_reached_consensus_rounds,
            messages_by_consensus_round,
            &access_structure,
        );

        assert_eq!(messages, None);
    }

    #[test]
    fn delays_and_builds_messages_for_round2() {
        let access_structure =
            WeightedThresholdAccessStructure::uniform(3, 4, 4, &mut OsCsRng).unwrap();

        let current_mpc_round = 2;
        let mpc_round_to_threshold_not_reached_consensus_rounds = HashMap::new();
        let round1_messages = HashMap::from([
            (1u16, vec![42u8]),
            (2u16, vec![0u8, 42u8]),
            (3, vec![43u8]),
            (4u16, vec![42u8]),
        ]);
        let messages_by_consensus_round = HashMap::from([
            (
                3,
                HashMap::from([(
                    1,
                    HashMap::from([
                        (1, round1_messages.get(&1).unwrap().clone()),
                        (3, round1_messages.get(&3).unwrap().clone()),
                    ]),
                )]),
            ),
            (4, HashMap::new()),
            (
                5,
                HashMap::from([(
                    1,
                    HashMap::from([(4, round1_messages.get(&4).unwrap().clone())]),
                )]),
            ),
            (6, HashMap::new()),
            (
                7,
                HashMap::from([(
                    1,
                    HashMap::from([(2, round1_messages.get(&2).unwrap().clone())]),
                )]),
            ),
            (8, HashMap::new()),
        ]);

        let rounds_to_delay = 1;
        let messages = build_messages_to_advance(
            current_mpc_round,
            rounds_to_delay,
            mpc_round_to_threshold_not_reached_consensus_rounds.clone(),
            messages_by_consensus_round.clone(),
            &access_structure,
        );
        let expected_messages = HashMap::from([(
            1,
            round1_messages
                .clone()
                .into_iter()
                .filter(|(pid, _)| *pid != 2)
                .collect(),
        )]);

        assert_eq!(messages, Some((Some(6), expected_messages)));

        let rounds_to_delay = 2;
        let messages = build_messages_to_advance(
            current_mpc_round,
            rounds_to_delay,
            mpc_round_to_threshold_not_reached_consensus_rounds.clone(),
            messages_by_consensus_round.clone(),
            &access_structure,
        );

        assert_eq!(
            messages,
            Some((Some(7), HashMap::from([(1, round1_messages.clone())])))
        );

        let rounds_to_delay = 3;
        let messages = build_messages_to_advance(
            current_mpc_round,
            rounds_to_delay,
            mpc_round_to_threshold_not_reached_consensus_rounds,
            messages_by_consensus_round,
            &access_structure,
        );

        assert_eq!(
            messages,
            Some((Some(8), HashMap::from([(1, round1_messages)])))
        );
    }

    #[test]
    fn builds_messages_for_round3() {
        let access_structure =
            WeightedThresholdAccessStructure::uniform(3, 4, 4, &mut OsCsRng).unwrap();

        let current_mpc_round = 3;
        let rounds_to_delay = 0;
        let mpc_round_to_threshold_not_reached_consensus_rounds = HashMap::new();
        let round1_messages = HashMap::from([
            (1u16, vec![42u8]),
            (2u16, vec![0u8, 42u8]),
            (3, vec![43u8]),
            (4u16, vec![42u8]),
        ]);
        let round2_messages =
            HashMap::from([(1u16, vec![]), (2u16, vec![0u8, 1u8]), (4u16, vec![42u8])]);
        let messages_by_consensus_round = HashMap::from([
            (
                3,
                HashMap::from([(
                    1,
                    HashMap::from([
                        (1, round1_messages.get(&1).unwrap().clone()),
                        (3, round1_messages.get(&3).unwrap().clone()),
                    ]),
                )]),
            ),
            (4, HashMap::new()),
            (
                5,
                HashMap::from([(
                    1,
                    HashMap::from([(4, round1_messages.get(&4).unwrap().clone())]),
                )]),
            ),
            (6, HashMap::new()),
            (
                7,
                HashMap::from([
                    (
                        1,
                        HashMap::from([(2, round1_messages.get(&2).unwrap().clone())]),
                    ),
                    (
                        2,
                        HashMap::from([
                            (1, round2_messages.get(&1).unwrap().clone()),
                            (4, round2_messages.get(&4).unwrap().clone()),
                        ]),
                    ),
                ]),
            ),
            (
                8,
                HashMap::from([(
                    2,
                    HashMap::from([(2, round2_messages.get(&2).unwrap().clone())]),
                )]),
            ),
        ]);

        let messages = build_messages_to_advance(
            current_mpc_round,
            rounds_to_delay,
            mpc_round_to_threshold_not_reached_consensus_rounds,
            messages_by_consensus_round,
            &access_structure,
        );
        let expected_messages = HashMap::from([(1, round1_messages), (2, round2_messages)]);

        assert_eq!(messages, Some((Some(8), expected_messages)));
    }

    #[test]
    fn builds_messages_with_threshold_not_reached() {
        let access_structure =
            WeightedThresholdAccessStructure::uniform(3, 4, 4, &mut OsCsRng).unwrap();

        let rounds_to_delay = 0;
        let round1_messages = HashMap::from([
            (1u16, vec![42u8]),
            (2u16, vec![0u8, 42u8]),
            (3, vec![43u8]),
            (4u16, vec![42u8]),
        ]);
        let round2_messages = HashMap::from([
            (1u16, vec![]),
            (2u16, vec![0u8, 1u8]),
            (3u16, vec![0u8, 1u8]),
            (4u16, vec![42u8]),
        ]);
        let messages_by_consensus_round = HashMap::from([
            (
                3,
                HashMap::from([(
                    1,
                    HashMap::from([
                        (1, round1_messages.get(&1).unwrap().clone()),
                        (3, round1_messages.get(&3).unwrap().clone()),
                    ]),
                )]),
            ),
            (4, HashMap::new()),
            (
                5,
                HashMap::from([(
                    1,
                    HashMap::from([(4, round1_messages.get(&4).unwrap().clone())]),
                )]),
            ),
            (6, HashMap::new()),
            (
                7,
                HashMap::from([
                    (
                        1,
                        HashMap::from([(2, round1_messages.get(&2).unwrap().clone())]),
                    ),
                    // 3 was malicious, sent round 2 even though threshold not reached
                    (
                        2,
                        HashMap::from([(3, round2_messages.get(&3).unwrap().clone())]),
                    ),
                ]),
            ),
            (
                8,
                HashMap::from([(
                    2,
                    HashMap::from([
                        (1, round2_messages.get(&1).unwrap().clone()),
                        (4, round2_messages.get(&4).unwrap().clone()),
                    ]),
                )]),
            ),
            (
                9,
                HashMap::from([(
                    2,
                    HashMap::from([(2, round2_messages.get(&2).unwrap().clone())]),
                )]),
            ),
        ]);

        let current_mpc_round = 2;
        let mpc_round_to_threshold_not_reached_consensus_rounds =
            HashMap::from([(2, HashSet::from([5]))]);
        let messages = build_messages_to_advance(
            current_mpc_round,
            rounds_to_delay,
            mpc_round_to_threshold_not_reached_consensus_rounds,
            messages_by_consensus_round
                .clone()
                .into_iter()
                .filter(|(consensus_round, _)| *consensus_round <= 6)
                .collect(),
            &access_structure,
        );
        assert_eq!(messages, None);

        let current_mpc_round = 2;
        let mpc_round_to_threshold_not_reached_consensus_rounds =
            HashMap::from([(2, HashSet::from([5]))]);
        let messages = build_messages_to_advance(
            current_mpc_round,
            rounds_to_delay,
            mpc_round_to_threshold_not_reached_consensus_rounds,
            messages_by_consensus_round.clone(),
            &access_structure,
        );
        let expected_messages = HashMap::from([(1, round1_messages.clone())]);

        assert_eq!(messages, Some((Some(7), expected_messages)));

        let current_mpc_round = 3;
        let mpc_round_to_threshold_not_reached_consensus_rounds =
            HashMap::from([(2, HashSet::from([5]))]);
        let messages = build_messages_to_advance(
            current_mpc_round,
            rounds_to_delay,
            mpc_round_to_threshold_not_reached_consensus_rounds,
            messages_by_consensus_round.clone(),
            &access_structure,
        );
        let expected_messages = HashMap::from([
            (1, round1_messages.clone()),
            (
                2,
                round2_messages
                    .clone()
                    .into_iter()
                    .filter(|(pid, _)| *pid != 2)
                    .collect(),
            ),
        ]);

        assert_eq!(messages, Some((Some(8), expected_messages)));

        let current_mpc_round = 3;
        let mpc_round_to_threshold_not_reached_consensus_rounds =
            HashMap::from([(2, HashSet::from([5])), (3, HashSet::from([8]))]);
        let messages = build_messages_to_advance(
            current_mpc_round,
            rounds_to_delay,
            mpc_round_to_threshold_not_reached_consensus_rounds,
            messages_by_consensus_round.clone(),
            &access_structure,
        );
        let expected_messages = HashMap::from([(1, round1_messages), (2, round2_messages)]);

        assert_eq!(messages, Some((Some(9), expected_messages)));
    }
}

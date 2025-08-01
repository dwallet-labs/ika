// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear
use std::{cmp::Ordering, fmt::Display};

use consensus_core::{BlockAPI, BlockRef, CommitDigest, TransactionIndex, VerifiedBlock};
use ika_types::{
    digests::ConsensusCommitDigest,
    messages_consensus::{AuthorityIndex, ConsensusTransaction},
};

pub(crate) struct ParsedTransaction {
    // Transaction from consensus output.
    pub(crate) transaction: ConsensusTransaction,
    // Whether the transaction was rejected in voting.
    pub(crate) rejected: bool,
    // Byte length of the serialized transaction.
    pub(crate) serialized_len: usize,
}

pub(crate) trait ConsensusCommitAPI: Display {
    fn reputation_score_sorted_desc(&self) -> Option<Vec<(AuthorityIndex, u64)>>;
    fn leader_round(&self) -> u64;
    fn leader_author_index(&self) -> AuthorityIndex;

    /// Returns epoch UNIX timestamp in milliseconds
    fn commit_timestamp_ms(&self) -> u64;

    /// Returns a unique global index for each committed sub-dag.
    fn commit_sub_dag_index(&self) -> u64;

    /// Returns all accepted and rejected transactions per block in the commit in deterministic order.
    fn transactions(&self) -> Vec<(BlockRef, Vec<ParsedTransaction>)>;

    /// Returns the digest of consensus output.
    fn consensus_digest(&self) -> ConsensusCommitDigest;
}

impl ConsensusCommitAPI for consensus_core::CommittedSubDag {
    fn reputation_score_sorted_desc(&self) -> Option<Vec<(AuthorityIndex, u64)>> {
        if !self.reputation_scores_desc.is_empty() {
            Some(
                self.reputation_scores_desc
                    .iter()
                    .map(|(id, score)| (id.value() as AuthorityIndex, *score))
                    .collect(),
            )
        } else {
            None
        }
    }

    fn leader_round(&self) -> u64 {
        self.leader.round as u64
    }

    fn leader_author_index(&self) -> AuthorityIndex {
        self.leader.author.value() as AuthorityIndex
    }

    fn commit_timestamp_ms(&self) -> u64 {
        // TODO: Enforce ordered timestamp in Mysticeti.
        self.timestamp_ms
    }

    fn commit_sub_dag_index(&self) -> u64 {
        self.commit_ref.index.into()
    }

    fn transactions(&self) -> Vec<(BlockRef, Vec<ParsedTransaction>)> {
        let no_transaction = vec![];
        self.blocks
            .iter()
            .map(|block| {
                let rejected_transactions = self
                    .rejected_transactions_by_block
                    .get(&block.reference())
                    .unwrap_or(&no_transaction);
                (
                    block.reference(),
                    parse_block_transactions(block, rejected_transactions),
                )
            })
            .collect()
    }

    fn consensus_digest(&self) -> ConsensusCommitDigest {
        // We port CommitDigest, a consensus space object, into ConsensusCommitDigest, an ika-core space object.
        // We assume they always have the same format.
        static_assertions::assert_eq_size!(ConsensusCommitDigest, CommitDigest);
        ConsensusCommitDigest::new(self.commit_ref.digest.into_inner())
    }
}

pub(crate) fn parse_block_transactions(
    block: &VerifiedBlock,
    rejected_transactions: &[TransactionIndex],
) -> Vec<ParsedTransaction> {
    let round = block.round();
    let authority = block.author().value() as AuthorityIndex;

    let mut rejected_idx = 0;
    block
        .transactions()
        .iter().enumerate()
        .map(|(index, tx)| {
            let transaction = match bcs::from_bytes::<ConsensusTransaction>(tx.data()) {
                Ok(transaction) => transaction,
                Err(err) => {
                    panic!("Failed to deserialize sequenced consensus transaction (this should not happen) {err} from {authority} at {round}");
                },
            };
            let rejected = if rejected_idx < rejected_transactions.len() {
                match (index as TransactionIndex).cmp(&rejected_transactions[rejected_idx]) {
                    Ordering::Less => {
                        false
                    },
                    Ordering::Equal => {
                        rejected_idx += 1;
                        true
                    },
                    Ordering::Greater => {
                        panic!("Rejected transaction indices are not in order. Block {block:?}, rejected transactions: {rejected_transactions:?}");
                    },
                }
            } else {
                false
            };
            ParsedTransaction {
                transaction,
                rejected,
                serialized_len: tx.data().len(),
            }
        })
        .collect()
}

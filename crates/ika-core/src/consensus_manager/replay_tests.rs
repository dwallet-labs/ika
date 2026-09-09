// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwap;
use consensus_config::{ConsensusProtocolConfig, NetworkKeyPair, ProtocolKeyPair};
use consensus_core::storage::rocksdb_store::RocksDBStore;
use consensus_core::storage::{Store, WriteBatch};
use consensus_core::{
    BlockAPI, Clock, CommitConsumerArgs, CommittedSubDag, ConsensusAuthority, Context, DagBuilder,
    NetworkType, TransactionVerifier, ValidationError,
};
use consensus_types::block::{BlockRef, TransactionIndex};
use prometheus::Registry;
use tempfile::TempDir;
use tokio::time::{sleep, timeout};

use crate::authority::AuthorityMetrics;
use crate::authority::authority_per_epoch_store::{
    AuthorityPerEpochStore, AuthorityPerEpochStoreTrait, EpochStoreParams,
};
use crate::authority::epoch_start_configuration::EpochStartConfiguration;
use crate::authority::round_transport::round_transport;
use crate::consensus_handler::{ConsensusCommitSink, ConsensusHandler, MysticetiConsensusHandler};
use crate::consensus_manager::ConsensusManagerMetrics;
use crate::consensus_throughput_calculator::ConsensusThroughputCalculator;
use crate::dwallet_checkpoints::DWalletCheckpointService;
use crate::epoch::epoch_metrics::EpochMetrics;
use ika_types::committee::Committee;
use ika_types::digests::ChainIdentifier;
use ika_types::messages_dwallet_mpc::IkaNetworkConfig;
use ika_types::sui::EpochStartSystem;

const CONSENSUS_COMMITTEE_SIZE: usize = 4;

struct AcceptEmptyTransactions;
impl TransactionVerifier for AcceptEmptyTransactions {
    fn verify_batch(&self, batch: &[&[u8]]) -> Result<(), ValidationError> {
        assert!(
            batch.is_empty(),
            "the replay fixture carries no application transactions"
        );
        Ok(())
    }
    fn verify_and_vote_batch(
        &self,
        _block: &BlockRef,
        batch: &[&[u8]],
    ) -> Result<Vec<TransactionIndex>, ValidationError> {
        self.verify_batch(batch)?;
        Ok(Vec::new())
    }
}

struct Fixture {
    _directory: TempDir,
    context: Arc<Context>,
    network_key: NetworkKeyPair,
    protocol_key: ProtocolKeyPair,
    commits: Vec<CommittedSubDag>,
}

impl Fixture {
    fn new(commits: u32) -> Self {
        let directory = TempDir::new().unwrap();
        let (mut context, mut keys) = Context::new_for_test(CONSENSUS_COMMITTEE_SIZE);
        context.parameters.db_path = directory.path().to_path_buf();
        context.parameters.sync_last_known_own_block_timeout = Duration::ZERO;
        context.protocol_config = ConsensusProtocolConfig::default();
        assert!(!context.protocol_config.transaction_voting_enabled());
        let context = Arc::new(context);
        let fixture_context = context.clone();
        // A separate runtime joins its blocking metrics workers on drop. The
        // fixture's writer is fully gone before the production authority opens
        // storage, just as it is after a real process restart.
        let produced = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let store =
                    RocksDBStore::new(&fixture_context.parameters.db_path.to_string_lossy());
                let mut result = Vec::new();
                if commits > 0 {
                    let mut dag = DagBuilder::new(fixture_context);
                    dag.layers(1..=(commits * 2 + 2)).build();
                    for (subdag, commit) in dag
                        .get_sub_dag_and_commits(1..=commits)
                        .into_iter()
                        .take(commits as usize)
                    {
                        // Production has no finalized rows with voting off.
                        store
                            .write(WriteBatch::new(
                                subdag.blocks.clone(),
                                vec![commit],
                                Vec::new(),
                                Vec::new(),
                            ))
                            .unwrap();
                        result.push(subdag);
                    }
                    // A real authority also recovers its pending DAG. Retain
                    // the quorum of parents at the stored commit's round so
                    // it can propose after replay, without adding future
                    // rounds that could form additional commits in this test.
                    let head = result.last().unwrap().leader.round;
                    store
                        .write(WriteBatch::new(
                            dag.all_blocks()
                                .into_iter()
                                .filter(|block| block.round() <= head)
                                .collect(),
                            Vec::new(),
                            Vec::new(),
                            Vec::new(),
                        ))
                        .unwrap();
                }
                assert_eq!(result.len(), commits as usize);
                result
            })
        })
        .join()
        .unwrap();
        let (network_key, protocol_key) = keys.remove(0);
        Self {
            _directory: directory,
            context,
            network_key,
            protocol_key,
            commits: produced,
        }
    }

    async fn start(&self, consumer: CommitConsumerArgs) -> ConsensusAuthority {
        ConsensusAuthority::start(
            NetworkType::Tonic,
            0,
            self.context.committee.clone(),
            self.context.parameters.clone(),
            self.context.protocol_config.clone(),
            Some(self.protocol_key.clone()),
            self.network_key.clone(),
            Arc::new(Clock::default()),
            Arc::new(AcceptEmptyTransactions),
            None,
            consumer,
            Registry::new(),
            1,
            None,
        )
        .await
    }
}

fn test_epoch_store(dir: &Path) -> Arc<AuthorityPerEpochStore> {
    let (committee, _keys) = Committee::new_simple_test_committee_of_size(CONSENSUS_COMMITTEE_SIZE);
    let committee = Arc::new(committee);
    let name = *committee.names().next().unwrap();
    let params = EpochStoreParams {
        name,
        committee,
        parent_path: dir.to_path_buf(),
        db_options: None,
        metrics: EpochMetrics::new(&Registry::new()),
        epoch_start_configuration: EpochStartConfiguration::new(
            EpochStartSystem::new_for_testing_with_epoch(0),
        )
        .unwrap(),
        chain_identifier: ChainIdentifier::default(),
        packages_config: IkaNetworkConfig::new_for_testing(),
    };
    AuthorityPerEpochStore::new(params).unwrap()
}

fn test_handler(
    epoch_store: Arc<AuthorityPerEpochStore>,
    context: &Context,
) -> ConsensusHandler<DWalletCheckpointService> {
    test_handler_with_sink(epoch_store, context, None)
}

fn test_handler_with_sink(
    epoch_store: Arc<AuthorityPerEpochStore>,
    context: &Context,
    commit_sink: Option<Arc<dyn ConsensusCommitSink>>,
) -> ConsensusHandler<DWalletCheckpointService> {
    let metrics = Arc::new(AuthorityMetrics::new(&Registry::new()));
    ConsensusHandler::new(
        epoch_store,
        None,
        None,
        Arc::new(ArcSwap::from_pointee(HashMap::new())),
        context.committee.clone(),
        metrics.clone(),
        Arc::new(ConsensusThroughputCalculator::new(None, metrics)),
        commit_sink,
    )
}

#[derive(Default)]
struct CountingCommitSink {
    rounds: Mutex<Vec<u64>>,
}

impl ConsensusCommitSink for CountingCommitSink {
    fn commit_received(&self, leader_round: u64) {
        self.rounds.lock().unwrap().push(leader_round);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn consensus_owned_replay_matches_the_live_handler_and_reports_every_round() {
    let fixture = Fixture::new(7);
    let epoch_dir = TempDir::new().unwrap();
    let epoch = test_epoch_store(epoch_dir.path());
    let (sender, mut rounds) = round_transport(1024, Arc::new(AtomicBool::new(false)));
    epoch.install_round_transport(sender);
    let sink = Arc::new(CountingCommitSink::default());
    let handler = test_handler_with_sink(epoch.clone(), &fixture.context, Some(sink.clone()));
    let metrics = Arc::new(ConsensusManagerMetrics::new(&Registry::new()));
    let (consumer, receiver) = CommitConsumerArgs::new_with_full_replay();
    let monitor = consumer.monitor();
    let mut handler =
        MysticetiConsensusHandler::new(handler, receiver, monitor.clone(), metrics.clone());
    let authority = timeout(Duration::from_secs(30), fixture.start(consumer))
        .await
        .unwrap();
    monitor
        .replay_to_consumer_last_processed_commit_complete()
        .await;
    assert_eq!(monitor.progress().replay_target, Some(7));
    assert_eq!(monitor.highest_handled_commit(), 7);
    assert_eq!(
        epoch
            .get_last_consensus_stats()
            .unwrap()
            .index
            .sub_dag_index,
        7
    );
    assert_eq!(sink.rounds.lock().unwrap().len(), 7);
    let mut received_rounds = Vec::new();
    while let Ok(round) = rounds.try_recv() {
        received_rounds.push(round.round);
    }
    assert_eq!(received_rounds.len(), 7);
    assert!(received_rounds.windows(2).all(|pair| pair[0] < pair[1]));

    let live_dir = TempDir::new().unwrap();
    let live_epoch = test_epoch_store(live_dir.path());
    let mut live_handler = test_handler(live_epoch.clone(), &fixture.context);
    for commit in fixture.commits.iter().cloned() {
        live_handler.report_commit_received(&commit);
        live_handler.handle_consensus_commit(commit).await;
    }
    let replayed = epoch.derived_state_snapshot();
    assert!(
        replayed
            .values()
            .filter(|bytes| bytes.as_slice() != [0])
            .count()
            >= 2,
        "the replay comparison must cover populated state"
    );
    assert_eq!(replayed, live_epoch.derived_state_snapshot());
    timeout(Duration::from_secs(2), async {
        while metrics.boot_replay_folded_commit_index.get() != 7 {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(metrics.boot_replay_target_commit_index.get(), 7);
    authority.stop().await;
    handler.abort().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn consensus_owned_replay_discovers_empty_and_short_histories() {
    for commits in [0, 3] {
        let fixture = Fixture::new(commits);
        let epoch_dir = TempDir::new().unwrap();
        let epoch = test_epoch_store(epoch_dir.path());
        let (consumer, receiver) = CommitConsumerArgs::new_with_full_replay();
        let monitor = consumer.monitor();
        assert_eq!(monitor.progress().replay_target, None);
        let mut handler = MysticetiConsensusHandler::new(
            test_handler(epoch.clone(), &fixture.context),
            receiver,
            monitor.clone(),
            Arc::new(ConsensusManagerMetrics::new(&Registry::new())),
        );
        let authority = timeout(Duration::from_secs(30), fixture.start(consumer))
            .await
            .unwrap();
        monitor
            .replay_to_consumer_last_processed_commit_complete()
            .await;
        assert_eq!(monitor.progress().replay_target, Some(commits));
        assert_eq!(monitor.highest_handled_commit(), commits);
        assert_eq!(
            epoch
                .get_last_consensus_stats()
                .unwrap()
                .index
                .sub_dag_index,
            u64::from(commits)
        );
        authority.stop().await;
        handler.abort().await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn consensus_head_is_visible_while_the_handler_is_blocked_and_replay_waits() {
    for commits in [2, 7] {
        let fixture = Fixture::new(commits);
        let epoch_dir = TempDir::new().unwrap();
        let epoch = test_epoch_store(epoch_dir.path());
        let (sender, mut rounds) = round_transport(1, Arc::new(AtomicBool::new(false)));
        epoch.install_round_transport(sender);
        let (consumer, receiver) = CommitConsumerArgs::new_with_full_replay();
        let monitor = consumer.monitor();
        let mut handler = MysticetiConsensusHandler::new(
            test_handler(epoch.clone(), &fixture.context),
            receiver,
            monitor.clone(),
            Arc::new(ConsensusManagerMetrics::new(&Registry::new())),
        );
        let start = fixture.start(consumer);
        tokio::pin!(start);
        assert!(
            timeout(Duration::from_millis(200), &mut start)
                .await
                .is_err(),
            "consensus startup must wait for the blocked replay fold"
        );
        let head = fixture.commits.last().unwrap().leader.round;
        timeout(Duration::from_secs(2), async {
            while epoch.observed_consensus_head_round() != u64::from(head) {
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the consensus head must be published independently of the blocked fold");
        assert!(monitor.highest_handled_commit() < commits);
        assert!(
            timeout(
                Duration::from_millis(50),
                monitor.replay_to_consumer_last_processed_commit_complete()
            )
            .await
            .is_err()
        );
        let drain = tokio::spawn(async move {
            for _ in 0..commits {
                rounds.recv().await.unwrap();
            }
        });
        let authority = timeout(Duration::from_secs(30), &mut start).await.unwrap();
        drain.await.unwrap();
        assert_eq!(monitor.highest_handled_commit(), commits);
        authority.stop().await;
        handler.abort().await;
    }
}

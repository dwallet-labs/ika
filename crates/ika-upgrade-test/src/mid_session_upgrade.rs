// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Resume one identified reconfiguration session across an OLD-to-NEW restart.
//! One peer stays suspended so the remaining OLD peers cannot complete without
//! the upgraded validator. All evidence is scoped to the same session and boot.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use fastcrypto::traits::KeyPair;
use ika_types::crypto::AuthorityName;
use tokio::time::{Instant, sleep, timeout as bounded};

use crate::cluster::{ClusterOfProcesses, parse_metric_samples};

const PROTOCOL: &str = "Network Encryption Key Reconfiguration";
const MISSING_CONTRIBUTION: &str = "mid-session upgrade missing post-upgrade contribution";

/// Freeze a live reconfiguration after OLD has committed its first two rounds,
/// restart validator zero on NEW, and require its accepted contribution to that
/// exact session. `participation_control` deliberately withholds NEW and lets
/// three OLD peers finish: the same participation guard must then fail.
///
/// The caller must enable DEBUG for `crytographic_computation::request`,
/// `crytographic_computation::orchestrator`, `dwallet_mpc_service`,
/// `mpc_manager`, and `mpc_session` before starting the literal OLD processes.
pub async fn verify_mid_session_upgrade(
    cluster: &mut ClusterOfProcesses,
    new_binary: PathBuf,
    epoch: u64,
    timeout: Duration,
    participation_control: bool,
) -> Result<()> {
    ensure!(
        cluster.validators.len() == 4,
        "mid-session upgrade requires exactly four validators"
    );
    ensure!(
        timeout <= Duration::from_secs(600),
        "mid-session suspension must be bounded to at most 600 seconds"
    );
    cluster.assert_mid_session_committee().await?;
    ensure!(
        cluster.current_epoch().await? == epoch,
        "wrong epoch before mid-session upgrade"
    );
    cluster
        .expect_network_key_reconfiguration_not_started(epoch)
        .await?;
    let result = bounded(
        timeout,
        verify_inner(cluster, new_binary, epoch, participation_control),
    )
    .await
    .context("mid-session upgrade timed out before its identified session completed")
    .and_then(|result| result);
    // Also run after a timeout or failed assertion: a stopped peer must never
    // remain suspended while a caller collects artifacts or tears down children.
    let mut cleanup_errors = Vec::new();
    for validator in &mut cluster.validators {
        if let Err(error) = validator.resume().await {
            cleanup_errors.push(format!("validator {}: {error:#}", validator.index));
        }
    }
    if !cleanup_errors.is_empty() {
        bail!(
            "mid-session cleanup failed: {}; original result: {result:?}",
            cleanup_errors.join("; ")
        );
    }
    result
}

async fn verify_inner(
    cluster: &mut ClusterOfProcesses,
    new_binary: PathBuf,
    epoch: u64,
    participation_control: bool,
) -> Result<()> {
    let authorities = cluster
        .validators
        .iter()
        .map(|validator| {
            let config = validator.read_config()?;
            Ok(AuthorityName::from_consensus_key(config.consensus_key_pair().public()).to_string())
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        authorities.iter().collect::<BTreeSet<_>>().len() == 4,
        "duplicate validator identities"
    );
    let target_authority = &authorities[0];
    let old_version = first_version(cluster.validators[0].log_path())?;
    let mut cursors = cluster
        .validators
        .iter()
        .map(|validator| LogCursor::at_end(validator.log_path()))
        .collect::<Result<Vec<_>>>()?;
    cluster.validators[3].suspend().await?;
    tracing::info!(
        epoch,
        target_authority,
        participation_control,
        "mid-session upgrade: spare suspended before the identified session"
    );

    let (session, old_lines) = wait_for_old_round_three(&mut cursors[0]).await?;
    // SIGSTOP acknowledgments make this a process boundary, not a timed sleep.
    cluster.validators[1].suspend().await?;
    cluster.validators[2].suspend().await?;
    ensure!(
        cluster.current_epoch().await? == epoch,
        "epoch changed before the OLD session was frozen"
    );
    let mut old = SessionEvidence::default();
    old.observe(&old_lines, &session, target_authority)?;
    old.observe(&cursors[0].read_lines()?, &session, target_authority)?;
    old.require_old_boundary()?;
    tracing::info!(epoch, %session, target_authority, "mid-session upgrade: OLD rounds one and two observed; round three running; peers frozen");
    cluster.validators[0].stop().await?;
    old.observe(&cursors[0].read_lines()?, &session, target_authority)?;
    old.require_old_boundary()?;
    let mut candidate_cursor = LogCursor::at_end(cluster.validators[0].log_path())?;
    let mut boot_cursor = LogCursor::at_end(cluster.validators[0].log_path())?;
    let mut peer_evidence = [SessionEvidence::default(), SessionEvidence::default()];
    for (peer, cursor) in peer_evidence.iter_mut().zip(&mut cursors[1..3]) {
        peer.observe(&cursor.read_lines()?, &session, target_authority)?;
    }
    ensure!(
        peer_evidence
            .iter()
            .all(|peer| !peer.quorum && !peer.target_output),
        "OLD peers completed before the binary swap"
    );
    ensure!(
        !cursors[3]
            .read_lines()?
            .iter()
            .any(|line| is_session(line, &session)),
        "suspended spare already participated in the identified session"
    );

    if participation_control {
        tracing::warn!(%session, "PARTICIPATION NEGATIVE CONTROL: NEW remains stopped; three OLD peers may complete but must not satisfy the upgrade guard");
        for peer in &mut cluster.validators[1..] {
            peer.resume().await?;
        }
    } else {
        let (target, peers) = cluster.validators.split_at_mut(1);
        // Candidate startup can need live consensus peers. Resume them once
        // the new process announces its version, before waiting for admin health.
        tokio::try_join!(target[0].swap_binary(new_binary), async {
            wait_for_new_boot(&mut boot_cursor, &old_version).await?;
            peers[0].resume().await?;
            peers[1].resume().await?;
            Ok::<_, anyhow::Error>(())
        })?;
    }

    let expected = if participation_control {
        &authorities[1..4]
    } else {
        &authorities[0..3]
    };
    let mut candidate = SessionEvidence::default();
    let mut epoch_check = Instant::now();
    loop {
        candidate.observe(&candidate_cursor.read_lines()?, &session, target_authority)?;
        for (peer, cursor) in peer_evidence.iter_mut().zip(&mut cursors[1..3]) {
            peer.observe(&cursor.read_lines()?, &session, target_authority)?;
        }
        if epoch_check.elapsed() >= Duration::from_secs(1) {
            ensure!(
                cluster.current_epoch().await? == epoch,
                "identified session escaped its original epoch"
            );
            epoch_check = Instant::now();
        }
        if peer_evidence.iter().all(|peer| peer.quorum) {
            let first =
                accepted_digest(&cluster.validators[1].metrics().await?, &session, expected)?;
            let second =
                accepted_digest(&cluster.validators[2].metrics().await?, &session, expected)?;
            if let (Some(first), Some(second)) = (first, second) {
                ensure!(
                    first == second,
                    "OLD peers disagree on the identified session's accepted output digest"
                );
                if participation_control || candidate.quorum {
                    tracing::info!(epoch, %session, authorities = ?expected,
                        output_digest = %first, participation_control,
                        "mid-session upgrade: both OLD observers confirmed the identified session's matching accepted output quorum");
                    require_participation(&old, &candidate, &peer_evidence)?;
                    let own = accepted_digest(
                        &cluster.validators[0].metrics().await?,
                        &session,
                        expected,
                    )?;
                    if let Some(own) = own {
                        ensure!(
                            own == first,
                            "NEW and OLD disagree on the identified session's accepted output digest"
                        );
                        ensure!(
                            cluster.current_epoch().await? == epoch,
                            "epoch changed at the participation checkpoint"
                        );
                        cluster
                            .expect_malicious_actors_exactly(&[0, 1, 2], 0)
                            .await?;
                        tracing::info!(epoch, %session, target_authority, output_digest = %first,
                            "mid-session upgrade PASSED: NEW resumed the OLD transcript, advanced round three, finalized and supplied an accepted output in the same session; both OLD peers observed the contribution");
                        break;
                    }
                }
            }
        }
        sleep(Duration::from_millis(100)).await;
    }
    Ok(())
}

struct LogCursor {
    file: File,
    pending: Vec<u8>,
}

impl LogCursor {
    fn at_end(path: &Path) -> Result<Self> {
        let mut file = File::open(path).with_context(|| format!("open {}", path.display()))?;
        file.seek(SeekFrom::End(0))?;
        Ok(Self {
            file,
            pending: Vec::new(),
        })
    }

    fn read_lines(&mut self) -> Result<Vec<String>> {
        self.file.read_to_end(&mut self.pending)?;
        let Some(end) = self.pending.iter().rposition(|byte| *byte == b'\n') else {
            return Ok(Vec::new());
        };
        let complete = self.pending.drain(..=end).collect::<Vec<_>>();
        let complete = String::from_utf8(complete).context("validator log is not UTF-8")?;
        Ok(complete.lines().map(strip_ansi).collect())
    }
}

fn strip_ansi(line: &str) -> String {
    line.split('\u{1b}')
        .map(|part| {
            part.strip_prefix('[')
                .and_then(|part| part.split_once('m').map(|(_, text)| text))
                .unwrap_or(part)
        })
        .collect()
}

fn first_version(path: &Path) -> Result<String> {
    let reader = BufReader::new(File::open(path)?);
    for line in reader.lines() {
        let line = strip_ansi(&line?);
        if let Some((_, version)) = line.split_once("Ika Node version: ") {
            return Ok(version.to_string());
        }
    }
    bail!("OLD validator log has no version marker")
}

async fn wait_for_new_boot(cursor: &mut LogCursor, old_version: &str) -> Result<()> {
    loop {
        for line in cursor.read_lines()? {
            if let Some((_, version)) = line.split_once("Ika Node version: ") {
                ensure!(
                    version != old_version,
                    "mid-session swap restarted the OLD binary"
                );
                tracing::info!(
                    old_version,
                    new_version = version,
                    "mid-session upgrade: NEW process started"
                );
                return Ok(());
            }
        }
        sleep(Duration::from_millis(10)).await;
    }
}

async fn wait_for_old_round_three(cursor: &mut LogCursor) -> Result<(String, Vec<String>)> {
    let mut observed = Vec::new();
    loop {
        let lines = cursor
            .read_lines()?
            .into_iter()
            .filter(|line| line.contains("session_type: System,"))
            .collect::<Vec<_>>();
        let session = lines
            .iter()
            .find(|line| {
                line.contains("Advancing session")
                    && line.contains("name: \"Network Encryption Key Reconfiguration\"")
                    && line.contains("current_round=Some(3)")
            })
            .map(|line| {
                session_id(line)
                    .map(str::to_string)
                    .context("OLD round-three log has no session identifier")
            })
            .transpose()?;
        // Keep the complete batch, including events appended after the start
        // marker. Dropping the tail could hide an OLD round-three submission.
        observed.extend(lines);
        ensure!(
            observed.len() <= 10_000,
            "too many System log events before the target round-three boundary"
        );
        if let Some(session) = session {
            return Ok((session, observed));
        }
        sleep(Duration::from_millis(10)).await;
    }
}

fn session_id(line: &str) -> Option<&str> {
    let value = line.split_once("session_identifier: 0x")?.1;
    let value = value.split_whitespace().next()?;
    (value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())).then_some(value)
}

fn is_session(line: &str, session: &str) -> bool {
    line.contains("session_type: System,") && session_id(line) == Some(session)
}

fn field<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    line.split_whitespace()
        .find_map(|word| word.strip_prefix(name))
}

#[derive(Default)]
struct SessionEvidence {
    started: BTreeSet<u64>,
    advanced: BTreeSet<u64>,
    completed: BTreeSet<u64>,
    target_messages: BTreeSet<(u64, usize)>,
    last_target_message_time: Option<String>,
    round_three_advance_time: Option<String>,
    reached_output: bool,
    target_output: bool,
    own_output: bool,
    quorum: bool,
    quorum_with_own_output: bool,
}

impl SessionEvidence {
    fn observe(&mut self, lines: &[String], session: &str, target: &str) -> Result<()> {
        for line in lines.iter().filter(|line| is_session(line, session)) {
            ensure!(
                !line.contains("Cryptographic computation failed")
                    && !line.contains("failed to submit")
                    && !line.contains("DIVERGES")
                    && !line.contains("rejected=true"),
                "identified session failed: {line}"
            );
            if line.contains("Advancing session")
                && let Some(round) = field(line, "current_round=Some(")
                    .and_then(|value| value.strip_suffix(')'))
                    .and_then(|value| value.parse().ok())
            {
                self.started.insert(round);
            }
            let round = line
                .split_once("mpc_round: ")
                .and_then(|(_, value)| value.split_whitespace().next())
                .and_then(|value| value.parse::<u64>().ok());
            if line.contains("Advanced session")
                && let Some(round) = round
            {
                self.advanced.insert(round);
                if round == 3 {
                    self.round_three_advance_time =
                        line.split_whitespace().next().map(str::to_string);
                }
            }
            if line.contains("Cryptographic computation completed successfully")
                && let Some(round) = round
            {
                self.completed.insert(round);
            }
            if line.contains("Received a dWallet MPC message")
                && field(line, "from_authority=") == Some(target)
            {
                let round = field(line, "consensus_round=")
                    .context("MPC message missing consensus round")?
                    .parse()?;
                let size = field(line, "message_size_bytes=")
                    .context("MPC message missing size")?
                    .parse()?;
                self.target_messages.insert((round, size));
                self.last_target_message_time = line.split_whitespace().next().map(str::to_string);
            }
            if line.contains("Received a dWallet MPC output")
                && field(line, "from_authority=") == Some(target)
            {
                self.target_output = true;
            }
            self.reached_output |= line.contains("Reached output for session");
            self.own_output |= line.contains(
                "Received our output from consensus, marking session as computation completed",
            );
            if line.contains("MPC output reached quorum") {
                for label in [
                    "malicious_voters=",
                    "reported_malicious_authorities=",
                    "final_malicious_authorities=",
                ] {
                    ensure!(
                        field(line, label) == Some("{}"),
                        "identified session has malicious or missing quorum reports: {line}"
                    );
                }
                self.quorum = true;
                self.quorum_with_own_output |=
                    field(line, "local_output_observed=") == Some("true");
            }
        }
        Ok(())
    }

    fn require_old_boundary(&self) -> Result<()> {
        ensure!(
            self.started.contains(&3)
                && self.advanced.is_superset(&BTreeSet::from([1, 2]))
                && self.completed.is_superset(&BTreeSet::from([1, 2]))
                && self.target_messages.len() == 2,
            "OLD did not commit exactly its first two intermediate messages before round three"
        );
        ensure!(
            !self.advanced.iter().any(|round| *round >= 3)
                && !self.reached_output
                && !self.own_output
                && !self.quorum,
            "OLD advanced round three or completed before shutdown; this is not a mid-session upgrade"
        );
        Ok(())
    }
}

fn require_participation(
    old: &SessionEvidence,
    new: &SessionEvidence,
    peers: &[SessionEvidence; 2],
) -> Result<()> {
    old.require_old_boundary()?;
    ensure!(
        new.started.is_superset(&BTreeSet::from([3, 4]))
            && new.started.iter().all(|round| *round >= 3)
            && new.advanced.iter().all(|round| *round >= 3)
            && new.advanced.contains(&3)
            && new.completed.contains(&4)
            && new.reached_output
            && new.own_output
            && new.quorum_with_own_output,
        "{MISSING_CONTRIBUTION}: NEW must advance round three, finalize round four and observe its own accepted output before same-session quorum"
    );
    let advanced_at = new
        .round_three_advance_time
        .as_ref()
        .context(MISSING_CONTRIBUTION)?;
    for (index, peer) in peers.iter().enumerate() {
        ensure!(
            peer.target_messages.len() >= 3
                && peer
                    .last_target_message_time
                    .as_ref()
                    .is_some_and(|time| time >= advanced_at)
                && peer.target_output
                && peer.quorum,
            "{MISSING_CONTRIBUTION}: OLD peer {} did not observe NEW's later intermediate message and accepted output",
            index + 1
        );
    }
    Ok(())
}

fn accepted_digest(body: &str, session: &str, expected: &[String]) -> Result<Option<String>> {
    let relevant = |metric| -> Result<Vec<_>> {
        Ok(parse_metric_samples(body, metric)?
            .into_iter()
            .filter(|sample| {
                sample.labels.get("protocol_name").map(String::as_str) == Some(PROTOCOL)
                    && sample.labels.get("session_id").map(String::as_str) == Some(session)
            })
            .collect())
    };
    let mut outputs = BTreeMap::new();
    for sample in relevant("ika_dwallet_mpc_session_output_info")? {
        ensure!(
            sample.value == 1.0,
            "invalid identified-session output gauge"
        );
        let authority = sample
            .labels
            .get("authority")
            .context("output gauge missing authority")?
            .clone();
        let digest = sample
            .labels
            .get("output_digest")
            .context("output gauge missing digest")?
            .clone();
        ensure!(
            expected.contains(&authority),
            "unexpected authority contributed to the held session: {authority}"
        );
        ensure!(
            digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "invalid output digest"
        );
        ensure!(
            outputs.insert(authority, digest).is_none(),
            "duplicate or conflicting identified-session output"
        );
    }
    if outputs.len() != expected.len() {
        return Ok(None);
    }
    let digest = outputs
        .values()
        .next()
        .context("empty expected output quorum")?;
    ensure!(
        outputs.values().all(|value| value == digest),
        "identified-session output digests diverge"
    );
    for metric in [
        "ika_dwallet_mpc_session_reported_malicious_actors",
        "ika_dwallet_mpc_session_output_rejected",
    ] {
        let mut seen = BTreeSet::new();
        for sample in relevant(metric)? {
            let authority = sample
                .labels
                .get("authority")
                .context("envelope gauge missing authority")?;
            ensure!(
                expected.contains(authority) && seen.insert(authority.clone()),
                "unexpected or duplicate envelope authority"
            );
            ensure!(
                sample.value == 0.0,
                "identified session has malicious or rejected output: {metric} authority={authority} value={}",
                sample.value
            );
        }
        if seen.len() != expected.len() {
            return Ok(None);
        }
    }
    Ok(Some(digest.clone()))
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::io::Write;

    use super::*;

    const SESSION: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const OTHER: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const TARGET: &str = "k#target";

    fn event(message: &str, fields: &str) -> String {
        format!(
            "2026-10-16T10:00:00.000000Z DEBUG target: {message} session_identifier=SessionIdentifier {{ session_type: System, session_identifier_preimage: 0x{OTHER}, session_identifier: 0x{SESSION} }} {fields}"
        )
    }

    fn old_evidence() -> SessionEvidence {
        let mut old = SessionEvidence::default();
        let lines = vec![
            event(
                "Advanced session",
                "computation_result_data=MPC { mpc_round: 1 }",
            ),
            event(
                "Cryptographic computation completed successfully",
                "computation_result_data=MPC { mpc_round: 1 }",
            ),
            event(
                "Received a dWallet MPC message",
                "from_authority=k#target consensus_round=10 message_size_bytes=100",
            ),
            event(
                "Advanced session",
                "computation_result_data=MPC { mpc_round: 2 }",
            ),
            event(
                "Cryptographic computation completed successfully",
                "computation_result_data=MPC { mpc_round: 2 }",
            ),
            event(
                "Received a dWallet MPC message",
                "from_authority=k#target consensus_round=20 message_size_bytes=200",
            ),
            event("Advancing session", "current_round=Some(3)"),
        ];
        old.observe(&lines, SESSION, TARGET).unwrap();
        old
    }

    fn completed_lines() -> Vec<String> {
        vec![
            event("Advancing session", "current_round=Some(3)"),
            event(
                "Advanced session",
                "computation_result_data=MPC { mpc_round: 3 }",
            ),
            event("Advancing session", "current_round=Some(4)"),
            event(
                "Cryptographic computation completed successfully",
                "computation_result_data=MPC { mpc_round: 4 }",
            ),
            event("Reached output for session", ""),
            event(
                "Received our output from consensus, marking session as computation completed",
                "rejected=false",
            ),
            event(
                "MPC output reached quorum",
                "malicious_voters={} reported_malicious_authorities={} final_malicious_authorities={} local_output_observed=true rejected=false",
            ),
        ]
    }

    fn new_evidence() -> SessionEvidence {
        let mut new = SessionEvidence::default();
        new.observe(&completed_lines(), SESSION, TARGET).unwrap();
        new
    }

    fn peer_evidence() -> SessionEvidence {
        let mut peer = old_evidence();
        peer.observe(&[
            event("Received a dWallet MPC message", "from_authority=k#target consensus_round=30 message_size_bytes=300"),
            event("Received a dWallet MPC output", "from_authority=k#target"),
            event("MPC output reached quorum", "malicious_voters={} reported_malicious_authorities={} final_malicious_authorities={} local_output_observed=true rejected=false"),
        ], SESSION, TARGET).unwrap();
        peer
    }

    fn metrics() -> String {
        [TARGET, "k#first", "k#second"].iter().flat_map(|authority| [
            format!("ika_dwallet_mpc_session_output_info{{protocol_name=\"{PROTOCOL}\",session_id=\"{SESSION}\",authority=\"{authority}\",output_digest=\"{OTHER}\"}} 1"),
            format!("ika_dwallet_mpc_session_reported_malicious_actors{{protocol_name=\"{PROTOCOL}\",session_id=\"{SESSION}\",authority=\"{authority}\"}} 0"),
            format!("ika_dwallet_mpc_session_output_rejected{{protocol_name=\"{PROTOCOL}\",session_id=\"{SESSION}\",authority=\"{authority}\"}} 0"),
        ]).collect::<Vec<_>>().join("\n")
    }

    fn expected() -> Vec<String> {
        [TARGET, "k#first", "k#second"].map(str::to_string).to_vec()
    }

    #[test]
    fn identified_post_boot_contribution_and_matching_quorum_pass() {
        require_participation(
            &old_evidence(),
            &new_evidence(),
            &[peer_evidence(), peer_evidence()],
        )
        .unwrap();
        assert_eq!(
            accepted_digest(&metrics(), SESSION, &expected()).unwrap(),
            Some(OTHER.to_string())
        );
    }

    #[test]
    fn wrong_session_and_pre_boot_only_evidence_do_not_prove_participation() {
        let mut wrong_session = SessionEvidence::default();
        wrong_session
            .observe(&completed_lines(), OTHER, TARGET)
            .unwrap();
        let error = require_participation(
            &old_evidence(),
            &wrong_session,
            &[peer_evidence(), peer_evidence()],
        )
        .unwrap_err();
        assert!(error.to_string().contains(MISSING_CONTRIBUTION));
        let error = require_participation(
            &old_evidence(),
            &SessionEvidence::default(),
            &[peer_evidence(), peer_evidence()],
        )
        .unwrap_err();
        assert!(error.to_string().contains(MISSING_CONTRIBUTION));
        assert_eq!(
            accepted_digest(&metrics(), OTHER, &expected()).unwrap(),
            None
        );
    }

    #[test]
    fn old_round_three_submission_rejects_the_restart_boundary() {
        let mut old = old_evidence();
        old.observe(
            &[event(
                "Advanced session",
                "computation_result_data=MPC { mpc_round: 3 }",
            )],
            SESSION,
            TARGET,
        )
        .unwrap();
        assert!(
            old.require_old_boundary()
                .unwrap_err()
                .to_string()
                .contains("OLD advanced round three")
        );
    }

    #[test]
    fn peer_only_quorum_cannot_replace_new_computation() {
        let new = SessionEvidence {
            quorum: true,
            quorum_with_own_output: true,
            own_output: true,
            ..Default::default()
        };
        assert!(
            require_participation(&old_evidence(), &new, &[peer_evidence(), peer_evidence()])
                .unwrap_err()
                .to_string()
                .contains(MISSING_CONTRIBUTION)
        );
        let peer_only = metrics().replace(TARGET, "k#spare");
        assert!(
            accepted_digest(&peer_only, SESSION, &expected())
                .unwrap_err()
                .to_string()
                .contains("unexpected authority")
        );
    }

    #[test]
    fn missing_target_and_late_output_do_not_count_as_accepted_output() {
        let body = metrics()
            .lines()
            .filter(|line| !line.contains(TARGET))
            .map(str::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(accepted_digest(&body, SESSION, &expected()).unwrap(), None);
        let mut new = new_evidence();
        new.own_output = false;
        new.observe(&[event("late network-key reconfiguration output matches the quorum-agreed output; session already completed, output not submitted", "")], SESSION, TARGET).unwrap();
        assert!(
            require_participation(&old_evidence(), &new, &[peer_evidence(), peer_evidence()])
                .unwrap_err()
                .to_string()
                .contains(MISSING_CONTRIBUTION)
        );
    }

    #[test]
    fn recomputing_the_old_first_rounds_is_not_transcript_continuation() {
        let mut new = new_evidence();
        new.observe(
            &[event("Advancing session", "current_round=Some(1)")],
            SESSION,
            TARGET,
        )
        .unwrap();
        assert!(
            require_participation(&old_evidence(), &new, &[peer_evidence(), peer_evidence()])
                .unwrap_err()
                .to_string()
                .contains(MISSING_CONTRIBUTION)
        );
    }

    #[test]
    fn malicious_rejected_and_divergent_outputs_fail_closed() {
        for metric in [
            "ika_dwallet_mpc_session_reported_malicious_actors",
            "ika_dwallet_mpc_session_output_rejected",
        ] {
            let bad = metrics()
                .lines()
                .map(|line| {
                    if line.starts_with(metric) && line.contains(TARGET) {
                        line.strip_suffix(" 0").unwrap().to_string() + " 1"
                    } else {
                        line.to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join("\n");
            assert!(
                accepted_digest(&bad, SESSION, &expected())
                    .unwrap_err()
                    .to_string()
                    .contains("malicious or rejected")
            );
        }
        let bad = metrics().replacen(
            &format!("output_digest=\"{OTHER}\""),
            &format!("output_digest=\"{SESSION}\""),
            1,
        );
        assert!(
            accepted_digest(&bad, SESSION, &expected())
                .unwrap_err()
                .to_string()
                .contains("digests diverge")
        );
    }

    #[test]
    fn stale_or_duplicate_peer_message_does_not_prove_new_receipt() {
        let mut peer = old_evidence();
        peer.target_output = true;
        peer.quorum = true;
        peer.observe(
            &[event(
                "Received a dWallet MPC message",
                "from_authority=k#target consensus_round=20 message_size_bytes=200",
            )],
            SESSION,
            TARGET,
        )
        .unwrap();
        assert!(
            require_participation(&old_evidence(), &new_evidence(), &[peer, peer_evidence()])
                .unwrap_err()
                .to_string()
                .contains("OLD peer 1")
        );
    }

    #[test]
    fn incremental_log_cursor_preserves_partial_lines_and_boot_offset() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("node.log");
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .unwrap();
        writeln!(file, "pre-boot evidence").unwrap();
        let mut cursor = LogCursor::at_end(&path).unwrap();
        write!(file, "new boot par").unwrap();
        assert!(cursor.read_lines().unwrap().is_empty());
        writeln!(file, "tial").unwrap();
        assert_eq!(cursor.read_lines().unwrap(), vec!["new boot partial"]);
    }

    #[tokio::test]
    async fn old_round_three_marker_does_not_drop_a_later_submission_in_same_read() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("node.log");
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .unwrap();
        let mut cursor = LogCursor::at_end(&path).unwrap();
        writeln!(
            file,
            "{}",
            event(
                "Advancing session",
                "mpc_protocol=DWalletSessionRequestMetricData { name: \"Network Encryption Key Reconfiguration\", curve: None, hash_scheme: None, signature_algorithm: None } current_round=Some(3)"
            )
        )
        .unwrap();
        writeln!(
            file,
            "{}",
            event(
                "Advanced session",
                "computation_result_data=MPC { mpc_round: 3 }"
            )
        )
        .unwrap();
        let (session, lines) = wait_for_old_round_three(&mut cursor).await.unwrap();
        let mut old = old_evidence();
        old.observe(&lines, &session, TARGET).unwrap();
        assert!(
            old.require_old_boundary()
                .unwrap_err()
                .to_string()
                .contains("OLD advanced round three")
        );
    }
}

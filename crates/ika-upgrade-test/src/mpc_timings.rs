// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Rough MPC-protocol timing collection for the cross-binary tests.
//!
//! Scrapes each validator's Prometheus endpoint for the dwallet-MPC duration
//! metrics (`dwallet_mpc_computation_duration_avg` /
//! `dwallet_mpc_advance_completions`, both labeled by protocol + curve +
//! round) and aggregates them into per-protocol-round rows. Snapshots taken
//! at different points of a scenario (e.g. before and after a binary swap)
//! are compared at the end of the run; large ratios are flagged in the
//! report so a human can judge whether the difference is expected.
//!
//! These are *rough* numbers: averages are cumulative since each validator
//! process started (a binary swap resets them — which conveniently scopes a
//! post-swap snapshot to the new binary's work), and wall-clock on a loaded
//! developer machine is noisy. The report is informational, not a hard
//! assertion.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use anyhow::{Context, Result};

use crate::cluster::ClusterOfProcesses;

/// Aggregated timing for one (protocol, curve, round) across all validators:
/// total advance completions and the completion-weighted average duration.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct TimingRow {
    pub completions: u64,
    pub avg_duration_ms: f64,
}

/// Key: (protocol_name, curve, mpc_round).
pub type TimingKey = (String, String, String);

/// One labeled scrape of the whole cluster.
#[derive(Clone, Debug)]
pub struct TimingSnapshot {
    pub label: String,
    pub rows: BTreeMap<TimingKey, TimingRow>,
}

/// A later/earlier average ratio above this factor is flagged in the report.
/// Generous on purpose: cumulative averages on a shared developer machine
/// move around; the flag is a prompt for human judgement, not a failure.
const REGRESSION_FLAG_FACTOR: f64 = 3.0;

/// Scrape every *running* validator's metrics endpoint and aggregate into a
/// labeled snapshot. Validators that are stopped (removed from the
/// committee) or unreachable are skipped with a warning — a partial scrape
/// is still useful, and a mid-reconfiguration node briefly not serving
/// metrics must not fail the scenario.
pub async fn record_snapshot(
    cluster: &ClusterOfProcesses,
    label: impl Into<String>,
) -> Result<TimingSnapshot> {
    let label = label.into();
    let http = reqwest::Client::new();
    // (key) -> (sum of completions, sum of avg*completions)
    let mut acc: BTreeMap<TimingKey, (u64, f64)> = BTreeMap::new();

    for proc in cluster.validators.iter().filter(|p| p.is_running()) {
        let url = format!("http://127.0.0.1:{}/metrics", proc.metrics_port());
        let body = match http.get(&url).send().await {
            Ok(resp) => resp.text().await.context("read metrics body")?,
            Err(e) => {
                tracing::warn!(index = proc.index, error = %e, "metrics scrape failed; skipping validator");
                continue;
            }
        };
        let completions = parse_metric(&body, "dwallet_mpc_advance_completions");
        let avgs = parse_metric(&body, "dwallet_mpc_computation_duration_avg");
        for (key, count) in completions {
            let avg = avgs.get(&key).copied().unwrap_or(0.0);
            let entry = acc.entry(key).or_insert((0, 0.0));
            entry.0 += count as u64;
            entry.1 += avg * count;
        }
    }

    let rows = acc
        .into_iter()
        .filter(|(_, (count, _))| *count > 0)
        .map(|(key, (completions, weighted_sum))| {
            (
                key,
                TimingRow {
                    completions,
                    avg_duration_ms: weighted_sum / completions as f64,
                },
            )
        })
        .collect();
    let snapshot = TimingSnapshot { label, rows };
    println!("{}", render_snapshot(&snapshot));
    Ok(snapshot)
}

/// Render one snapshot as a fixed-width table.
pub fn render_snapshot(snapshot: &TimingSnapshot) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "=== MPC timings [{}] ===", snapshot.label);
    let _ = writeln!(
        out,
        "{:<28} {:<12} {:<22} {:>12} {:>14}",
        "protocol", "curve", "round", "completions", "avg ms"
    );
    for ((protocol, curve, round), row) in &snapshot.rows {
        let _ = writeln!(
            out,
            "{protocol:<28} {curve:<12} {round:<22} {:>12} {:>14.1}",
            row.completions, row.avg_duration_ms
        );
    }
    out
}

/// Compare consecutive snapshots and render a per-(protocol, round) ratio
/// table. Rows whose later/earlier average exceeds [`REGRESSION_FLAG_FACTOR`]
/// are marked `POSSIBLE REGRESSION`; the inverse is marked `faster`.
pub fn render_comparison(snapshots: &[TimingSnapshot]) -> String {
    let mut out = String::new();
    for pair in snapshots.windows(2) {
        let (earlier, later) = (&pair[0], &pair[1]);
        let _ = writeln!(
            out,
            "=== MPC timing comparison [{}] -> [{}] ===",
            earlier.label, later.label
        );
        let _ = writeln!(
            out,
            "{:<28} {:<22} {:>12} {:>12} {:>8}  flag",
            "protocol", "round", "earlier ms", "later ms", "ratio"
        );
        for (key, later_row) in &later.rows {
            let (protocol, _curve, round) = key;
            let Some(earlier_row) = earlier.rows.get(key) else {
                let _ = writeln!(
                    out,
                    "{protocol:<28} {round:<22} {:>12} {:>12.1} {:>8}  (new)",
                    "-", later_row.avg_duration_ms, "-"
                );
                continue;
            };
            if earlier_row.avg_duration_ms <= 0.0 {
                continue;
            }
            let ratio = later_row.avg_duration_ms / earlier_row.avg_duration_ms;
            let flag = if ratio > REGRESSION_FLAG_FACTOR {
                "POSSIBLE REGRESSION"
            } else if ratio < 1.0 / REGRESSION_FLAG_FACTOR {
                "faster"
            } else {
                ""
            };
            let _ = writeln!(
                out,
                "{protocol:<28} {round:<22} {:>12.1} {:>12.1} {:>7.2}x  {flag}",
                earlier_row.avg_duration_ms, later_row.avg_duration_ms, ratio
            );
        }
    }
    out
}

/// Parse all samples of one Prometheus metric out of text-format exposition,
/// keyed by (protocol_name, curve, mpc_round). Lines without those labels
/// (or unparsable values) are skipped.
fn parse_metric(body: &str, metric: &str) -> BTreeMap<TimingKey, f64> {
    body.lines()
        .filter_map(|line| {
            let rest = line.strip_prefix(metric)?;
            let rest = rest.strip_prefix('{')?;
            let (labels, value_part) = rest.split_once('}')?;
            let value: f64 = value_part.trim().parse().ok()?;
            let mut protocol = None;
            let mut curve = None;
            let mut round = None;
            for pair in labels.split(',') {
                let (key, val) = pair.split_once('=')?;
                let val = val.trim_matches('"').to_string();
                match key {
                    "protocol_name" => protocol = Some(val),
                    "curve" => curve = Some(val),
                    "mpc_round" => round = Some(val),
                    _ => {}
                }
            }
            Some(((protocol?, curve?, round?), value))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_round_labeled_metric_lines() {
        let body = concat!(
            "# HELP dwallet_mpc_computation_duration_avg Average duration of MPC computations in milliseconds\n",
            "# TYPE dwallet_mpc_computation_duration_avg gauge\n",
            "dwallet_mpc_computation_duration_avg{curve=\"Secp256k1\",hash_scheme=\"\",mpc_round=\"first_round\",protocol_name=\"Presign\",signature_algorithm=\"ECDSA\"} 321.5\n",
            "dwallet_mpc_computation_duration_avg{curve=\"Secp256k1\",hash_scheme=\"\",mpc_round=\"second_round\",protocol_name=\"Presign\",signature_algorithm=\"ECDSA\"} 100\n",
            "other_metric{mpc_round=\"x\"} 5\n",
        );
        let parsed = parse_metric(body, "dwallet_mpc_computation_duration_avg");
        assert_eq!(parsed.len(), 2);
        assert_eq!(
            parsed[&(
                "Presign".to_string(),
                "Secp256k1".to_string(),
                "first_round".to_string()
            )],
            321.5
        );
    }

    #[test]
    fn comparison_flags_large_ratio() {
        let key = (
            "Sign".to_string(),
            "Secp256k1".to_string(),
            "first_round".to_string(),
        );
        let earlier = TimingSnapshot {
            label: "old".into(),
            rows: BTreeMap::from([(
                key.clone(),
                TimingRow {
                    completions: 4,
                    avg_duration_ms: 100.0,
                },
            )]),
        };
        let later = TimingSnapshot {
            label: "new".into(),
            rows: BTreeMap::from([(
                key,
                TimingRow {
                    completions: 4,
                    avg_duration_ms: 400.0,
                },
            )]),
        };
        let report = render_comparison(&[earlier, later]);
        assert!(report.contains("POSSIBLE REGRESSION"), "{report}");
    }
}

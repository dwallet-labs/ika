# Cross-binary protocol upgrade (heterogeneous committees)

Status: active. Ika upgrades its protocol version **in place on a live
chain**: there is no flag day. During a rollout, committee members run
different compiled `ika-validator` binaries at the same time, and the
network must keep producing checkpoints, reconfigure across epochs, and
serve dWallet sessions throughout. This file is the protocol-level
contract that any change touching versioning, serialization, or the
epoch boundary must preserve. The out-of-process harness that verifies
it lives in `crates/ika-upgrade-test/`; the design record and findings
are in [`../plans/cross-binary-upgrade-testing.md`](../plans/cross-binary-upgrade-testing.md).

## How a version advances

The version is not config-driven — it is a stake-weighted on-chain vote:

- Each validator announces its `supported_protocol_versions` range in a
  `CapabilityNotificationV1` consensus message.
- At `EndOfPublish` every validator independently runs
  `choose_highest_protocol_version_and_move_contracts_upgrades_v1`: the
  highest candidate version supported by **≥ 2f+1 stake plus a
  buffer-stake margin** (protocol-config default 5000 bps) wins.
- On `advance_epoch()` the chosen `next_protocol_version` becomes the new
  on-chain `protocol_version`, announced via the
  `SET_NEXT_PROTOCOL_VERSION` system checkpoint message.

Move packages upgrade through Sui package upgrades; the coordinator
schema may gain behavior at a version boundary (e.g.
`internal_presign_sessions` activates at v4). Crypto/MPC payloads are
versioned implicitly inside bcs-encoded enums — `VersionedMPCData`,
`VersionedNetworkDkgOutput`, `VersionedPresignOutput`,
`VersionedSignOutput`.

## Invariants

Any binary that participates in a mixed committee, and any
serialization/schema change, MUST preserve all of the following.

1. **Vote arithmetic.** The version advances if and only if ≥ 2f+1 stake
   plus the buffer margin supports it, and never one boundary earlier.
   The margin rounds *up* on small committees: at n=4 the default 5000
   bps margin makes the threshold effectively unanimous, so a single
   validator whose fresh capability has not yet committed at the
   boundary tally blocks the upgrade. The per-epoch buffer-stake
   override (admin RPC) exists to drop the threshold to a bare quorum;
   this is the realistic behavior on larger committees and is the
   supported way to cross an upgrade boundary under churn.

2. **Reconfiguration survives the swap.** The mid-epoch reconfiguration
   MPC (run at the ~50% epoch mark) must complete across a binary swap,
   and the next committee's encryption-key shares must be present at the
   boundary. A swap whose downtime overlaps the reconfiguration window
   stalls the epoch — rollouts must land each validator's swap clear of
   that window (the harness uses long epochs and swaps well before the
   50% mark for exactly this reason). The cross-epoch agreement on which
   artifacts the next epoch inherits is the handoff; see
   [`handoff.md`](handoff.md) and
   [`validator-mpc-data-announcements.md`](validator-mpc-data-announcements.md).

3. **Session lifecycle — no silent drops, no wedge.** A dWallet session
   started in epoch N either completes in N or is cleanly rejected
   (`epoch != current_epoch`); it is never silently dropped or left
   hanging. `last_user_initiated_session_to_complete_in_current_epoch`
   must drain before the epoch advances, and `advance_epoch` requires
   `all_current_epoch_sessions_completed`. The corollary is a hard
   failure mode: **an in-flight session that can never complete on the
   running version wedges the epoch permanently** — the epoch cannot
   close, so the version can never advance to the one that would serve
   it. The pre-activation global-presign fallback in `handle_mpc_request`
   exists precisely for this: a global presign requested at v3 on a
   binary that *serves* global presigns from the v4-only internal pool
   must fall through to a user-requested MPC session, or one in-flight
   presign at restart deadlocks the whole network. See
   [`epoch-close-session-lock.md`](epoch-close-session-lock.md) for the
   completion-target / close-predicate rules this builds on.

4. **Wire and cryptographic-output compatibility.** A vN binary MUST
   correctly deserialize the consensus and MPC messages produced by vN−1
   peers, and vice versa. It MUST also construct the same canonical MPC
   transcript and output while both select the same on-chain protocol
   version. Matching `protocol_version` values are not enough: dependency
   behavior, transcript construction, serialization, and output finalization
   are compiled into each binary. A validator-by-validator rollout therefore
   requires a literal previous-release/current mixed committee to exchange
   real MPC messages and agree on output bytes. A dependency boundary that
   cannot do so blocks the release; it is not grounds to replace the
   historical binary with current source pinned to an older advertised
   version.

5. **On-disk compatibility.** `AuthorityPerpetualTables` written by a
   vN−1 binary MUST reopen under vN. A validator stopped on vN−1 and
   restarted on vN against the *same* RocksDB data dir must resume and
   catch up — verified by a positive read-back (it reaches the live
   epoch), not merely by "did not panic". This extends to ANY durable
   local table whose value schema changes across a version bump: a binary
   reads its OWN store written by its previous version, so the reader must
   tolerate the prior layout (a fallback decode or a versioned envelope),
   not just the current one. **Known instance:** `Committee` gained a
   `consensus_keys` field at v4 (second-to-last, before `index_map`), so a
   `committee_map` record written by mainnet-v1.1.8 does not decode under
   the v4 `Committee` (bcs is positional). `CommitteeStore` migrates such
   records at store open (`migrate_legacy_records`): each record that fails
   the current decode but decodes as `LegacyCommittee` is rewritten in the
   current layout with empty `consensus_keys`, so every later read is a
   plain decode. The migration is idempotent (already-migrated records pass
   the current decode and are skipped), hence crash-safe, and the
   `LegacyCommittee` mirror is deletable once no fleet upgrades directly
   from 1.1.8 data dirs. The
   empty `consensus_keys` is sound because a legacy record always DESCRIBES
   a ≤v3 epoch, for which no handoff certificate can exist (cert minting is
   v4-gated), so the keys are never asked to verify anything. That holds
   through a three-link chain: (1) 1.1.8's `MAX_PROTOCOL_VERSION = 3`; (2)
   1.1.8's `reconfigure` runs `check_protocol_version` BEFORE
   `insert_new_committee`, so 1.1.8 can never persist a committee record
   for a v4 epoch; (3) the state-sync `insert_committee` plumbing has no
   live callers on either version. If a future change breaks any link —
   letting a pre-`consensus_keys` record describe a cert-minting epoch —
   cert verification skips every signer it cannot resolve and then fails
   quorum, so an honest validator fail-closes far from the cause; re-check
   this chain before reusing the legacy migration for anything else.
   **Rollback caveat (reverse direction, unfixable from the v4 side):** a
   `committee_map` record written by a v4 binary is NOT readable by
   mainnet-v1.1.8 (same positional-bcs reason; 1.1.8 has no fallback).
   Rolling a validator back to 1.1.8 after it has written any new-layout
   committee record requires clearing the `committee_map` column family.
   Clearing is safe, but note what actually happens afterwards: past-epoch
   history is NOT rebuilt (nothing repopulates old epochs —
   `insert_new_committee` fires only inside `AuthorityState::reconfigure`,
   at future epoch boundaries), so the map stays empty until the next
   reconfiguration inserts the then-next committee. That is acceptable
   because nothing on 1.1.8 reads `committee_map` history at runtime; the
   current-epoch committee is always rebuilt from chain state at startup.

## Genesis must start at v3 and upgrade into v4

A network must genesis at v3 (`ProtocolVersion::MIN`) and reach v4
through the vote above; a **v4 genesis is rejected forever**. At v4 the
network DKG needs PVSS keys that arrive only through the off-chain
next-committee assembly, which by construction never serves the genesis
(epoch-0) committee — so a v4 genesis DKG can never satisfy its key
requirement (4/4 class-groups keys, 0/4 PVSS). This is also the path
mainnet itself takes, so upgrade testing must follow it.

## Literal previous-release compatibility is a release requirement

> **Enforcement note (2026-07-23).** This was an automated gate: the release
> workflow called `upgrade-test.yaml` with `test=v118_mixed_rollout` on every
> release tag and blocked the draft on it. **PR #1891 removed that job** —
> release tags no longer block on anything, and the workflow now builds,
> uploads and drafts unconditionally. The compatibility requirement below is
> unchanged and still binding; only its enforcement moved from CI to the
> release manager, who must dispatch the scenario against the exact candidate
> SHA and record the result in the release notes (the notes scaffold prompts
> for it). Treat a release whose notes carry no such record as unvalidated.

The decentralized rollout topology is one release-candidate validator and
the rest of the committee on the literal previous release. That topology must
remain valid through a network-key reconfiguration while the on-chain
protocol version remains v3. Operational instructions cannot turn a
validator-by-validator deployment into an atomic restart, and quorum progress
cannot establish compatibility: three matching old validators can advance the
chain while the upgraded validator produces different bytes, falls behind, or
records itself as malicious.

The `mainnet-v1.1.8` → current boundary is especially important because
v1.1.8 links the former `class_groups`/`inkrypto` dependency while current
source links `cryptography-private`. The prior assumption was that their MPC
wire formats were not interchangeable and therefore that every validator had
to be replaced before the next MPC boundary. That assumption conflicts with
the deployment contract. The scenario must therefore run the literal binaries
with real cryptography and either prove compatible canonical output or expose a
release blocker.

Protocol v4 also changes validator-key publication from the bare
`ClassGroupsEncryptionKeyAndProof` shape to the combined
`ValidatorEncryptionKeysAndProofs`. Current code can read the historical key
shape; v1.1.8 cannot read the new shape. The mixed-rollout gate deliberately
holds v3 and does not register new-shape validators during its mixed phase.
Forward-only v4 state therefore does not excuse incompatibility for the v3
network-key reshare.

Any crypto-library, transcript, validator-key, or serialization change MUST
state how the literal previous release interoperates during a rolling rollout.
If it cannot, the candidate is not releasable until compatibility is restored
or the decentralized rollout contract is explicitly changed outside this test.

## How this is verified

`crates/ika-upgrade-test/` spawns real, separately-compiled
`ika-validator` child processes against an external `sui` localnet and
drives them across epochs:

> **Post-#1751 caveat:** the v3→v4 migration scaffolding (chain-read
> fallback for keys DKG'd under v3) is removed from the current binary,
> so any scenario in which the CURRENT build crosses the v3→v4 boundary
> over a v3-DKG'd network key no longer passes on it: `workload.rs`,
> `cross_binary.rs`, `legacy_config.rs`, `v118_upgrade.rs`,
> `v118_churn.rs`. These rehearse rollouts the deployed networks have
> completed (both run protocol v5); retire or retarget them (genesis
> v4 → v5) in a follow-up. `v118_mixed_rollout.rs` — the PR-gating
> scenario — holds protocol v3 throughout and remains valid, as does
> `smoke.rs`; in `v121_rollout.rs` the v3→v4 crossing happens on the
> literal v1.2.1 binaries (which retain the scaffolding), so it is
> unaffected in principle but rehearses a completed rollout too.

- `tests/smoke.rs` — harness plumbing: four same-binary processes reach
  epoch 2 on the genesis epoch cadence.
- `tests/workload.rs` — the session-lifecycle invariant: a v3→v4 upgrade
  followed by a full user DKG → Presign → Sign completing on-chain.
- `tests/cross_binary.rs` — a rolling swap with committee churn between
  two wire-compatible builds (an OLD build of the current branch pinned
  to `MAX_PROTOCOL_VERSION = 3`, and the current `dev`): the vote
  advances v3 → v4 while the committee reshapes 4 → 3 → 5 → 4.
- `tests/v118_upgrade.rs` — the coordinated full-committee mainnet
  rehearsal: boot the literal `mainnet-v1.1.8` binary, run the mainnet user
  flow at v3, sequentially restart all validators onto the current build
  before the tested reshare, and confirm the network upgrades to v4 and keeps
  serving through the pre-activation presign window.
- `tests/v118_mixed_rollout.rs` — the production deployment topology (the
  scenario the release manager must run, see the enforcement note above):
  upgrade exactly one member of a four-validator literal v1.1.8 committee,
  hold protocol v3, and require two network-key reconfigurations to complete
  with every validator healthy and locally current, zero reported malicious
  actors, no stranded work, and identical canonical per-authority outputs.
- `tests/v118_churn.rs` — `v118_upgrade` plus a post-upgrade committee join,
  so the v4 reshare of a genuine 1.1.8-origin key includes a new party
  (the lighter, more faithful exercise of the OCS joiner trust-anchor path).
- `tests/v121_rollout.rs` — the aggregated-outputs (protocol v5) rehearsal:
  boot the literal `release/testnet-v1.2.1` binary at v4, converge two mixed
  pre-aggregation reshares, then swap the rest, vote to v5, and confirm the
  first aggregated reconfiguration output installs everywhere.
- `tests/legacy_config.rs` — the current build on old-style (1.1.8-shape)
  YAMLs for validators AND the notifier, covering the legacy JSON-RPC
  transport nothing else exercises.
- `tests/malicious_cross_binary.rs` — the deliberate-corruption counterpart:
  corrupts the outgoing reconfiguration message so the output-quorum tally
  must convict, which is what proves the compatibility scenarios above would
  actually react to a real divergence rather than passing vacuously.

How the mixed-rollout scenario weighs the upgraded validator's output: production
finalizes a reconfiguration at a Byzantine quorum and does not wait for
stragglers — a validator whose computation finishes after it processed the
quorum discards its own result without submitting it, and ANY honest
validator (including the upgraded one) can be that straggler. Requiring the
upgraded validator's submitted output at every boundary therefore made the
gate nondeterministic (the same candidate SHA passed or failed on a
scheduling race). The scenario instead classifies each boundary:

- the upgraded validator's output appears inside the converged quorum set →
  conclusive byte-level evidence;
- the quorum discarded its late `Finalize`, but the node recorded the
  discarded output's raw-bytes digest equal to the quorum output's raw-bytes
  digest (`ika_dwallet_mpc_session_late_output_info`, zero late malicious
  actors) → equally conclusive;
- the digests differ, the late output reports malicious actors, or any
  submitted output diverges / is rejected / reports malicious actors → hard
  failure, and the release must not ship;
- clean quorum convergence with no comparable candidate output at all →
  the boundary is *inconclusive*: it does not fail (the ordering is
  legitimate), but quorum-only progress is never accepted as compatibility
  proof.

The scenario as a whole must witness conclusive candidate byte-equality on at
least one reconfiguration boundary or it fails with "insufficient
cross-version compatibility evidence". Every boundary still requires healthy
validators, correct local epochs, protocol v3, quorum output convergence,
zero malicious actors, zero rejected envelopes, no self-malicious logs, and
no stranded sessions.

The current validator's per-authority output observations and pending-session
counts are collected protocol-generically and labeled by protocol name. This
scenario filters that data to network-key reconfiguration because that is the
deployment boundary it specifies. The per-authority output series are exported
only for an allow-listed set of protocols (`OUTPUT_OBSERVATION_EXPORT_PROTOCOLS`
in `mpc_manager.rs`, currently just network-key reconfiguration) to keep their
session-id/authority cardinality bounded on production validators; a future DKG,
presign, sign, or verification compatibility scenario adds its protocol to that
allow-list rather than adding protocol-specific node instrumentation — and, if
it also wants straggler evidence, must extend the late-output capture too: the
quorum raw-digest stash and the discard-site recording are separately gated on
the session being a network-key reconfiguration (the raw-bytes digest is
computed from that protocol's output chunks), so an allow-list entry alone
yields submitted-output observations but no late-computation evidence. The
late-output digest capture is observability-only: it never publishes the
discarded output, delays finalization, or re-activates a completed session.

Run them on CI via the **Upgrade Test** workflow
(`.github/workflows/upgrade-test.yaml`); see
[`../playbooks/ci-suites.md`](../playbooks/ci-suites.md).

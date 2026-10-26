# Cross-binary protocol upgrade (heterogeneous committees)

Status: active. Ika upgrades its protocol version **in place on a live
chain**: there is no flag day. During a rollout, committee members run
different compiled `ika-validator` binaries at the same time, and the
network must keep producing checkpoints, reconfigure across epochs, and
serve dWallet sessions throughout. This file is the protocol-level
contract that any change touching versioning, serialization, or the
epoch boundary must preserve. The out-of-process harness that verifies
it lives in `crates/ika-upgrade-test/`; the design record and findings
are in [`../plans/archive/cross-binary-upgrade-testing.md`](../plans/archive/cross-binary-upgrade-testing.md).

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
schema may gain behavior at a version boundary (the worked example,
`internal_presign_sessions` activating at v4, is now history — the flag is
true at every supported version and its gates have been swept). Crypto/MPC
payloads are versioned implicitly inside bcs-encoded enums — `VersionedMPCData`,
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
   boundary. Downtime overlapping reconfiguration can delay its completion,
   so the ordinary rollout uses long epochs and swaps before the 50% mark.
   The dedicated active-session scenario below instead interrupts a known
   round and verifies the upgraded validator resumes participating. The
   cross-epoch agreement on which artifacts the next epoch inherits is the handoff; see
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
   it. The worked instance was the v3→v4 global-presign boundary:
   `handle_mpc_request` carried a pre-activation fallback so that a global
   presign requested while the internal pool that serves it did not yet
   exist ran as an ordinary user-requested MPC session, rather than
   stranding and deadlocking the network on one in-flight presign. That
   fallback is **gone** — the flag it tested is true at every supported
   version and its gates were swept — but the hazard it answered is one
   any future activation boundary must answer again. See
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

## Genesis version

Fresh networks genesis at `ProtocolVersion::MAX` (currently 7). The
genesis network DKG's PVSS keys are served by the current-epoch off-chain
key assembly (`sui_syncer::sync_next_committee` assembles the CURRENT
committee's self-announced bundles at genesis), so no upgrade-into-a-
version bootstrap path exists or is needed. (Historically — through the
mainnet v1.1.8→v4 era — a v4+ genesis DKG was impossible and networks
had to genesis at v3 and vote upward; that constraint died with the
current-epoch assembly, and v3/v4 support was removed entirely once both
deployed networks reached v5, then v6, then v7:
`MIN_PROTOCOL_VERSION = 7`.)

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
the rest of the committee on the literal previous release. That topology
must remain valid through a network-key reconfiguration at the current
protocol version. Operational instructions cannot turn a
validator-by-validator deployment into an atomic restart, and quorum progress
cannot establish compatibility: three matching old validators can advance the
chain while the upgraded validator produces different bytes, falls behind, or
records itself as malicious.

Any crypto-library, transcript, validator-key, or serialization change MUST
state how the literal previous release interoperates during a rolling rollout.
If it cannot, the candidate is not releasable until compatibility is restored
or the decentralized rollout contract is explicitly changed outside this test.

**Status of the verification machinery:** each `MIN_PROTOCOL_VERSION` bump
retires the rehearsals whose old binary no longer shares a protocol version
with the current one — their topologies cannot boot. Retired at MIN = 5: the
v1.1.8→v4 and v1.2.1→v5 rehearsals (`v118_upgrade`, `v118_churn`,
`v118_mixed_rollout`, `v121_rollout`, `cross_binary`,
`malicious_cross_binary`). Retired at MIN = 6: the v1.2.5-based
`v125_rollout`, `v125_churn` and `malicious_v125` — including the historical
v5 gate, which cannot boot once genesis is MIN = 6. Retired at MIN = 7: the
v1.2.7-based `v127_rollout`, `v127_churn` and `malicious_v127`, along with
BOTH protocol-transition gates (`v127_v7_upgrade` and the in-process
`protocol_version_transition` cluster test) — MIN = MAX = 7 leaves no
boundary for them to cross, so they were retired outright rather than
retargeted, and whichever change introduces v8 must resurrect them. Every one
of those rollouts completed on the deployed networks.

Beyond the MIN-driven retirements, the mixed-committee family is retargeted
whenever the DEPLOYED release moves — the scenario names carry the old
binary's release (`v125_*` → `v127_*` → `v128_*` → `v131_*` → `v140_*` →
`v141_*`), so the maintenance is visible rather than silent. The current
deployed-release gate is `tests/v141_rollout.rs`: the one-upgraded-validator
mixed topology against the literal **v1.4.1** release at protocol v7. Both
sides support v7 and only v7, so the boundary under test is a pure binary
swap. It is the PR-gating scenario and the one a release manager dispatches
against every release tag.

**No scenario crosses the storage-model change any more.**
`tests/mid_epoch_rollback.rs` was the one that did: it was deliberately kept
out of that sweep and pinned to **v1.3.1**, the last release from before the
epoch was event-sourced (#2074), because its subject was precisely an old
binary reopening an epoch store whose fold-side tables it expects and does
not find. Every other member of the family followed the deployed release;
that one followed a capability. It was deleted once v1.4.0 shipped and was
validated in production (#2077, #2064), as a deliberate retirement of the
rollback safety net.

Note what that leaves the forward gate standing on. The v1.3.1-based
`v131_rollout` straddled the storage-model change by accident of timing;
`v141_rollout` has both sides post-#2074 and stands behind wire and
MPC-output agreement only. Nothing in it was weakened to get there, and that
ingredient used to survive in the scenario pinned for it — but with that
scenario retired it now lives nowhere in the matrix. Any future change that
reintroduces a storage-model boundary needs a scenario built for it; there is
none to inherit.

## How this is verified

`crates/ika-upgrade-test/` spawns real, separately-compiled
`ika-validator` child processes against an external `sui` localnet and
drives them across epochs. The surviving scenarios (current build only):

- `tests/smoke.rs` — harness plumbing: four same-binary processes reach
  epoch 2 on the genesis epoch cadence.
- `tests/workload.rs` — the session-lifecycle invariant: a full user
  DKG → Presign → Sign completing on-chain at genesis protocol v7.
- `tests/v141_rollout.rs` — the current deployed-release compatibility gate:
  boot the literal v1.4.1 release at genesis protocol v7, upgrade exactly one
  of four validators to the candidate, require two mixed
  network-key reshares to converge byte-identically with zero malicious
  reports and a served user lifecycle after each, then swap the remaining
  validators and converge again. The upgrade workflow runs this scenario by
  default for relevant pull requests and release candidates.
- No PROTOCOL-upgrade gate currently exists: with MIN = MAX = 7 there is no
  boundary to cross, so `v127_v7_upgrade` and its in-process counterpart
  `crates/ika-test-cluster/tests/protocol_version_transition.rs` were retired
  with the v6 support they exercised. Both must be resurrected, retargeted at
  the new boundary, by whichever change introduces v8 — a release blocker for
  it, not a follow-up. The out-of-process flavor is the load-bearing one
  whenever the boundary changes process-wide state (v7's `AuthorityName`
  width was such a case): only separately-compiled validator PROCESSES flip
  it independently the way a fleet does, while the in-process cluster test
  shares one such global across all four simulated validators and can only
  gate the vote arithmetic and the cross-epoch handoff path.
- `tests/v141_churn.rs` — the churn counterpart: full sequential swap over
  the literal v1.4.1 committee (on-disk RocksDB continuity), then a
  peer-only-mirrored joiner folds into the reshared v1.4.1-origin key
  (4→5, the OCS joiner trust-anchor path) and a shrink reshare removes an
  original validator (5→4).
- `tests/malicious_v141.rs` — the test-testing counterpart: an honest
  literal-v1.4.1 committee plus ONE current-build validator carrying the
  `test-testing`-gated reconfiguration-message fault (the hook lives in
  the main reconfiguration advance path in
  `crytographic_computation/mpc_computations.rs`); honest validators must
  convict it and reshare without it, asserted via the malicious-actors
  gauge. Green = the compatibility gates above are not vacuous. The
  workflow's `test_testing_fault` input runs the same fault through
  `v141_rollout` itself (that run must fail closed); `malicious_v141` is
  also directly dispatchable (the workflow builds the faulty binary).
- **There is no BACKWARD direction in the matrix, and no scenario whose OLD
  side is pinned to a capability rather than to the deployed release.**
  `tests/mid_epoch_rollback.rs` used to be both — the candidate ran the
  network, then the **v1.3.1** release (the last one from before #2074) was
  put back on one validator MID-EPOCH, on stores the candidate had been
  writing. It proved that rollback safe for the **v1.4.0 release commit**
  (#2077, plus the production validation in #2064) and was deleted once v1.4.0
  shipped and was validated in production, as a deliberate retirement of the
  rollback safety net. What it measured is kept, marked historical, in
  [`event-sourced-epoch.md`](event-sourced-epoch.md) ("Rolling back"). A
  mid-epoch rollback to v1.3.1 from a commit later than v1.4.0 is untested.
- `tests/restart_spectator.rs` — a validator restarted mid-epoch must
  resume contributing rather than following consensus as a spectator,
  asserted on the internal presign pool's ordinal-stream log lines.
- `tests/wedged_drain.rs` — a validator whose MPC drain is stuck but ALIVE
  (parked by the production binary's `IKA_TEST_PARK_MPC_DRAIN_AFTER_ROUND=<n>`
  hook — `n >= 1`, `0` is off — per-validator, via the harness's extra-env
  support) must fill its
  round channel, park its consensus fold, HOLD the commit-liveness watchdog
  rather than exit, keep committing in consensus, leave its peers untouched,
  and resume on release without a restart — all asserted from `/metrics`,
  which is the only evidence this failure has (ika #2102).
How the mixed-rollout evidence weighs the upgraded validator's output: production
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

Before swapping the remaining OLD validators, the rollout must witness
conclusive candidate byte-equality on at least one mixed reconfiguration
boundary or its evidence checkpoint fails with "insufficient cross-version
compatibility evidence". Evidence from a later all-current boundary cannot
rescue an unevidenced mixed phase. The final scenario-wide evidence check
remains in place for every validator observed by its convergence steps.
Every boundary still requires healthy validators, correct local epochs,
protocol v7, quorum output convergence, zero malicious actors, zero rejected
envelopes, no self-malicious logs, and no stranded sessions.

The dependency upgrade has a separate **validator encryption-key preservation
checkpoint** in `v141_rollout`. Before the first swap, the harness verifies
that the certified handoff into epoch 2 contains every original validator's
public keys. That authenticated snapshot is the baseline for the upgraded
committee. The existing store-backed seed-recovery regression separately
requires production derivation to reproduce the frozen deployed native bundle,
including all keys and proofs; the rollout does not duplicate that derivation.
After the remaining swaps in epoch 4, epoch 5 runs entirely on the candidate.
The handoff produced in epoch 5 must retain every validator's public keys in
epoch 6, after a complete all-current epoch.

At each checkpoint, every original validator must serve the same attestation
for the preceding epoch. The harness verifies its committee signatures,
quorum, exact epoch and membership, then hash-checks the certified blobs and
compares all seven public keys for every validator. All six class-group keys
(three CRT and three PVSS) and the VSS HPKE key must equal their legacy values.
A different blob digest or different proof bytes does not change key identity.
The guard's fault control changes each public-key slot in turn and requires
its specific preservation error; unchanged identities with changed proof bytes
must still pass the identity check.

The checkpoint client resolves the generated YAML's on-chain identity using
the node's config resolver before selecting its Anemo chain namespace.
Deserialization alone leaves the runtime object IDs unset; connecting with
those IDs fails the TLS handshake before any certified key can be checked.

The epoch-6 checkpoint also requires every validator's selected and prepared
key epochs to equal the active epoch, plus its matching seed-identity metric.
Merely opening the epoch store does not establish that key preparation finished.
The full user workload runs again after this checkpoint, with zero malicious
reports on all four validators. This proves preservation and continued use of
native validator encryption keys across the upgrade. New browser keys created
through the V2 APIs use the same sampling as native; the original APIs retain
historical WASM32 derivation. Neither path changes the protocol version or any
contract.

The TypeScript SDK preserves historical WASM32 derivation through its existing
`createClassGroupsKeypair` and `fromRootSeedKey` entry points. Both are deprecated
but retain their original seed-to-key behavior when the SDK is upgraded. Callers
explicitly opt into current sampling with `createClassGroupsKeypairV2` or
`fromRootSeedKeyV2`. The original direct WASM export
`generate_secp_cg_keypair_from_seed` also preserves historical sampling; its `_v2`
counterpart opts into portable sampling.
The direct keypair API does not expose a sampler option.
Real-WASM fixtures check both public entry points against captured historical
keys and native current keys.

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

## Binary upgrade during an active session

`tests/v141_mid_session.rs` covers a different boundary from the rollout:
OLD has already contributed to an identified epoch-2 network-key
reconfiguration when its process is replaced. The harness waits for OLD's
round-three computation to start and rejects any run where OLD already
advanced that round or finalized before shutdown. NEW reopens the same
configuration and database, replays OLD's committed rounds one and two,
and must advance round three and finalize that exact session.

The committee has four original, equal-stake validators, with its actual
three-of-four quorum checked from chain state. Validator three is suspended
before the session starts. At the interruption point the two remaining OLD
peers are briefly suspended while the target shuts down, then resumed when
NEW boots. Validator three remains suspended until the participation gate
passes, so the two OLD peers cannot complete without the target. Pauses are
bounded and resumed on error; neither historical source nor validator
runtime scheduling parameters are changed. This is a controlled interruption
scenario, not a measurement of an unattended deployment's timing.

Evidence is scoped to one session identifier, epoch and validator identity.
Pre-upgrade log evidence cannot satisfy the post-upgrade round/Finalize
guards. The target's fresh advancement, OLD peers receiving its message,
accepted matching output from the three participating authorities, same-epoch
completion and zero malicious reports are required. Consensus-only recovery,
a different completed session, or a late local output without participation
cannot make this test pass. It covers the reconfiguration round-two/three
boundary; it does not establish every protocol or interruption point.

With `test_testing_fault=true`, this scenario deliberately withholds NEW and
resumes all three OLD peers. They must complete the selected session, and
the same participation gate must reject the absent upgraded contribution.
This negative control is expected to fail, with evidence that OLD-only quorum
completion was insufficient. It changes only harness process control and is
never counted as a successful upgrade run.

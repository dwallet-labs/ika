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

4. **Wire compatibility.** A vN binary MUST correctly deserialize the
   consensus messages and MPC messages produced by vN−1 peers, and vice
   versa. The versioned-enum payloads are the trap: adding a variant in
   vN+1 breaks vN deserialization unless vN was written to tolerate it.
   Wire compatibility is what makes a **rolling** swap (mixed committee,
   peers exchanging consensus + MPC messages mid-epoch) valid at all — it
   is only valid between builds that are mutually wire-compatible (see
   the crypto-boundary exception below).

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

## The crypto-boundary exception: a naive rolling swap is NOT always valid

A rolling, mixed-committee swap is valid **only between builds that share
the same crypto and differ solely in the protocol version they
advertise**. Across a crypto-library boundary it is not, and the upgrade
must instead be an **atomic, coordinated full-network restart**.

The concrete instance that defines this rule (`mainnet-v1.1.8` → current
`dev`):

- v1.1.8 links `class_groups` from the `inkrypto` crypto library; `dev`
  links `cryptography-private` (the migration between the two). Their MPC
  wire formats are not interchangeable, so a mixed v1.1.8/`dev` committee
  cannot exchange MPC messages.
- v4 also changed validator-key publication from the bare
  `ClassGroupsEncryptionKeyAndProof` shape to the combined
  `ValidatorEncryptionKeysAndProofs`. A v1.1.8 binary booted into a
  committee whose validator records were registered in the new shape
  fails to decode the on-chain record (`class groups public key …
  remaining input`) and panics on the key-mismatch check at startup.
- The current build carries **backward** compatibility for the v1.1.8
  key shape, so it can read state v1.1.8 wrote; v1.1.8 has no **forward**
  compatibility for the new shape. Compatibility across this boundary is
  therefore one-directional, which is exactly why the swap must be atomic
  (every validator restarts onto the new binary together) rather than
  rolling.

A change that introduces a new crypto-library or validator-key-shape
boundary inherits this constraint: it MUST document whether mixed
committees remain wire-compatible, and if not, that its rollout is an
atomic restart, not a rolling swap.

## How this is verified

`crates/ika-upgrade-test/` spawns real, separately-compiled
`ika-validator` child processes against an external `sui` localnet and
drives them across epochs:

- `tests/smoke.rs` — harness plumbing: four same-binary processes reach
  epoch 2 on the genesis epoch cadence.
- `tests/workload.rs` — the session-lifecycle invariant: a v3→v4 upgrade
  followed by a full user DKG → Presign → Sign completing on-chain.
- `tests/cross_binary.rs` — a rolling swap with committee churn between
  two wire-compatible builds (an OLD build of the current branch pinned
  to `MAX_PROTOCOL_VERSION = 3`, and the current `dev`): the vote
  advances v3 → v4 while the committee reshapes 4 → 3 → 5 → 4.
- `tests/v118_upgrade.rs` — the atomic mainnet rehearsal: boot the literal
  `mainnet-v1.1.8` binary, run the mainnet user flow at v3, swap all
  validators at once to the current build, and confirm the network
  upgrades to v4 and keeps serving through the pre-activation presign
  window.

Run them on CI via the **Upgrade Test** workflow
(`.github/workflows/upgrade-test.yaml`); see
[`../playbooks/ci-suites.md`](../playbooks/ci-suites.md).

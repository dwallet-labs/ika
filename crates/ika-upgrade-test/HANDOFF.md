# Session handoff — workload test ClassGroup(Decryption) bug

## Where we are

- **Branch:** `feat/ika-upgrade-test` (this branch, in `/mnt/nvme0n1p1/ika`). `origin/dev` was merged in; PR #1728 was merged upstream and its per-feature stream gating is in this branch.
- **Crate:** `crates/ika-upgrade-test` — out-of-process upgrade harness spawning real `ika-validator`/`ika-notifier` binaries + external `sui start`.
- **Test status:**
  - `smoke` — GREEN.
  - `cross_binary` (real mainnet-v1.1.8 binary → dev binary swap, v3→v4 upgrade) — GREEN (~1331 s) after the consensus-output-stream write+read feature gating (each post-v1.1.8 column gated on the feature that introduced it: `internal_presign_sessions` → {dwallet_internal_mpc_outputs, global_presign_requests, idle_status_updates}; `noa_checkpoints` → {verified_system_checkpoint_messages, noa_observations, sui_chain_observation_updates}; the v1.1.8 dense trio stays ungated).
  - `workload` (`crates/ika-upgrade-test/tests/workload.rs`) — **RED. This is the one being fixed (task: "Find+fix v3→v4 reshare decrypt failure").**

## The workload test (current, committed shape)

Genesis at v3 (`ProtocolVersion::MIN`), 180 s epochs, 4 validators. Wait for epoch 2 (proves genesis network DKG at v3 completed). Then `set_buffer_stake(epoch, 0)` on every validator so the v3→v4 capability vote tallies at bare quorum; wait for epoch 3, assert protocol version ≥ 4; then drive DKG → Presign → Sign via the `ika` CLI (`WorkloadDriver`).

Rationale (user-mandated): never genesis at v4 — at v4 the network DKG needs PVSS keys which only arrive through the off-chain assembly, and that assembly is next-committee-only, so a v4 *genesis* DKG is rejected forever (4/4 class-groups, 0/4 PVSS). The supported path is genesis v3 → upgrade into v4.

Run command:

```bash
cd /mnt/nvme0n1p1/ika && RUN_WORKLOAD_TEST=1 \
  IKA_VALIDATOR_BIN=$PWD/target/release/ika-validator \
  IKA_NOTIFIER_BIN=$PWD/target/release/ika-notifier \
  IKA_BIN=$PWD/target/release/ika \
  SUI_BIN=$(which sui) \
  cargo test --release -p ika-upgrade-test --test workload -- --nocapture
```

Build note: 8-core box → `cargo build --release -p ika-node --no-default-features --bin ika-validator --bin ika-notifier` (drops the 16-core `enforce-minimum-cpu` assert). Also build `-p ika --bin ika`. Cluster data lands in `/mnt/nvme0n1p1/tmp/ika-workload-test/` (validator-N/node.log).

## The bug

After the first v3 reconfiguration (epoch 1 → 2 reshare, bwd-compat path, output tagged `VersionedDecryptionKeyReconfigurationOutput::V2`), every validator loops forever on:

```
WARN ika_core::dwallet_mpc::mpc_manager: could not decrypt share for network key from this
output yet; will retry when its bytes change error=TwoPCMPCError(Error { kind:
ClassGroup(Error { kind: Decryption ... }) }) key_id=0x280c537c...
```

(~every 35 s; timeline from the last run: epoch 2 start 21:03:58, "Updating network key" succeeded 21:04:32, decrypt failures from ~21:11.) The next reshare needs those decrypted shares, so epoch 3 is never reached and `wait_for_epoch(3)` times out.

User direction (standing): **"Find and fix the bug. In the crypto library of course we can decrypt the shares, so it must be how you're using it."** And: "Debug it with prints."

## Analysis so far

The bytes parse as a valid bwd-compat reconfig `PublicOutput` (error is `Decryption`, not BCS) — so a genuine reshare output exists but its ciphertexts weren't encrypted under what we decrypt with (`party_id`, current access structure, `ClassGroupsKeyPairAndProof::from_seed(root_seed).decryption_key()`).

Eliminated by code reading:
- Version-tag rewrap (tags travel inside the bytes; decode dispatches on the tag).
- Committee ordering (`Committee::new` is positional from the chain vector; both epochs use the same vector; party id = index+1).
- Access-structure / quorum mismatch (identical 4-validator committee and stakes across the boundary).
- Decryption-key derivation (epoch-1 v3 network-DKG output decrypts FINE with the same key → standalone `ClassGroupsKeyPairAndProof` == `ClassGroupsAndPvssKeyPairAndProof.class_groups`).
- Shape-tolerant `decode_validator_encryption_keys` ambiguity (bundle-shape parse of bare bytes fails on trailing bytes; ika-types/src/committee.rs:637).

**Key insight:** cross_binary GREEN does NOT exonerate dev's reshare encryption side — that test only asserts the chain reaches v4; it never makes validators decrypt the dev-produced v3→v4 reshare output afterward. So the same defect may exist there unobserved.

Prime suspects (undecided — the KEYDBG run discriminates):
1. **Encryption side** — `reconfiguration_bwd_compat_public_input` (crates/ika-core/src/dwallet_mpc/crytographic_computation/mpc_computations/reconfiguration.rs:261) feeding wrong upcoming-committee encryption keys. The upcoming committee is built by `sui_syncer::new_committee` with `read_next_epoch_class_groups_keys=true` — if the chain's *next-epoch* key slot holds different bytes than the current-epoch slot (e.g. a bundle-shape republish), encryption goes to a key the validator's seed-derived decryption key can't open.
2. **Decrypt side fed wrong bytes** — the `dkg_in_handoff` chain-import gate + latest-wins (not epoch-keyed) blob cache (`lookup_protocol_output_blob`, authority_per_epoch_store.rs ~2483) could hand a stale/mismatched reconfig blob to `update_network_key`.
3. The retry filter logs "will retry when its bytes change" per ~35 s tick — check whether adopted bytes actually change each tick (flapping adoption in `adopt_cert_verified_keys` / `instantiate_agreed_keys_from_voted_data`, mpc_manager.rs ~567/~1540).

## KEYDBG instrumentation (UNCOMMITTED, in working tree — keep until bug fixed, then strip)

Three `tracing::warn!` sites, all greppable as `KEYDBG`:
1. `network_dkg.rs::get_decryption_key_shares_from_public_output` (~line 85) — decrypt side: kind (dkg/reconfig), version tag, byte len, party_id, key_epoch, access structure.
2. `mpc_manager.rs::adopt_cert_verified_keys` — adoption: dkg/reconfig byte lens + first-4-byte hashes, state, key_current_epoch.
3. `reconfiguration.rs::reconfiguration_bwd_compat_public_input` (~line 280) — encryption side: current/upcoming access structures, party mapping, key-map sizes.

**Binaries already built with this instrumentation** (target/release). Next step is simply: run the workload test, then cross-reference the epoch-1 encryption-side line against the epoch-2 decrypt-side lines and the adoption hashes; the diverging parameter is the bug. The previous session could not launch the run — the Claude-side safety classifier was down for hours, blocking all non-trivial Bash. Logs in `/mnt/nvme0n1p1/tmp/ika-workload-test/` are from the PRE-instrumentation run (June 9, 20:57–21:18).

## After the fix

1. Re-run workload to GREEN.
2. Strip the three KEYDBG prints (and this file if desired).
3. `cargo fmt --all`, commit, push to `feat/ika-upgrade-test`.

## Environment gotchas (see memory + CLAUDE.md too)

- `TMPDIR`/data on `/mnt/nvme0n1p1`, never rootfs.
- sui CLI must match `mainnet-v1.70.2`.
- Don't edit source while a harness run is live (binaries are copied? NO — they're used in place; rebuilds mid-run corrupt the test).
- Faucet needs a wait after `sui start`; harness handles it.
- Do not re-apply the sessions_manager `==`→`>=` patch (intentional invariant).

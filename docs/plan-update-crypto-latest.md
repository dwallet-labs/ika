# Plan: Update crypto-private to `main` on `update-crypto-latest` branch

## Context

Mainnet runs `mainnet-v1.1.8` against `cryptography-private @ babbb483`. The next
crypto rev (`main`) introduces sweeping breaking changes (see
`docs/breaking-changes-inkrypto-to-main.md`): new validator keys (HPKE + per-curve
PVSS), an extended 7-round network DKG, a new threshold_encryption_to_sharing
sub-protocol, modified `Reconfiguration::Message` and `dkg::Message` wire
formats, removed `From<tuple>` constructors, GroupElement operator removal, and
new associated types on `sign`/`presign`/`dkg::Protocol`.

We need the new crypto in the binary now so we can build against its APIs and
generate/parse the new wire formats — without breaking interop with
`babbb483`-era validators that will still be running during the rollout (mixed
committees during the upgrade window, exactly like other Sui/Ika rolling
upgrades). Move-side contracts are NOT modified — they are already deployed on
Sui and must continue to deserialize what they deserialize today.

**Out of scope for this branch:**
- Activating any V2 protocol (no 7-round network DKG, no VSS sign/presign).
- Move-contract changes.
- Distribution of HPKE/PVSS public keys via consensus (a follow-up will add the
  `ConsensusTransactionKind::ValidatorPublicMPCData` broadcast).
- Bumping the deployed `MAX_PROTOCOL_VERSION` of any live network.

**In scope:**
- Binary builds against both `babbb483` and `main` crypto-private revs at once.
- Mechanical API breaks fixed in all callers (centralized-party, ika-core, etc.).
- New `Versioned…` enums extended with a V… variant whose bytes are produced
  with the v2 crate; existing variants keep their `babbb483` bytes.
- HPKE + PVSS keypair generation (seed-derived) wired into validator startup;
  public components held in-memory only for now.
- Protocol-version slot v5 added, gated by feature flag, **default OFF**.

## Architecture decision: dual-pin crypto-private

The two crypto revs are NOT wire-compatible (DKG `Message` gained variants,
`Reconfiguration::Message` changed tuple→struct variant, DKG `PublicOutput`
gained `threshold_encryption_to_sharing_output`). We cannot drop `babbb483` while
mainnet-v1.1.8 validators still serve sessions, so the new binary must contain
both crypto stacks and dispatch by protocol version.

**Cargo approach:** add v2 deps under `_v2` aliases, leave v1 deps at their
current names. New code uses `twopc_mpc_v2::…`; existing code keeps `twopc_mpc::…`.

```toml
# v1 — unchanged; deserializes/produces babbb483 wire formats.
twopc_mpc           = { git = "…/cryptography-private", rev = "babbb483" }
class_groups        = { git = "…/cryptography-private", rev = "babbb483", features = ["threshold"] }
# … (mpc, proof, commitment, group, homomorphic_encryption — unchanged)

# v2 — new; main rev (pin to a specific commit, e.g. 6ae3d92b per the doc).
twopc_mpc_v2           = { package = "twopc_mpc",           git = "…/cryptography-private", rev = "<MAIN_REV>" }
class_groups_v2        = { package = "class_groups",        git = "…/cryptography-private", rev = "<MAIN_REV>", features = ["threshold"] }
mpc_v2                 = { package = "mpc",                 git = "…/cryptography-private", rev = "<MAIN_REV>" }
proof_v2               = { package = "proof",               git = "…/cryptography-private", rev = "<MAIN_REV>" }
commitment_v2          = { package = "commitment",          git = "…/cryptography-private", rev = "<MAIN_REV>" }
group_v2               = { package = "group",               git = "…/cryptography-private", rev = "<MAIN_REV>", features = ["os_rng"] }
homomorphic_encryption_v2 = { package = "homomorphic_encryption", git = "…/cryptography-private", rev = "<MAIN_REV>" }
```

**Cargo concerns to verify early (Phase 0):**
1. Two revs of the same git source compile in one workspace — Cargo supports
   this routinely (different `rev =` → different `[[package]]` lock entries).
2. No `#[no_mangle]` symbols collide between v1 and v2 (spot-check by building
   a 10-line throwaway binary that depends on both before doing any other work).
3. Build time / binary size cost is acceptable — both stacks are heavyweight
   crypto. Expect significant cold-build increase; CI may need attention.
4. Transitive deps: shared bigint / curves crates may resolve to one version
   (fine) or two (fine but bloats). Whatever cargo resolves is acceptable.

If Phase 0 fails, fall back to: do not dual-pin; instead, bump to v2 outright
and accept that mixed-committee interop is broken — escalate to user for
decision before continuing.

## Phased work

### Phase 0 — Prove dual-pin builds (1–2 hrs, do before any other code work)

1. Pick the exact `main`-rev commit to pin. The breaking-changes doc names
   `6ae3d92b` ("Take latest inkrypto"); confirm with user or use latest main of
   `cryptography-private` at the time of work. Pin a specific commit hash.
2. In a throwaway scratch crate (or in `dwallet-mpc-types` behind a `cfg(test)`
   module), import a single type from each of `twopc_mpc` and `twopc_mpc_v2`.
   Run `cargo build --release -p <crate>` — must succeed.
3. If it builds, proceed. If it fails, capture the failure and stop.

### Phase 1 — Wire up workspace dependencies

**Files:**
- `Cargo.toml` (root) — add the seven `_v2` aliased workspace deps.
- Per-crate `Cargo.toml`s — add `_v2` deps to the crates that will actually use
  v2 in later phases. Concretely:
  - `crates/dwallet-mpc-types/Cargo.toml`
  - `crates/dwallet-mpc-centralized-party/Cargo.toml`
  - `crates/ika-core/Cargo.toml`
  - `crates/ika-types/Cargo.toml`
  - `crates/dwallet-rng/Cargo.toml`
- `Cargo.lock` will gain a parallel set of crypto-private entries — expected.

No code changes yet. `cargo build --release` must still pass.

### Phase 2 — `Versioned…` enums extended for v2 wire formats

**File:** `crates/dwallet-mpc-types/src/dwallet_mpc.rs` (currently has these
enums around lines 299–367).

The breaking-changes doc tells us which wire formats actually changed. Treat
each Versioned enum individually:

| Enum | Current variants | Wire-format change in v2? | Action |
|------|------------------|---------------------------|--------|
| `VersionedNetworkDkgOutput` | V1, V2 | YES (new `threshold_encryption_to_sharing_output` field) | Add `V3(MPCPublicOutput)` carrying v2 bytes |
| `VersionedDecryptionKeyReconfigurationOutput` | V1, V2 | YES (Message variant changes propagate to output struct shape) | Add `V3(MPCPublicOutput)` |
| `VersionedDwalletDKGPublicOutput` | V1, V2 | NO per doc (identical) | Leave as-is |
| `VersionedDwalletDKGFirstRoundPublicOutput` | V1 | NO | Leave as-is |
| `VersionedPresignOutput` | V1, V2 | NO (Presign output is wire-stable) | Leave as-is |
| `VersionedSignOutput` | V1 | NO | Leave as-is |
| `VersionedCentralizedDKGPublicOutput` | V1, V2 | NO | Leave as-is |
| `VersionedDwalletUserSecretShare` | V1 | NO | Leave as-is |
| `VersionedUserSignedMessage` | V1 | NO | Leave as-is |
| `VersionedEncryptionKeyValue` | V1 | NO | Leave as-is |
| `VersionedPublicKeyShareAndProof` | V1 | NO | Leave as-is |

Update `VersionedNetworkDkgOutput::as_bytes()` to include V3.

Add the new validator-keys envelope:

```rust
#[derive(Deserialize, Serialize, Clone, Debug, Eq, PartialEq)]
pub enum VersionedValidatorPublicMPCData {
    /// What ika sees today: class-groups encryption key + proof per validator,
    /// read from the on-chain committee. Bytes formatted per babbb483 schema.
    V1 { class_groups_public_key_and_proof: Vec<u8> },
    /// Adds HPKE (Curve25519) and per-curve PVSS encryption keys. In this
    /// branch, V2 is constructible and BCS-roundtrips but is NOT produced by
    /// any consensus path — a follow-up PR will broadcast V2 via consensus.
    V2 {
        class_groups_public_key_and_proof: Vec<u8>,
        hpke_public_key_and_proof: Vec<u8>,
        /// Index 0 = secp256k1, 1 = ristretto, 2 = secp256r1 (matches
        /// upstream PVSS curve ordering).
        pvss_encryption_keys_and_proofs: Vec<Vec<u8>>,
    },
}
```

No new fields on `Committee` yet — V2 will live on `DWalletMPCManager` once
broadcast is wired (follow-up PR). For this branch, V1 is what callers
construct and read from on-chain (unchanged Move path).

### Phase 3 — Mechanical API breaks fixed in centralized-party

`crates/dwallet-mpc-centralized-party/src/lib.rs` is the only ika-side crate
that directly invokes the heavy v2-only-API surface. Per the doc, all changes
here are mechanical:

- Replace `+ - * +=  -=  unary -` on `GroupElement` with
  `add_vartime / add_constant_time / sub_constant_time / neg_constant_time`,
  each taking `&public_parameters`.
- Add `&pp` to every `scale*()` call (`scale`, `scale_vartime`, `scale_integer`,
  `scale_*_accelerated` → `scale_*_by`).
- `GroupElement` and `GroupElement::Value` are no longer `Copy` — sprinkle
  `.clone()`; add explicit `+ Copy` where the generic actually needs it.
- `HomomorphicCommitmentScheme::commit(...)` now takes an extra `&pp`.
- Replace `From<tuple>` constructions on `ProtocolPublicParameters::new`,
  `SignCentralizedPartyPublicInput::from(tuple)`, DKG centralized inputs, etc.
  with struct-literal construction.
- Update `Error` matches to cover the new variants (`InvalidSignatureShare`,
  `DecryptionFailed`, `IdentityEphemeralKey`, `TorsionEphemeralKey`,
  `MaliciousMessageAsync`, `MaliciousMessagePreventsAdvance`,
  `Serialization(String)`); `AsyncProofAggregation` source changed to
  `proof_aggregation`.
- Apply path renames: `schnorr::presign` → `schnorr::ahe::presign`,
  `schnorr::sign::centralized_party::PartialSignature` →
  `schnorr::PartialSignature`, PVSS types → `chinese_remainder_theorem` submod,
  `mpc::SeedableCollection` → `group::SeedableCollection`,
  `proof::aggregation` → standalone `proof_aggregation` crate,
  `maurer::aggregation` → standalone `maurer_aggregation` crate.

**Decision for this phase:** the centralized party migrates to **v2 imports
only**. This is safe because per the doc, all wire types it produces/consumes
(centralized DKG output, sign messages, partial signatures, protocol public
params, encrypted-share proofs) are byte-identical between v1 and v2. So one
v2-built centralized party serves both v4-active and v5-active sessions; no
dispatch needed at this layer.

If we discover any wire format that turns out to be NOT byte-identical despite
the doc, stop and reassess — that's a discovery that warrants a user check-in.

### Phase 4 — ika-core compiles against unchanged v1 paths

Existing MPC computation modules (`network_dkg.rs`, `reconfiguration.rs`,
`dwallet_dkg.rs`, `sign.rs`, `presign.rs` under
`crates/ika-core/src/dwallet_mpc/crytographic_computation/mpc_computations/`)
keep using the v1 crates. Their imports stay as `twopc_mpc::…`. No dispatch
code yet — V2 protocol paths come in a follow-up.

Things to verify still compile:
- `extract_encryption_keys_from_committee()` in `reconfiguration.rs`
- `decrypt_decryption_key_shares()` call in `network_dkg.rs`
- All `From<tuple>` builders for public inputs — these only exist in v1, and
  v1 hasn't changed, so they keep working as-is.

### Phase 5 — Seed-derived HPKE + PVSS keypair generation

**File:** `crates/dwallet-rng/src/lib.rs`

Add to `RootSeed` (mirrors the PLAN-v2-keys-upgrade.md design — independent
Merlin transcript labels, no domain reuse):

```rust
fn hpke_key_seed(&self) -> [u8; Self::SEED_LENGTH] {
    let mut transcript = Transcript::new(b"HPKE Encryption Key Seed");
    transcript.append_message(b"root seed", &self.0);
    let mut seed = [0u8; Self::SEED_LENGTH];
    transcript.challenge_bytes(b"seed", &mut seed);
    seed
}

fn pvss_encryption_key_seed(&self, curve_index: u8) -> [u8; Self::SEED_LENGTH] {
    let mut transcript = Transcript::new(b"PVSS Encryption Key Seed");
    transcript.append_message(b"root seed", &self.0);
    transcript.append_message(b"curve index", &[curve_index]);
    let mut seed = [0u8; Self::SEED_LENGTH];
    transcript.challenge_bytes(b"seed", &mut seed);
    seed
}

pub fn hpke_key_rng(&self) -> ChaCha20Rng { ChaCha20Rng::from_seed(self.hpke_key_seed()) }
pub fn pvss_encryption_key_rng(&self, curve_index: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed(self.pvss_encryption_key_seed(curve_index))
}
```

Then write a small helper (likely in `dwallet-mpc-types` or a new module under
`crates/ika-core/src/dwallet_mpc/`) that takes a `RootSeed` and produces a
fully populated `VersionedValidatorPublicMPCData::V2` using the **v2** crypto
crates:

- `hpke_public_key_and_proof`: generated via the v2 HPKE keygen + Schnorr-style
  knowledge-of-secret-key proof (exact API name TBD from v2 crate inspection).
- `pvss_encryption_keys_and_proofs[i]`: for each `i in [0, 1, 2]` correspond to
  the three secp256k1 / ristretto / secp256r1 PVSS curves; each is a v2
  `class_groups`-flavored encryption key + `KnowledgeOfDiscreteLogUCProof`.

The exact API surface here is the first place this branch actually consumes v2
code at runtime — expect to discover the exact constructor names by reading
the v2 crate. Treat as a focused investigation that may surface follow-up
items.

This generator function is exercised in unit tests this PR (deterministic seed
→ deterministic V2 bytes). It is NOT wired into a startup path nor a consensus
broadcast in this PR.

### Phase 6 — Protocol-version slot (off by default)

**File:** `crates/ika-protocol-config/src/lib.rs`

- Bump `MAX_PROTOCOL_VERSION` from 4 to 5.
- Add the v5 arm in the per-version `match cur` ladder, setting a new feature
  flag `use_inkrypto_v2 = true` (or similar name; mirror existing flag style).
- Default the flag to `false` for all versions ≤ 4 — i.e. live networks running
  v4 are unaffected.
- A follow-up PR will flip a deployed network's max version to 5 once
  validator-key broadcast and V2 protocol implementations are ready.

This branch deliberately does NOT add any code that reads the flag yet.
The flag exists as a slot for follow-ups to gate on.

### Phase 7 — Tests + verification

Run end-to-end:

```bash
cargo build --release                             # must pass
cargo clippy --all-targets --all-features         # must pass (fix new lints)
cargo test --release -p dwallet-mpc-centralized-party
cargo test --release -p dwallet-mpc-types
cargo test --release -p ika-core dwallet_mpc      # full mpc integration tests
cargo test --release -p dwallet-rng               # new HPKE/PVSS seed tests
cd sdk/typescript && pnpm install && pnpm build && pnpm test
cargo fmt --all                                   # commit any reformat
```

Specific assertions to add:
1. `VersionedValidatorPublicMPCData` BCS roundtrips for both V1 and V2.
2. Deterministic V2 keygen — given a fixed `RootSeed`, the generated V2 bytes
   are stable across runs (lock in the wire format early).
3. `VersionedNetworkDkgOutput::V3` and `VersionedDecryptionKeyReconfigurationOutput::V3`
   BCS roundtrip and don't collide with V1/V2 deserialization (BCS variant tag
   differentiates).
4. All integration tests under `crates/ika-core/src/dwallet_mpc/integration_tests/`
   still pass — they exercise v1 paths only, which we haven't disturbed.

Manual sanity check: build an `ika-node` binary and run a local swarm
(`ika-swarm`) at protocol version 4 — must behave identically to `dev`.

## Critical files

- `Cargo.toml` (root, workspace deps)
- `crates/dwallet-mpc-types/src/dwallet_mpc.rs` (Versioned enums)
- `crates/dwallet-mpc-types/Cargo.toml`
- `crates/dwallet-mpc-centralized-party/src/lib.rs` (mechanical v2 migration)
- `crates/dwallet-mpc-centralized-party/Cargo.toml`
- `crates/dwallet-rng/src/lib.rs` (HPKE/PVSS seed derivation)
- `crates/dwallet-rng/Cargo.toml`
- `crates/ika-protocol-config/src/lib.rs` (v5 slot, feature flag)
- `crates/ika-core/Cargo.toml` (add v2 deps; no source changes this branch)
- `crates/ika-types/Cargo.toml` (add v2 deps; no source changes this branch)
- New helper module for V2 validator-key generation (location TBD: leaning
  `crates/dwallet-mpc-types/src/validator_public_mpc_data.rs` or a dedicated
  small crate to keep v2 deps out of the leaf types crate).

## Things deliberately deferred to follow-up PRs

1. `ConsensusTransactionKind::ValidatorPublicMPCData` broadcast + collection on
   `DWalletMPCManager` — needed before v5 can activate.
2. V2 implementations of `network_dkg.rs`, `reconfiguration.rs`,
   `dwallet_dkg.rs` using v2 crypto and the 7-round DKG — gated on the new
   feature flag.
3. VSS-mode sign/presign paths — gated on the same flag.
4. Tying `Committee` (or replacement) to V2 validator keys at epoch start.
5. Eventually retiring v1 deps once mainnet has moved past v4.

## Verification end-to-end

1. `cargo build --release` succeeds with both crypto-private revs in the
   dependency tree (Phase 0 sanity gate).
2. `cargo test --release` passes — including all existing MPC integration tests
   (which only exercise v1 paths and should be untouched).
3. New BCS-roundtrip + deterministic-keygen tests pass.
4. A clean `ika-swarm` run at protocol version 4 produces the same on-chain
   artifacts (DKG outputs, presigns, sign outputs) as `dev` — bit-for-bit if
   feasible, otherwise semantically (sign a transaction with a freshly created
   dWallet, all flows green).
5. No network at v5 yet — the feature flag is provably off in all default
   `ProtocolConfig` instances.

## Risks and unknowns

- **Dual-pin build viability** — addressed by Phase 0; user already flagged
  this concern. If it fails, we escalate before doing more work.
- **Compile-time/binary-size blowup** — measurable, expected, acceptable for
  the transition window; remove v1 once mainnet has fully migrated.
- **v2 API discovery for HPKE/PVSS keygen** — exact constructor names need
  reading; flagged as an investigation step in Phase 5.
- **Move-side assumes V1 only** — confirmed by user; on-chain deserialization
  always reads V1 today, V2 will arrive via consensus in a follow-up PR.

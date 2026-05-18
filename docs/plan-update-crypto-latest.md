# Plan: Update inkrypto on `update-crypto-latest` branch

## Context

Mainnet-v1.1.8 ika depends on **`inkrypto @ 37bb549f`** ("Backward compatible
relaxed check"). That rev contains the `decentralized_party_backward_compatible/`
parallel-protocol modules that were added on top of `dba2cba` to roll the
network forward from the prior wire format. It is the binary every mainnet
validator is running today.

The migration target is **`inkrypto @ abd7f01`** ("Revert backward
compatability") — inkrypto `main` today, which deleted the
`decentralized_party_backward_compatible/` modules now that the prior
transition window has closed. Between `37bb549f` and `abd7f01` the
cryptography library introduced the changes catalogued in
`docs/breaking-changes-inkrypto-to-main.md`: new validator keys (HPKE +
per-curve PVSS), an extended 7-round network DKG, the
`threshold_encryption_of_secret_key_share_parts_to_sharing` sub-protocol,
modified `Reconfiguration::Message` and `dkg::Message` wire formats,
`From<tuple>` constructor removals, GroupElement operator removal, `Copy`
removal on GroupElement/Value, new associated types on
`sign`/`presign`/`dkg::Protocol`, and a swathe of path renames and lower-crate
refactors.

ika's `dev` branch currently points its crypto deps at
`cryptography-private @ babbb483` directly, bypassing inkrypto. That was a
development convenience; for the migration we are going **back** to the
inkrypto repo as the canonical dependency source, because that's where
released, audited revs live and that's what mainnet validators consume.

Mixed-version committees are a hard requirement: validators upgrading from
mainnet-v1.1.8 binaries to the new binary will share MPC sessions during the
rollout window. The new binary must therefore be wire-compatible with the old
binary for every protocol whose format changed. Move-side contracts are NOT
modified — they are already deployed on Sui and must continue to deserialize
exactly what they deserialize today.

**Out of scope for this branch:**
- Activating any V2 protocol (no 7-round network DKG, no VSS sign/presign).
- Move-contract changes.
- Distribution of HPKE/PVSS public keys via consensus (a follow-up will add
  the `ConsensusTransactionKind::ValidatorPublicMPCData` broadcast).
- Bumping the deployed `MAX_PROTOCOL_VERSION` of any live network.

**In scope:**
- ika builds against both `inkrypto @ 37bb549f` and `inkrypto @ abd7f01`
  (dual-pin) at the same time.
- Mechanical API breaks fixed in all callers that move to the v2 surface.
- New `Versioned…` enums extended with a new variant whose bytes are produced
  by the v2 crate; existing variants keep their `37bb549f` bytes.
- HPKE + PVSS keypair generation (seed-derived) wired into a helper that can
  produce a `VersionedValidatorPublicMPCData::V2` — exercised in unit tests
  only this branch, no consensus path yet.
- Protocol-version slot v5 added in `ika-protocol-config`, gated by feature
  flag, **default OFF**.

## Architecture decision: dual-pin inkrypto

ika is going to import inkrypto TWICE in the same build:

| Alias | Source | Rev | Role |
|---|---|---|---|
| `twopc_mpc`, `class_groups`, `mpc`, `proof`, `commitment`, `group`, `homomorphic_encryption` (canonical names) | `dwallet-labs/inkrypto` | `37bb549f` | Old crate — frozen, byte-identical to what mainnet runs. Drives all existing v4-protocol MPC paths unchanged. |
| `twopc_mpc_v2`, `class_groups_v2`, `mpc_v2`, `proof_v2`, `commitment_v2`, `group_v2`, `homomorphic_encryption_v2` (aliased) | `dwallet-labs/inkrypto` | `abd7f01` (or a later pinned commit on inkrypto main) | New crate — surfaces the new APIs. Consumed by centralized-party and the new HPKE/PVSS key-generation helper. |

`cryptography-private` is removed as a direct ika dependency. All crypto goes
through inkrypto in this branch and afterward.

Note on naming: the canonical (un-suffixed) names point at the **old** rev,
not the new one. This minimises diff in existing ika code — no rename of
`use twopc_mpc::…` imports anywhere. New code that needs the v2 surface
opts in with `use twopc_mpc_v2::…`. When the rollout window closes and v1
is no longer needed, deletion is: drop the un-suffixed deps, rename the
`_v2` aliases to canonical, mechanical s/twopc_mpc_v2/twopc_mpc/ across
the codebase. One commit.

```toml
# Cargo.toml (workspace) — old (mainnet binary's crypto, frozen).
mpc                    = { git = "https://github.com/dwallet-labs/inkrypto", rev = "37bb549f" }
proof                  = { git = "https://github.com/dwallet-labs/inkrypto", rev = "37bb549f" }
class_groups           = { git = "https://github.com/dwallet-labs/inkrypto", rev = "37bb549f", features = ["threshold"] }
commitment             = { git = "https://github.com/dwallet-labs/inkrypto", rev = "37bb549f" }
twopc_mpc              = { git = "https://github.com/dwallet-labs/inkrypto", rev = "37bb549f" }
group                  = { git = "https://github.com/dwallet-labs/inkrypto", rev = "37bb549f", features = ["os_rng"] }
homomorphic_encryption = { git = "https://github.com/dwallet-labs/inkrypto", rev = "37bb549f" }

# Cargo.toml (workspace) — new (inkrypto main, aliased).
mpc_v2                    = { package = "mpc",                    git = "https://github.com/dwallet-labs/inkrypto", rev = "abd7f01" }
proof_v2                  = { package = "proof",                  git = "https://github.com/dwallet-labs/inkrypto", rev = "abd7f01" }
class_groups_v2           = { package = "class_groups",           git = "https://github.com/dwallet-labs/inkrypto", rev = "abd7f01", features = ["threshold"] }
commitment_v2             = { package = "commitment",             git = "https://github.com/dwallet-labs/inkrypto", rev = "abd7f01" }
twopc_mpc_v2              = { package = "twopc_mpc",              git = "https://github.com/dwallet-labs/inkrypto", rev = "abd7f01" }
group_v2                  = { package = "group",                  git = "https://github.com/dwallet-labs/inkrypto", rev = "abd7f01", features = ["os_rng"] }
homomorphic_encryption_v2 = { package = "homomorphic_encryption", git = "https://github.com/dwallet-labs/inkrypto", rev = "abd7f01" }
```

Pick the exact new rev with the crypto team before pinning — `abd7f01` is the
latest commit on inkrypto main as of this writing; a later vetted commit may
exist by implementation time. The choice must match whatever commit the crypto
team commits to support as the next release.

## Why not the in-crate `_backward_compatible/` pattern this time

This is the question that drove the design. The team's standard SOP for crypto
upgrades has been: add a `decentralized_party_backward_compatible/` parallel
module inside inkrypto, keep it alive for the rollout window, then revert it
once the window closes. Evidence: the explicit cycle in inkrypto's history —
`3ae2d07` → `cafeb4a` (add reconfig compat, revert after window),
`dba2cba` → `37bb549f` → `abd7f01` (add DKG+reconfig compat for the
mainnet-v1.1.8 window, revert after). It is a proven, lived pattern.

For this transition window I think dual-pin is the better choice anyway,
because the breaking changes go far beyond protocol layer. The
`_backward_compatible/` precedent succeeded when changes were mostly
additive at the protocol-message level on top of relatively-stable lower
crates. **This time the lower crates themselves were heavily reshaped.** A
crypto-side `_backward_compatible/` module is no longer "copy the old
protocol code"; it's "port the old protocol code to a new primitive
foundation that's been deliberately redesigned, then verify the ported
code produces bit-identical wire output." That's a different job.

A deliberately-thorough inventory of what shifted, by crate:

**`group`**
- All `GroupElement` operator overloads (`+`, `-`, `*`, `+=`, `-=`, unary `-`)
  removed. Replaced by `add_vartime(&b, &pp)` /
  `add_constant_time(&b, &pp)`, `sub_constant_time(&b, &pp)`,
  `neg_constant_time(&pp)`. Every legacy arithmetic call site must be
  rewritten **and** classified as vartime or constant-time, which is a
  cryptographic decision (timing-channel exposure), not a mechanical
  rewrite. The old code didn't surface this distinction.
- All `scale*()` methods (`scale`, `scale_vartime`, `scale_integer`,
  `scale_*_accelerated`) now take `&PublicParameters`. Every legacy call site
  threads `&pp` through.
- `Copy` removed from `GroupElement` and `GroupElement::Value`. Every place
  the legacy code relied on implicit copies must explicitly `.clone()`, and
  generic bounds in the legacy code that took `+ Copy` for free now need
  explicit bounds or an architectural rethink.
- `LinearlyCombinable` trait removed entirely; its methods moved onto
  `GroupElement` with new signatures. Anywhere the legacy code consumed
  `LinearlyCombinable::linear_combination(...)` needs a hand-port: figure
  out what the trait did, find the new equivalent (or write one), and
  preserve identical output.
- Scale method renames (`*_accelerated` → `*_by`).
- `SeedableCollection` moved out of `mpc` into `group`. Import paths shift.

**`commitment`**
- `HomomorphicCommitmentScheme::commit(...)` gained a `&public_parameters`
  parameter. Every commit call site in the legacy code threads a new
  parameter through — and where the legacy code didn't have a `pp` value in
  scope, the legacy *callers* need refactoring to plumb one in.

**`homomorphic_encryption`**
- `Copy` bounds added to `CiphertextSpaceGroupElement` and
  `RandomnessSpaceGroupElement` associated types. Legacy generic code that
  didn't impose `Copy` now needs to (and may not be able to, given `Copy`
  was removed from `GroupElement` itself — composes with the previous bullet).
- `GroupsPublicParametersAccessors` trait — accessor surface changed.

**`proof`**
- `proof::aggregation` removed from `proof` and re-emerged as a standalone
  `proof_aggregation` crate. Every import shifts; the API may differ.
- Error enum: `AsyncProofAggregation` source type changed to
  `proof_aggregation`. Legacy code that constructed or matched on this
  variant needs rework.

**`mpc`**
- Error enum gained: `InvalidSignatureShare`, `DecryptionFailed`,
  `IdentityEphemeralKey`, `TorsionEphemeralKey`, `MaliciousMessageAsync`,
  `MaliciousMessagePreventsAdvance`, `Serialization(String)`. Exhaustive
  matches in legacy code now break.
- `SeedableCollection` left `mpc` (moved to `group`); transitive callers
  shift imports.

**`maurer`**
- `maurer::aggregation` removed from `maurer` and re-emerged as a standalone
  `maurer_aggregation` crate. Same import / API issues as `proof_aggregation`.

**`class_groups`**
- `DKGProtocol` type aliases (per-curve) point to a structurally different
  type (`class_groups::asynchronous::DKGProtocol<...>`) than before. Legacy
  code that uses `DKGProtocol` references the wrong shape under the new
  crate.
- PVSS types relocated into a `chinese_remainder_theorem` submodule. Import
  shifts.
- New `asynchronous` module subtree.

**`twopc_mpc`**
- `sign::Protocol` no longer extends `dkg::Protocol`. Trait hierarchy
  refactor; legacy `Self::DKGOutput` lookups don't resolve under the new
  trait shape.
- New required associated types on `sign::Protocol` (`VerifiedSignData`,
  `SignDecentralizedPartyPrivateInput`), `presign::Protocol`
  (`HPKEEncryptionKey`, `PresignPrivateInput`), `dkg::Protocol`
  (associated types for threshold_encryption_to_sharing).
- New required method `dkg::Protocol::threshold_dkg_output`.
- `DecryptionKeyShare` and `DecryptionKeySharePublicParameters` types
  removed. Legacy code that named these types needs replacement targets,
  but the replacements only exist in the v2 surface (`SignDecentralizedPartyPrivateInput`).
- All `From<tuple>` constructors for `PublicInput` types removed. Struct
  literals only.
- New `SignData { Unverified, Verified, ToBeEmulated }` enum wraps
  `SignMessage` in sign public inputs — changes the shape of public inputs
  the legacy code constructs.
- `verify_centralized_party_partial_signature` return type changed from
  `Result<()>` to `Result<Self::VerifiedSignData>`. Callers of the legacy
  version of this function adapted.
- Path renames: `schnorr::presign` → `schnorr::ahe::presign`,
  `schnorr::sign::centralized_party::PartialSignature` →
  `schnorr::PartialSignature`. Legacy code's imports shift.
- `Take Arc<> of big data structures` (`7bc9472`): protocol public
  parameters, decryption key share public parameters are now consumed via
  `Arc<>`. Legacy code that owned values directly needs to either accept
  `Arc<>` or have its callers clone-out. Ownership-shape change.

What the in-crate `_backward_compatible/` pattern would have to do here:

1. Copy ~5,000 lines of frozen v1 protocol code into a new
   `decentralized_party_backward_compatible/` module in inkrypto main
   (i.e. on top of `abd7f01`).
2. For every GroupElement arithmetic call site in that copy, rewrite it
   into `add_vartime(&pp)` / `add_constant_time(&pp)` — making the
   timing-channel decision correctly for each site.
3. Plumb `&pp` through every commitment call.
4. Plumb `&pp` through every `scale*()` call.
5. Sprinkle `.clone()` everywhere `Copy` was relied on; widen generic
   bounds where needed.
6. Reimplement what `LinearlyCombinable` provided, or call the equivalent
   new method.
7. Update imports for relocated types (`SeedableCollection`,
   `chinese_remainder_theorem` PVSS submodule, `proof_aggregation` and
   `maurer_aggregation` standalone crates).
8. Adapt to the `Arc<>` ownership change.
9. Resolve the trait-hierarchy issue: legacy `sign::Protocol: dkg::Protocol`
   needs to become legacy traits (e.g.
   `sign_backward_compatible::Protocol`) that re-establish the old
   relationship.
10. Re-add the legacy `DecryptionKeyShare` /
    `DecryptionKeySharePublicParameters` types — they were removed; the
    legacy module needs them back, separately from the v2
    `SignDecentralizedPartyPrivateInput` flow.
11. Resolve the `verify_centralized_party_partial_signature` return-type
    divergence: keep a legacy variant that returns `Result<()>`.
12. Build a snapshot-test fixture suite from captured mainnet-v1.1.8 bytes
    and gate merge on bit-identical wire output for every step in DKG,
    reconfiguration, presign, sign — every curve, every error path,
    every variant. This is the load-bearing verification surface and
    today doesn't exist.
13. Maintain all of the above through any future inkrypto-main change
    that touches lower crates, for the duration of the rollout window.

Dual-pin sidesteps all 13 points. The 13-point list is real work, with real
verification risk at each step, and the wire-format-equivalence guarantee at
the end is only as strong as the snapshot fixtures we build. With dual-pin
the equivalence is "same code, same bytes, by construction" — git pin enforces
it. There is no snapshot suite to maintain because there is nothing to
verify; we are literally running the same code mainnet runs.

The dual-pin downsides are measurable and bounded:

- **Build time** roughly doubles for the crypto stack (two complete builds
  of inkrypto in the workspace). Mitigatable: ccache, sccache, splitting
  CI into "build" and "test" jobs.
- **Binary size** grows (two copies of crypto types in the linked binary).
  Not free, but in the noise vs. the rest of the validator binary's deps.
- **Type-system silos**: a `GroupElement` from v1 cannot be passed to a v2
  function. ika code dispatches at module boundaries by protocol version;
  no cross-conversion is attempted.
- **Cargo workspace caveat**: Cargo handles two revs of the same git source
  routinely (different `[[package]]` entries in `Cargo.lock`), but Phase 0
  below verifies this empirically before any other work.
- **Aesthetic**: Cargo.toml lists each crypto crate twice. The diff to
  retire dual-pin (post-rollout) is a single commit dropping the
  un-suffixed deps and s/_v2//-ing the codebase.

vs. the `_backward_compatible/` path's downsides:

- **Verification gap**: snapshot fixtures are not "have to write a few" —
  they have to comprehensively cover the wire-format surface, and any gap
  in coverage is a place a porting bug can hide. Building that test
  infrastructure to the necessary breadth is itself a project.
- **Cryptographic judgment per rewrite site**: vartime vs constant-time
  for GroupElement ops, identity element handling for new error variants
  — these aren't mechanical rewrites; they're decisions that can be
  silently wrong.
- **Ongoing maintenance**: every inkrypto change that touches lower
  crates after the compat module lands has the potential to ripple into
  the compat module. The maintenance horizon is "until the rollout
  window closes" — likely months.
- **Bus factor / review surface**: only people with deep familiarity
  with both the v1 protocol semantics AND the v2 primitive APIs can
  review the compat module. That set is small.

**Conclusion:** dual-pin this transition. Not because the
`_backward_compatible/` pattern is wrong in general — it's been the right
call twice. The previous windows had smaller blast radii in the lower
crates. This window has a wide blast radius, and the verification effort
to make a ported `_backward_compatible/` module trustworthy exceeds the
build-cost penalty of dual-pin.

## Phased work

### Phase 0 — Prove dual-pin builds (1–2 hrs, gate)

Before any other code work:

1. Pick the exact `abd7f01`-or-later rev to pin for the v2 side. Confirm
   with the crypto team.
2. In a throwaway scratch crate (or in `dwallet-mpc-types` behind a
   `cfg(test)` module), import a single type from each of `twopc_mpc` and
   `twopc_mpc_v2`. Run `cargo build --release -p <crate>` — must succeed.
3. Spot-check no `#[no_mangle]` symbols are exported by either side that
   would collide. Cargo errors loudly if so.
4. Measure: cold full-workspace `cargo build --release` wallclock and the
   resulting `ika-node` binary size before vs. after. Sanity-check the
   numbers; not a blocker, but useful to know.

If Phase 0 fails — say transitive crates collide irreconcilably — stop and
escalate. Don't paper over it.

### Phase 1 — Wire up workspace dependencies

**Files:**
- `Cargo.toml` (root) — replace existing `cryptography-private` deps with
  inkrypto-`37bb549f` at canonical names; add the seven `_v2` aliased
  inkrypto-main deps.
- Per-crate `Cargo.toml`s — add `_v2` deps to the crates that will use v2
  in later phases:
  - `crates/dwallet-mpc-types/Cargo.toml`
  - `crates/dwallet-mpc-centralized-party/Cargo.toml`
  - `crates/ika-core/Cargo.toml`
  - `crates/ika-types/Cargo.toml`
  - `crates/dwallet-rng/Cargo.toml`
- `Cargo.lock` will gain a parallel set of inkrypto entries — expected.

No code changes yet. `cargo build --release` must still pass with the
canonical-name deps now pointing at inkrypto-`37bb549f` (vs the previous
`cryptography-private @ babbb483`). If `37bb549f`'s API differs from
`babbb483`'s in any way that affects existing ika code, that's a real
discrepancy and needs to be reconciled before going further — likely a
small mechanical patch, but flag it if it surfaces.

### Phase 2 — `Versioned…` enums extended for v2 wire formats

**File:** `crates/dwallet-mpc-types/src/dwallet_mpc.rs` (currently has these
enums around lines 299–367).

The breaking-changes doc identifies which wire formats actually changed.
Treat each Versioned enum individually:

| Enum | Current variants | Wire-format change in v2? | Action |
|------|------------------|---------------------------|--------|
| `VersionedNetworkDkgOutput` | V1, V2 | YES (gains `threshold_encryption_to_sharing_output`) | Add `V3(MPCPublicOutput)` carrying v2 bytes |
| `VersionedDecryptionKeyReconfigurationOutput` | V1, V2 | YES (Message variant changes propagate) | Add `V3(MPCPublicOutput)` |
| `VersionedDwalletDKGPublicOutput` | V1, V2 | NO per doc | Leave as-is |
| `VersionedDwalletDKGFirstRoundPublicOutput` | V1 | NO | Leave as-is |
| `VersionedPresignOutput` | V1, V2 | NO | Leave as-is |
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
    /// What ika sees today: class-groups encryption key + proof per
    /// validator, read from the on-chain committee. Bytes formatted per
    /// the inkrypto-`37bb549f` schema.
    V1 { class_groups_public_key_and_proof: Vec<u8> },
    /// Adds HPKE (Curve25519) and per-curve PVSS encryption keys. In this
    /// branch, V2 is constructible and BCS-roundtrips but is NOT produced
    /// by any consensus path — a follow-up PR will broadcast V2 via
    /// consensus.
    V2 {
        class_groups_public_key_and_proof: Vec<u8>,
        hpke_public_key_and_proof: Vec<u8>,
        /// Index 0 = secp256k1, 1 = ristretto, 2 = secp256r1.
        pvss_encryption_keys_and_proofs: Vec<Vec<u8>>,
    },
}
```

No new fields on `Committee` yet — V2 will live on `DWalletMPCManager` once
broadcast is wired (follow-up PR). For this branch, V1 is what callers
construct and read from on-chain (unchanged Move path).

### Phase 3 — Mechanical API breaks fixed in centralized-party

`crates/dwallet-mpc-centralized-party/src/lib.rs` is the only ika-side crate
that this branch intentionally migrates to the v2 surface. Per the doc, all
wire types it produces/consumes (centralized DKG output, sign messages,
partial signatures, protocol public params, encrypted-share proofs) are
byte-identical between v1 and v2, so a v2-built centralized party serves
both v4-active and v5-active sessions; no dispatch needed at this layer.

Mechanical changes in this crate:

- Replace `+ - * += -=` and unary `-` on `GroupElement` with
  `add_vartime(&b, &pp)` / `add_constant_time(&b, &pp)` /
  `sub_constant_time(&b, &pp)` / `neg_constant_time(&pp)`. **For each
  site, make the timing-channel decision correctly** — vartime is fine
  for public inputs, constant-time is required for anything touching
  private values. Where the existing centralized-party code is purely
  client-side and only operates on public data, vartime is generally
  correct; flag any ambiguous site.
- Add `&pp` to every `scale*()` call.
- `.clone()` in lieu of `Copy`. Add explicit `+ Copy` only where the
  generic genuinely needs it.
- `HomomorphicCommitmentScheme::commit(...)` now takes `&pp`.
- Replace `From<tuple>` constructions on `ProtocolPublicParameters::new`,
  `SignCentralizedPartyPublicInput::from(tuple)`, DKG centralized inputs,
  etc., with struct-literal construction.
- Update `Error` matches to cover the new variants
  (`InvalidSignatureShare`, `DecryptionFailed`, `IdentityEphemeralKey`,
  `TorsionEphemeralKey`, `MaliciousMessageAsync`,
  `MaliciousMessagePreventsAdvance`, `Serialization(String)`);
  `AsyncProofAggregation` source changed to `proof_aggregation`.
- Apply path renames: `schnorr::presign` → `schnorr::ahe::presign`,
  `schnorr::sign::centralized_party::PartialSignature` →
  `schnorr::PartialSignature`, PVSS types →
  `chinese_remainder_theorem` submod, `mpc::SeedableCollection` →
  `group::SeedableCollection`, `proof::aggregation` → standalone
  `proof_aggregation` crate, `maurer::aggregation` → standalone
  `maurer_aggregation` crate.

If we discover any wire format produced by centralized-party that turns out
to be NOT byte-identical despite the doc, stop and reassess — that's a
discovery that warrants a user check-in.

### Phase 4 — ika-core compiles against unchanged v1 paths

Existing MPC computation modules (`network_dkg.rs`, `reconfiguration.rs`,
`dwallet_dkg.rs`, `sign.rs`, `presign.rs` under
`crates/ika-core/src/dwallet_mpc/crytographic_computation/mpc_computations/`)
keep using the canonical-name (= inkrypto-`37bb549f`) crates. Their imports
stay as `twopc_mpc::…`. No dispatch code yet — v2 protocol paths come in a
follow-up.

Things to verify still compile after Phase 1's dep swap from
`cryptography-private @ babbb483` to `inkrypto @ 37bb549f`:
- `extract_encryption_keys_from_committee()` in `reconfiguration.rs`
- `decrypt_decryption_key_shares()` call in `network_dkg.rs`
- All `From<tuple>` builders for public inputs — these exist in v1 and
  should still exist at `37bb549f`.

If `37bb549f` differs subtly from `babbb483` in API surface (it shouldn't
significantly, given inkrypto is curated from cryptography-private revs),
fix forward in the v1 callers.

### Phase 5 — Seed-derived HPKE + PVSS keypair generation

**File:** `crates/dwallet-rng/src/lib.rs`

Add to `RootSeed` (mirrors the prior PLAN-v2-keys-upgrade.md design —
independent Merlin transcript labels, no domain reuse):

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

Then write a small helper (likely in `dwallet-mpc-types` or a new module
under `crates/ika-core/src/dwallet_mpc/`) that takes a `RootSeed` and
produces a fully populated `VersionedValidatorPublicMPCData::V2` using the
**v2** crypto crates:

- `hpke_public_key_and_proof`: generated via the v2 HPKE keygen +
  Schnorr-style knowledge-of-secret-key proof (exact API name TBD from
  v2 crate inspection).
- `pvss_encryption_keys_and_proofs[i]`: for each `i in [0, 1, 2]`
  corresponding to secp256k1 / ristretto / secp256r1; each is a v2
  `class_groups`-flavored encryption key + `KnowledgeOfDiscreteLogUCProof`.

The exact API surface here is the first place this branch actually consumes
v2 code at runtime — expect to discover the exact constructor names by
reading the v2 crate. Treat as a focused investigation that may surface
follow-up items.

This generator function is exercised in unit tests this PR (deterministic
seed → deterministic V2 bytes). It is NOT wired into a startup path nor a
consensus broadcast in this PR.

### Phase 6 — Protocol-version slot (off by default)

**File:** `crates/ika-protocol-config/src/lib.rs`

- Bump `MAX_PROTOCOL_VERSION` from 4 to 5.
- Add the v5 arm in the per-version `match cur` ladder, setting a new
  feature flag `use_inkrypto_v2 = true` (or similar name; mirror existing
  flag style).
- Default the flag to `false` for all versions ≤ 4 — i.e. live networks
  running v4 are unaffected.
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
2. Deterministic V2 keygen — given a fixed `RootSeed`, the generated V2
   bytes are stable across runs (lock in the wire format early).
3. `VersionedNetworkDkgOutput::V3` and
   `VersionedDecryptionKeyReconfigurationOutput::V3` BCS roundtrip and
   don't collide with V1/V2 deserialization (BCS variant tag
   differentiates).
4. All integration tests under
   `crates/ika-core/src/dwallet_mpc/integration_tests/` still pass — they
   exercise v1 paths only, which we haven't disturbed.

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
  `crates/dwallet-mpc-types/src/validator_public_mpc_data.rs` or a
  dedicated small crate to keep v2 deps out of the leaf types crate).

## Things deliberately deferred to follow-up PRs

1. `ConsensusTransactionKind::ValidatorPublicMPCData` broadcast + collection
   on `DWalletMPCManager` — needed before v5 can activate.
2. v2 implementations of `network_dkg.rs`, `reconfiguration.rs`,
   `dwallet_dkg.rs` using the v2 crypto and the 7-round DKG — gated on the
   new feature flag.
3. VSS-mode sign/presign paths — gated on the same flag.
4. Tying `Committee` (or replacement) to V2 validator keys at epoch start.
5. Eventually retiring v1 deps once mainnet has moved past v4: drop
   un-suffixed deps, rename `_v2` to canonical, one cleanup commit.

## Verification end-to-end

1. `cargo build --release` succeeds with both inkrypto revs in the
   dependency tree (Phase 0 sanity gate).
2. `cargo test --release` passes — including all existing MPC integration
   tests (which only exercise v1 paths and should be untouched).
3. New BCS-roundtrip + deterministic-keygen tests pass.
4. A clean `ika-swarm` run at protocol version 4 produces the same on-chain
   artifacts (DKG outputs, presigns, sign outputs) as `dev` — bit-for-bit
   if feasible, otherwise semantically (sign a transaction with a freshly
   created dWallet, all flows green).
5. No network at v5 yet — the feature flag is provably off in all default
   `ProtocolConfig` instances.

## Risks and unknowns

- **Dual-pin build viability** — addressed by Phase 0; user already flagged
  this concern. If it fails, we escalate before doing more work.
- **Compile-time / binary-size blowup** — measurable, expected, acceptable
  for the transition window; remove v1 once mainnet has fully migrated.
- **API drift between `cryptography-private @ babbb483` (where ika `dev`
  currently points) and `inkrypto @ 37bb549f` (where mainnet binaries
  actually point and where we're moving the canonical names)** — if there
  is any meaningful drift, ika code that calls these crates may need
  small mechanical fixes during Phase 1. Likely small but unknown.
- **v2 API discovery for HPKE/PVSS keygen** — exact constructor names
  need reading; flagged as an investigation step in Phase 5.
- **Move-side assumes V1 only** — confirmed by user; on-chain
  deserialization always reads V1 today, V2 will arrive via consensus in
  a follow-up PR.
- **Cryptographic-judgment-per-rewrite-site in centralized-party** —
  vartime vs constant-time for each GroupElement op needs to be a
  deliberate choice. Wrong choice doesn't break correctness but can
  introduce a timing-channel; flag any ambiguous site for review.

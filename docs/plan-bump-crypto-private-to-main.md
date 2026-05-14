# Plan: bump dev's cryptography-private from `babbb483` to `main` (= `9d35fa76`)

## Scope (deliberately narrow)

This is the **first step** of the broader crypto migration. The only goal
is: make ika's `dev`-branch source compile, run unit tests green, and run
the local-swarm integration smoke test (single-version network, no
mainnet interop) against `cryptography-private @ origin/main` instead of
`@ babbb483`.

**What this plan does NOT cover** (separate, later plans):

- Wire-format compatibility with `mainnet-v1.1.8` validators (`inkrypto @
  37bb549f`). After this bump, ika at `dev` cannot decode messages from
  mainnet validators or vice versa — the network DKG `Message` enum,
  Reconfiguration `Message` enum, and DKG `PublicOutput` struct have all
  shifted. Mainnet interop comes from the dual-pin / `_backward_compatible`
  work tracked in `docs/plan-update-crypto-latest.md`.
- Activating the new VSS Schnorr, threshold_encryption_to_sharing
  sub-protocol, or 7-round DKG. Those are new capabilities that exist in
  main but aren't wired into ika by this bump.
- HPKE / PVSS validator key generation. Separate plan.
- Move-contract changes (none needed for this bump anyway).
- Protocol-version bumps in `ika-protocol-config`.

In short: this plan gets `dev` compiling against `main` while preserving
identical observable behavior at the ika protocol layer (still 4-round
DKG, still AHE-mode sign/presign, still the wire format `main` happens
to emit when run in those code paths).

The differences this plan must accommodate are catalogued in
`docs/inkrypto-bump-diff.md`. That file is the contract; this plan acts
on it.

## Target rev

- New pin: `9d35fa76` ("Preserve mpc::Error::ThresholdNotReached at
  threshold-check call sites (#485)") — current tip of
  `dwallet-labs/cryptography-private` `main` as of this writing
  (2026-05-13). Confirm with the crypto team before pinning.

## Phased work

### Phase 0 — single-rev build sanity gate (≈30 min)

Before doing anything else, prove `cargo build --release` works with the
new pin applied to a SINGLE scratch crate. This catches gross workspace
incompatibility (transitive dep conflicts, broken features) early.

```bash
# in a throwaway crate elsewhere on disk, or guarded behind a cfg(test) module:
[dependencies]
twopc_mpc = { git = "https://github.com/dwallet-labs/cryptography-private", rev = "9d35fa76" }

# build it. If it fails, stop and escalate — do not proceed.
```

### Phase 1 — workspace Cargo.toml: bump revs + add new crates

**File:** `Cargo.toml` (root).

Bump all seven existing crypto deps to `9d35fa76`:

```toml
[workspace.dependencies]
mpc                    = { git = "https://github.com/dwallet-labs/cryptography-private", rev = "9d35fa76" }
proof                  = { git = "https://github.com/dwallet-labs/cryptography-private", rev = "9d35fa76" }
class_groups           = { git = "https://github.com/dwallet-labs/cryptography-private", rev = "9d35fa76", features = ["threshold"] }
commitment             = { git = "https://github.com/dwallet-labs/cryptography-private", rev = "9d35fa76" }
twopc_mpc              = { git = "https://github.com/dwallet-labs/cryptography-private", rev = "9d35fa76" }
group                  = { git = "https://github.com/dwallet-labs/cryptography-private", rev = "9d35fa76", features = ["os_rng"] }
homomorphic_encryption = { git = "https://github.com/dwallet-labs/cryptography-private", rev = "9d35fa76" }
```

Do NOT add `proof_aggregation` / `maurer_aggregation` to ika's workspace
deps. They're new standalone crates upstream (holding what used to be
`proof::aggregation` and `maurer::aggregation`), but ika doesn't import
them directly — confirmed by grep across `crates/` and `sdk/`. They get
pulled in transitively through `twopc_mpc` where needed; ika's
`Cargo.toml` does not list them.

Update `Cargo.lock` via `cargo build` after this phase.

### Phase 2 — preserve two `ThresholdNotReached` match arms across the `Error→ErrorKind` rewrap

`mpc::Error` and `twopc_mpc::Error` are now struct wrappers around an
`ErrorKind` enum. Matching on the bare enum variant
(`Err(mpc::Error::ThresholdNotReached) => …`) no longer compiles. The
actual ika surface, confirmed by grep, is **two sites**, both on the
same variant:

- `crates/ika-core/src/dwallet_mpc/mpc_manager.rs:654` (in
  `compute_idle_status_majority_vote`)
- `crates/ika-core/src/dwallet_mpc/mpc_manager.rs:1715` (in
  `outputs_to_finalize`)

Both call `weighted_majority_vote(...)`. Both deliberately treat
`ThresholdNotReached` as a **silent "not enough votes yet, try again"
signal** distinct from real errors:

```rust
match … weighted_majority_vote(&self.access_structure) {
    Ok((_, majority_vote)) => majority_vote,
    Err(mpc::Error::ThresholdNotReached) => false,        // SILENT, no log
    Err(e) => {
        error!(error = %e, "Failed to compute idle status majority vote");
        false
    }
}
```

That distinction must be preserved. The fix is a guard, not a collapse
into the catch-all:

```rust
match … weighted_majority_vote(&self.access_structure) {
    Ok((_, majority_vote)) => majority_vote,
    Err(e) if matches!(e.kind, mpc::ErrorKind::ThresholdNotReached) => false,  // still SILENT
    Err(e) => {
        error!(error = %e, "Failed to compute idle status majority vote");
        false
    }
}
```

(Exact accessor — `e.kind` direct field vs `e.kind()` method — verify
against `mpc/src/lib.rs` at `9d35fa76` line ~42; the struct is small,
look at it once.)

Apply the same shape to site 2 with its `None` and its
`"Failed to build outputs to finalize"` log.

No other ika code needs to change for the `Error→ErrorKind` rewrap. The
remaining `mpc::Error` / `twopc_mpc::Error` reach-points all compile
unchanged because nothing else pattern-destructures them:

- `crates/ika-types/src/dwallet_mpc_error.rs` has
  `#[from] mpc::Error` / `#[from] twopc_mpc::Error` and a
  `FailedToAdvanceMPC(mpc::Error)` field. These store / convert from
  the struct type and work unchanged — thiserror's `#[from]` doesn't
  care that the source went from enum to struct.
- `crates/dwallet-mpc-centralized-party/src/lib.rs:974` calls
  `twopc_mpc::Error::from(…)?`. `From` impls on the struct cover the
  same source types as before; works unchanged.
- The eight `FailedToAdvanceMPC(e.into())` wrap sites
  (`mpc_computations.rs`, `mpc_computations/{dwallet_dkg,sign,presign}.rs`)
  use `.into()` to convert the upstream `mpc::Error` into ika's
  `DwalletMPCError::FailedToAdvanceMPC(mpc::Error)` field. Type is
  unchanged; works.

**The third reach-point that's worth calling out explicitly**:
`crates/ika-core/src/dwallet_mpc/dwallet_mpc_service.rs:1597` — the
"advance failed catch" that consumes the propagated
`DwalletMPCResult<GuaranteedOutputDeliveryRoundResult>`:

```rust
Err(err) => match request.session_type {
    SessionType::InternalPresign | SessionType::NetworkOwnedAddressSign => {
        error!(should_never_happen = true, …, error=?err, "internal session failed");
    }
    _ => self.submit_failed_session(…, err).await,
}
```

`err` here is `DwalletMPCError` (typically
`FailedToAdvanceMPC(mpc::Error)`). Nothing destructures variants — the
arm logs and either marks the session permanently failed (regular
sessions) or treats it as `should_never_happen` (internal sessions).
This compiles unchanged across the rewrap.

Behavior question to flag (NOT a code change for this bump):

- For the two `mpc_manager.rs` majority-vote sites: the new ErrorKind
  variants (`DecryptionFailed`, `MaliciousMessagePreventsAdvance`, etc.)
  are not expected to surface from `weighted_majority_vote`, which is a
  vote-counting helper. If one ever did, it would land in the existing
  catch-all arm (logged + return the "not ready" sentinel) — acceptable
  fallback.
- For the `dwallet_mpc_service.rs:1597` catch:
  - `DecryptionFailed`, `IdentityEphemeralKey`, `TorsionEphemeralKey`,
    `Serialization`, `InvalidSignatureShare`, `MaliciousMessageAsync` —
    all genuinely fatal; routing to `submit_failed_session` matches
    today's behavior.
  - `MaliciousMessagePreventsAdvance` ("at this round" wording) MIGHT
    mean "wait and retry, not permanent failure." Today's code marks the
    session permanently failed for any Err. The upstream protocol with
    guaranteed output delivery is expected to surface that case via
    `GuaranteedOutputDeliveryRoundResult::Advance { malicious_parties, … }`
    on the success path, not as Err — but verify against the upstream
    code if behavior diverges in testing. Leave alone for this bump;
    revisit if it shows up.

### Phase 3 — fix relocated module paths

**`mpc::SeedableCollection` → `group::SeedableCollection`**:
```bash
grep -rE 'mpc::SeedableCollection' --include='*.rs' crates/ sdk/
# Replace each with group::SeedableCollection.
```

ika currently imports `MajorityVote` from `mpc` (`use mpc::{MajorityVote,
…}`) — that import is unused (per the breaking-changes doc + spot
check); drop it cleanly while passing through, but don't make it a
required change.

**`proof::aggregation` / `maurer::aggregation`:** confirmed-grep shows
zero direct ika imports of these paths today, so no rewrite needed. If
the build surfaces a use buried in a macro or generic bound, rewrite to
the standalone-crate path (`proof_aggregation::*` /
`maurer_aggregation::*`).

**`schnorr::presign` → `schnorr::ahe::presign`** etc.: confirmed-grep
shows zero direct ika imports of these paths.

### Phase 4 — `sign::Protocol` adapter changes

**File touch list:**
- `crates/ika-core/src/dwallet_mpc/crytographic_computation/mpc_computations/sign.rs`
- `crates/ika-core/src/dwallet_mpc/crytographic_computation/native_computations/native_computations.rs`
  (and any sibling file that calls `verify_centralized_party_partial_signature`)
- `crates/dwallet-mpc-centralized-party/src/lib.rs`
- `crates/ika-types/src/messages_dwallet_mpc.rs`

#### 4a. DKG types now accessed via `<Self::DKGProtocol as dkg::Protocol>::…`

Every place ika has `<P as sign::Protocol>::DKGOutput` or refers to
`P::DecentralizedPartyDKGOutput` through the sign trait must adapt to
the new indirection. Concretely:

Old:
```rust
fn foo<P: sign::Protocol>() {
    let _: P::DecentralizedPartyDKGOutput = …;
    let _: P::ProtocolPublicParameters = …;
}
```

New:
```rust
fn foo<P: sign::Protocol>() {
    let _: <P::DKGProtocol as dkg::Protocol>::DecentralizedPartyDKGOutput = …;
    let _: <P::DKGProtocol as dkg::Protocol>::ProtocolPublicParameters = …;
}
```

In ika's `sign.rs` the type names `Secp256k1ECDSAProtocol` etc. (which
implement `sign::Protocol`) must now have a `type DKGProtocol = …` that
points at the corresponding curve's `DKGProtocol`. These impls live
upstream in twopc_mpc; ika just consumes them. Update bounds in ika's
generic helpers to express `DKGProtocol` linkage via the `presign::Protocol`
supertrait.

#### 4b. `DecryptionKeyShare` / `DecryptionKeySharePublicParameters` removed

These two associated types are gone from `sign::Protocol`. Find ika uses:
```bash
grep -rE '(DecryptionKeyShare|DecryptionKeySharePublicParameters)' --include='*.rs' crates/ sdk/
```

For AHE-mode protocols (which is all ika has today), the concrete shapes
are still the same:
- `DecryptionKeyShare` was `HashMap<PartyID, SecretKeyShareSizedInteger>`.
  At main this becomes the value type carried by
  `Self::SignDecentralizedPartyPrivateInput` for AHE protocols.
- `DecryptionKeySharePublicParameters` data is now embedded inside the
  v2 sign public input struct directly.

Sites that named the old types need to be rewritten to use the new
PrivateInput type or extract from the public input.

#### 4c. `From<(tuple)>` removed from `SignDecentralizedPartyPublicInput`, `DKGSignDecentralizedPartyPublicInput`, `SignCentralizedPartyPublicInput`

Find construction sites:
```bash
grep -rE '(SignDecentralizedPartyPublicInput|DKGSignDecentralizedPartyPublicInput|SignCentralizedPartyPublicInput)::from\(' --include='*.rs' crates/ sdk/
```

Replace each `T::from((a, b, c, …))` with a struct literal
`T { field_a: a, field_b: b, … }`. The exact field names are visible by
reading the new struct definition in
`2pc-mpc/src/ecdsa/sign/decentralized_party/class_groups.rs` and sibling
files. Expect ~10 such sites in ika.

#### 4d. `verify_centralized_party_partial_signature` return type changed

Old: `Result<()>`. New: `Result<P::VerifiedSignData>`.

Find sites:
```bash
grep -rE 'verify_centralized_party_partial_signature' --include='*.rs' crates/ sdk/
```

Callers either:
1. Discard the returned `VerifiedSignData` (use `let _ = …?;`) — fine
   for callers that only cared about the boolean validity.
2. Capture and pass through. The new `SignData` enum's `Verified(...)`
   variant wraps `VerifiedSignData`; any code that constructs
   `SignData::Unverified(SignMessage)` from a verified context should
   use `SignData::Verified(verified_sign_data)` instead.

For this bump's scope, option (1) is sufficient — ika doesn't currently
use the verified-data optimization. Document the discarded data as a
follow-up optimization.

### Phase 5 — `presign::Protocol` adapter changes

**File touch list:**
- `crates/ika-core/src/dwallet_mpc/crytographic_computation/mpc_computations/presign.rs`

#### 5a. `DKGProtocol` indirection

Same pattern as Phase 4a. `<P as presign::Protocol>::DKGProtocol` is the
DKG protocol; access `<P::DKGProtocol as dkg::Protocol>::…` for DKG-flavored
associated types.

#### 5b. New `HPKEEncryptionKey` and `PresignPrivateInput` assoc types

For AHE-mode protocols, both are `()`. ika's existing presign code never
provided HPKE keys or a private input, which is consistent with `()`.
The generic bound machinery handles this transparently; the only place
ika needs to be aware is when constructing the presign public input
(no longer via `From<(Arc<…>, Option<…>)>` — see 5c) or invoking the
party with a `PrivateInput`.

#### 5c. `From<(tuple)>` removed from `PresignPublicInput`

Find construction sites:
```bash
grep -rE 'PresignPublicInput::from\(' --include='*.rs' crates/ sdk/
```

Replace with struct-literal construction. The new struct lives in
`2pc-mpc/src/ecdsa/presign/decentralized_party.rs` line 14:

```rust
pub struct PublicInput<GroupElementValue, CiphertextSpaceValue, ProtocolPublicParameters> {
    pub protocol_public_parameters: Arc<ProtocolPublicParameters>,
    pub targeted_dkg_output: Option<…>,
    // … verify fields
}
```

### Phase 6 — `dkg::Protocol` new required method

`dkg::Protocol` gained `fn threshold_dkg_output(...)` at main.

If ika has its own impl of `dkg::Protocol` for any type, it needs to
implement this method. **In practice ika does not implement
`dkg::Protocol` directly** — it consumes the upstream impls for the
per-curve protocols. So no ika source change is required here. Verify
by:
```bash
grep -rE 'impl.+dkg::Protocol for' --include='*.rs' crates/
# expected: zero hits
```

If hits exist, port them by reading the new method signature from
`2pc-mpc/src/dkg.rs` line ~232 and providing a sensible body
(typically: delegate to upstream's reference implementation for the
specific curve).

### Phase 7 — `GroupElement` API in centralized-party

**File:** `crates/dwallet-mpc-centralized-party/src/lib.rs` (and any
helper modules under it).

#### 7a. Operators

Find sites:
```bash
grep -nE '\b(GroupElement|secp256k1::GroupElement|ristretto::GroupElement|curve25519::GroupElement|secp256r1::GroupElement)\b' crates/dwallet-mpc-centralized-party/src/lib.rs
# then look for surrounding +, -, *, +=, -=, unary - on these types
```

Replace by the new methods. **Per call site, decide vartime vs
constant-time.** Rule of thumb:
- Centralized party operates on its own private secret key share +
  public parameters from the protocol. Operations involving the secret
  share require `constant_time` to avoid timing channels.
- Operations on purely-public values (challenges, public keys received
  from the network) can use `vartime` for performance.

Substitutions:

| Old | New |
|---|---|
| `a + b` | `a.add_vartime(&b, &pp)` (public) or `a.add_constant_time(&b, &pp)` (private) |
| `a - b` | `a.sub_constant_time(&b, &pp)` (no vartime variant exists) |
| `-a` | `a.neg_constant_time(&pp)` |
| `a += b` | `a = a.add_*(&b, &pp);` |
| `a -= b` | `a = a.sub_constant_time(&b, &pp);` |

For each site, the `pp` value needs to be in scope. The centralized party
already threads protocol public parameters; pull the relevant subgroup's
public parameters from there.

#### 7b. Scaling

Find: any `.scale*(...)` call. Add `&pp` as a final arg.

#### 7c. `Copy` removed — add `.clone()` where needed

`GroupElement` and `GroupElement::Value` are no longer `Copy`. Find sites
where they're moved/copied implicitly (struct field assignment, function
args by value). Most cases are simple `.clone()` insertions.

If a generic bound elsewhere reads `T: GroupElement + Copy`, the `Copy`
becomes unsatisfiable; remove it and adjust the body to clone where
needed. Verify no upstream API actually requires `Copy` on `GroupElement`
itself — main removed `Copy` from the supertrait list, but the
`homomorphic_encryption::CiphertextSpaceGroupElement` and
`RandomnessSpaceGroupElement` assoc types DID gain a `+ Copy` bound, so
concrete ciphertext/randomness types must independently impl `Copy`. If
they don't, that's an upstream bug — file it.

### Phase 8 — `HomomorphicCommitmentScheme::commit` extra `&pp` parameter

Find sites:
```bash
grep -rE '\.commit\(' --include='*.rs' crates/ sdk/
```

Filter to sites where `self` is a `HomomorphicCommitmentScheme`. Each
gets `&public_parameters` as a third argument.

Hard part: callers must have a `&group::PublicParameters<…CommitmentSpaceGroupElement>`
in scope. Where the existing call site doesn't have one, plumb the value
through from the appropriate Protocol or PublicInput it has access to.

### Phase 9 — `SignData` enum wraps `SignMessage` in sign public inputs

The new struct shape (visible in `2pc-mpc/src/ecdsa/sign/decentralized_party/class_groups.rs`
fields) accepts `SignData<SignMessage, VerifiedSignData>` where the old
shape accepted `SignMessage` directly.

For this bump's scope, every `SignMessage` value flowing into a sign
public input from ika should be wrapped as
`SignData::Unverified(sign_message)`. This is the variant that triggers
the verifier inside the protocol, preserving today's behavior.

Find sites:
```bash
grep -rE 'sign_message|SignMessage' crates/ika-core/src/dwallet_mpc/ sdk/typescript/
# focus on construction sites for SignDecentralizedPartyPublicInput / DKGSignDecentralizedPartyPublicInput.
```

Wrap each in `SignData::Unverified(...)`.

### Phase 10 — wire-format Versioned enum variants (deferred)

The DKG `Message` enum, `Reconfiguration` `Message` enum, and DKG
`PublicOutput` struct changed shape at main. ika's `VersionedNetworkDkgOutput`,
`VersionedDecryptionKeyReconfigurationOutput` etc. (currently V1/V2) need a
V3 variant to carry the new-format bytes.

**For this bump's scope, do NOT add V3 yet.** This bump is single-version
(one binary talking to itself in a local swarm). The current V2 variant
will be deserialized using the v2-crate struct definition, which is the
NEW shape — meaning the output WILL contain
`threshold_encryption_to_sharing_output` and the new `Message` variants.
That's fine because no babbb483 peer is involved.

The V3 variant work belongs to the wire-format compatibility plan
(`docs/plan-update-crypto-latest.md`), where dual-pin or
`_backward_compatible` modules handle the cross-version case.

Note: this means **the bump alone is incompatible with mainnet** — that
is by design and that's why this is step 1 only. Compatibility comes from
the next plan.

### Phase 11 — Tests and verification

```bash
cargo build --release                              # must pass
cargo clippy --all-targets --all-features          # fix any new lints
cargo fmt --all                                    # commit reformat

cargo test --release -p dwallet-mpc-centralized-party
cargo test --release -p dwallet-mpc-types
cargo test --release -p ika-core dwallet_mpc       # full MPC integration tests
cargo test --release -p ika-types
cd sdk/typescript && pnpm install && pnpm build && pnpm test

# Manual smoke: local swarm.
cargo run --release --bin ika-swarm -- …           # exact args TBD; the standard local-test invocation
```

Pass criteria:
- All Rust unit/integration tests pass at `9d35fa76`.
- TypeScript SDK tests pass.
- A local swarm of new-binary validators completes a full DKG → Presign
  → Sign cycle for at least one curve (secp256k1 ECDSA is the canonical
  smoke).

Acknowledged-broken at this step:
- New-binary validator CANNOT participate in a swarm with any
  babbb483-era binary. That's expected; addressed by the follow-up plan.

## Critical files

- `Cargo.toml` (root, workspace deps) — Phase 1
- `crates/ika-core/src/dwallet_mpc/crytographic_computation/mpc_computations/sign.rs` — Phase 4
- `crates/ika-core/src/dwallet_mpc/crytographic_computation/mpc_computations/presign.rs` — Phase 5
- `crates/ika-core/src/dwallet_mpc/crytographic_computation/mpc_computations/dwallet_dkg.rs` — Phase 6 verification
- `crates/ika-core/src/dwallet_mpc/crytographic_computation/mpc_computations/network_dkg.rs` — verify error-match arms
- `crates/ika-core/src/dwallet_mpc/crytographic_computation/mpc_computations/reconfiguration.rs` — verify error-match arms
- `crates/ika-core/src/dwallet_mpc/crytographic_computation/mpc_computations.rs` — verify error-match arms
- `crates/dwallet-mpc-centralized-party/src/lib.rs` — Phases 7, 8, 9
- `crates/ika-types/src/messages_dwallet_mpc.rs` — verify DKGProtocol type aliases still resolve
- `crates/ika-types/src/committee.rs` — verify CRT imports
- `crates/dwallet-classgroups-types/src/lib.rs` — verify CRT imports
- Any error-handling site (ad-hoc) — Phase 2

## Things deferred to follow-up plans

1. **Mainnet wire-format compatibility** — `docs/plan-update-crypto-latest.md`
   (dual-pin or `_backward_compatible` modules).
2. **HPKE + PVSS validator key generation and broadcast** — separate plan.
3. **Activating new protocols** (VSS Schnorr sign/presign, 7-round
   network DKG, threshold_encryption_to_sharing sub-protocol) — separate
   plan.
4. **Protocol version 5 slot in `ika-protocol-config`** — separate plan.
5. **Move-side adaptation** if any — separate plan (likely none).
6. **`VersionedValidatorPublicMPCData`** — separate plan.

## Risks and unknowns

- **Error-handling-site enumeration completeness** — match arms on
  `mpc::Error` / `twopc_mpc::Error` may be scattered across helper code.
  `cargo build` will surface them deterministically; iterate.
- **Vartime vs constant-time decision per `GroupElement` op site** in
  centralized-party requires cryptographic judgment per site. Get a
  second pair of eyes from someone with the security threat model in
  mind before merging.
- **`Copy` removal cascade** — the `+ Copy` bound on
  `CiphertextSpaceGroupElement` / `RandomnessSpaceGroupElement` requires
  concrete types to impl `Copy` directly. If an upstream type doesn't,
  the new `Copy` bound is unsatisfiable; coordinate with the crypto
  team.
- **`schnorr::sign::centralized_party::PartialSignature` → `schnorr::PartialSignature`**
  rename per breaking-changes doc — confirm against current main. If
  ika imports the old path indirectly, fix.
- **Unknown transitives**: ika's `Cargo.lock` will gain entries from
  HPKE, AEAD, chacha20poly1305, generic-array. Verify no conflict with
  existing versions in the workspace; cargo will catch most issues
  loudly.

## Definition of done

1. `cargo build --release` and `cargo clippy --all-targets
   --all-features` are clean at the new pin.
2. `cargo test --release` is green across the workspace.
3. `cd sdk/typescript && pnpm test` is green.
4. A local single-version swarm completes a DKG/Presign/Sign for
   secp256k1 ECDSA.
5. `docs/inkrypto-bump-diff.md` is referenced from this plan as the
   authoritative API-change catalog, and no item in it goes unaddressed
   in the diff this branch produces (or is explicitly deferred with a
   comment in the relevant Cargo.toml/source).

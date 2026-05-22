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

#### 4a. Bind DKG via the per-curve aliases, not via `<P::DKGProtocol as dkg::Protocol>::…`

Upstream, `sign::Protocol` no longer extends `dkg::Protocol`; DKG types
are reachable through the `DKGProtocol` associated type that lives on
`presign::Protocol`. The seemingly-natural rewrite for code generic
over `sign::Protocol` is to chase types through that associated type:

```rust
let _: <P::DKGProtocol as dkg::Protocol>::DecentralizedPartyDKGOutput = …;
```

**We deliberately don't do that.** There is exactly one DKG protocol
per curve, shared across all signature algorithms on that curve. ika
already exposes the bindings:

```rust
// crates/ika-types/src/messages_dwallet_mpc.rs
pub type Secp256k1AsyncDKGProtocol = twopc_mpc::secp256k1::class_groups::DKGProtocol;
pub type Secp256r1AsyncDKGProtocol = twopc_mpc::secp256r1::class_groups::DKGProtocol;
pub type Curve25519AsyncDKGProtocol = twopc_mpc::curve25519::class_groups::DKGProtocol;
pub type RistrettoAsyncDKGProtocol    = twopc_mpc::ristretto::class_groups::DKGProtocol;
```

Use those directly. Generic helpers that today are generic over
`<P: sign::Protocol>` and reach for `P::DecentralizedPartyDKGOutput`
should be reshaped to take the DKG protocol as a separate, explicit
generic parameter (or to bind the per-curve concrete DKG type at the
call site). Two acceptable shapes:

```rust
// (preferred) explicit second generic, paired by curve at the call site:
fn foo<P, D>()
where
    P: sign::Protocol,
    D: dkg::Protocol,                              // = Secp256k1AsyncDKGProtocol, etc.
{
    let _: D::DecentralizedPartyDKGOutput = …;
}

// or: bind the curve concretely where the generic isn't load-bearing:
fn foo_secp256k1() {
    let _: <Secp256k1AsyncDKGProtocol as dkg::Protocol>::DecentralizedPartyDKGOutput = …;
}
```

Rationale: routing through `<P::DKGProtocol as dkg::Protocol>::…`
re-couples sign-protocol-generic code to a particular DKG-protocol
choice via an associated-type chain, when the design intent is "there's
just one DKG per curve, every signature algorithm uses it." Naming the
DKG type directly makes that intent visible at the type-system level
and keeps the call sites readable.

#### 4b. `DecryptionKeyShare` / `DecryptionKeySharePublicParameters` removed

These two `sign::Protocol` associated types are gone at main. ika
references them in `mpc_computations/sign.rs`:

- `decryption_pp: Arc<P::DecryptionKeySharePublicParameters>` parameter
  on multiple helpers (lines 670, 692, 744, 759, 772, 858) — drop the
  parameter. Its data now lives inside the sign public input struct
  directly; callers should construct the public input with that field
  populated (see 4c) and read it from there inside the helpers if they
  still need it.
- `Option<<SignParty<P> as AsynchronouslyAdvanceable>::PrivateInput>`
  parameter (line 942, also 1004 for `DKGAndSignParty<P>`) — keep the
  type indirection. At main, this resolves to
  `Option<HashMap<PartyID, P::SignDecentralizedPartyPrivateInput>>`,
  which for AHE protocols is `Option<HashMap<PartyID, SecretKeyShareSizedInteger>>`
  — the same data ika already produces via `decrypt_decryption_key_shares()`
  on the network DKG output. No new data to source; same `Option<HashMap<…>>`
  shape; just a different concrete type underneath.

If any other ika site names `DecryptionKeyShare` or
`DecryptionKeySharePublicParameters` by their bare type names, surface
it via grep before starting:

```bash
grep -rE '(DecryptionKeyShare|DecryptionKeySharePublicParameters)' --include='*.rs' crates/ sdk/
```

and rewrite each to either the per-curve concrete type or to traversal
through `SignDecentralizedPartyPrivateInput` / the public input.

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

Note: the public input struct now embeds the data that used to be
plumbed separately as `DecryptionKeySharePublicParameters` (per 4b).
When constructing the struct literal, populate that field from where
the old call site got the `Arc<…>` value.

#### 4d. New presign-private-output → sign-private-input shape

Main exposes a conversion-point between presign and sign:

```rust
// 2pc-mpc/src/sign.rs ~5603 / 5794 / 5980 (3 protocol surfaces):
fn(
    &HashMap<PartyID, <P::PresignParty as mpc::Party>::PrivateOutput>,
    &P::Presign,
) -> HashMap<PartyID, P::SignDecentralizedPartyPrivateInput>
```

The `HashMap<PartyID, PresignPrivateOutput>` shape here is a **test /
orchestrator harness shape** — one entity simulating all parties. In
production each validator's `advance_with_guaranteed_output` call
carries a `PrivateInput` derived from values it locally holds, not a
cross-party map.

For ika's AHE-mode protocols today, the concrete shapes are:

- `<P::PresignParty as mpc::Party>::PrivateOutput = ()` (verified in
  `2pc-mpc/src/ecdsa/presign/decentralized_party/class_groups.rs:174`)
- `P::SignDecentralizedPartyPrivateInput = HashMap<PartyID, SecretKeyShareSizedInteger>`
  — the same data ika gets from
  `network_encryption_keys → decrypt_decryption_key_shares()`.

**For this bump: change nothing in ika's plumbing.** Keep the
`decryption_key_shares: Option<<SignParty<P> as AsynchronouslyAdvanceable>::PrivateInput>`
parameter (sign.rs:942/1004) exactly as today. For AHE its concrete
type resolves to `Option<HashMap<PartyID, SecretKeyShareSizedInteger>>`;
ika's existing source for that value (the network-DKG decryption-key-shares
map) is the same source as before. No new storage path, no new
persistence, no new call shape.

**Document the VSS seam in code, not just in this plan.** At each of
the two helper definitions in `sign.rs` that take this parameter (the
`SignParty<P>` and `DKGAndSignParty<P>` variants), add a doc-comment
naming what changes when VSS lands:

```rust
/// `decryption_key_shares` is the sign-protocol private input.
///
/// For AHE-mode protocols this resolves to
/// `Option<HashMap<PartyID, SecretKeyShareSizedInteger>>` and is
/// sourced from the network DKG's decryption-key-shares map (i.e. the
/// output of `decrypt_decryption_key_shares` on the network DKG
/// output).
///
/// TODO(vss): when VSS-mode sign protocols are activated, this
/// parameter's concrete type will resolve to a different shape
/// (containing nonce shares / HPKE blobs / etc. derived from the
/// presign protocol's `PrivateOutput`). The generic shape stays the
/// same; only the source of the value changes. The presign session
/// must persist each validator's own `<P::PresignParty as mpc::Party>::PrivateOutput`
/// keyed by `(presign_id, validator_id)` so the sign session can
/// recover it. That storage path does not exist today.
```

Same comment at `DKGAndSignParty<P>` site. The TODO marker keeps the
future PR honest about what work it implies.

**Forward-looking seam for VSS.** When VSS lands the meaningful work
will be at ika's session boundaries, not at the generic helper
signature:

- Presign sessions must persist each validator's own
  `<P::PresignParty as mpc::Party>::PrivateOutput` (a concrete VSS type
  containing nonce shares / HPKE blobs / etc.), keyed by `(presign_id,
  validator_id)`. Presign and sign happen in separate consensus
  sessions, potentially separated in time — this is real session-
  spanning state ika does not track today.
- Sign sessions must read the corresponding presign private output and
  combine it with any other locally-held inputs to construct the sign
  `PrivateInput`.
- The generic helper signature
  `Option<<SignParty<P> as AsynchronouslyAdvanceable>::PrivateInput>`
  is the right seam: it abstracts AHE vs VSS at the type level. Only
  the *source* of the value changes per protocol; the call shape stays
  identical.

What this bump deliberately does NOT do, and why:

- **No `()`-carrying presign-private-output storage path.** For AHE it
  would carry meaningless state; not worth adding to "exercise the seam"
  before there's a real type to carry.
- **No `SignPrivateInputByProtocol` enum yet.** Today ika's only sign
  protocols are AHE-mode; the type indirection through
  `<SignParty<P> as AsynchronouslyAdvanceable>::PrivateInput` is enough.
  When the first VSS sign protocol arrives the natural pattern
  (mirroring `PresignPublicInputByProtocol` etc.) is to add the
  protocol-keyed enum then.
- **No commitment to a VSS storage format.** The upstream VSS surface
  is still in flux (per the open work in `2pc-mpc/src/schnorr/vss/`);
  pinning a storage shape now would prejudice that PR.

#### 4e. `verify_centralized_party_partial_signature` return type changed — capture the value, don't discard

Old: `Result<()>`. New: `Result<P::VerifiedSignData>`.

This is not a cosmetic signature change — it's an enablement for two
related optimizations the upstream rev was designed around. Capture the
returned `VerifiedSignData` and keep it alive; do not `let _ = …?;`.

**Why it matters: `VerifiedSignData` is much smaller than `SignMessage`.**
Reading `ecdsa/sign/decentralized_party/class_groups.rs:745`, the
verified form for ECDSA is three ciphertext / nonce fields:

```rust
VerifiedSignDataRaw {
    public_signature_nonce,
    encryption_of_partial_signature,
    encryption_of_displaced_decentralized_party_nonce_share,
}
```

— three group / ciphertext values, vs. `SignMessage` which additionally
carries the full ZK proofs ($\pi_k, \pi_\alpha, \pi_\beta$, commitment-
equality proof, encryption proofs) that justify those fields. Once a
validator has verified the proofs, persisting / re-transmitting the
verified form is a real wire and storage shrink for any follow-up
round, broadcast, or future-tx replay.

**Where this surfaces in ika.**

Find call sites:
```bash
grep -rE 'verify_centralized_party_partial_signature' --include='*.rs' crates/ sdk/
```

For each site, classify:

1. **Verifier-only call (boolean validity check)**: capture the value
   into a local binding even if not yet used downstream — at minimum
   so a follow-up can wire it through. A bare `let _ = …?;` discards
   the entire optimization opportunity.
2. **Verifier-as-precursor-to-sign-input call**: feed the captured
   `VerifiedSignData` into the next sign-public-input construction as
   `SignData::Verified(verified_sign_data)` instead of re-wrapping
   the original `SignMessage` as `SignData::Unverified(...)`. The
   upstream protocol's `emulate_or_verify_or_unpack_sign_data` short-
   circuits the `Verified` case as "return as-is, no re-verification"
   (per `ecdsa/sign/decentralized_party/class_groups.rs:756`).

Whether this bump fully wires the wire-size optimization end-to-end is
a scope call (it touches consensus message types). At minimum: capture
the value, surface it on the helper's return signature, and leave the
wiring to a follow-up. Do NOT `let _ = …?;` — that buries the work.

#### 4f. Delete ika's NOA emulation in full — DKG side AND sign-centralized side

This is a **mandatory** part of the bump, not a deferrable cleanup.
Reason: the sign-centralized emulation is a known performance hole, and
the upstream rev now provides the exact fix ika's own team predicted
two years ago. Shipping the bump without this deletion ships a worse
regression (ika's slow emulator runs AND THEN the upstream protocol's
fast emulator runs on top).

**The performance issue ika's own comment already calls out.**
`crates/ika-core/src/dwallet_mpc/mpc_session/input.rs:295-299`:

```rust
// Emulate the centralized party's partial signature using ZeroRng.
// All validators will produce identical output.
// NOTE: this is a cryptographic computation done outside of a Rayon context; it could be expensive.
// Currently, we are using schnorr signatures for which it is cheap;
// if in the future we should support other signature algorithms for network-owned-address sign,
// e.g. ECDSA, we would have to add an option to the Sign protocol to emulate the message internally,
// or compute it separately within a rayon context.
```

For ECDSA NOA sign, that emulation runs on the order of *seconds*,
synchronously on the input-handler thread, outside the rayon pool — a
hard blocker for any production NOA-ECDSA flow. `SignData::ToBeEmulated`
is precisely "an option to the Sign protocol to emulate the message
internally" the comment predicted: the emulation moves inside the
protocol's advance code, which runs through the computation
orchestrator (rayon-dispatched, properly budgeted).

**File targeted for full deletion** (or near-full):

`crates/ika-core/src/dwallet_mpc/crytographic_computation/mpc_computations/network_owned_address_sign_dkg_emulation.rs`
(734 lines). Complete inventory:

| Item (file:line) | Action | Replacement |
|---|---|---|
| `EmulatedCentralizedDKGResult` struct (59) | **Delete** | Upstream `threshold_dkg_output` returns `DecentralizedPartyDKGOutput` directly; the ika-side wrapper is dead weight. |
| `NetworkOwnedAddressSignDKGOutput` struct (75) | **Delete or shrink** | Inspect contents; if it just bundles `(decentralized_dkg_public_output, centralized_dkg_result)`, replace consumer sites with using the upstream output directly. Keep only fields that carry ika-bookkeeping that doesn't exist upstream. |
| `emulate_centralized_dkg_for_network_owned_address_sign` (108) | **Delete** | `<DKGProtocol as dkg::Protocol>::threshold_dkg_output(pp, session_id)` |
| `emulate_centralized_dkg_v2` (152) | **Delete** | Same. The per-curve dispatch goes away; pick the right `DKGProtocol` type alias at the call site (Phase 4a). |
| `get_zero_centralized_secret` (220) | **Delete** | Upstream `ToBeEmulated` path enforces `x_A = 0` internally (`ecdsa/sign/decentralized_party/class_groups.rs:1014`: "`ToBeEmulated` mode requires $x_A = 0$, so $X_A$ must be neutral"). |
| `get_zero_centralized_secret_internal` (241) | **Delete** | Same. |
| `emulate_centralized_party_partial_signature` (282) | **Delete** | `SignData::ToBeEmulated` in the sign public input. The synchronous-outside-rayon path goes with it. |
| `emulate_sign_centralized` (358) | **Delete** | Same. This is the function that took seconds for ECDSA — kill it. |
| `advance_and_finalize_decentralized_party_dkg` (413) | **Inline or delete** | Inspect: if it's just a thin wrapper around the normal decentralized-party advance loop, fold into the caller (or use the existing orchestration in `network_dkg.rs` / `dwallet_dkg.rs`). |
| `compute_decentralized_dkg_output` (508) | **Inline or delete** | Same; reduces to: call `threshold_dkg_output`, then run the standard decentralized DKG advance loop. The standard loop is already in ika; no duplication needed. |
| `network_owned_address_sign_dkg_session_identifier` (612) | **Keep, relocate** | Pure ika-side session-id derivation. Move to a small `noa.rs` (or fold into `mpc_session/input.rs` where the only production caller lives, alongside the integration-test caller). |
| `compute_network_owned_address_sign_dkg_output` (655) | **Inline or delete** | Same; reduces to `threshold_dkg_output` + standard DKG advance. |

Net deletion: ~700 of the 734 lines. The file may end up empty enough
to delete entirely; if so, do.

**Caller updates** (external to the emulation file):

1. **`crates/ika-core/src/dwallet_mpc/crytographic_computation/mpc_computations/network_dkg.rs:387`** —
   currently calls `compute_network_owned_address_sign_dkg_output(network_key_id, curve, &protocol_pp, access_structure, party_id)` after network DKG completes, then deserializes into `NetworkOwnedAddressSignDKGOutput` and pulls out `centralized_dkg_result.public_key` for the per-curve NOA public key. Rewrite to: call `<DKGProtocol as dkg::Protocol>::threshold_dkg_output(pp, noa_session_id)` directly, run the decentralized-party DKG advance with the resulting public input, and read the public key off the resulting `DecentralizedPartyDKGOutput`. The `noa_session_id` comes from the kept `network_owned_address_sign_dkg_session_identifier`. The `NetworkOwnedAddressSignDKGOutput` type is gone; use the upstream `DecentralizedPartyDKGOutput` directly (or wrap it in a thin ika-side bookkeeping struct only if other consumers need fields the upstream type doesn't expose).

2. **`crates/ika-core/src/dwallet_mpc/mpc_session/input.rs:300`** —
   currently builds `message_centralized_signature` via the slow-path emulator and passes it into `SignPublicInputByProtocol::try_new(...)`. Rewrite: drop the `emulate_centralized_party_partial_signature` call entirely; `SignPublicInputByProtocol::try_new` (or its successor) takes `SignData::ToBeEmulated` for NOA paths and `SignData::Unverified(msg)` for normal user-driven paths. The five-line comment at line 295 also goes — the regression it warned about is fixed.

3. **`crates/ika-core/src/dwallet_mpc/integration_tests/network_owned_address_sign.rs`** —
   tests that exercised the emulator (`test_network_owned_address_sign_dkg_session_identifier_determinism` is fine; tests that touch `emulate_centralized_party_partial_signature` need rework or deletion). Keep the session-id determinism tests; rewrite end-to-end NOA tests to drive the new `ToBeEmulated` path; delete tests of the deleted emulator helpers.

4. **`SignPublicInputByProtocol::try_new`** (in `mpc_computations/sign.rs` /
   wherever it lives) — its current signature takes a
   `message_centralized_signature: &[u8]` (or similar bytes-of-SignMessage).
   New signature should take `sign_data: SignData<SignMessage, VerifiedSignData>`
   (or, for ika ergonomics, an enum-of-enum variant that distinguishes
   `Unverified(bytes)` / `ToBeEmulated` and constructs the upstream
   `SignData` inside). Update all callers, NOA and user-driven alike.

**Scope is mandatory.** No deferral option. Reasons:

- The sign-centralized emulator's *only* production caller is
  `mpc_session/input.rs:300`. If we keep it and also pass
  `SignData::Unverified(synthetic_message)`, the upstream protocol will
  run its OWN emulation on top, producing wire-incompatible output
  versus what ika's synthetic message expected. That's not a "small
  rough edge"; that's a wrong-result bug.
- Even if we hack around that by skipping the upstream emulation, ika's
  emulator's `ZeroRng` semantics may not bit-match what
  `emulate_threshold_verified_sign_data` produces upstream (different
  hands wrote them at different times). Validators on the new build
  would disagree with each other on the synthetic message bytes.
- The performance hole the comment warned about (O(seconds) ECDSA
  blocking the input-handler thread) is unacceptable for any production
  NOA-ECDSA flow; fixing it is the whole point of the upstream change.

**Verification.** A local swarm running an NOA-ECDSA sign should
complete the sign cycle without the input-handler thread blocking for
multi-second windows. Compare wall-clock latency vs. dev (which today
takes seconds per NOA-ECDSA sign).

#### 4g. Restore ECDSA NOA tests

`crates/ika-core/src/dwallet_mpc/integration_tests/network_owned_address_sign.rs`
has two `#[ignore]`'d end-to-end NOA tests for ECDSA — the bump
unblocks both:

- `test_network_owned_address_sign_ecdsa_secp256k1` (line 270)
- `test_network_owned_address_sign_ecdsa_secp256r1` (line 283)

Both are `#[ignore = "ECDSA centralized party emulation with ZeroRng
fails: Commitment(InvalidPublicParameters)"]`. The explanatory comment
block at lines 248-266 is precise about both blockers:

1. **Correctness**: ika's emulator with `ZeroRng` fails ECDSA's commitment
   public-parameter validation. Schnorr's commitment scheme tolerates the
   zero secret key share, ECDSA's does not.
2. **Performance**: even if (1) were fixed, ECDSA emulation in
   `mpc_session/input.rs` runs synchronously off-Rayon at O(seconds).

The comment block then names two candidate fixes; the second is verbatim:

> "Adapt the Sign protocol to accept a flag that makes it compute the
> centralized party partial signature internally (within its own Rayon
> task), eliminating the need to pre-compute it in
> `session_input_from_request`."

That fix is `SignData::ToBeEmulated`. PR #448 ("Threshold mode: t-out-of-n
signing without centralized party") made the upstream commitment scheme
handle the zero-secret math correctly (per the comment at
`ecdsa/sign/decentralized_party/class_groups.rs:1014`: "ToBeEmulated mode
requires $x_A = 0$, so $X_A$ must be neutral") and moves the emulation
into the rayon-dispatched protocol advance. Both blockers go away.

Actions:

1. Remove both `#[ignore = …]` attributes.
2. Delete the explanatory comment block at lines 248-266 — it documents
   a problem that no longer exists. The two tests can keep brief
   per-test doc comments if useful.
3. Run them. They must pass as part of this bump's verification.
4. Sanity-check wall-clock: ECDSA NOA sign in the local swarm should
   complete with the same order-of-magnitude latency as ECDSA
   user-driven sign (no off-Rayon multi-second stall).

The bump's Definition of Done gains: ECDSA NOA tests pass.

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

### Phase 9 — `SignData` enum wraps `SignMessage` in sign public inputs (per-site classification)

The new sign public input struct (visible in
`2pc-mpc/src/ecdsa/sign/decentralized_party/class_groups.rs`) carries
a `SignData<SignMessage, VerifiedSignData>` field where the old shape
took a `SignMessage` directly. Three variants, three semantics:

```rust
pub enum SignData<SignMessage, VerifiedSignData> {
    Unverified(SignMessage),     // full message with ZK proofs; protocol verifies internally
    Verified(VerifiedSignData),  // post-verification compact form; protocol short-circuits verification
    ToBeEmulated,                // no centralized party participated; protocol emulates internally
}
```

Find all construction sites:
```bash
grep -rE 'sign_message|SignMessage' crates/ika-core/src/dwallet_mpc/ sdk/typescript/
# Focus on SignDecentralizedPartyPublicInput / DKGSignDecentralizedPartyPublicInput construction.
```

Classify each site:

| Call origin | SignData variant |
|---|---|
| User-driven sign (dWallet owned by an external user; the centralized party produced a real `SignMessage`) | `SignData::Unverified(sign_message)` — same effective semantics as today's flow. |
| Network-owned-address (NOA) sign (no real centralized party; today: synthetic `SignMessage` from ika's emulator) | `SignData::ToBeEmulated` — replaces the synthetic-message construction entirely. See Phase 4f for the corresponding emulator deletion. |
| Post-verification re-construction (e.g. if ika persists a sign attempt across sessions and reconstructs the public input later) | `SignData::Verified(verified_sign_data)` from the captured `VerifiedSignData` (Phase 4e) — protocol skips re-verification. |

Don't blanket-wrap every site as `SignData::Unverified(...)` — that
would mask the NOA simplification opportunity (Phase 4f) and ship the
wire-size optimization unused (Phase 4e).

For the NOA → `ToBeEmulated` conversion specifically: the call sites
that currently look like:

```rust
let sign_message = emulate_centralized_party_partial_signature(…)?;
let public_input = SignDecentralizedPartyPublicInput { …, sign_message, … };
```

become:

```rust
let public_input = SignDecentralizedPartyPublicInput { …, sign_data: SignData::ToBeEmulated, … };
```

and the `emulate_*` calls (and their 600-line emulator file) are
deleted in Phase 4f.

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
5. **ECDSA NOA tests pass** — `test_network_owned_address_sign_ecdsa_secp256k1`
   and `test_network_owned_address_sign_ecdsa_secp256r1` no longer
   `#[ignore]`'d, and run green. (Phase 4g.) This is a real capability
   gain unlocked by the bump — ECDSA NOA was never functional on dev.
6. **NOA-ECDSA sign wall-clock**: in the local swarm, ECDSA NOA sign
   completes with the same order-of-magnitude latency as user-driven
   ECDSA sign. No multi-second off-Rayon stall in the input handler.
7. `network_owned_address_sign_dkg_emulation.rs` is deleted or reduced
   to thin bookkeeping (Phase 4f); its prior ~700 lines of emulation
   code are gone.
8. `docs/inkrypto-bump-diff.md` is referenced from this plan as the
   authoritative API-change catalog, and no item in it goes unaddressed
   in the diff this branch produces (or is explicitly deferred with a
   comment in the relevant Cargo.toml/source).

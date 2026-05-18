# cryptography-private @ babbb483 → main: surface diff for ika

Scope: catalog every API/wire-format change that affects ika's current
consumption of cryptography-private. Verified directly against
`/mnt/nvme0n1p1/cryptography-private2` clone of
`github.com/dwallet-labs/cryptography-private`.

| | rev | sha | commit subject |
|---|---|---|---|
| dev pins | `babbb483` | `babbb4837` | "Remove redundant public key and nonce is neutral check" |
| target | `origin/main` | `9d35fa76` | "Preserve mpc::Error::ThresholdNotReached at threshold-check call sites (#485)" |

Range: 40 commits, 248 files changed, +46,412 / −11,146 lines.

This file is descriptive, not prescriptive — the plan in
`docs/plan-bump-crypto-private-to-main.md` says what to do about it.

---

## 0. Workspace-level changes

### New workspace members in cryptography-private

```toml
# in cryptography-private/Cargo.toml at main
members = [
    "group",
    "commitment",
    "proof",
    "proof-aggregation",   # NEW
    "homomorphic-encryption",
    "mpc",
    "enhanced-maurer",
    "maurer",
    "maurer-aggregation",  # NEW
    "tiresias",
    "2pc-mpc",
    "class-groups",
]
```

`proof::aggregation` and `maurer::aggregation` modules were extracted into
standalone crates. The old module paths cease to exist.

### New transitive workspace deps

```toml
hpke = { git = "https://github.com/ycscaly/rust-hpke.git", rev = "94b318c", default-features = false, features = ["alloc", "x25519"] }
aead = "0.5"
generic-array = "0.14"
chacha20poly1305 = "0.10"
```

These are pulled in by `mpc::hybrid_public_key_encryption` (a new module).
ika does NOT need to add these to its own `Cargo.toml` — they're transitive
through `mpc`.

### File-level shape of the diff

- **46 file additions** — most are new VSS Schnorr code under
  `2pc-mpc/src/schnorr/vss/`, the new
  `decentralized_party::threshold_encryption_of_secret_key_share_parts_to_sharing`
  module + its four round files, three new DKG round files
  (`fifth_round.rs`, `sixth_round.rs`, `seventh_round.rs`), the new
  `mpc/src/hybrid_public_key_encryption.rs`, the new
  `mpc/src/secret_sharing/shamir/known_order/` subtree, the new
  `class-groups/src/threshold_encryption_to_sharing.rs`, the new
  `class-groups/src/publicly_verifiable_secret_sharing/small_prime/`
  subtree, the new `group/src/seedable_collection.rs`, and the standalone
  `proof-aggregation/` and `maurer-aggregation/` crates.
- **3 file deletions** — `maurer/src/aggregation.rs`,
  `maurer/tests/halborn.rs`, `proof/src/aggregation.rs`.
- **23 file renames** — schnorr namespace partition (`schnorr/presign` →
  `schnorr/ahe/presign`, `schnorr/sign/decentralized_party/*` →
  `schnorr/ahe/sign/decentralized_party/*`), PVSS relocation
  (`publicly_verifiable_secret_sharing/{party,deal_shares,verify_shares,test_consts}`
  → `publicly_verifiable_secret_sharing/chinese_remainder_theorem/$&`), and
  the proof/maurer aggregation crate splits.
- **176 file modifications** — body changes touching trait signatures,
  type definitions, public API.

---

## 1. `group` crate

Largest single-file diff: `group/src/lib.rs` is +716 −102 lines.

### `GroupElement` supertrait list — heavy refactor

**babbb483:**
```rust
pub trait GroupElement:
    Neg<Output = Self>
    + Add<Self, Output = Self>
    + for<'r> Add<&'r Self, Output = Self>
    + Sub<Self, Output = Self>
    + for<'r> Sub<&'r Self, Output = Self>
    + AddAssign<Self>
    + for<'r> AddAssign<&'r Self>
    + SubAssign<Self>
    + for<'r> SubAssign<&'r Self>
    + Into<Self::Value>
    + Debug
    + PartialEq
    + Eq
    + Copy
    + Clone
    + LinearlyCombinable
    + ConstantTimeEq
    + ConditionallySelectable
    + Send
    …
```

**main:**
```rust
pub trait GroupElement:
    Into<Self::Value> + Debug + PartialEq + Eq + Clone + ConstantTimeEq + Send + Sync
{
```

**Removed:** `Neg`, `Add` / `for<'r> Add`, `Sub` / `for<'r> Sub`, `AddAssign` /
`for<'r> AddAssign`, `SubAssign` / `for<'r> SubAssign`, `Copy`,
`LinearlyCombinable`, `ConditionallySelectable`.

**Added:** `Sync`.

### `GroupElement::Value` bounds

**babbb483:** `Serialize + for<'r> Deserialize<'r> + Clone + Debug + PartialEq +
Eq + ConstantTimeEq + ConditionallySelectable + Copy + Default + …`

**main:** `Serialize + for<'r> Deserialize<'r> + Clone + Debug + PartialEq +
Eq + ConstantTimeEq + Default + Send + Sync;`

**Removed:** `ConditionallySelectable`, `Copy`.
**Added:** `Send`, `Sync`.

### Arithmetic method changes

| Method | babbb483 | main |
|---|---|---|
| `+`, `-`, `+=`, `-=`, unary `-` | supertrait operators | **removed** |
| `add_vartime` | `fn add_vartime(self, other: &Self) -> Self` | `fn add_vartime(&self, other: &Self, pp: &Self::PublicParameters) -> Self` |
| `add_constant_time` | does not exist | `fn add_constant_time(&self, other: &Self, pp: &Self::PublicParameters) -> Self` |
| `sub_vartime` | `fn sub_vartime(self, other: &Self) -> Self` | only `sub_constant_time` exists |
| `sub_constant_time` | does not exist | `fn sub_constant_time(&self, other: &Self, pp: &Self::PublicParameters) -> Self` |
| `neg_constant_time` | does not exist | `fn neg_constant_time(&self, pp: &Self::PublicParameters) -> Self` |
| `add_randomized` / `sub_randomized` | exist | removed (replaced by `scale_randomized_*` family) |

### Scaling method changes

All `scale*` methods at babbb483 took `&self, scalar`. At main they ALL take
an additional `public_parameters: &Self::PublicParameters` argument.

Method renames (`*_accelerated` → `*_by` style) and new methods added:

- New: `scale_vartime_scalar`, `scale_integer_vartime_scalar`,
  `scale_public_base`, `scale_public_base_bounded`,
  `scale_integer_public_base`, `scale_integer_public_base_bounded`,
  `scale_randomized`, `scale_randomized_bounded`,
  `scale_randomized_public_base`, `scale_randomized_public_base_bounded`,
  `scale_integer_randomized` and all its variants,
  `scale_randomized_vartime_scalar`,
  `scale_integer_randomized_vartime_scalar`.
- Renamed: `scale_*_accelerated` → integrated into `*_public_base` family.

### `LinearlyCombinable` removed

At babbb483, `LinearlyCombinable` was a separate trait that `GroupElement`
extended. At main, the trait is gone; its `linear_combination(...)` method is
now a method on `GroupElement` (now requires `&pp`).

### `SeedableCollection` moved

- babbb483: defined in `mpc/src/lib.rs`, re-exported as `mpc::SeedableCollection`.
- main: defined in `group/src/seedable_collection.rs`, re-exported as
  `group::SeedableCollection`.

### New: `GroupElement::new_unchecked()`

A new optional method (or required, must verify) added at main. Bypasses
input validation; useful for deserialization paths.

### ika impact in `group`

Direct ika `use` lines:

```
use group::CsRng;
use group::HashScheme;
use group::OsCsRng;
use group::PartyID;
use group::secp256k1;
use group::{CyclicGroupElement, GroupElement, HashScheme, OsCsRng, Samplable, secp256k1};
use group::{CsRng, OsCsRng};
use group::{CsRng, PartyID};
use group::{HashScheme, OsCsRng, PartyID};
```

All of these still resolve at main. Operator usage in ika
(`crates/dwallet-mpc-centralized-party/src/lib.rs` is the primary
caller) breaks because operators are removed; needs to use the
`add_vartime` / `add_constant_time` / `sub_constant_time` /
`neg_constant_time` methods, each threading `&public_parameters`.

Implicit `Copy` usage: any code that relied on `GroupElement: Copy` or
`GroupElement::Value: Copy` needs explicit `.clone()` or `+ Copy` bounds
that are no longer satisfiable (since `Copy` is removed from the trait).

`mpc::SeedableCollection` import sites must be rewritten to
`group::SeedableCollection`.

---

## 2. `commitment` crate

Smaller diff: `commitment/src/lib.rs` is +59 −8.

### `HomomorphicCommitmentScheme::commit` signature

**babbb483:**
```rust
fn commit(
    &self,
    message: &Self::MessageSpaceGroupElement,
    randomness: &Self::RandomnessSpaceGroupElement,
) -> Self::CommitmentSpaceGroupElement;
```

**main:**
```rust
fn commit(
    &self,
    message: &Self::MessageSpaceGroupElement,
    randomness: &Self::RandomnessSpaceGroupElement,
    public_parameters: &group::PublicParameters<Self::CommitmentSpaceGroupElement>,
) -> Self::CommitmentSpaceGroupElement;
```

Every call site adds a `&pp` argument.

### ika impact in `commitment`

ika directly imports only `commitment::CommitmentSizedNumber` (a type
alias), which is unchanged. But transitively, every protocol that
internally calls `commit` is rebuilt — no source change in ika is needed
purely for `commitment`'s API.

---

## 3. `homomorphic_encryption` crate

`homomorphic-encryption/src/lib.rs` is +77 −20.

### `Copy` bounds added on associated types

```rust
// at main (newly required):
type CiphertextSpaceGroupElement: ... + Copy;
type RandomnessSpaceGroupElement: ... + Copy;
```

But `Copy` was REMOVED from `GroupElement` at the same time, so these
new `Copy` bounds are only satisfiable by group element types that
implement `Copy` independently. Verify per concrete impl.

### `GroupsPublicParametersAccessors` trait

ika imports this trait. Its accessor surface is unchanged in shape but
exact method names may have shifted; verify against new code.

### ika impact in `homomorphic_encryption`

```
use homomorphic_encryption::GroupsPublicParametersAccessors;
```

This single import remains valid; spot-check that the methods ika calls on
it still exist.

---

## 4. `proof` and `maurer` crates — aggregation extracted

- `proof::aggregation` no longer exists. The submodule was relocated to a
  standalone crate `proof_aggregation` (workspace member `proof-aggregation`).
  - `proof::aggregation::asynchronous` → `proof_aggregation::asynchronous`
  - `proof::aggregation::synchronous` → `proof_aggregation::synchronous`
  - `proof::aggregation::*Round` and bulletproof commit/decommit modules
    → `proof_aggregation::range::bulletproofs::*` and
    `proof_aggregation::*`.
- `maurer::aggregation` no longer exists; moved to `maurer_aggregation`.

### `twopc_mpc::Error::AsyncProofAggregation` source type

**babbb483:** `#[from] ::proof::aggregation::asynchronous::Error`
**main:** `#[from] ::proof_aggregation::asynchronous::Error`

### ika impact

ika does not directly import `proof::aggregation` or `maurer::aggregation`,
but any indirect/transitive paths that flow through the public surface
need verification. No `ika` `use` line of the form
`use proof::aggregation` or `use maurer::aggregation` exists today
(confirmed by grep across `crates/` and `sdk/`).

---

## 5. `mpc` crate

`mpc/src/lib.rs` is +52 −31. Top-level public surface changes:

### `Error` enum became `Error` struct + `ErrorKind` enum

```rust
// at babbb483:
pub enum Error { InvalidParameters, ThresholdNotReached, NonParticipatingParty, … }

// at main:
pub struct Error {                  // NEW WRAPPER
    pub kind: ErrorKind,
    pub backtrace: …,
}
pub enum ErrorKind { InvalidParameters, DecryptionFailed, IdentityEphemeralKey, TorsionEphemeralKey, ThresholdNotReached, … }
```

**Why:** commit "Wrap mpc::Error with backtrace for construction-site
tracing" — adds a backtrace to each construction site.

**New `ErrorKind` variants at main** (not present at babbb483):
- `DecryptionFailed`
- `IdentityEphemeralKey`
- `TorsionEphemeralKey`
- `MaliciousMessageAsync`
- `MaliciousMessagePreventsAdvance`
- `Serialization(String)`

**Impact on ika:** ANY match on `mpc::Error` (i.e. matching on what is
now `ErrorKind`) breaks. ika has match arms in mpc-protocol error
handling that need to be rewritten — either match on `err.kind` against
`ErrorKind::…` or unwrap appropriately. Plus new variants must be
covered.

### `SeedableCollection` moved out

- babbb483: `pub trait SeedableCollection<T> …` defined in `mpc/src/lib.rs`.
- main: `pub use seedable_collection::SeedableCollection;` re-exports from
  the new `group` location. Importing as `mpc::SeedableCollection` will
  fail.

### New module `mpc::hybrid_public_key_encryption`

1,269 lines. Provides HPKE keygen, encryption, decryption used by the new
VSS-mode protocols. Not consumed by ika dev yet.

### New module `mpc::secret_sharing::shamir::known_order`

3,180 lines. Adds known-order Shamir secret sharing used by VSS.
Not consumed by ika dev yet.

### `mpc::Party` and `mpc::AsynchronouslyAdvanceable` etc.

These are unchanged at the trait level. ika's many imports of
`mpc::{Party, GuaranteedOutputDeliveryRoundResult, GuaranteesOutputDelivery,
WeightedThresholdAccessStructure, Weight, MajorityVote, two_party::Round,
guaranteed_output_delivery::AdvanceRequest, …}` remain valid.

### ika impact in `mpc`

Direct ika imports:

```
use mpc::GuaranteedOutputDeliveryRoundResult;
use mpc::Party;
use mpc::WeightedThresholdAccessStructure;
use mpc::guaranteed_output_delivery::AdvanceRequest;
use mpc::guaranteed_output_delivery::{AdvanceRequest, Party, ReadyToAdvanceResult};
use mpc::guaranteed_output_delivery::{AdvanceRequest, ReadyToAdvanceResult};
use mpc::two_party::Round;
use mpc::{AsynchronouslyAdvanceable, GuaranteesOutputDelivery};
use mpc::{GuaranteedOutputDeliveryRoundResult, Party, Weight, WeightedThresholdAccessStructure};
use mpc::{MajorityVote, WeightedThresholdAccessStructure};
```

All resolve. The break is at match sites against `mpc::Error`, which is
now `mpc::Error` struct wrapping `ErrorKind`. Replace any
`match err { mpc::Error::X => … }` with
`match err.kind() { mpc::ErrorKind::X => … }` (or whatever accessor
shape main exposes).

---

## 6. `class_groups` crate

### New module `class_groups::threshold_encryption_to_sharing`

Implements the new 4-round sub-protocol embedded in network DKG rounds 5-7
and reconfiguration. Consumed only by the v2 protocol paths in
`2pc-mpc/src/decentralized_party/threshold_encryption_of_secret_key_share_parts_to_sharing/`.
Not consumed by ika dev yet.

### PVSS module reshape

Files previously at `class-groups/src/publicly_verifiable_secret_sharing/`
moved INTO `…/chinese_remainder_theorem/`:

| Was | Now |
|---|---|
| `…/deal_shares.rs` | `…/chinese_remainder_theorem/deal_shares.rs` |
| `…/party.rs` | `…/chinese_remainder_theorem/party.rs` |
| `…/test_consts.rs` | `…/chinese_remainder_theorem/test_consts.rs` |
| `…/verify_shares.rs` | `…/chinese_remainder_theorem/verify_shares.rs` |

**At babbb483**, `publicly_verifiable_secret_sharing` had `pub use party::Party`
at its root; `Party` was reachable as
`class_groups::publicly_verifiable_secret_sharing::Party`.

**At main**, the top-level module just declares two submodules:
```rust
pub mod chinese_remainder_theorem;
pub mod small_prime;
```
`Party` is reachable only as
`class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::Party`.

### New PVSS submodule `class_groups::publicly_verifiable_secret_sharing::small_prime`

Adds a small-prime PVSS variant. Not consumed by ika dev yet.

### DKGProtocol type aliases — same name, different concrete type

The per-curve aliases `twopc_mpc::secp256k1::class_groups::DKGProtocol`,
`twopc_mpc::secp256r1::class_groups::DKGProtocol`,
`twopc_mpc::curve25519::class_groups::DKGProtocol`,
`twopc_mpc::ristretto::class_groups::DKGProtocol` exist at both revs but
at main they point to a different underlying type
(`class_groups::asynchronous::DKGProtocol<...>` per the breaking-changes
doc — verify against current code).

### ika impact in `class_groups`

ika imports — all still valid at main, since the import paths used today
already target `chinese_remainder_theorem`:

```
use class_groups::CiphertextSpaceGroupElement;
use class_groups::CiphertextSpaceValue;
use class_groups::CompactIbqf;
use class_groups::SecretKeyShareSizedInteger;
use class_groups::dkg::Secp256k1Party;
use class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::{
    CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS, KnowledgeOfDiscreteLogUCProof, MAX_PRIMES,
};
use class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::{
    CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS, CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS, MAX_PRIMES,
    construct_knowledge_of_decryption_key_public_parameters_per_crt_prime,
    construct_setup_parameters_per_crt_prime, generate_keypairs_per_crt_prime,
    generate_knowledge_of_decryption_key_proofs_per_crt_prime,
};
use class_groups::{CompactIbqf, DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER};
```

All present at main with same names.

DKGProtocol type-aliases name resolution: still works. But the concrete
type the alias resolves to is different, which means the trait surface
the alias offers is different — see §7 below.

---

## 7. `twopc_mpc` crate

Largest churn: `2pc-mpc/src/sign.rs` is +4828 −807, `presign.rs` is
+879 −109, `dkg.rs` is +277 −70, `lib.rs` is +575 −34.

### `Error` enum → `Error` struct + `ErrorKind`

Same wrapping treatment as `mpc::Error`. New variant: `InvalidSignatureShare`.
Source type change: `AsyncProofAggregation` now wraps
`::proof_aggregation::asynchronous::Error` (not `::proof::aggregation::…`).

### `sign::Protocol` trait — supertrait hierarchy and new types

**babbb483:**
```rust
pub trait Protocol: dkg::Protocol + presign::Protocol {
    type Signature: EncodableSignature;
    type DecryptionKeyShare: Sync + Send;
    type DecryptionKeySharePublicParameters: …;
    type SignDecentralizedPartyPublicInput: From<(
        HashSet<PartyID>, Arc<Self::ProtocolPublicParameters>, Vec<u8>, HashScheme,
        Self::DecentralizedPartyDKGOutput, Self::Presign, Self::SignMessage,
        Arc<Self::DecryptionKeySharePublicParameters>,
    )> + …;
    type SignDecentralizedParty: mpc::Party<…>
        + AsynchronouslyAdvanceable<PrivateInput = HashMap<PartyID, Self::DecryptionKeyShare>>
        + …;
    type DKGSignDecentralizedPartyPublicInput: From<(…)> + …;
    type DKGSignDecentralizedParty: mpc::Party<…>
        + AsynchronouslyAdvanceable<PrivateInput = HashMap<PartyID, Self::DecryptionKeyShare>>
        + …;
    type SignCentralizedPartyPublicInput: From<(
        Vec<u8>, HashScheme, Self::CentralizedPartyDKGOutput, Self::Presign,
        Self::ProtocolPublicParameters,
    )> + …;
    type SignMessage: …;
    type SignCentralizedParty: two_party::Round<…>;
    fn verify_centralized_party_partial_signature(…) -> crate::Result<()>;
}
```

**main:**
```rust
pub enum SignData<SignMessage, VerifiedSignData> {
    Unverified(SignMessage),
    Verified(VerifiedSignData),
    ToBeEmulated,
}

pub trait Protocol: presign::Protocol {            // no longer extends dkg::Protocol
    type Signature: EncodableSignature;
    type SignDecentralizedPartyPrivateInput: Sync + Send;         // NEW (replaces DecryptionKeyShare)
    type SignDecentralizedPartyPublicInput: Clone + Debug + PartialEq + Eq + Sync + Send;  // NO From<tuple>
    type SignDecentralizedParty: mpc::Party<…>
        + AsynchronouslyAdvanceable<PrivateInput = Self::SignDecentralizedPartyPrivateInput>
        + …;
    type DKGSignDecentralizedPartyPublicInput: Clone + Debug + PartialEq + Eq + Sync + Send;  // NO From<tuple>
    type DKGSignDecentralizedParty: mpc::Party<
            …,
            PublicOutputValue = (<Self::DKGProtocol as dkg::Protocol>::DecentralizedPartyDKGOutput, Self::Signature),
            PublicOutput = (<Self::DKGProtocol as dkg::Protocol>::DecentralizedPartyDKGOutput, Self::Signature),
        > + AsynchronouslyAdvanceable + …;
    type SignCentralizedPartyPublicInput: Serialize + Clone + Debug + PartialEq + Eq;  // NO From<tuple>
    type SignMessage: …;
    type VerifiedSignData: Serialize + for<'a> Deserialize<'a> + Clone + Debug + PartialEq + Eq + Sync + Send;  // NEW
    type SignCentralizedParty: two_party::Round<
        IncomingMessage = (), OutgoingMessage = Self::SignMessage,
        PrivateInput = <Self::DKGProtocol as dkg::Protocol>::CentralizedPartySecretKeyShare,
        …, PublicInput = Self::SignCentralizedPartyPublicInput,
    >;
    fn verify_centralized_party_partial_signature(
        message: &[u8], hash_type: HashScheme,
        dkg_output: <Self::DKGProtocol as dkg::Protocol>::DecentralizedPartyDKGOutput,
        presign: Self::Presign, sign_message: Self::SignMessage,
        protocol_public_parameters: &<Self::DKGProtocol as dkg::Protocol>::ProtocolPublicParameters,
        rng: &mut impl CsRng,
    ) -> crate::Result<Self::VerifiedSignData>;       // return type changed
}
```

Changes:
- `dkg::Protocol` removed as supertrait. DKG types accessed via
  `<Self::DKGProtocol as dkg::Protocol>::…`. (Where does `DKGProtocol`
  come from? From `presign::Protocol`, which now declares it — see §7.2.)
- `DecryptionKeyShare` / `DecryptionKeySharePublicParameters` removed
  as associated types. Replaced by single
  `SignDecentralizedPartyPrivateInput`.
- New required `VerifiedSignData` associated type.
- `From<tuple>` removed on `SignDecentralizedPartyPublicInput`,
  `DKGSignDecentralizedPartyPublicInput`, `SignCentralizedPartyPublicInput`.
- `verify_centralized_party_partial_signature` return type changed from
  `Result<()>` to `Result<Self::VerifiedSignData>`.

### `presign::Protocol` trait

**babbb483:**
```rust
pub trait Protocol: dkg::Protocol {
    type Presign: …;
    type PresignPublicInput: AsRef<Self::ProtocolPublicParameters>
        + From<(Arc<Self::ProtocolPublicParameters>, Option<Self::DecentralizedPartyTargetedDKGOutput>)>
        + …;
    type PresignParty: mpc::Party<…>
        + AsynchronouslyAdvanceable<PrivateInput = ()>
        + …;
}
```

**main:**
```rust
pub trait Protocol {                                   // no longer extends dkg::Protocol
    type DKGProtocol: dkg::Protocol;                   // NEW assoc type
    type Presign: …;
    type HPKEEncryptionKey: Clone + Debug + PartialEq + Eq + Send + Sync;        // NEW (= () for AHE)
    type PresignPublicInput: AsRef<<Self::DKGProtocol as dkg::Protocol>::ProtocolPublicParameters>
        + Clone + Debug + PartialEq + Eq + Send + Sync;                          // NO From<tuple>
    type PresignPrivateInput: Clone + PartialEq + Eq + Send + Sync;              // NEW (= () for AHE)
    type PresignParty: mpc::Party<…>
        + AsynchronouslyAdvanceable<PrivateInput = Self::PresignPrivateInput>
        + …;
}
```

### `dkg::Protocol` trait

Largely unchanged in structure. Notable additions:

- New required method `threshold_dkg_output(...)` at line 232 (between
  `verify_centralized_party_public_key_share` and the trusted-dealer
  types).
- `DKGDecentralizedPartyPublicInput: From<(...)>` and
  `DKGCentralizedPartyPublicInput: From<(...)>` are PRESERVED. The
  breaking-changes doc's claim that ALL `From<tuple>` constructors are
  removed is only true for sign and presign — DKG keeps them.
- `From<tuple>` on `TrustedDealerDKGDecentralizedPublicInput` is also preserved.

### `SignData` enum

```rust
pub enum SignData<SignMessage, VerifiedSignData> {
    Unverified(SignMessage),
    Verified(VerifiedSignData),
    ToBeEmulated,
}
```

This is the wrapper that lets the protocol carry either an unverified
message, a post-verification extract, or a "to be emulated" marker. ika
sign code paths that construct `SignMessage` directly may now need to
wrap them in `SignData::Unverified(...)` depending on where they're
passed.

### Wire-format type changes

#### `decentralized_party::dkg::Message` (BCS-serialized between validators)

**babbb483 variants:**
1. `DealDecryptionKeyContributionAndProveCoefficientCommitments { … }`
2. `VerifiedDecryptionKeyContributionDealers(...)`
3. `EncryptDecryptionKeySharesAndSecretKeyShares { … }`

**main variants** (3 + 3 new):

1. `DealDecryptionKeyContributionAndProveCoefficientCommitments { … }` (unchanged shape)
2. `VerifiedDecryptionKeyContributionDealers(...)` (unchanged)
3. `EncryptDecryptionKeySharesAndSecretKeyShares { … }` (unchanged)
4. **NEW** `VerifiedDealers { fourth_round_output, threshold_encryption_dealing_message: DealingRoundMessage }`
5. **NEW** `AccusedDealers { threshold_encryption_accusation_message: AccusationRoundMessage }`
6. **NEW** `ThresholdDecryptSecretKeyShares { threshold_encryption_decryption_round_message: ThresholdDecryptionRoundMessage }`

#### `decentralized_party::dkg::PublicOutput`

Gains one new field at main:
```rust
pub(crate) threshold_encryption_to_sharing_output:
    decentralized_party::threshold_encryption_of_secret_key_share_parts_to_sharing::PublicOutput,
```
plus a few other CRT-related fields that weren't visible to ika (they're
`pub(crate)`).

The BCS encoding of the struct CHANGES because a new field was appended.
Old V2 bytes can be deserialized only by the babbb483-era struct
definition.

#### `decentralized_party::reconfiguration::Message`

**babbb483:**
1. `DealRandomizerContributionAndProveCoefficientCommitments { deal_randomizer_message, equality_of_coefficients_commitments_proof, coefficients_commitments }`
2. `VerifiedRandomizerDealers(class_groups::reconfiguration::Message<…>)`    // tuple variant
3. `ThresholdDecryptShares { threshold_decrypt_message, malicious_coefficients_committers }`

**main:**
1. `DealRandomizerContributionAndProveCoefficientCommitments { deal_randomizer_message, equality_of_coefficients_commitments_proof, coefficients_commitments, threshold_encryption_of_secret_key_share_parts_to_sharing_dealing_message }`    // GAINED field
2. `VerifiedRandomizerDealers { class_groups_message, threshold_encryption_of_secret_key_share_parts_to_sharing_accusation_message }`     // STRUCT VARIANT now, tuple-→-struct break
3. `ThresholdDecryptShares { threshold_decrypt_message, malicious_coefficients_committers, threshold_encryption_of_secret_key_share_parts_to_sharing_decryption_round_message }`    // GAINED field

Variant 2's tuple → struct change is the most visually striking — BCS
re-encodes anonymous-tuple variants differently from named-field-struct
variants, so this is a hard wire break.

#### Other wire types — STABLE per direct comparison

- `dkg::{centralized,decentralized}_party::{Output, VersionedOutput}` —
  shape unchanged.
- `ProtocolPublicParameters` (all curves) — shape unchanged.
- Signature types (`ECDSASecp256k1Signature`, `ECDSASecp256r1Signature`,
  `EdDSASignature`, `SchnorrkelSubstrateSignature`, `TaprootSignature`) —
  unchanged.
- `Presign` output, all per-curve sign Message/PublicOutput — unchanged.
- `CompactIbqf`, `KnowledgeOfDiscreteLogUCProof`, `CiphertextSpaceValue` —
  unchanged.
- `schnorr::PartialSignature` — only the path moved (see §7.5); the type
  is unchanged.

### Path renames inside twopc_mpc

- `schnorr::presign` → `schnorr::ahe::presign`
- `schnorr::presign::decentralized_party::*` → `schnorr::ahe::presign::decentralized_party::*`
- `schnorr::sign::decentralized_party::class_groups` → `schnorr::ahe::sign::decentralized_party::class_groups`
- `schnorr::sign::decentralized_party::signature_partial_decryption_round` → `schnorr::ahe::sign::decentralized_party::signature_partial_decryption_round`
- `schnorr::sign::decentralized_party::signature_threshold_decryption_round` → `schnorr::ahe::sign::decentralized_party::signature_threshold_decryption_round`
- `schnorr::sign::class_groups` → `schnorr::ahe::sign::class_groups`
- `schnorr::sign::centralized_party::PartialSignature` → `schnorr::PartialSignature` (per breaking-changes doc; verify)

ika does NOT import any of the relocated `schnorr::*` paths directly.

---

## 8. Cross-cutting: `Arc<>` ownership for big public params

Commit `7bc9472` ("Take `Arc<>` of big data structures (protocol public
parameters, decryption key share public parameters) in decentralized
party protocols' inputs") changes ownership shape at construction sites:

- `Arc<Self::ProtocolPublicParameters>` is what
  `DKGDecentralizedPartyPublicInput::from((Arc<…>, …))` now expects, and
  similarly throughout. babbb483 was already using `Arc` in many places,
  so the diff is incremental, but every `From<(...)>` constructor that
  takes a public-parameters argument expects `Arc<…>`.

ika construction sites should already use `Arc` since babbb483 already
threaded `Arc<ProtocolPublicParameters>`. Verify no spots regressed to
owned values.

---

## 9. Summary by ika-side consumer

### `crates/dwallet-mpc-centralized-party/`

This crate is the heaviest consumer of low-level crypto and absorbs
nearly all of §1 (GroupElement), §2 (commit `&pp` parameter), §7.5
(SignData wrapper, From<tuple> removal on Sign PublicInput).

Expect mechanical churn across ~50 sites:
- `+` / `-` / `*` operators → `add_vartime(&pp)` / `sub_constant_time(&pp)` /
  `scale*(&pp)`.
- Decide vartime vs constant-time per call site.
- `.clone()` everywhere `Copy` was relied on.
- Struct-literal construction in place of `From<(...)>` tuples for sign
  public inputs.
- Wrap `SignMessage` in `SignData::Unverified(...)` where called from
  protocol entry points.

### `crates/ika-core/src/dwallet_mpc/crytographic_computation/mpc_computations/`

- `sign.rs` — needs trait-hierarchy adaptation (`<Self::DKGProtocol as
  dkg::Protocol>::…` path access), `SignDecentralizedPartyPrivateInput`
  in place of `DecryptionKeyShare`, struct-literal construction for
  sign public inputs.
- `presign.rs` — same trait-hierarchy adaptation. New `HPKEEncryptionKey`
  and `PresignPrivateInput` assoc types accessed; for AHE-mode they're
  both `()`.
- `dwallet_dkg.rs` — `dkg::Protocol` gains `threshold_dkg_output(...)`
  required method; impls must provide it.
- `network_dkg.rs` — wire-format break on `decentralized_party::dkg::Message`
  and `PublicOutput`; cannot communicate with babbb483 peers.
- `reconfiguration.rs` — wire-format break on
  `decentralized_party::reconfiguration::Message`; cannot communicate with
  babbb483 peers.

### `crates/ika-types/`

- `committee.rs` — imports from CRT remain valid (`KnowledgeOfDiscreteLogUCProof`,
  `CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS`, `MAX_PRIMES`).
- `messages_dwallet_mpc.rs` — per-curve `*AsyncDKGProtocol` type aliases
  resolve, but to a different concrete type (per breaking-changes doc).

### `crates/dwallet-classgroups-types/`

- Imports remain valid (`construct_*_per_crt_prime`, `generate_*_per_crt_prime`,
  etc., all live at `class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem`).

### Match arms on `mpc::Error` and `twopc_mpc::Error`

Wherever ika `match`es on these errors directly, the pattern is now
`match err.kind() { mpc::ErrorKind::X => … }` (or whatever accessor
shape main exposes). Plus the new `ErrorKind` variants must be covered.

---

## 10. Things the breaking-changes doc got right vs. drifted

The doc was written when cryptography-private main was `33fa7e1e`. Main
has since moved to `9d35fa76` (+8 commits). Spot checks:

- Doc's claim "All `From<tuple>` constructors removed" — **partially
  wrong**. `dkg::Protocol`'s `DKGDecentralizedPartyPublicInput`,
  `DKGCentralizedPartyPublicInput`, and
  `TrustedDealerDKGDecentralizedPublicInput` still expose `From<tuple>`
  at main. Only sign and presign public inputs lost the tuple
  constructors.
- Doc's claim that DKG `PublicOutput` gained `threshold_encryption_to_sharing_output`
  — **confirmed** (line shown in §7.4).
- Doc's `decentralized_party::reconfiguration::Message`
  `VerifiedRandomizerDealers` tuple → struct — **confirmed**.
- Doc's three new `decentralized_party::dkg::Message` variants — **confirmed**.
- Doc's `mpc::Error` new variants — **confirmed and extended**; the doc
  did not mention the `Error → Error{kind: ErrorKind}` wrapper struct
  refactor.
- Doc's `twopc_mpc::Error::AsyncProofAggregation` source change to
  `proof_aggregation` — **confirmed**.
- Doc's `sign::Protocol` no-longer-extends-`dkg::Protocol` — **confirmed**.
- Doc's `dkg::Protocol::threshold_dkg_output` new required method —
  **confirmed**.
- Doc's `GroupElement` operator removal, `Copy` removal,
  `LinearlyCombinable` removal, `scale*` signature changes with `&pp` —
  **all confirmed**.
- Doc's `HomomorphicCommitmentScheme::commit` extra `&pp` parameter —
  **confirmed**.
- Doc's `mpc::SeedableCollection` → `group::SeedableCollection` —
  **confirmed**.
- Doc's `proof::aggregation` and `maurer::aggregation` extraction into
  standalone crates — **confirmed**.

The breaking-changes doc is broadly accurate; the only material drift
is the `Error → ErrorKind` wrapper refactor and the DKG-side
`From<tuple>` constructors which are NOT removed.

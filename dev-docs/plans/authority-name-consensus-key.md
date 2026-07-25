# Plan: consensus keys reachable by name (toward consensus-key-signed certs)

Status: landed (2026-07-01, PR #1762 — `c875d88795`).

**SHIPPED DESIGN: consensus keys are carried as `Committee` data; the
identity (`AuthorityName`) stays the BLS key.** Jump to the
[Redesign](#redesign-consensus-keys-are-committee-data-not-the-identity)
section for what actually landed. Everything before it documents the
*rejected* first approach — making `AuthorityName` itself the consensus key
(a v4-gated flip) — and **why it was abandoned** (it wedged the v3→v4 rolling
upgrade). Kept as design rationale for the next person who asks "why not just
make `AuthorityName` the consensus key?"

Branch: `feat/authority-name-consensus-key`.

## Rejected approach (below): `AuthorityName` = consensus key, gated at v4

## Goal

Make a validator's `AuthorityName` (its canonical identity, used as the
key for committees, MPC, handoff, checkpoints) be its **consensus
Ed25519 public key** instead of its **BLS12381 protocol key**, gated by a
protocol-config flag so the behavior turns on at protocol version 4.
v4 is still pre-mainnet, so there is no live v4 state to preserve; but
mainnet still crosses v3→v4 live when v4 ships, and both keys are on
chain for every validator, so any boundary mapping is constructible.

Today: `pub type AuthorityName = AuthorityPublicKeyBytes` — the BLS key,
a `Copy` `[u8; 48]` newtype (`crates/ika-types/src/crypto.rs:66`, `:141`,
`:154`). The Ed25519 consensus key (`NetworkPublicKey`, 32 bytes) already
exists separately per validator (committee.rs:459;
`epoch_start_system` `consensus_pubkey`).

## Design decision: keep the fixed-size container; gate the *value*

**Keep `AuthorityName = AuthorityPublicKeyBytes` (the 48-byte container).
Under v4 it HOLDS the Ed25519 consensus key (32 bytes, zero-padded to
48).** A runtime protocol flag cannot change a compile-time type, and one
binary must speak both v3 (BLS-name) and v4 (Ed25519-name) during the
rolling upgrade — a 48-byte container holds either and keeps the BCS wire
format byte-identical (so the ~268 map-key sites, which treat the bytes
as opaque identity, and all persisted/serialized names, are untouched).

Alternatives considered and rejected:
- **`AuthorityName = Vec<u8>`** (size-honest, BCS-variable-length): loses
  `Copy`. `AuthorityName` is a `Copy` identity used by-value across
  hundreds of sites and as a hash-map key on consensus/MPC hot paths;
  `Vec<u8>` forces `.clone()` everywhere + a heap allocation per name, and
  changes the BCS encoding for everyone (fixed 48 raw bytes →
  ULEB-length-prefixed), breaking reads of v3-persisted data. Too costly.
- **`enum { Bls([u8;48]), Consensus([u8;32]) }`** (stays `Copy`,
  size-honest): also changes the BCS wire format (adds a variant tag) and
  forces match-on-variant churn at every byte-access site.
- **New 32-byte type:** cleanest end state, but not runtime-gatable (the
  type is fixed at compile time) and breaks deserialization of
  v3-persisted 48-byte names.

Encoding under v4: store the 32 Ed25519 bytes canonically (first 32 bytes
= key, last 16 = zero), enforced at construction so equality/hashing are
consistent. The Ed25519 key is then recoverable from the name (take the
first 32 bytes) — symmetric to how v3 recovers the BLS key from the name.

## Risk map (where the BLS→Ed25519 basis is load-bearing)

The 395 references are mostly noise — `AuthorityName` is used as opaque
identity (map keys, message fields) almost everywhere, and those don't
care about the basis. The few places that DO:

### Consensus messages — basis-agnostic, NOT a problem
Each consensus message carries a self-declared `authority: AuthorityName`
(messages_consensus.rs:260). It is authenticated by checking that name
equals `committee.authority_by_index(block_author)` (committee.rs:203) — a
**positional** lookup into `voting_rights`; there is no payload signature
to check, because the consensus layer already authenticated the block
author via the **Ed25519 consensus key** (authority_per_epoch_store.rs:1971).
So attribution is name-equality + index lookup; it works identically
whether the name is BLS or Ed25519. Making the name the consensus key
makes this *more* aligned, not less.

### The actual break: BLS aggregate-signature verification
The one place `AuthorityName` is consumed AS a BLS key. The decode is
`TryFrom<AuthorityPublicKeyBytes> for AuthorityPublicKey`
(crypto.rs:218), funneled through:
- `Committee::load_inner` builds `expanded_keys: AuthorityName -> BLS pubkey`
  by decoding each name (committee.rs:179-189),
- `Committee::public_key()` reads it (committee.rs:211),
- aggregate cert verification pushes `committee.public_key(authority)`
  into the BLS `batch_verify` (crypto.rs:462 and :657) — checkpoint /
  strong-quorum certs.

Ed25519 bytes can't decode to a BLS key, so this is what breaks. `bls_checkpoints`
is ON at v4, so BLS aggregate verification MUST keep working.
**Fix (contained):** under v4, populate `expanded_keys` from a *separate*
`AuthorityName -> BLS pubkey` map supplied by the on-chain read (which has
both keys), instead of decoding the name. Every `public_key()` call site
then works unchanged.

### Name derivation from chain
`read_bls_committee` (system_inner_v1.rs:~235) and
`epoch_start_system::authority_name` (epoch_start_system.rs:166) derive
the name from the BLS protocol pubkey. Under v4, derive it from the
consensus key and populate the separate BLS map alongside.

### Direct decode site
`crypto.rs:326` (`AuthorityPublicKey::try_from(author)`) decodes a name to
BLS in a verification path — route it through the committee BLS map under
v4 (or gate it).

### Proof-of-possession — unchanged
BLS-signed, validated on chain (crypto.rs:74-107); it binds the Sui
address to the BLS key and is independent of the name basis. Stays BLS.

### Ordering — LOW risk under protocol gating; one rule
Positional invariants depend on `voting_rights` order matching the
consensus `AuthorityIndex` order: the consensus attribution above AND the
MPC party-id derivation (`authority_index` into `voting_rights`). **Because
the change is protocol-config-gated, every v4 validator derives the name
identically, so ordering cannot diverge *between* validators.** And the
basis change does not reorder `voting_rights` by itself — its order is
on-chain position (read_bls_committee iterates the on-chain committee),
not a sort on the name. The single rule: **do not introduce a
name-derived sort of `voting_rights`** (it would stay consistent across
validators but could desync from the consensus `AuthorityIndex` order).
Audit `CommitteeWithNetworkMetadata` (committee.rs:475), which holds a
`BTreeMap<AuthorityName, …>` (name-sorted) — confirm nothing derives
consensus/party ordering from it; it should be network-metadata lookup
only.

## Implementation outline

1. Protocol flag `consensus_key_authority_name` (name TBD) in
   `crates/ika-protocol-config/src/lib.rs`, set true at version 4
   (alongside the existing v4 flags).
2. Committee carries an explicit `AuthorityName -> BLS pubkey` map. Under
   v4, `load_inner`/construction populates `expanded_keys` from it instead
   of decoding the name. Plumb the BLS keys in from the on-chain read.
3. `read_bls_committee` / `epoch_start_system::authority_name`: derive the
   name from the consensus key under v4; supply the BLS map.
4. Gate the direct decode (crypto.rs:326) and any other
   `AuthorityPublicKey::try_from(name)` sites found in the audit.
5. Leave proof-of-possession, map-key uses, and consensus message
   attribution untouched.

Audit before coding: grep every `AuthorityPublicKey::try_from` /
`::from_bytes` applied to a name, and every place that assumes the name's
48-byte BLS shape, and confirm each is either gated or basis-agnostic.

## Direction: first step toward consensus-key-signed certs

This change is **step 1 of an arc** that ends with checkpoint / quorum
certs signed by each validator's consensus Ed25519 key — a per-signer
list, exactly like the handoff cert already does — instead of a BLS
aggregate signature, and eventually dropping the BLS protocol key.

What that means for THIS step:
- It does the **identity** change only: `AuthorityName` becomes the
  consensus key, gated at v4. Current BLS aggregate certs keep working.
- The committee's separate `AuthorityName -> BLS pubkey` map (the
  contained fix above) is a **deliberate temporary bridge** — it lets the
  identity move to the consensus key while existing BLS certs keep
  verifying. The follow-up cert migration removes the BLS path (and the
  map) for the cert types it migrates.
- Design accordingly: don't entrench *new* BLS-from-name assumptions, and
  keep all cert verification flowing through `committee.public_key()`
  (already the case) so swapping it for per-signer Ed25519 verification
  later stays localized.

Sequencing note (not a blocker): the cert migration does **not** strictly
depend on this identity change — the handoff already produces
consensus-key-signed certs while `AuthorityName` is still BLS
(`handoff_cert.rs`; signatures use the Ed25519 consensus key). So the two
are loosely coupled. Changing `AuthorityName` first is an alignment /
simplification step (identity == the key that signs), worthwhile mainly
because the end state drops BLS entirely; the cert migration could also
proceed in parallel.

## Test plan

- Unit: committee construction under the flag (BLS map populated; name =
  consensus key); `public_key()` returns the right BLS key under v4.
- Cluster: a v4 network boots, reconfigures, and signs (checkpoint BLS
  certs verify) with consensus-key names; the `protocol_version_transition`
  v3→v4 path still advances.

## Foundation review: refinements (after the inert foundation landed)

An adversarial review of the inert foundation (the protocol flag + the
committee BLS-map plumbing) confirmed the foundation is correct and
validated several risk-map claims, and corrected/expanded the
next-step site list.

Validated:
- Grace-rounds version-gating is safe — every read of
  `end_of_publish_grace_rounds` / `mpc_data_freeze_grace_rounds` is
  reachable only at v4 (the four sites in the EOP-close / freeze blocks).
- `new_with_protocol_keys` is inert (zero callers); `index_map` is
  identical across both `load_inner` paths.
- `expanded_keys` IS serialized (no `#[serde(skip)]`, no custom
  `Deserialize`), so the explicit BLS map survives serialization
  round-trips — no v4 deserialize-rebuild hazard.
- Consensus message attribution is positional (`authority_by_index`),
  name-agnostic; `voting_rights` and the consensus committee share
  on-chain order; `CommitteeWithNetworkMetadata` is not used for
  ordering. Handoff / joiner signature verification already uses Ed25519
  consensus keys via a name-keyed `ConsensusPubkeyProvider` (the
  v4-correct pattern).
- `staking.rs` `from_bytes` decodes the genuine BLS field, not the name.

Correction to step 3 — `read_bls_committee` has NO consensus key.
`read_bls_committee` (system_inner_v1.rs:260) iterates
`bls_committee.members`, which carry `validator_id` + `protocol_pubkey`
(BLS) only — the consensus Ed25519 key is NOT in `BlsCommittee`. So the
consensus-key name CANNOT be derived there. The consensus key IS
available one level up at `EpochStartValidatorInfoV1` (it has both
`protocol_pubkey` and `consensus_pubkey`), so under v4 the name must be
derived at the `epoch_start_system` level (which also builds the BLS map
for `new_with_protocol_keys`), and `read_bls_committee` must either be
fed the consensus key (a `validator_id -> consensus_pubkey` lookup) or be
bypassed for committee construction under v4.

Additional sites the next step must gate (beyond the original risk map):
- `EpochStartValidatorInfoV1::authority_name()` (epoch_start_system.rs:369)
  is a NO-ARG trait method — it structurally can't see the protocol
  version, so the flag/version must be threaded into the name-derivation
  path (or the basis decided by a caller that has it).
- `NodeConfig::protocol_public_key()` (ika-config/src/node.rs:379, used at
  ika-node/src/lib.rs:441/494/1472/1528/2968) defines the node's OWN
  `AuthorityName` at startup as its BLS key — must flip under v4.
- `get_consensus_committee` (epoch_start_system.rs:245) builds the
  Mysticeti committee assuming `name == protocol_pubkey`; under v4 that
  equality breaks (would log an error every epoch) — gate it.
- `IkaAuthoritySignature::verify_secure` → `AuthorityPublicKey::try_from(author)`
  (crypto.rs:326) is a second name→BLS decode path; it has no production
  caller today, but gate or remove it so it can't be reached with a
  consensus-key name.
- The single decode primitive every name→BLS site funnels through is
  `TryFrom<AuthorityPublicKeyBytes> for AuthorityPublicKey` (crypto.rs:218);
  it is only safe when fed real BLS bytes.

## read_bls_committee path (the remaining flip)

`read_bls_committee` (system_inner_v1.rs:260) is sync and operates on a
`BlsCommittee`, whose members carry only `validator_id` + BLS
`protocol_pubkey` — no consensus key. The consensus key per `validator_id`
is fetched from chain via `SuiClient::get_validators_info_by_ids`
(async; each result has `consensus_pubkey`). The model already exists:
`pubkey_provider_updater::fetch_previous_committee_consensus_pubkeys`.

So the flip lives in the (async) callers, not in sync
`read_bls_committee`:
- `sui_syncer` builds the next-epoch committee at `read_bls_committee`
  (:364) and constructs `Committee` at :555 (off-chain assembly) and :700
  (chain path). Under v4: fetch `validator_id -> consensus_pubkey` for the
  `BlsCommittee` members, derive consensus-key names
  (`authority_name_from_consensus_key`), build the `name -> BLS pubkey`
  map (BLS = the member's `protocol_pubkey`), and construct via
  `Committee::new_with_protocol_keys`.
- `pubkey_provider_updater::fetch_previous_committee` (:128) already has
  the consensus-key fetch available; derive consensus-key names + the BLS
  map and use `new_with_protocol_keys` (it currently `Committee::new`s
  with empty crypto maps for handoff-cert verification).

A shared async helper `(bls_committee, sui_client, consensus_key_identity)
-> (voting_rights, Option<protocol_keys>)` keeps the two callers
consistent (BLS names + `None` under v3; consensus-key names + the map
under v4).

## Status: flip complete (all name-minting sites)

Every live site that mints or consumes `AuthorityName` now threads the
`consensus_key_authority_name` flag:

- `epoch_start_system` committee/peer/hostname builders + the
  consensus-order check; `EpochStartValidatorInfoTrait::authority_name`
  branches on the flag.
- `node.rs::authority_name` and every `ika-node` self-identity site
  (epoch-store name, network identity, both checkpoint submitters, p2p
  self-exclusion) use `config.authority_name(flag)`.
- `dwallet_mpc_service::verify_validator_keys`.
- `pubkey_provider_updater`: `refresh` + `fetch_previous_committee_consensus_pubkeys`
  (provider maps) via a shared `validator_authority_name` helper;
  `fetch_previous_committee` (handoff-cert committee) via a v4 branch with
  `Committee::new_with_protocol_keys`.
- `sui_syncer`: `rekey_committee_by_consensus` re-keys the next-epoch
  committee by consensus key (fetching validator infos in committee order,
  length-checked) and threads the BLS map into both committee-build sites.
- `ika-test-cluster::JoinerHandle::authority_name` takes the flag; the
  joiner test derives it from the live committee's protocol config.

Intentionally left BLS (not wedges): `lib.rs` startup log (cosmetic, flag
unavailable there); `VerifiedValidatorInfo::ika_pubkey_bytes` (no callers,
dead); `crypto.rs::verify_secure` decode (no production caller).

### Validation: genesis runs at v4

`InitiationParameters::default_protocol_version() == ProtocolVersion::MAX
== 4`, so a fresh cluster genesis at protocol version 4 — every default
cluster/integration test already exercises `consensus_key_authority_name
== true` end-to-end (reconfiguration, handoff-cert verification, off-chain
committee assembly, joiner freeze). No v4-specific test is needed; the
existing cluster suite IS the v4 validation, and this completed flip is the
first point where it is internally consistent enough to pass.

Build/lint/unit all green: full workspace `cargo build --release`, clippy
on the touched crates (no new warnings), `ika-protocol-config` snapshots,
`ika-types` unit tests. Cluster-suite validation pending.

## SUPERSEDED — the flip wedged the v3→v4 upgrade; redesign below

Everything above describes the *flip* approach (make `AuthorityName` BE the
consensus key at v4). The full cluster suite found it wedges the rolling
v3→v4 upgrade: `test_protocol_version_gradual_upgrade_v3_to_v4` was the only
failure (14/15 passed). When the protocol version crosses to v4 the name's
basis flips BLS→consensus *mid-upgrade*, and the two committee builders
disagree:

- producing side (`sui_syncer`) keys the next committee's basis on the
  CURRENT epoch's version — epoch N is v3 → BLS names for the epoch-N+1
  committee;
- consuming side (`get_ika_committee`) keys on the epoch's OWN version —
  epoch N+1 is v4 → consensus names.

So the epoch-N+1 committee assembled in epoch N doesn't match the one epoch
N+1 builds for itself, and reconfiguration into the new epoch can't converge.
The naive fix (assemble with `next_protocol_version`) doesn't work either:
`next_protocol_version` is only visible on-chain *after* the off-chain
mpc-data freeze pins the committee, so the producing side can't look ahead.

### Redesign: consensus keys are Committee *data*, not the identity

`AuthorityName` stays the stable BLS-derived label — it never flips, so there
is no cross-boundary disagreement to begin with. The consensus key rides along
as committee data:

- `Committee` carries a `consensus_keys` (`AuthorityName -> Ed25519`) map
  alongside `expanded_keys` (the BLS map, still decoded from the name), with a
  `consensus_key()` accessor and `impl ConsensusPubkeyProvider for Committee`.
  `new()` takes the map; `new_with_protocol_keys` is gone.
- Build sites populate it: `get_ika_committee` and `sui_syncer` from validator
  info, `fetch_previous_committee` from chain.
- Handoff verification reads consensus keys from the relevant `Committee` (the
  epoch store's current committee for live signatures; the chain-read prior
  committee for joiner bootstrap). The async `ConsensusPubkeyProvider` side
  channel — epoch-store field, `install_consensus_pubkey_provider`, the
  active-committee `PubkeyProviderUpdater`, and its restart race — is removed.
  The `JoinerPubkeyProvider` updater stays (joiners aren't committee members
  yet, so their keys can't come from a committee).
- The `consensus_key_authority_name` protocol flag and the consensus-key name
  codec are removed.

This is ~500 fewer lines than the flip and has no transition wedge. It does
NOT migrate the identity off BLS — `AuthorityName` is still BLS-derived — so
dropping the BLS key entirely is a separate future step (TODO left on
`Committee::expanded_keys`/`public_key()`). For the stated goal
(consensus-key-signed certs) the key only needs to be *reachable by name*,
which it now is.

Validated: `test_swarm_reaches_epoch_2` (steady-state v4 reconfig) passes;
76 handoff/freeze unit tests + committee/handoff units + snapshots green;
full workspace builds, no new clippy. Local cluster tests are ~9 min per
single reconfiguration, so the v3→v4 transition is validated on CI.

### One regression found and fixed: the assembled-committee consensus-key fetch

The first CI run wedged `test_protocol_version_gradual_upgrade_v3_to_v4`
(14/15 passed; it passes on `dev` in 432s, so the wedge was a regression, not
the AuthorityName change). Cause: to populate `consensus_keys` on the
*sui_syncer-assembled next committee*, the assembly fetched each member's
consensus key from chain every tick. But that committee feeds only the
reconfiguration MPC input (`session_input_from_request`), which never reads
consensus keys — so the fetch was dead data, and its `continue`-on-error
blocked the next-committee send during the upgrade's validator restarts
(`get_validators_info_by_ids` / the length-check transiently fail mid-restart)
→ reconfiguration wedged. Fix: drop the fetch, pass an empty map to the
assembled committee. Only the committees that actually verify consensus-key
signatures — `get_ika_committee` (active) and `fetch_previous_committee`
(prior) — populate `consensus_keys`. Transition test then passes (418s).

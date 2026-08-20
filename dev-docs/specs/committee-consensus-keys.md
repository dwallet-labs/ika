# Committee consensus keys

Status: active and unconditional. **`AuthorityName` IS the validator's
Ed25519 consensus key, emitted as raw 32 bytes.** `MIN_PROTOCOL_VERSION`
and `MAX_PROTOCOL_VERSION` are both 7, so no supported version chooses a
different identity basis or a different encoding width, and the code that
used to switch between them has been deleted rather than disabled.
The design record — including the first, reverted identity-flip attempt
and why it failed — is
[`../plans/authority-name-consensus-key.md`](../plans/authority-name-consensus-key.md).

A validator has **two** long-lived public keys with different jobs:

| Key | Type | Role |
|---|---|---|
| BLS (`AuthorityPublicKey`) | aggregatable | aggregate stake certificates (BLS checkpoints) verify against it. It is NOT the validator's identity, and is not recoverable from one |
| consensus (`NetworkPublicKey`, Ed25519) | not aggregatable | signs **individually-signed** messages (handoff attestation signatures today), and IS the validator's identity — `AuthorityName` is its raw 32 bytes |

So a signer identifies itself by its consensus key, and an Ed25519
signature verifies against that same key. The direction that does not work
is the BLS one: **a name cannot recover the BLS key** — they are
independent keypairs. That map has to be carried as data, and this spec is
the contract for where each map comes from, who may trust it, and what
happens when one is missing.

## The decision rule

**`Committee` carries both mappings.** A name is the consensus key, so
the consensus-key map is nearly an identity; the BLS map is the one that
must come from chain. `Committee::new_with_protocol_keys` carries it, and
that is now a **type-level** guarantee rather than an audited one: a
committee built through plain `Committee::new` has an EMPTY
`expanded_keys` and fails closed at `public_key()`. `Committee::load_inner`
performs no name-decode at all — it returns an empty BLS map
unconditionally, because no BLS key can be derived from an Ed25519 name.
A committee that must verify BLS aggregate certificates therefore has to
be built through `new_with_protocol_keys`; there is no longer a
half-populated middle state to audit for.

**Identity-basis rule.** A committee's names are always derived from the
consensus key, at every supported version. The basis used to be decided
per epoch from its protocol version, and that activation boundary carried
a KNOWN LIMITATION: the next-epoch committee is assembled mid-epoch under
the CURRENT epoch's version, while the next epoch rebuilds it under its
OWN, so at the single activation boundary the two disagreed — the
asymmetry that wedged the first flip attempt. That boundary is now behind
every supported version, and the mitigations that straddled it —
dual-basis membership matching, the alternate next-committee pubkey set
offered to cert verification, and the per-basis prior-committee candidate
list — are gone. `EpochStartSystem::V2` still RECORDS the basis because
the field is part of a persisted BCS shape; nothing reads it. **The same
asymmetry governs any FUTURE change to the identity basis** — it would
have to ride a protocol version and would reintroduce exactly this
boundary.

Two known gaps remain, both about consensus-key ROTATION rather than the
basis flip, which is finished:

1. **The cert-hash straddle across a consensus-key rotation — OPEN, and the
   one with fleet-wide blast radius.** A consensus
   key is NOT fixed at registration — `set_next_epoch_consensus_pubkey_bytes`
   is operator-callable and `rotate_next_epoch_info` effectuates it at
   `advance_epoch`. `next_committee_pubkey_set_hash` is therefore computed
   during epoch E from PRE-effectuation keys and re-verified in E+1 against
   POST-effectuation keys, so one rotation changes the digest and every node
   fail-closed halts. Per-epoch read freshness cannot fix this: the producer
   is structurally before the boundary and the consumer after. The agreed
   resolution is to hash the committee's VALIDATOR IDs rather than its
   names, which removes rotation from the hash's sensitivity permanently.
   Mitigated for now by `verify_joiner_bootstrap_cert` treating the
   next-committee hash as ADVISORY — a stake quorum of valid prior-committee
   signatures accepts the cert regardless — so a rotation logs a warn rather
   than halting; but treat consensus-key rotation as an operational hazard,
   not a routine action.

2. **Prior-epoch artifacts are keyed by the rotating member's old identity**
   — ACCEPTED DEGRADATION, deliberately not fixed. Because the name IS the
   consensus key, rotating that key changes the member's identity outright:
   the prior epoch's handoff cert names it under the key it held then, and
   nothing in the new epoch resolves that name to the same validator.
   Consequences, all confined to that one member for one epoch:
   its `ValidatorMpcData` carry-forward misses and it lands in
   `epoch_excluded_validators` (only if it also did not freshly announce
   that epoch); prior-cert key ingest misses, leaving it MPC-dead for the
   epoch if it also restarted mid-epoch; and its prior-cert blob repair
   silently no-ops. This is a per-member degradation that quorum absorbs —
   rotation is not a fleet-wide simultaneous action, and handoff certs carry
   more signatures than quorum.

   **For on-call:** a freeze-laggard or excluded-validator alert naming a
   validator that rotated its consensus key at the preceding boundary is
   THIS, not an incident. It self-heals the following epoch, when the member
   announces under its new identity.

**Node-side naming discipline.** A node's own `AuthorityName` is
per-epoch state, never process state: it lives on
`AuthorityPerEpochStore::name` (derived by `NodeConfig::authority_name`
at boot and again at every reconfiguration), and `AuthorityState`
deliberately carries no name field. Every self-identifying value the node
emits must read the epoch store's name: the state-sync notifier decision
at boot, `ConsensusAdapter`'s own-position lookup, capability
notifications, checkpoint-signature attribution, and log fields. The BLS
protocol key is absent from the committee, so a name derived from it has
two concrete failure modes: a validator boots state-sync in pull mode as
a non-member, and a capability notification naming the BLS key is dropped
by `verify_consensus_transaction` (consensus attributes the submission
under the committee's basis), silencing the node's upgrade vote — on a
whole fleet of such names, no protocol or Move upgrade can ever pass.
The one place a BLS-derived name is still correct is a self-lookup in the
RAW validator records (`EpochStartValidatorInfoTrait::authority_name`,
used by `verify_validator_keys`), which are a different name space from
the committee identity.

**Encoding width.** `AuthorityName` serializes as the raw 32 bytes,
always. Through protocol v6 it was those bytes zero-padded into the
48-byte container the BLS protocol key occupied; v7 flipped the whole
committee to the short form at one epoch boundary. No supported version
emits the padded form any more, so the machinery that carried the choice —
a process-wide static, a thread-local override, and the cross-epoch
retry that consumed them — is **deleted**, not disabled. Do not write new
code that reasons about a width.

**Decoding stays lenient on purpose** (`LenientAuthorityName`): rows and
archives written before the v7 boundary hold the 48-byte form, and a node
must keep reading its own history. A 48-byte value whose tail is NOT zero
is a pre-v6 BLS-basis name; it has no consensus-key representation, so it
is REJECTED rather than silently truncated. Nothing live decodes such a
record, and failing loudly is what keeps a truncated, wrong-identity name
out of a committee.

**Why that flip needed a protocol version, which is the part worth
keeping.** Tolerant decoding was necessary but never sufficient. Signature
and digest bytes are reconstructed by RE-SERIALIZING locally:
`verify_handoff_signature` rebuilds the signed payload from its own decoded
copy, and `hash_next_committee_pubkey_set` BCS-encodes a
`Vec<AuthorityName>` before hashing. `AuthorityName` is also a field of
`AuthorityCapabilitiesV1`, of ten MPC consensus messages, and of
`HandoffItemKey`. Two validators emitting different widths therefore
compute different digests for the same committee and reject each other's
signatures while parsing each other's messages perfectly. What a version
gate buys is not readability but **simultaneous emission** — the whole
committee flipping together. Any future change to a wire encoding must ride
a protocol version for the same reason; a per-binary switch splits the
network.

```rust
// ika-types/src/committee.rs
expanded_keys:  HashMap<AuthorityName, AuthorityPublicKey>,  // BLS
consensus_keys: HashMap<AuthorityName, NetworkPublicKey>,    // Ed25519
```

A committee is the natural home because verification is *always* relative
to a committee: "did a quorum of epoch N's members sign this?" needs
membership, stake, the quorum threshold, and each member's verifying key —
four facts that must describe the *same* snapshot. Splitting the keys into
a side channel invites verifying a signature against one epoch's key while
counting stake from another's.

That is expressed directly:

```rust
// ika-core/src/handoff_cert.rs
impl ConsensusPubkeyProvider for Committee {
    fn consensus_pubkey(&self, signer: &AuthorityName) -> Option<Ed25519PublicKey>
}
```

`ConsensusPubkeyProvider` returning `None` means **"I have no consensus key
for this signer"**, and every caller must then **drop the signature**
(`HandoffSignatureVerdict::UnknownSigner`). An unknown signer is never
treated as valid and never fails the whole verification — it simply does
not count toward quorum.

## Invariants

1. **The mapping is chain-sourced, never derived.** `consensus_keys` is
   supplied at construction from on-chain validator metadata. No code path
   may synthesize, guess, or default a consensus key for a member.

2. **Key and stake come from the same snapshot.** When building a committee
   for verification, the map KEY must be the `AuthorityName` from *that
   epoch's* committee snapshot. The consensus pubkey VALUE is fixed at
   validator registration, so reading the current on-chain value is
   correct — but the name it is filed under is not, because names are
   per-snapshot. Getting this backwards produces a weight-0 signer whose
   signature silently fails to count.

3. **A missing key costs one signature, never the read.** A member whose
   `validator_info` fails to decode is skipped with a warning, not
   propagated as an error. `verify()` rejects on ANY malformed metadata
   field (addresses, next-epoch keys), and a departed member may have a
   stale record nobody can fix; failing the whole fetch would block joiner
   bootstrap forever on a deterministic error. The certificate only needs a
   quorum of members that DO verify.

4. **An empty map is legal, and only for committees that never verify.**
   Test committees, legacy committees, and stake-only aggregation paths may
   carry an empty map. It is a bug for a committee that will verify
   individually-signed messages to carry one — every signer resolves to
   `None`, every signature drops, and the certificate fails quorum. The
   failure is fail-closed but far from its cause, so treat "cert never
   forms" as a signal to check this map first.

## Where committees are built

Two sites populate `consensus_keys`, both from chain:

- **`EpochStartSystem::get_ika_committee`** (`ika-types/src/sui/epoch_start_system.rs`)
  — the current epoch's committee, from each active validator's
  `consensus_pubkey`. This is the CHAIN view; see the two-committee-objects
  warning in [`../learnings/pitfalls.md`](../learnings/pitfalls.md).
- **The prior-committee fetch** (`sui_connector/pubkey_provider_updater.rs`)
  — reconstructs the *previous* committee for handoff-certificate
  verification, reading each member's
  `StakingPool.validator_info.consensus_pubkey_bytes` and filing it under
  the name from the `previous_committee` snapshot (invariant 2). Members
  absent from that snapshot, or whose `validator_info` fails `verify()`,
  are skipped (invariant 3).

`SuiSyncer::new_committee` (the next-epoch committee assembled for the
reconfiguration MPC input) deliberately carries an EMPTY map: that
committee never verifies consensus-key-signed messages (invariant 4) —
handoff verification uses the epoch store's `get_ika_committee` committee.

`StaticConsensusPubkeyProvider` exists for tests and as the empty default
before the syncer is up. It is not a production source.

## On-disk compatibility

`consensus_keys` was added mid-struct at protocol v4, and `Committee`
derives bcs (positional, no field skips). A `committee_map` record written
by mainnet-v1.1.8 therefore **cannot** be decoded by a v4 `Committee`.

`CommitteeStore` migrates at store open (`migrate_legacy_records`): a
record that fails the current decode but decodes as `LegacyCommittee` is
rewritten in the current layout with an **empty** `consensus_keys`. The
migration is:

- **idempotent** — already-migrated records pass the current decode and are
  skipped, so it is crash-safe;
- **marker-guarded**, with the marker written AFTER the scan completes, so
  a crash mid-migration re-scans rather than stranding unmigrated rows
  behind the marker;
- **generation-tracked** — the 1.1.8 layout is generation 1, the current
  layout generation 2.

The empty map is sound only because a legacy record always DESCRIBES a ≤v3
epoch, for which no handoff certificate can exist (cert minting is
v4-gated), so those keys are never asked to verify anything. That relies on
a three-link chain spelled out in
[`cross-binary-upgrade.md`](cross-binary-upgrade.md) (1.1.8 caps at
`MAX_PROTOCOL_VERSION = 3`; its `reconfigure` checks the version before
persisting a committee; the state-sync `insert_committee` path has no live
callers). **If a future change breaks any link, re-verify this before
reusing the legacy migration for anything else** — a pre-`consensus_keys`
record describing a cert-minting epoch would make every signer unresolvable
and fail quorum.

**Rollback is one-way.** A `committee_map` record written by a v4 binary is
NOT readable by mainnet-v1.1.8 (same positional-bcs reason; 1.1.8 has no
fallback). Rolling back requires clearing the `committee_map` column
family — see the rollback caveat in
[`cross-binary-upgrade.md`](cross-binary-upgrade.md).

`LegacyCommittee` and this migration are deletable together once no fleet
upgrades directly from 1.1.8 data dirs.

## Direction of travel

The identity flip is done. What remains is the BLS key itself, which
survives only because aggregate stake certificates need aggregatability.
Once those are replaced by consensus-key-signed certificates,
`expanded_keys` / `public_key()` and the validators' BLS key can be
dropped entirely — the `TODO(consensus-key-certs)` on the field in
`ika-types/src/committee.rs` marks the spot. Until then, **both keys are
load-bearing and neither may be treated as derivable from the other.**

Consumer today: [`handoff.md`](handoff.md) (attestation signatures and
certificate verification).

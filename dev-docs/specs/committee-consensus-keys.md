# Committee consensus keys

Status: active and unconditional. The identity basis flipped at protocol v6,
which is LIVE on mainnet and testnet; with `MIN_PROTOCOL_VERSION = 6` the
`AuthorityName` IS the consensus key at every supported version and no
version-gated basis choice remains in the code.
Landed 2026-07-01, PR #1762. The design record — including the first,
reverted identity-flip attempt and why it failed — is
[`../plans/authority-name-consensus-key.md`](../plans/authority-name-consensus-key.md).

A validator has **two** long-lived public keys with different jobs:

| Key | Type | Role |
|---|---|---|
| BLS (`AuthorityPublicKey`) | aggregatable | aggregate stake certificates (BLS checkpoints) verify against it; below protocol v6 it was ALSO the validator's identity (`AuthorityName` was its byte encoding) |
| consensus (`NetworkPublicKey`, Ed25519) | not aggregatable | signs **individually-signed** messages (handoff attestation signatures today); from protocol v6 it is ALSO the validator's identity — `AuthorityName` is the 32 key bytes zero-padded to the 48-byte container |

A signer identifies itself by `AuthorityName` (BLS-derived), but an
Ed25519 signature must verify against the consensus key. **The BLS name
cannot recover the consensus key** — they are independent keypairs. So
the mapping has to be carried as data, and this spec is the contract for
where it comes from, who may trust it, and what happens when it is
missing.

## The decision rule

**`Committee` carries the mapping.** Below protocol v6 `AuthorityName` is
the BLS key; from v6 (`consensus_key_authority_names`) it is the
zero-padded consensus key, and the BLS keys are then carried explicitly
too (`Committee::new_with_protocol_keys` — a consensus-basis name cannot
be decoded into a BLS key, and BLS aggregate-certificate verification
still needs it; `Committee::load_inner`'s name-decode is lossy, failing
closed at `public_key()` instead of panicking). The lossy decode makes
the split wiring-dependent: a consensus-basis committee mis-built through
`Committee::new` carries an EMPTY `expanded_keys` with no construction
error. `public_key()` on it fails closed per lookup, and
`name_translation()` — whose callers all fall back to identity on a
missing entry, so a degraded map would silently reinstate the boundary
misses it exists to prevent — logs a `should_never_happen` error naming
every member whose BLS alias is unrecoverable. Both production
`Committee::new` sites that can carry consensus-basis names are safe by
audit, not by type: the `SuiSyncer::new_committee` committees feed only
the reconfiguration MPC input, and the prior-committee fetch
(`pubkey_provider_updater.rs`) verifies handoff certs through
`consensus_key()` only — neither reaches `public_key()` or
`name_translation()`.

**Identity-basis rule.** A committee's names are always derived from the
consensus key. The basis used to be decided per epoch from its protocol
version, and the activation boundary carried a KNOWN LIMITATION: the
next-epoch committee is assembled mid-epoch under the CURRENT epoch's
version, while the next epoch rebuilds it under its OWN, so at the single
activation boundary the two disagreed (this asymmetry is what wedged the
first flip attempt). With `MIN_PROTOCOL_VERSION = 6` that boundary is
behind every supported version and the mitigations that straddled it —
dual-basis membership matching, the alternate next-committee pubkey set
offered to cert verification, and the per-basis prior-committee candidate
list — are gone. `EpochStartSystem::V2` still RECORDS the basis, because
the field is part of the persisted BCS shape a v1.2.7 binary reads back
after a downgrade; nothing reads it. **The same asymmetry governs any
FUTURE change to the identity basis** — it would have to be gated on a
protocol version and would reintroduce exactly this boundary.

**Status: v6 is LIVE on mainnet and testnet, and is this binary's minimum.**
Two known gaps come with it, both about consensus-key ROTATION (the basis
flip itself is done):

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
   — ACCEPTED DEGRADATION, deliberately not fixed. The prior epoch's handoff
   cert names members under the keys they held then; `name_translation` is
   built from the current committee and aliases only the current consensus
   key and the BLS key, so a member that rotated at the boundary resolves to
   nothing. Consequences, all confined to that one member for one epoch:
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

**Encoding width (protocol v7).** The identity is the consensus key at every
supported version; what v7 changes is only how it is WRITTEN.
`short_authority_names` switches `AuthorityName` from the 32 key bytes
zero-padded into the 48-byte container to the raw 32 bytes.

Decoding has accepted both widths since v1.2.7 (`LenientAuthorityKeyBytes`),
so no deployed binary rejects the short form. That tolerance is necessary but
NOT sufficient, and the reason is the crux of this flip: signature and digest
bytes are reconstructed by RE-SERIALIZING locally — `verify_handoff_signature`
rebuilds the signed payload from its own decoded copy, and
`hash_next_committee_pubkey_set` BCS-encodes a `Vec<AuthorityName>` before
hashing. Two validators emitting different widths therefore compute different
digests for the same committee and reject each other's signatures, even though
each parses the other's messages perfectly. What the version gate buys is not
readability but **simultaneous emission**.

Two consequences worth knowing before touching this:

1. **The width is process-wide state** (`AUTHORITY_NAME_SHORT_ENCODING`), set
   from the protocol config when an epoch store is built. It is the only
   protocol flag in ika consumed outside its call site, because serde has no
   access to the config. A thread-scoped override exists for one purpose only
   (below); do not reach for it to paper over a width mismatch elsewhere.
2. **The handoff cert straddles the boundary.** It is signed at the end of
   epoch N under the old width and verified in N+1 under the new one, so
   `verify_certified_handoff_attestation` retries once at the other width
   before rejecting. This does not widen what is accepted — both widths encode
   the same attestation value. Anything new that verifies a re-serialized
   cross-epoch payload must do the same.

A BLS-basis name is never shortened: the short encoding applies only to values
whose trailing 16 bytes are zero, which is what keeps historical BLS-basis
committee records round-tripping unchanged.

**Why the 48-byte container is not ambiguous across bases.** A
consensus-basis name is the 32-byte Ed25519 key followed by 16 zero bytes;
a BLS-basis name is a valid BLS12-381 G1 point. For the two to collide an
attacker would need a valid G1 point whose last 16 bytes are zero AND whose
discrete log it knows — roughly 2^128 grinding past the registration
proof-of-possession. That is what makes `expanded_keys` alias translation
safe: committees persisted under BLS-basis names stay readable without
widening what is accepted.

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

The BLS key is still the identity because aggregate stake certificates
need aggregatability. The plan records the intended end state: once those
are replaced by consensus-key-signed certificates, `expanded_keys` /
`public_key()` and the validators' BLS key can be dropped entirely and
`AuthorityName` can become the consensus key. Until then, **both keys are
load-bearing and neither may be treated as derivable from the other.**

Consumer today: [`handoff.md`](handoff.md) (attestation signatures and
certificate verification).

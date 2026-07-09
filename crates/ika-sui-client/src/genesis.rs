// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Load and verify a Sui **genesis blob** as the OCS trust root.
//!
//! This replaces the operator-pinned end-of-epoch "anchor" (a recent,
//! out-of-band, weak-subjectivity digest). The genesis checkpoint digest *is*
//! the Sui chain identifier, which ika already hardcodes per chain
//! ([`ika_types::digests::get_mainnet_chain_identifier`] /
//! [`get_testnet_chain_identifier`](ika_types::digests::get_testnet_chain_identifier)).
//!
//! So the trust root shrinks to a 32-byte compiled-in constant: we load the
//! genesis blob, recompute its checkpoint digest, assert it equals the
//! compiled-in identifier for the configured chain, and only then return
//! `committee[0]`. Verify everything, trust nothing — the blob itself is
//! checked against the constant, never trusted wholesale. From `committee[0]`
//! the OCS committee ratchet walks the end-of-epoch checkpoint chain forward to
//! the live epoch (see the OCS spec).
//!
//! On localnet / private nets (`Devnet` / `Custom`) there is no canonical
//! compiled-in identifier, so the genesis blob's own digest is taken as the
//! root — the swarm/operator is responsible for supplying a trusted blob, the
//! same trust placement Sui's own nodes use for a local genesis.

use std::collections::HashMap;
use std::path::Path;

use ika_config::node::SuiChainIdentifier;
use ika_types::digests::{
    ChainIdentifier, get_mainnet_chain_identifier, get_testnet_chain_identifier,
};
use sui_config::genesis::Genesis;
use sui_types::base_types::{ObjectID, ObjectRef};
use sui_types::committee::Committee;
use sui_types::effects::TransactionEffects;
use sui_types::message_envelope::Message;
use sui_types::messages_checkpoint::CheckpointSummary;
use sui_types::object::Object;
use sui_types::sui_system_state::get_sui_system_state;

/// Error loading or verifying a Sui genesis blob.
#[derive(Debug, thiserror::Error)]
pub enum GenesisError {
    #[error("failed to load Sui genesis blob from {path}: {source}")]
    Load {
        path: String,
        #[source]
        source: anyhow::Error,
    },
    #[error("failed to decode embedded Sui genesis blob: {0}")]
    Decode(#[source] anyhow::Error),
    #[error(
        "Sui genesis chain identifier mismatch for {chain}: blob's genesis \
         checkpoint digest is {got}, but the binary's compiled-in identifier \
         for this chain is {expected} — wrong genesis blob for this chain"
    )]
    ChainMismatch {
        chain: SuiChainIdentifier,
        got: String,
        expected: String,
    },
    #[error(
        "Sui genesis blob is internally inconsistent — committee[0] is not \
         committed by the verified genesis checkpoint digest: {detail}"
    )]
    InconsistentBlob { detail: String },
}

/// The verified bootstrap material extracted from a Sui genesis blob: the
/// epoch-0 committee and the (verified) chain identifier.
#[derive(Clone, Debug)]
pub struct SuiGenesisBootstrap {
    /// `committee[0]` — the genesis Sui committee the OCS ratchet starts from.
    pub committee: Committee,
    /// The genesis checkpoint digest, i.e. the Sui chain identifier this blob
    /// belongs to. For `Mainnet`/`Testnet` this has been verified to equal the
    /// compiled-in constant; for `Devnet`/`Custom` it is the blob's own digest.
    pub chain_identifier: ChainIdentifier,
}

/// Load a Sui genesis blob from `path` and verify it against the compiled-in
/// chain identifier for `chain`.
pub fn load_and_verify_sui_genesis(
    path: impl AsRef<Path>,
    chain: SuiChainIdentifier,
) -> Result<SuiGenesisBootstrap, GenesisError> {
    let path = path.as_ref();
    let genesis = Genesis::load(path).map_err(|source| GenesisError::Load {
        path: path.display().to_string(),
        source,
    })?;
    verify_genesis(genesis, chain)
}

/// Decode a Sui genesis blob from in-memory bytes (e.g. release-embedded via
/// `include_bytes!`) and verify it against the compiled-in chain identifier.
pub fn load_and_verify_sui_genesis_bytes(
    bytes: &[u8],
    chain: SuiChainIdentifier,
) -> Result<SuiGenesisBootstrap, GenesisError> {
    let genesis: Genesis = bcs::from_bytes(bytes).map_err(|e| GenesisError::Decode(e.into()))?;
    verify_genesis(genesis, chain)
}

fn verify_genesis(
    genesis: Genesis,
    chain: SuiChainIdentifier,
) -> Result<SuiGenesisBootstrap, GenesisError> {
    // Fail closed with an error before touching the panicking accessors.
    // `Genesis::{checkpoint, committee}` both `.expect()`/`.unwrap()` on a
    // structurally-decodable-but-inconsistent blob, and the binary aborts on
    // panic (`panic = "abort"`), so a bad blob would crash the node with a
    // backtrace instead of a diagnosable error. Sui (an upstream pin) exposes
    // no non-panicking accessor, so guard the reachable source — a missing or
    // unreadable system-state object, which is where `committee()` panics.
    // (A blob that additionally carries an invalid checkpoint *signature* still
    // aborts inside `checkpoint()`; there is no way to verify that over the
    // upstream API without the raw certificate. It is fail-closed either way.)
    require_readable_system_state(genesis.objects())?;

    // The genesis checkpoint digest IS the chain identifier.
    let checkpoint = genesis.checkpoint();
    let summary = checkpoint.data();
    let genesis_digest = summary.digest();
    let chain_identifier = ChainIdentifier::from(ObjectID::new(genesis_digest.into_inner()));

    // Verify the blob against the binary's compiled-in 32-byte root for the
    // public chains. A swapped/forged summary is caught here.
    if let Some(expected) = compiled_in_chain_identifier(chain)
        && chain_identifier != expected
    {
        return Err(GenesisError::ChainMismatch {
            chain,
            got: chain_identifier.base58_encode(),
            expected: expected.base58_encode(),
        });
    }

    // Bind committee[0] to that verified digest. The check above only pins the
    // checkpoint *summary*; the committee is read from the blob's system-state
    // object, which the summary does not itself contain. Without re-tying that
    // object back to the summary, an attacker could pair the real genesis
    // summary (so the digest matches the compiled-in constant) with a forged
    // validator set — plus a checkpoint cert re-signed by that forged committee
    // — and we would hand back a forged committee[0], forging the whole OCS
    // trust chain. Re-establish the summary -> contents -> effects -> objects
    // hash chain so committee[0] is committed by the same 32 bytes.
    verify_committee_binding(&genesis, summary)?;

    Ok(SuiGenesisBootstrap {
        committee: genesis.committee(),
        chain_identifier,
    })
}

/// Fail closed if the genesis blob has no readable Sui system-state object.
/// `Genesis::committee()` (and `checkpoint()`, which reads the committee to
/// verify the cert) `.expect()` on it, so checking it first turns the common
/// corrupt-blob abort into a returnable [`GenesisError`].
fn require_readable_system_state(objects: &[Object]) -> Result<(), GenesisError> {
    get_sui_system_state(&objects)
        .map(|_| ())
        .map_err(|source| GenesisError::InconsistentBlob {
            detail: format!("system-state object is missing or unreadable: {source}"),
        })
}

/// Re-establish the hash chain from the (digest-verified) genesis checkpoint
/// summary down to every genesis object, so the committee read from the genesis
/// system-state object is committed by the summary digest — i.e. by the
/// compiled-in chain identifier — rather than merely present in an unverified
/// field of the blob. Mirrors Sui's light-client verifier: verify the contents
/// against the summary, the transaction effects against the contents, then each
/// object against those effects.
fn verify_committee_binding(
    genesis: &Genesis,
    summary: &CheckpointSummary,
) -> Result<(), GenesisError> {
    // summary -> checkpoint contents
    let contents = genesis.checkpoint_contents();
    if summary.content_digest != *contents.digest() {
        return Err(GenesisError::InconsistentBlob {
            detail: "checkpoint contents digest does not match the summary's content_digest"
                .to_string(),
        });
    }

    // checkpoint contents -> genesis transaction effects
    let genesis_execution = genesis.effects().execution_digests();
    if !contents.iter().any(|digests| *digests == genesis_execution) {
        return Err(GenesisError::InconsistentBlob {
            detail: "the genesis transaction effects are not listed in the checkpoint contents"
                .to_string(),
        });
    }

    // genesis transaction effects -> every genesis object (so the system-state
    // object the committee is read from is one of them, bound by digest)
    verify_objects_committed_by_effects(genesis.effects(), genesis.objects())
}

/// Every object in the blob must be committed, by `ObjectRef` digest, by the
/// genesis transaction effects. This is the link that rejects a forged
/// system-state object — and thus a forged committee: the forged object's
/// digest will not match the effects the verified summary commits to.
fn verify_objects_committed_by_effects(
    effects: &TransactionEffects,
    objects: &[Object],
) -> Result<(), GenesisError> {
    let changed: HashMap<ObjectID, ObjectRef> = effects
        .all_changed_objects()
        .into_iter()
        .map(|(object_ref, _owner, _write_kind)| (object_ref.0, object_ref))
        .collect();
    for object in objects {
        let object_ref = object.compute_object_reference();
        if changed.get(&object_ref.0) != Some(&object_ref) {
            return Err(GenesisError::InconsistentBlob {
                detail: format!(
                    "genesis object {} is not committed by the verified genesis effects",
                    object_ref.0,
                ),
            });
        }
    }

    Ok(())
}

/// The binary's compiled-in Sui chain identifier (= genesis checkpoint digest)
/// for the public chains. `None` for `Devnet`/`Custom`, where the genesis
/// blob's own digest is the root.
pub fn compiled_in_chain_identifier(chain: SuiChainIdentifier) -> Option<ChainIdentifier> {
    match chain {
        SuiChainIdentifier::Mainnet => Some(get_mainnet_chain_identifier()),
        SuiChainIdentifier::Testnet => Some(get_testnet_chain_identifier()),
        SuiChainIdentifier::Devnet | SuiChainIdentifier::Custom => None,
    }
}

/// The inverse of [`compiled_in_chain_identifier`]: derive which chain a genesis
/// checkpoint digest belongs to by matching it against the compiled-in
/// mainnet/testnet identifiers. `Custom` if it matches neither (localnet /
/// private net). This is how a node learns its chain from the *verified* genesis
/// blob rather than from the operator-declared config.
pub fn chain_of_chain_identifier(id: ChainIdentifier) -> SuiChainIdentifier {
    if id == get_mainnet_chain_identifier() {
        SuiChainIdentifier::Mainnet
    } else if id == get_testnet_chain_identifier() {
        SuiChainIdentifier::Testnet
    } else {
        SuiChainIdentifier::Custom
    }
}

impl SuiGenesisBootstrap {
    /// The chain this genesis blob belongs to, derived from its verified
    /// checkpoint digest (see [`chain_of_chain_identifier`]).
    pub fn chain(&self) -> SuiChainIdentifier {
        chain_of_chain_identifier(self.chain_identifier)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sui_types::SUI_SYSTEM_STATE_OBJECT_ID;
    use sui_types::base_types::SuiAddress;
    use sui_types::messages_checkpoint::CheckpointContentsDigest;

    // A real Sui genesis blob (a local test chain, not mainnet/testnet),
    // vendored from the pinned Sui upstream's light-client test fixtures.
    const FIXTURE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/sui_genesis.blob"
    );

    #[test]
    fn loads_genesis_and_derives_chain_identifier_for_custom() {
        let boot = load_and_verify_sui_genesis(FIXTURE, SuiChainIdentifier::Custom)
            .expect("a Custom chain skips the compiled-in check, so a test genesis loads");
        assert!(
            boot.committee.num_members() > 0,
            "committee[0] must be non-empty"
        );
        assert_ne!(
            boot.chain_identifier,
            ChainIdentifier::default(),
            "the chain identifier is the genesis checkpoint digest"
        );
    }

    #[test]
    fn committee_binding_rejects_a_summary_that_does_not_commit_the_contents() {
        // The honest fixture binds (proven above). Prove the binding is not
        // vacuous: corrupt the summary so its content_digest no longer commits
        // to the checkpoint contents, and the binding must reject rather than
        // return a committee[0] that isn't tied to the verified digest. This is
        // the first link of the chain that stops a real-summary + forged-
        // committee blob from being accepted.
        let genesis = Genesis::load(FIXTURE).expect("fixture loads");
        let mut summary = genesis.checkpoint().data().clone();
        summary.content_digest = CheckpointContentsDigest::random();
        let err = verify_committee_binding(&genesis, &summary)
            .expect_err("a summary that does not commit the contents must be rejected");
        assert!(
            matches!(err, GenesisError::InconsistentBlob { .. }),
            "expected InconsistentBlob, got {err:?}"
        );
    }

    #[test]
    fn rejects_a_blob_with_no_readable_system_state_object() {
        // The panic guard: `Genesis::committee()` aborts (panic = "abort") on a
        // blob with no system-state object. Prove the guard returns a clean
        // error first — the fixture has one, a blob stripped of it does not.
        let genesis = Genesis::load(FIXTURE).expect("fixture loads");
        require_readable_system_state(genesis.objects())
            .expect("the real genesis has a readable system-state object");

        let without_system_state: Vec<Object> = genesis
            .objects()
            .iter()
            .filter(|object| object.id() != SUI_SYSTEM_STATE_OBJECT_ID)
            .cloned()
            .collect();
        let err = require_readable_system_state(&without_system_state)
            .expect_err("a blob missing its system-state object must be rejected");
        assert!(
            matches!(err, GenesisError::InconsistentBlob { .. }),
            "expected InconsistentBlob, got {err:?}"
        );
    }

    #[test]
    fn committee_binding_rejects_a_forged_system_state_object() {
        // The forged-committee attack at the object level: keep the real
        // summary/contents/effects, but swap the system-state object (id 0x5) —
        // part of the object set `committee[0]` is read from — for a forged one.
        // Its `ObjectRef` digest no longer matches the effects the verified
        // summary commits to, so the binding must reject; an attacker cannot
        // pair the real genesis digest with a committee of their choosing. (The
        // committee's inner dynamic-field object is bound by the same check.)
        let genesis = Genesis::load(FIXTURE).expect("fixture loads");

        // Sanity: the untampered object set binds cleanly, so a rejection below
        // is caused by the forgery and not by a check that rejects everything.
        verify_objects_committed_by_effects(genesis.effects(), genesis.objects())
            .expect("the real genesis objects are all committed by the effects");

        let mut objects: Vec<Object> = genesis.objects().to_vec();
        let system_state = objects
            .iter_mut()
            .find(|object| object.id() == SUI_SYSTEM_STATE_OBJECT_ID)
            .expect("a genesis blob always has a system-state object");
        *system_state =
            Object::with_id_owner_for_testing(SUI_SYSTEM_STATE_OBJECT_ID, SuiAddress::ZERO);

        let err = verify_objects_committed_by_effects(genesis.effects(), &objects)
            .expect_err("a forged system-state object must be rejected");
        assert!(
            matches!(err, GenesisError::InconsistentBlob { .. }),
            "expected InconsistentBlob, got {err:?}"
        );
    }

    #[test]
    fn rejects_genesis_whose_digest_is_not_the_compiled_in_mainnet_identifier() {
        // The test genesis is not mainnet, so verifying it against the
        // compiled-in mainnet identifier must fail closed.
        let err = load_and_verify_sui_genesis(FIXTURE, SuiChainIdentifier::Mainnet)
            .expect_err("a non-mainnet blob must be rejected against the mainnet root");
        assert!(
            matches!(err, GenesisError::ChainMismatch { .. }),
            "expected ChainMismatch, got {err:?}"
        );
    }

    #[test]
    fn bytes_and_path_loaders_agree() {
        let from_path = load_and_verify_sui_genesis(FIXTURE, SuiChainIdentifier::Custom).unwrap();
        let bytes = std::fs::read(FIXTURE).unwrap();
        let from_bytes =
            load_and_verify_sui_genesis_bytes(&bytes, SuiChainIdentifier::Custom).unwrap();
        assert_eq!(from_path.chain_identifier, from_bytes.chain_identifier);
    }

    #[test]
    fn corrupt_genesis_bytes_fail_closed() {
        // Garbage / truncated bytes must not deserialize into a Genesis — the
        // loader fails closed rather than bootstrapping from junk.
        let garbage = b"not a valid Sui genesis blob";
        let err = load_and_verify_sui_genesis_bytes(garbage, SuiChainIdentifier::Custom)
            .expect_err("garbage bytes must be rejected");
        assert!(matches!(err, GenesisError::Decode(_)), "got {err:?}");

        // A truncated prefix of a real blob is also rejected.
        let real = std::fs::read(FIXTURE).unwrap();
        let truncated = &real[..real.len() / 2];
        let err = load_and_verify_sui_genesis_bytes(truncated, SuiChainIdentifier::Custom)
            .expect_err("a truncated blob must be rejected");
        assert!(matches!(err, GenesisError::Decode(_)), "got {err:?}");
    }

    #[test]
    fn compiled_in_identifiers_map_public_chains_only() {
        assert_eq!(
            compiled_in_chain_identifier(SuiChainIdentifier::Mainnet),
            Some(get_mainnet_chain_identifier())
        );
        assert_eq!(
            compiled_in_chain_identifier(SuiChainIdentifier::Testnet),
            Some(get_testnet_chain_identifier())
        );
        assert_eq!(
            compiled_in_chain_identifier(SuiChainIdentifier::Devnet),
            None
        );
        assert_eq!(
            compiled_in_chain_identifier(SuiChainIdentifier::Custom),
            None
        );
    }

    #[test]
    fn chain_is_derived_from_the_genesis_digest() {
        // The test fixture is a local (Custom) chain, not mainnet/testnet.
        let boot = load_and_verify_sui_genesis(FIXTURE, SuiChainIdentifier::Custom).unwrap();
        assert_eq!(boot.chain(), SuiChainIdentifier::Custom);
        // The compiled-in constants map back to their chains.
        assert_eq!(
            chain_of_chain_identifier(get_mainnet_chain_identifier()),
            SuiChainIdentifier::Mainnet
        );
        assert_eq!(
            chain_of_chain_identifier(get_testnet_chain_identifier()),
            SuiChainIdentifier::Testnet
        );
    }
}

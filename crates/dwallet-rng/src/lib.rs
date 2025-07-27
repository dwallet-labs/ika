use commitment::CommitmentSizedNumber;
use fastcrypto::encoding::{Base64, Encoding};
use group::OsCsRng;
use ika_types::dwallet_mpc_error::{DwalletMPCError, DwalletMPCResult};
use merlin::Transcript;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::{RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

/// The Root Seed for this validator, used to deterministically derive purpose-specific child seeds
/// for all cryptographically-secure random generation operations.
///
/// SECURITY NOTICE: *MUST BE KEPT PRIVATE*.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct RootSeed([u8; RootSeed::SEED_LENGTH]);

impl RootSeed {
    pub const SEED_LENGTH: usize = 32;

    pub fn new(seed: [u8; Self::SEED_LENGTH]) -> Self {
        RootSeed(seed)
    }

    /// Generates a cryptographically secure random seed.
    pub fn random_seed() -> Self {
        let mut bytes = [0u8; Self::SEED_LENGTH];
        OsCsRng.fill_bytes(&mut bytes);
        RootSeed(bytes)
    }

    /// Reads a class group seed (encoded in Base64) from a file.
    pub fn from_file<P: AsRef<std::path::Path>>(path: P) -> DwalletMPCResult<Self> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| DwalletMPCError::FailedToReadSeed(e.to_string()))?;
        let decoded = Base64::decode(contents.as_str().trim())
            .map_err(|e| DwalletMPCError::FailedToReadSeed(e.to_string()))?;
        Ok(RootSeed::new(decoded.try_into().map_err(|e| {
            DwalletMPCError::FailedToReadSeed(format!("failed to read class group seed: {e:?}"))
        })?))
    }

    /// Writes the seed, encoded in Base64,
    /// to a file and returns the encoded seed string.
    pub fn save_to_file<P: AsRef<std::path::Path> + Clone>(
        &self,
        path: P,
    ) -> DwalletMPCResult<String> {
        let contents = Base64::encode(self.0);
        std::fs::write(path.clone(), contents.clone())
            .map_err(|e| DwalletMPCError::FailedToWriteSeed(e.to_string()))?;
        Ok(contents)
    }

    /// Derive a seed for deterministically generating
    /// this validator's class-groups decryption key and proof [`ClassGroupsKeyPairAndProof`].
    ///
    /// We don't use the root seed directly, as it would be used for other purposes.
    /// Instead, we derive a seed from it using a distinct hard-coded label.
    fn class_groups_decryption_key_seed(&self) -> [u8; Self::SEED_LENGTH] {
        // Add a distinct descriptive label, and the root seed itself.
        let mut transcript = Transcript::new(b"Class Groups Decryption Key Seed");
        transcript.append_message(b"root seed", &self.0);

        // Generate a new seed from it (internally, it uses a hash function to pseudo-randomly generate it).
        let mut seed: [u8; Self::SEED_LENGTH] = [0; Self::SEED_LENGTH];
        transcript.challenge_bytes(b"seed", &mut seed);

        seed
    }

    /// Derive a seed deterministically for advancing an MPC round.
    ///
    /// We don't use the root seed directly, as it may be used for other purposes.
    /// Instead, we derive a seed from it using a distinct hard-coded label.
    fn mpc_round_seed(
        &self,
        session_identifier: CommitmentSizedNumber,
        current_round: u64,
        attempts_count: u64,
    ) -> [u8; Self::SEED_LENGTH] {
        mpc::derive_seed_for_round(&self.0, session_identifier, current_round, attempts_count)
    }

    /// Instantiates a deterministic secure pseudo-random generator (using the ChaCha20 algorithm)
    /// with which to generate this validator's class-groups decryption key and proof [`ClassGroupsKeyPairAndProof`].
    pub fn class_groups_decryption_key_rng(&self) -> ChaCha20Rng {
        let seed = self.class_groups_decryption_key_seed();

        ChaCha20Rng::from_seed(seed)
    }

    /// Instantiates a deterministic secure pseudo-random generator (using the ChaCha20 algorithm)
    /// with which to advance an MPC round.
    pub fn mpc_round_rng(
        &self,
        session_identifier: CommitmentSizedNumber,
        current_round: u64,
        attempts_count: u64,
    ) -> ChaCha20Rng {
        let seed = self.mpc_round_seed(session_identifier, current_round, attempts_count);

        ChaCha20Rng::from_seed(seed)
    }
}

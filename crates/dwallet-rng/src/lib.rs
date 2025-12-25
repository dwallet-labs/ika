use commitment::CommitmentSizedNumber;
use fastcrypto::encoding::{Base64, Encoding};
use group::{CsRng, OsCsRng};
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

// =============================================================================
// ZERO RNG - DETERMINISTIC ZERO-RETURNING RANDOM NUMBER GENERATOR
// =============================================================================

use rand_chacha::rand_core::CryptoRng;

/// A deterministic random number generator that **ALWAYS RETURNS ZEROS**.
///
/// # ⚠️ CRITICAL SECURITY WARNING ⚠️
///
/// **THIS RNG IS CRYPTOGRAPHICALLY INSECURE AND MUST NEVER BE USED FOR:**
/// - Generating cryptographic keys
/// - Generating nonces or initialization vectors
/// - Any security-sensitive random number generation
/// - User-facing dWallet operations
/// - Production cryptographic protocols where randomness provides security
///
/// # Intended Use Case
///
/// This RNG exists **EXCLUSIVELY** for internal network signing operations where:
///
/// 1. **Determinism is Required**: All validators must produce identical outputs when
///    emulating the "centralized party" (user) role in the 2PC-MPC protocol for
///    internal signing operations (e.g., checkpoint signing).
///
/// 2. **No Secret is Protected**: The "user secret" in internal signing is not actually
///    secret - it's a placeholder that all validators agree upon. The security comes
///    from the network's threshold signature, not from randomness.
///
/// 3. **Reproducibility is Essential**: For internal network operations, all validators
///    must be able to independently compute the same values without coordination.
///
/// # How It Works
///
/// This RNG implements the [`RngCore`] and [`CryptoRng`] traits from `rand_core`,
/// which makes it compatible with the [`group::CsRng`] trait alias used by the
/// twopc_mpc library. However, instead of generating random bytes, it always
/// fills buffers with zeros.
///
/// # Security Model for Internal Signing
///
/// In the 2PC-MPC protocol:
/// - Normal dWallet operations: User provides real randomness, protecting their key share
/// - Internal network signing: No user exists; validators collectively act as both parties
///
/// For internal signing (e.g., checkpoints), the "user randomness" doesn't provide security
/// because:
/// 1. There is no user secret to protect
/// 2. Security comes from the network's distributed key (threshold signature)
/// 3. All validators must agree on the same "user" values
///
/// Using zero randomness ensures determinism while the actual cryptographic security
/// is provided by the network's threshold signature scheme.
///
/// # Example
///
/// ```ignore
/// // ONLY use for internal network signing operations!
/// let mut rng = ZeroRng::new();
///
/// // This will fill the buffer with zeros
/// let mut buffer = [0u8; 32];
/// rng.fill_bytes(&mut buffer);
/// assert!(buffer.iter().all(|&b| b == 0));
/// ```
///
/// # Panics
///
/// This implementation never panics.
///
/// # Why Not Use a Seeded RNG?
///
/// A seeded RNG (like ChaCha20Rng with seed [0u8; 32]) would also be deterministic,
/// but using explicit zeros makes the intent clearer and the code more auditable.
/// When reviewing cryptographic code, seeing `ZeroRng` immediately signals that
/// determinism is intentional and the randomness is not providing security.
#[derive(Debug, Clone, Copy, Default)]
pub struct ZeroRng;

impl ZeroRng {
    /// Creates a new [`ZeroRng`] instance.
    ///
    /// # ⚠️ Security Warning
    ///
    /// Only use this for internal network signing operations where all validators
    /// must produce identical outputs. See the type-level documentation for details.
    #[inline]
    pub const fn new() -> Self {
        ZeroRng
    }
}

impl RngCore for ZeroRng {
    /// Returns zero.
    ///
    /// # ⚠️ Warning
    /// This always returns 0, providing no randomness.
    #[inline]
    fn next_u32(&mut self) -> u32 {
        0
    }

    /// Returns zero.
    ///
    /// # ⚠️ Warning
    /// This always returns 0, providing no randomness.
    #[inline]
    fn next_u64(&mut self) -> u64 {
        0
    }

    /// Fills the destination buffer with zeros.
    ///
    /// # ⚠️ Warning
    /// This fills the entire buffer with zeros, providing no randomness.
    #[inline]
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.fill(0);
    }
}

/// Marker trait implementation indicating this RNG is "cryptographically secure".
///
/// # ⚠️ CRITICAL WARNING ⚠️
///
/// **THIS IS A LIE.** This RNG is NOT cryptographically secure in any meaningful sense.
///
/// This trait is implemented ONLY to satisfy the type system requirements of the
/// twopc_mpc library, which requires [`CryptoRng`] bounds. The actual cryptographic
/// security for internal signing comes from the network's threshold signature,
/// NOT from this RNG.
///
/// **NEVER** use this RNG in any context where randomness is expected to provide security.
impl CryptoRng for ZeroRng {}

/// Implementation of [`group::CsRng`] for [`ZeroRng`].
///
/// # ⚠️ CRITICAL WARNING ⚠️
///
/// This implementation exists **ONLY** to enable `ZeroRng` to be used with the
/// twopc_mpc library's APIs that require [`CsRng`] bounds.
///
/// **NEVER** use this RNG in any context where randomness is expected to provide security.
/// See the [`ZeroRng`] type documentation for details on the intended use case.
impl CsRng for ZeroRng {}

#[cfg(test)]
mod zero_rng_tests {
    use super::*;

    #[test]
    fn test_zero_rng_returns_zeros() {
        let mut rng = ZeroRng::new();

        // Test next_u32
        assert_eq!(rng.next_u32(), 0);

        // Test next_u64
        assert_eq!(rng.next_u64(), 0);

        // Test fill_bytes
        let mut buffer = [0xFFu8; 64];
        rng.fill_bytes(&mut buffer);
        assert!(buffer.iter().all(|&b| b == 0));

        // Test fill_bytes again with different size
        let mut buffer = [0xFFu8; 128];
        rng.fill_bytes(&mut buffer);
        assert!(buffer.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_zero_rng_is_deterministic() {
        let mut rng1 = ZeroRng::new();
        let mut rng2 = ZeroRng::new();

        let mut buf1 = [0u8; 32];
        let mut buf2 = [0u8; 32];

        rng1.fill_bytes(&mut buf1);
        rng2.fill_bytes(&mut buf2);

        assert_eq!(buf1, buf2);
    }

    /// Test that [`ZeroRng`] satisfies the [`CsRng`] trait bound.
    /// This is critical for compatibility with twopc_mpc library APIs.
    #[test]
    fn test_zero_rng_satisfies_csrng_bound() {
        // This function requires CsRng bound
        fn use_csrng<R: CsRng>(rng: &mut R) -> [u8; 32] {
            let mut buf = [0u8; 32];
            rng.fill_bytes(&mut buf);
            buf
        }

        let mut rng = ZeroRng::new();
        let result = use_csrng(&mut rng);

        // Verify it returns zeros
        assert!(result.iter().all(|&b| b == 0));
    }
}

/**
 * Constants shared by both the Sui and Solana ikavery SDKs.
 *
 * Domain-separation tags are NOT here — those vary per chain (e.g. Move's
 * `recovery::propose` vs Solana's per-program-id tag). Each chain SDK defines
 * its own `TAG_*` strings and bakes them into the WebAuthn challenge so a
 * passkey assertion authorising one chain cannot replay on the other.
 */

// Curve / signature-algorithm / hash codes (mirror Ika's coordinator):
export const SOLANA_CURVE = 2; // ED25519
export const SOLANA_SIG_ALGO = 0; // EdDSA
export const SOLANA_HASH = 0; // SHA512

export const ECDSA_R1_SHA256 = 1;

/** Maximum number of Solana txs in one sweep bundle. */
export const MAX_BUNDLE_SIZE = 8;

/** Salt fed into WebAuthn-PRF to derive the per-device encryption identity. */
export const PRF_SALT = 'ika-recovery-prf-v1';

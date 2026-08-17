import { PublicKey } from '@solana/web3.js';

/**
 * Ika dWallet 2pc-mpc program — pre-alpha devnet deployment.
 *
 * Source of truth: `ika-pre-alpha` repo, declared in
 * `chains/solana/program-sdk/native/src/lib.rs`.
 */
export const IKA_DWALLET_PROGRAM_ID = new PublicKey('87W54kGYFQ1rgWqMeu4XTPHWXWmXSQCcjm8vCTfiq1oY');

/** Default pre-alpha gRPC endpoint (mock signer; not production MPC). */
export const IKA_GRPC_URL = 'pre-alpha-dev-1.ika.ika-network.net:443';

/** dWallet curve tags — match `DWalletCurve` BCS variants. */
export const CURVE_SECP256K1 = 0;
export const CURVE_SECP256R1 = 1;
export const CURVE_CURVE25519 = 2;
export const CURVE_RISTRETTO = 3;

/**
 * Solana `signature_scheme` (u16) the dWallet program stamps on the
 * MessageApproval PDA. Curve25519 + EdDSA-SHA512 is the only combo the
 * mock signer supports for Solana keys today.
 *
 * Index = curve_index * 16 + (algo_index * 4) + hash_index — a packed
 * (curve, algorithm, hash) triple. EdDSA on Curve25519 with SHA-512 = 5.
 */
export const SIG_SCHEME_EDDSA_SHA512 = 5;

/** PDA seed prefixes consumed by `ika_dwallet_program`. */
export const SEED_DWALLET = Buffer.from('dwallet');
export const SEED_MESSAGE_APPROVAL = Buffer.from('message_approval');
export const SEED_DWALLET_COORDINATOR = Buffer.from('dwallet_coordinator');

/** PDA seed for the per-caller-program CPI authority. */
export const SEED_CPI_AUTHORITY = Buffer.from('__ika_cpi_authority');

/**
 * `IkaDWalletInstructionDiscriminators::TransferOwnership` — direct invoke
 * (not CPI) used once after DKG to hand the dWallet's authority over to
 * a Quasar caller program's CPI authority PDA.
 */
export const IX_DWALLET_TRANSFER_OWNERSHIP = 24;

/** Account discriminator the dWallet program writes on a `DWallet` row. */
export const DWALLET_DISC = 2;
/** Account discriminator on a `MessageApproval` row. */
export const MESSAGE_APPROVAL_DISC = 5;

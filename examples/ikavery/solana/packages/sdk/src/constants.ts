import { PublicKey } from '@solana/web3.js';

/** Deployed program id — keep in sync with `declare_id!` in `lib.rs`. */
export const IKAVERY_PROGRAM_ID = new PublicKey('4ZrXgy2Grv9RH3gWF7mksQvRqSUgc4atQyhcss569fw7');

/** Solana sysvar program (owns the rent + instructions sysvar accounts). */
export const SYSVAR_INSTRUCTIONS_ID = new PublicKey('Sysvar1nstructions1111111111111111111111111');
export const SYSVAR_RENT_ID = new PublicKey('SysvarRent111111111111111111111111111111111');
export const SYSTEM_PROGRAM_ID = new PublicKey('11111111111111111111111111111111');

/** Solana ed25519 / secp256r1 signature precompile program ids. */
export const ED25519_PRECOMPILE_ID = new PublicKey('Ed25519SigVerify111111111111111111111111111');
export const SECP256R1_PRECOMPILE_ID = new PublicKey('Secp256r1SigVerify1111111111111111111111111');

/** Instruction discriminators — match `#[instruction(discriminator = N)]` in `lib.rs`. */
export const IX_CREATE_RECOVERY = 0;
export const IX_PROPOSE = 1;
export const IX_APPROVE = 2;
export const IX_EXECUTE = 3;
export const IX_PROPOSE_ROSTER_CHANGE = 4;
export const IX_APPROVE_ROSTER_CHANGE = 5;
export const IX_EXECUTE_ROSTER_CHANGE = 6;
export const IX_PROPOSE_ENROLLMENT = 7;
export const IX_APPROVE_ENROLLMENT = 8;
export const IX_EXECUTE_ENROLLMENT = 9;
export const IX_STAGE_ROSTER_CHANGE_PAYLOAD = 10;

/** Account discriminators — match `#[account(discriminator = N)]` in `state.rs`. */
export const DISC_RECOVERY = 1;
export const DISC_PROPOSAL = 2;
export const DISC_ROSTER_CHANGE_PROPOSAL = 3;
export const DISC_APPROVAL = 4;
export const DISC_ROSTER_CHANGE_APPROVAL = 5;
export const DISC_ENROLLMENT_PROPOSAL = 6;
export const DISC_ENROLLMENT_APPROVAL = 7;
export const DISC_ROSTER_CHANGE_STAGING = 8;

/** Credential scheme tags — byte-for-byte parity with Sui's `auth.move`. */
export const SCHEME_ED25519 = 0;
export const SCHEME_SECP256K1 = 1;
export const SCHEME_SECP256R1 = 2;
export const SCHEME_WEBAUTHN = 3;
export const SCHEME_SOLANA_ADDRESS = 4;

/** Per-scheme pubkey lengths. */
export const ED25519_PUBKEY_LEN = 32;
export const SECP256K1_PUBKEY_LEN = 33;
export const SECP256R1_PUBKEY_LEN = 33;
export const WEBAUTHN_PUBKEY_LEN = 33;
export const SOLANA_ADDRESS_LEN = 32;

/** Roster + buffer sizing — matches `state.rs`. */
export const MAX_MEMBERS = 8;
export const MEMBER_SLOT_LEN = 34;
export const MAX_MESSAGE_BYTES = 512;
export const MAX_CLIENT_DATA_JSON_BYTES = 256;
export const AUTH_PUBKEY_BYTES = 33;
export const AUTH_SIGNATURE_BYTES = 65;
export const CREATE_MEMBERS_BYTES = MAX_MEMBERS * MEMBER_SLOT_LEN;
/** Maximum tx count per proposal bundle — Sui-parity with `MAX_BUNDLE_SIZE`. */
export const MAX_BUNDLE_PER_PROPOSAL = 8;
/** Packed digest buffer length on the propose ix wire. */
export const PROPOSE_DIGESTS_BYTES = MAX_BUNDLE_PER_PROPOSAL * 32;

/** Proposal lifecycle flags. */
export const STATUS_ACTIVE = 0;
export const STATUS_APPROVED = 1;
export const STATUS_EXECUTED = 2;

/** PDA seed prefixes — match `#[seeds(...)]` in `state.rs`. */
export const SEED_RECOVERY = Buffer.from('recovery');
export const SEED_PROPOSAL = Buffer.from('proposal');
export const SEED_ROSTER = Buffer.from('roster');
export const SEED_ROSTER_STAGING = Buffer.from('roster_staging_v2');
export const SEED_APPROVAL = Buffer.from('approval');
export const SEED_ROSTER_APPROVAL = Buffer.from('roster_approval');
export const SEED_ENROLLMENT = Buffer.from('enrollment');
export const SEED_ENROLLMENT_APPROVAL = Buffer.from('enrollment_approval');

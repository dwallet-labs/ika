import { PublicKey } from '@solana/web3.js';

import {
	IKA_DWALLET_PROGRAM_ID,
	SEED_CPI_AUTHORITY,
	SEED_DWALLET,
	SEED_DWALLET_COORDINATOR,
	SEED_MESSAGE_APPROVAL,
} from './constants';

const u16le = (n: number): Buffer => {
	const b = Buffer.alloc(2);
	b.writeUInt16LE(n & 0xffff, 0);
	return b;
};

/**
 * Pack `(curve, pubkey)` into the on-chain dWallet seed payload —
 * `curve_u16_le || pubkey_bytes`. Same bytes the Rust SDK builds via
 * `DWalletPdaSeeds::new`.
 */
export function packDwalletSeedPayload(curve: number, pubkey: Uint8Array): Buffer {
	const buf = Buffer.alloc(2 + pubkey.length);
	buf.writeUInt16LE(curve & 0xffff, 0);
	buf.set(pubkey, 2);
	return buf;
}

/**
 * Solana caps each PDA seed at 32 bytes (`MAX_SEED_LEN`), so the dWallet
 * program splits its `(curve || pubkey)` payload into 32-byte chunks. A
 * Curve25519 dWallet has a 34-byte payload — first 32 bytes, then 2 bytes.
 */
function chunkSeed(payload: Buffer): Buffer[] {
	const chunks: Buffer[] = [];
	for (let i = 0; i < payload.length; i += 32) {
		chunks.push(payload.subarray(i, Math.min(i + 32, payload.length)));
	}
	return chunks;
}

/**
 * dWallet PDA on the dWallet program — seeds are `["dwallet", ...chunks]`
 * where the chunks come from `pack_dwallet_seed_payload(curve, pubkey)`
 * split into 32-byte slices.
 */
export function dwalletPda(curve: number, pubkey: Uint8Array): { pda: PublicKey; bump: number } {
	const payload = packDwalletSeedPayload(curve, pubkey);
	const seeds: (Buffer | Uint8Array)[] = [SEED_DWALLET, ...chunkSeed(payload)];
	const [pda, bump] = PublicKey.findProgramAddressSync(seeds, IKA_DWALLET_PROGRAM_ID);
	return { pda, bump };
}

/**
 * MessageApproval PDA — sits *under* the dWallet's seed prefix:
 *   ["dwallet", ...chunks(curve||pubkey), "message_approval",
 *     scheme_u16_le, message_digest, [optional metadata_digest]]
 *
 * The handler accepts a metadata digest when non-zero; for the recovery
 * sweep path we always pass it as zeros, so the seed list omits it.
 */
export function messageApprovalPda(
	curve: number,
	pubkey: Uint8Array,
	signatureScheme: number,
	messageDigest: Uint8Array,
): { pda: PublicKey; bump: number } {
	if (messageDigest.length !== 32) {
		throw new Error(`message_digest must be 32 bytes, got ${messageDigest.length}`);
	}
	const payload = packDwalletSeedPayload(curve, pubkey);
	const seeds: (Buffer | Uint8Array)[] = [
		SEED_DWALLET,
		...chunkSeed(payload),
		SEED_MESSAGE_APPROVAL,
		u16le(signatureScheme),
		messageDigest,
	];
	const [pda, bump] = PublicKey.findProgramAddressSync(seeds, IKA_DWALLET_PROGRAM_ID);
	return { pda, bump };
}

/** Singleton `DWalletCoordinator` PDA — stores the current epoch. */
export function coordinatorPda(): { pda: PublicKey; bump: number } {
	const [pda, bump] = PublicKey.findProgramAddressSync(
		[SEED_DWALLET_COORDINATOR],
		IKA_DWALLET_PROGRAM_ID,
	);
	return { pda, bump };
}

/**
 * CPI authority PDA on a calling program — `["__ika_cpi_authority"]`. The
 * dWallet program checks the signer is this PDA before letting a caller
 * program issue a `MessageApproval` on its behalf.
 */
export function cpiAuthorityPda(callerProgramId: PublicKey): {
	pda: PublicKey;
	bump: number;
} {
	const [pda, bump] = PublicKey.findProgramAddressSync([SEED_CPI_AUTHORITY], callerProgramId);
	return { pda, bump };
}

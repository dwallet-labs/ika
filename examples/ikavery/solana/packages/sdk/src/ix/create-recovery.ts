import { PublicKey, SystemProgram, TransactionInstruction } from '@solana/web3.js';

import {
	CREATE_MEMBERS_BYTES,
	IKAVERY_PROGRAM_ID,
	IX_CREATE_RECOVERY,
	SYSVAR_RENT_ID,
} from '../constants';
import { packMembers } from '../credential';
import { recoveryPda } from '../pda';
import { padInto, writeBytes, writeU8, writeU16le } from './encode';

export interface CreateRecoveryParams {
	/** Funded payer + signer; pays rent for the new Recovery PDA. */
	creator: PublicKey;
	/**
	 * Fresh keypair the caller controls. Used as the seed nonce so a creator
	 * can host multiple recoveries; signs once at create-time and is never
	 * referenced again.
	 */
	recoveryId: PublicKey;
	/**
	 * 32-byte dWallet account address. On Solana ika pre-alpha this is just
	 * an opaque handle stored on-chain — the dWallet program owns its
	 * lifecycle separately.
	 */
	dwallet: Uint8Array;
	/**
	 * dWallet curve tag (matches Sui `Curve`). 0 = secp256k1, 1 = secp256r1,
	 * 2 = ed25519, 3 = ristretto.
	 */
	dwalletCurve: number;
	/** Approval threshold: 1 ≤ threshold ≤ members.length, ≤ MAX_MEMBERS. */
	threshold: number;
	/**
	 * Pre-packed `MemberSlot` byte arrays (one per member). Use
	 * `packSolanaMember` / `packMemberSlot` from `../credential` to build them.
	 */
	members: Uint8Array[];
	/**
	 * `i`-th bit set ⇔ member i is approver-only (votes but doesn't hold a
	 * share). Bits past the active member count must be zero.
	 */
	approverOnlyBitmap?: number;
}

export interface CreateRecoveryIx {
	ix: TransactionInstruction;
	recovery: PublicKey;
}

export function buildCreateRecoveryIx(params: CreateRecoveryParams): CreateRecoveryIx {
	if (params.dwallet.length !== 32) {
		throw new Error(`dwallet must be 32 bytes, got ${params.dwallet.length}`);
	}
	if (params.members.length === 0) {
		throw new Error('create_recovery requires at least one member');
	}
	if (params.threshold < 1 || params.threshold > params.members.length) {
		throw new Error(`threshold ${params.threshold} out of range 1..=${params.members.length}`);
	}

	const recovery = recoveryPda(params.recoveryId);
	const { packed } = packMembers(params.members, CREATE_MEMBERS_BYTES);

	// 1 (disc) + 32 (dwallet) + 2 (curve) + 2 (threshold) + 1 (count) +
	// 2 (bitmap) + 544 (members buffer)
	const data = new Uint8Array(1 + 32 + 2 + 2 + 1 + 2 + CREATE_MEMBERS_BYTES);
	let off = 0;
	off = writeU8(data, off, IX_CREATE_RECOVERY);
	off = writeBytes(data, off, params.dwallet, 32);
	off = writeU16le(data, off, params.dwalletCurve);
	off = writeU16le(data, off, params.threshold);
	off = writeU8(data, off, params.members.length);
	off = writeU16le(data, off, params.approverOnlyBitmap ?? 0);
	off = padInto(data, off, packed, CREATE_MEMBERS_BYTES);

	const ix = new TransactionInstruction({
		programId: IKAVERY_PROGRAM_ID,
		keys: [
			{ pubkey: params.creator, isSigner: true, isWritable: true },
			{ pubkey: params.recoveryId, isSigner: true, isWritable: false },
			{ pubkey: recovery, isSigner: false, isWritable: true },
			{ pubkey: SYSVAR_RENT_ID, isSigner: false, isWritable: false },
			{ pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
		],
		data: Buffer.from(data),
	});

	return { ix, recovery };
}

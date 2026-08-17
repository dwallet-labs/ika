import { sha256 } from '@noble/hashes/sha2';
import { PublicKey } from '@solana/web3.js';

import {
	IKAVERY_PROGRAM_ID,
	SEED_APPROVAL,
	SEED_ENROLLMENT,
	SEED_ENROLLMENT_APPROVAL,
	SEED_PROPOSAL,
	SEED_RECOVERY,
	SEED_ROSTER,
	SEED_ROSTER_APPROVAL,
	SEED_ROSTER_STAGING,
} from './constants';
import { memberIdBytes } from './credential';

const u32le = (n: number): Buffer => {
	const b = Buffer.alloc(4);
	b.writeUInt32LE(n >>> 0, 0);
	return b;
};

export function recoveryPda(recoveryId: PublicKey): PublicKey {
	const [pda] = PublicKey.findProgramAddressSync(
		[SEED_RECOVERY, recoveryId.toBuffer()],
		IKAVERY_PROGRAM_ID,
	);
	return pda;
}

export function proposalPda(recovery: PublicKey, index: number): PublicKey {
	const [pda] = PublicKey.findProgramAddressSync(
		[SEED_PROPOSAL, recovery.toBuffer(), u32le(index)],
		IKAVERY_PROGRAM_ID,
	);
	return pda;
}

export function rosterChangePda(recovery: PublicKey, index: number): PublicKey {
	const [pda] = PublicKey.findProgramAddressSync(
		[SEED_ROSTER, recovery.toBuffer(), u32le(index)],
		IKAVERY_PROGRAM_ID,
	);
	return pda;
}

export function rosterChangeStagingPda(recovery: PublicKey, index: number): PublicKey {
	const [pda] = PublicKey.findProgramAddressSync(
		[SEED_ROSTER_STAGING, recovery.toBuffer(), u32le(index)],
		IKAVERY_PROGRAM_ID,
	);
	return pda;
}

export function enrollmentPda(recovery: PublicKey, index: number): PublicKey {
	const [pda] = PublicKey.findProgramAddressSync(
		[SEED_ENROLLMENT, recovery.toBuffer(), u32le(index)],
		IKAVERY_PROGRAM_ID,
	);
	return pda;
}

/**
 * `member_id` slot for a credential is `[scheme, ...pubkey_or_address_bytes]`.
 * For approval PDAs we need its sha256 over the canonical id (scheme tag +
 * active pubkey, no trailing zero pad) — same bytes the program hashes via
 * `slot_id(slot)` before checking the supplied `member_id` UncheckedAccount.
 */
export function memberIdHash(memberSlot: Uint8Array): PublicKey {
	return new PublicKey(sha256(memberIdBytes(memberSlot)));
}

/** Approval PDA for a sweep proposal. `memberIdAddress` carries the hash. */
export function approvalPda(proposal: PublicKey, memberIdAddress: PublicKey): PublicKey {
	const [pda] = PublicKey.findProgramAddressSync(
		[SEED_APPROVAL, proposal.toBuffer(), memberIdAddress.toBuffer()],
		IKAVERY_PROGRAM_ID,
	);
	return pda;
}

export function rosterChangeApprovalPda(
	rosterChange: PublicKey,
	memberIdAddress: PublicKey,
): PublicKey {
	const [pda] = PublicKey.findProgramAddressSync(
		[SEED_ROSTER_APPROVAL, rosterChange.toBuffer(), memberIdAddress.toBuffer()],
		IKAVERY_PROGRAM_ID,
	);
	return pda;
}

export function enrollmentApprovalPda(
	enrollment: PublicKey,
	memberIdAddress: PublicKey,
): PublicKey {
	const [pda] = PublicKey.findProgramAddressSync(
		[SEED_ENROLLMENT_APPROVAL, enrollment.toBuffer(), memberIdAddress.toBuffer()],
		IKAVERY_PROGRAM_ID,
	);
	return pda;
}

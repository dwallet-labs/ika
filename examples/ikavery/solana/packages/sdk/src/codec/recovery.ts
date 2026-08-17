import { PublicKey } from '@solana/web3.js';

import { DISC_RECOVERY, MAX_MEMBERS, MEMBER_SLOT_LEN } from '../constants';

/** Decoded `Recovery` account — the shared root of an ikavery vault. */
export interface RecoveryAccount {
	recoveryId: PublicKey;
	creator: PublicKey;
	/** dWallet pubkey on the target Solana key being recovered. */
	dwallet: PublicKey;
	dwalletCurve: number;
	threshold: number;
	/** Bit `i` set ⇒ member at index `i` is approver-only (no key share). */
	approverOnlyBitmap: number;
	proposalCount: number;
	rosterChangeCount: number;
	enrollmentCount: number;
	/**
	 * Active member set. Each entry is a 34-byte `MemberSlot` —
	 * `[scheme_byte, ...pubkey_or_address, ...zero_pad]`.
	 */
	members: Uint8Array[];
}

const RECOVERY_FIXED_LEN = 1 + 32 + 32 + 32 + 2 + 2 + 2 + 4 + 4 + 4; // 115

export function decodeRecovery(data: Uint8Array): RecoveryAccount {
	if (data[0] !== DISC_RECOVERY) {
		throw new Error(`expected Recovery discriminator ${DISC_RECOVERY}, got ${data[0]}`);
	}
	if (data.length < RECOVERY_FIXED_LEN + 2) {
		throw new Error(`Recovery account truncated: ${data.length}b`);
	}
	let off = 1;
	const recoveryId = new PublicKey(data.slice(off, off + 32));
	off += 32;
	const creator = new PublicKey(data.slice(off, off + 32));
	off += 32;
	const dwallet = new PublicKey(data.slice(off, off + 32));
	off += 32;
	const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
	const dwalletCurve = dv.getUint16(off, true);
	off += 2;
	const threshold = dv.getUint16(off, true);
	off += 2;
	const approverOnlyBitmap = dv.getUint16(off, true);
	off += 2;
	const proposalCount = dv.getUint32(off, true);
	off += 4;
	const rosterChangeCount = dv.getUint32(off, true);
	off += 4;
	const enrollmentCount = dv.getUint32(off, true);
	off += 4;

	// Vec<MemberSlot, 16> — 2-byte LE length, then N slots.
	const memberCount = dv.getUint16(off, true);
	off += 2;
	if (memberCount > MAX_MEMBERS) {
		throw new Error(`Recovery member count ${memberCount} > MAX_MEMBERS`);
	}
	const members: Uint8Array[] = [];
	for (let i = 0; i < memberCount; i++) {
		members.push(new Uint8Array(data.slice(off, off + MEMBER_SLOT_LEN)));
		off += MEMBER_SLOT_LEN;
	}
	return {
		recoveryId,
		creator,
		dwallet,
		dwalletCurve,
		threshold,
		approverOnlyBitmap,
		proposalCount,
		rosterChangeCount,
		enrollmentCount,
		members,
	};
}

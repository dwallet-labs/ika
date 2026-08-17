import { PublicKey } from '@solana/web3.js';

import { DISC_ROSTER_CHANGE_PROPOSAL, MAX_MEMBERS, MEMBER_SLOT_LEN } from '../constants';

export interface RosterChangeProposalAccount {
	recovery: PublicKey;
	rosterChangeIndex: number;
	proposerSlot: Uint8Array;
	payloadHash: Uint8Array;
	/** Per-addition approver-only flag, bit `i` for `additions[i]`. */
	additionApproverOnlyBitmap: number;
	newThreshold: number;
	/** 1 if the proposal also changes the threshold; 0 to keep current. */
	hasNewThreshold: number;
	approvalCount: number;
	status: number;
	additions: Uint8Array[];
	removals: Uint8Array[];
}

const ROSTER_FIXED_LEN = 1 + 32 + 4 + MEMBER_SLOT_LEN + 32 + 2 + 2 + 1 + 2 + 1; // 111

export function decodeRosterChangeProposal(data: Uint8Array): RosterChangeProposalAccount {
	if (data[0] !== DISC_ROSTER_CHANGE_PROPOSAL) {
		throw new Error(
			`expected RosterChangeProposal disc ${DISC_ROSTER_CHANGE_PROPOSAL}, got ${data[0]}`,
		);
	}
	if (data.length < ROSTER_FIXED_LEN + 4) {
		throw new Error(`RosterChangeProposal truncated: ${data.length}b`);
	}
	const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
	let off = 1;
	const recovery = new PublicKey(data.slice(off, off + 32));
	off += 32;
	const rosterChangeIndex = dv.getUint32(off, true);
	off += 4;
	const proposerSlot = new Uint8Array(data.slice(off, off + MEMBER_SLOT_LEN));
	off += MEMBER_SLOT_LEN;
	const payloadHash = new Uint8Array(data.slice(off, off + 32));
	off += 32;
	const additionApproverOnlyBitmap = dv.getUint16(off, true);
	off += 2;
	const newThreshold = dv.getUint16(off, true);
	off += 2;
	const hasNewThreshold = data[off]!;
	off += 1;
	const approvalCount = dv.getUint16(off, true);
	off += 2;
	const status = data[off]!;
	off += 1;

	// Two Vec<MemberSlot, 16> — each prefixed by its own 2-byte length.
	const additions = readMemberVec(data, dv, off);
	off = additions.next;
	const removals = readMemberVec(data, dv, off);

	return {
		recovery,
		rosterChangeIndex,
		proposerSlot,
		payloadHash,
		additionApproverOnlyBitmap,
		newThreshold,
		hasNewThreshold,
		approvalCount,
		status,
		additions: additions.items,
		removals: removals.items,
	};
}

function readMemberVec(
	data: Uint8Array,
	dv: DataView,
	off: number,
): { items: Uint8Array[]; next: number } {
	const count = dv.getUint16(off, true);
	off += 2;
	if (count > MAX_MEMBERS) {
		throw new Error(`Vec<MemberSlot> count ${count} > MAX_MEMBERS`);
	}
	const items: Uint8Array[] = [];
	for (let i = 0; i < count; i++) {
		items.push(new Uint8Array(data.slice(off, off + MEMBER_SLOT_LEN)));
		off += MEMBER_SLOT_LEN;
	}
	return { items, next: off };
}

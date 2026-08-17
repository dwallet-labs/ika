import { PublicKey } from '@solana/web3.js';

import { DISC_PROPOSAL, MAX_BUNDLE_PER_PROPOSAL, MEMBER_SLOT_LEN } from '../constants';

/** Decoded sweep `Proposal` account. */
export interface ProposalAccount {
	recovery: PublicKey;
	proposalIndex: number;
	/** 34-byte member slot of the proposer at propose time. */
	proposerSlot: Uint8Array;
	/** dWallet user pubkey passed to the eventual `approve_message` CPI. */
	userPubkey: Uint8Array;
	signatureScheme: number;
	approvalCount: number;
	/** `STATUS_ACTIVE` | `STATUS_APPROVED` | `STATUS_EXECUTED`. */
	status: number;
	/** Bit `i` set iff `intentDigests[i]`'s `approve_message` CPI has fired. */
	executedBitmap: number;
	/** One BCS-keccak intent digest per tx in this proposal's sweep bundle. */
	intentDigests: Uint8Array[];
}

// Fixed prefix: disc(1) + recovery(32) + proposal_index(4) + proposer_id(34)
// + user_pubkey(32) + signature_scheme(2) + approval_count(2) + status(1)
// + executed_bitmap(1) = 109. Trailing Vec<[u8;32], 8> is length-prefixed.
const PROPOSAL_FIXED_LEN = 1 + 32 + 4 + MEMBER_SLOT_LEN + 32 + 2 + 2 + 1 + 1;

export function decodeProposal(data: Uint8Array): ProposalAccount {
	if (data[0] !== DISC_PROPOSAL) {
		throw new Error(`expected Proposal disc ${DISC_PROPOSAL}, got ${data[0]}`);
	}
	if (data.length < PROPOSAL_FIXED_LEN + 2) {
		throw new Error(`Proposal account truncated: ${data.length}b`);
	}
	const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
	let off = 1;
	const recovery = new PublicKey(data.slice(off, off + 32));
	off += 32;
	const proposalIndex = dv.getUint32(off, true);
	off += 4;
	const proposerSlot = new Uint8Array(data.slice(off, off + MEMBER_SLOT_LEN));
	off += MEMBER_SLOT_LEN;
	const userPubkey = new Uint8Array(data.slice(off, off + 32));
	off += 32;
	const signatureScheme = dv.getUint16(off, true);
	off += 2;
	const approvalCount = dv.getUint16(off, true);
	off += 2;
	const status = data[off]!;
	off += 1;
	const executedBitmap = data[off]!;
	off += 1;

	// Vec<[u8; 32], 8> — 2-byte LE length, then N digests.
	const digestCount = dv.getUint16(off, true);
	off += 2;
	if (digestCount > MAX_BUNDLE_PER_PROPOSAL) {
		throw new Error(`Proposal bundle length ${digestCount} > MAX_BUNDLE_PER_PROPOSAL`);
	}
	const intentDigests: Uint8Array[] = [];
	for (let i = 0; i < digestCount; i++) {
		intentDigests.push(new Uint8Array(data.slice(off, off + 32)));
		off += 32;
	}

	return {
		recovery,
		proposalIndex,
		proposerSlot,
		userPubkey,
		signatureScheme,
		approvalCount,
		status,
		executedBitmap,
		intentDigests,
	};
}

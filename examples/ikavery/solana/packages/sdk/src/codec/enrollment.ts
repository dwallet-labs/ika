import { PublicKey } from '@solana/web3.js';

import { DISC_ENROLLMENT_PROPOSAL, MEMBER_SLOT_LEN } from '../constants';

export interface EnrollmentProposalAccount {
	recovery: PublicKey;
	enrollmentIndex: number;
	proposerSlot: Uint8Array;
	newMember: Uint8Array;
	/**
	 * Where to deliver the re-encrypted user share when Solana mainnet ships
	 * share encryption. Stored opaquely; pre-alpha doesn't fire a CPI here.
	 */
	newEncryptionKeyAddress: PublicKey;
	/** 1 if the new member is approver-only; 0 if key-holding. */
	additionApproverOnly: number;
	approvalCount: number;
	status: number;
}

const ENROLLMENT_LEN = 1 + 32 + 4 + MEMBER_SLOT_LEN + MEMBER_SLOT_LEN + 32 + 1 + 2 + 1;

export function decodeEnrollmentProposal(data: Uint8Array): EnrollmentProposalAccount {
	if (data[0] !== DISC_ENROLLMENT_PROPOSAL) {
		throw new Error(`expected EnrollmentProposal disc ${DISC_ENROLLMENT_PROPOSAL}, got ${data[0]}`);
	}
	if (data.length < ENROLLMENT_LEN) {
		throw new Error(`EnrollmentProposal truncated: ${data.length}b`);
	}
	const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
	let off = 1;
	const recovery = new PublicKey(data.slice(off, off + 32));
	off += 32;
	const enrollmentIndex = dv.getUint32(off, true);
	off += 4;
	const proposerSlot = new Uint8Array(data.slice(off, off + MEMBER_SLOT_LEN));
	off += MEMBER_SLOT_LEN;
	const newMember = new Uint8Array(data.slice(off, off + MEMBER_SLOT_LEN));
	off += MEMBER_SLOT_LEN;
	const newEncryptionKeyAddress = new PublicKey(data.slice(off, off + 32));
	off += 32;
	const additionApproverOnly = data[off]!;
	off += 1;
	const approvalCount = dv.getUint16(off, true);
	off += 2;
	const status = data[off]!;
	return {
		recovery,
		enrollmentIndex,
		proposerSlot,
		newMember,
		newEncryptionKeyAddress,
		additionApproverOnly,
		approvalCount,
		status,
	};
}

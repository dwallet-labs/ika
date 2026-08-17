import { PublicKey } from '@solana/web3.js';

import { DISC_APPROVAL, DISC_ENROLLMENT_APPROVAL, DISC_ROSTER_CHANGE_APPROVAL } from '../constants';

interface ApprovalLike {
	parent: PublicKey;
	memberIdHash: PublicKey;
	approvedAtCount: number;
}

function decode(data: Uint8Array, expectedDisc: number, label: string): ApprovalLike {
	if (data[0] !== expectedDisc) {
		throw new Error(`expected ${label} disc ${expectedDisc}, got ${data[0]}`);
	}
	if (data.length < 1 + 32 + 32 + 2) {
		throw new Error(`${label} truncated: ${data.length}b`);
	}
	const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
	let off = 1;
	const parent = new PublicKey(data.slice(off, off + 32));
	off += 32;
	const memberIdHash = new PublicKey(data.slice(off, off + 32));
	off += 32;
	const approvedAtCount = dv.getUint16(off, true);
	return { parent, memberIdHash, approvedAtCount };
}

export interface ApprovalAccount {
	proposal: PublicKey;
	memberIdHash: PublicKey;
	approvedAtCount: number;
}
export function decodeApproval(data: Uint8Array): ApprovalAccount {
	const a = decode(data, DISC_APPROVAL, 'Approval');
	return { proposal: a.parent, memberIdHash: a.memberIdHash, approvedAtCount: a.approvedAtCount };
}

export interface RosterChangeApprovalAccount {
	rosterChange: PublicKey;
	memberIdHash: PublicKey;
	approvedAtCount: number;
}
export function decodeRosterChangeApproval(data: Uint8Array): RosterChangeApprovalAccount {
	const a = decode(data, DISC_ROSTER_CHANGE_APPROVAL, 'RosterChangeApproval');
	return {
		rosterChange: a.parent,
		memberIdHash: a.memberIdHash,
		approvedAtCount: a.approvedAtCount,
	};
}

export interface EnrollmentApprovalAccount {
	enrollment: PublicKey;
	memberIdHash: PublicKey;
	approvedAtCount: number;
}
export function decodeEnrollmentApproval(data: Uint8Array): EnrollmentApprovalAccount {
	const a = decode(data, DISC_ENROLLMENT_APPROVAL, 'EnrollmentApproval');
	return { enrollment: a.parent, memberIdHash: a.memberIdHash, approvedAtCount: a.approvedAtCount };
}

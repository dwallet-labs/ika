/**
 * Unit tests for account decoders in `src/codec/*`. Each test builds a
 * synthetic byte buffer that mirrors the on-chain `repr(C)` layout, decodes
 * it, and asserts the parsed structure matches. Truncation / wrong-disc
 * paths are also exercised so future layout changes blow up loudly.
 */

import { PublicKey } from '@solana/web3.js';
import { describe, expect, test } from 'bun:test';

import {
	decodeApproval,
	decodeEnrollmentApproval,
	decodeEnrollmentProposal,
	decodeProposal,
	decodeRecovery,
	decodeRosterChangeApproval,
	decodeRosterChangeProposal,
	DISC_APPROVAL,
	DISC_ENROLLMENT_APPROVAL,
	DISC_ENROLLMENT_PROPOSAL,
	DISC_PROPOSAL,
	DISC_RECOVERY,
	DISC_ROSTER_CHANGE_APPROVAL,
	DISC_ROSTER_CHANGE_PROPOSAL,
	MAX_BUNDLE_PER_PROPOSAL,
	MAX_MEMBERS,
	MEMBER_SLOT_LEN,
	STATUS_ACTIVE,
	STATUS_APPROVED,
} from '../src';

function pubkey(byte: number): PublicKey {
	return new PublicKey(new Uint8Array(32).fill(byte));
}

function writeU16le(out: Uint8Array, off: number, v: number): number {
	out[off] = v & 0xff;
	out[off + 1] = (v >>> 8) & 0xff;
	return off + 2;
}

function writeU32le(out: Uint8Array, off: number, v: number): number {
	out[off] = v & 0xff;
	out[off + 1] = (v >>> 8) & 0xff;
	out[off + 2] = (v >>> 16) & 0xff;
	out[off + 3] = (v >>> 24) & 0xff;
	return off + 4;
}

function writeBytes(out: Uint8Array, off: number, src: Uint8Array): number {
	out.set(src, off);
	return off + src.length;
}

function fillSlot(filler: number): Uint8Array {
	const s = new Uint8Array(MEMBER_SLOT_LEN);
	s.fill(filler);
	return s;
}

describe('decodeRecovery', () => {
	test('round-trips a 2-member roster', () => {
		const buf = new Uint8Array(1 + 32 + 32 + 32 + 2 + 2 + 2 + 4 + 4 + 4 + 2 + MEMBER_SLOT_LEN * 2);
		let off = 0;
		buf[off++] = DISC_RECOVERY;
		off = writeBytes(buf, off, pubkey(0x01).toBytes());
		off = writeBytes(buf, off, pubkey(0x02).toBytes());
		off = writeBytes(buf, off, pubkey(0x03).toBytes());
		off = writeU16le(buf, off, 2); // curve = 2 (ed25519)
		off = writeU16le(buf, off, 2); // threshold
		off = writeU16le(buf, off, 0b10); // bitmap: member 1 is approver-only
		off = writeU32le(buf, off, 7); // proposalCount
		off = writeU32le(buf, off, 3); // rosterChangeCount
		off = writeU32le(buf, off, 1); // enrollmentCount
		off = writeU16le(buf, off, 2); // memberCount
		off = writeBytes(buf, off, fillSlot(0xaa));
		off = writeBytes(buf, off, fillSlot(0xbb));

		const decoded = decodeRecovery(buf);
		expect(decoded.recoveryId.equals(pubkey(0x01))).toBe(true);
		expect(decoded.creator.equals(pubkey(0x02))).toBe(true);
		expect(decoded.dwallet.equals(pubkey(0x03))).toBe(true);
		expect(decoded.dwalletCurve).toBe(2);
		expect(decoded.threshold).toBe(2);
		expect(decoded.approverOnlyBitmap).toBe(0b10);
		expect(decoded.proposalCount).toBe(7);
		expect(decoded.rosterChangeCount).toBe(3);
		expect(decoded.enrollmentCount).toBe(1);
		expect(decoded.members.length).toBe(2);
		expect(Array.from(decoded.members[0]!)).toEqual(Array.from(fillSlot(0xaa)));
		expect(Array.from(decoded.members[1]!)).toEqual(Array.from(fillSlot(0xbb)));
	});

	test('rejects wrong discriminator', () => {
		const buf = new Uint8Array(200);
		buf[0] = 99;
		expect(() => decodeRecovery(buf)).toThrow(/Recovery discriminator/);
	});

	test('rejects truncated buffer', () => {
		const buf = new Uint8Array(50);
		buf[0] = DISC_RECOVERY;
		expect(() => decodeRecovery(buf)).toThrow(/truncated/);
	});

	test('rejects member count > MAX_MEMBERS', () => {
		const fixed = 1 + 32 + 32 + 32 + 2 + 2 + 2 + 4 + 4 + 4;
		const buf = new Uint8Array(fixed + 2);
		buf[0] = DISC_RECOVERY;
		writeU16le(buf, fixed, MAX_MEMBERS + 1);
		expect(() => decodeRecovery(buf)).toThrow(/MAX_MEMBERS/);
	});

	test('handles empty member set', () => {
		const fixed = 1 + 32 + 32 + 32 + 2 + 2 + 2 + 4 + 4 + 4;
		const buf = new Uint8Array(fixed + 2);
		buf[0] = DISC_RECOVERY;
		// memberCount stays 0
		const decoded = decodeRecovery(buf);
		expect(decoded.members.length).toBe(0);
	});
});

describe('decodeProposal', () => {
	test('decodes a 2-tx proposal with full status', () => {
		const fixed = 1 + 32 + 4 + MEMBER_SLOT_LEN + 32 + 2 + 2 + 1 + 1;
		const buf = new Uint8Array(fixed + 2 + 64);
		let off = 0;
		buf[off++] = DISC_PROPOSAL;
		off = writeBytes(buf, off, pubkey(0x10).toBytes());
		off = writeU32le(buf, off, 42); // proposalIndex
		off = writeBytes(buf, off, fillSlot(0x11)); // proposerSlot
		off = writeBytes(buf, off, pubkey(0x12).toBytes()); // userPubkey
		off = writeU16le(buf, off, 1); // sigScheme = secp256k1
		off = writeU16le(buf, off, 3); // approvalCount
		buf[off++] = STATUS_APPROVED;
		buf[off++] = 0b01; // executedBitmap: first tx executed
		off = writeU16le(buf, off, 2); // digestCount
		const d0 = new Uint8Array(32).fill(0x21);
		const d1 = new Uint8Array(32).fill(0x22);
		off = writeBytes(buf, off, d0);
		off = writeBytes(buf, off, d1);

		const decoded = decodeProposal(buf);
		expect(decoded.recovery.equals(pubkey(0x10))).toBe(true);
		expect(decoded.proposalIndex).toBe(42);
		expect(decoded.signatureScheme).toBe(1);
		expect(decoded.approvalCount).toBe(3);
		expect(decoded.status).toBe(STATUS_APPROVED);
		expect(decoded.executedBitmap).toBe(0b01);
		expect(decoded.intentDigests.length).toBe(2);
		expect(Array.from(decoded.intentDigests[0]!)).toEqual(Array.from(d0));
		expect(Array.from(decoded.intentDigests[1]!)).toEqual(Array.from(d1));
		expect(decoded.userPubkey.length).toBe(32);
	});

	test('rejects wrong disc', () => {
		const buf = new Uint8Array(200);
		buf[0] = 99;
		expect(() => decodeProposal(buf)).toThrow(/Proposal disc/);
	});

	test('rejects truncated buffer', () => {
		const buf = new Uint8Array(30);
		buf[0] = DISC_PROPOSAL;
		expect(() => decodeProposal(buf)).toThrow(/truncated/);
	});

	test('rejects bundle > MAX_BUNDLE_PER_PROPOSAL', () => {
		const fixed = 1 + 32 + 4 + MEMBER_SLOT_LEN + 32 + 2 + 2 + 1 + 1;
		const buf = new Uint8Array(fixed + 2);
		buf[0] = DISC_PROPOSAL;
		writeU16le(buf, fixed, MAX_BUNDLE_PER_PROPOSAL + 1);
		expect(() => decodeProposal(buf)).toThrow(/MAX_BUNDLE_PER_PROPOSAL/);
	});

	test('empty bundle is accepted (STATUS_ACTIVE with 0 digests)', () => {
		const fixed = 1 + 32 + 4 + MEMBER_SLOT_LEN + 32 + 2 + 2 + 1 + 1;
		const buf = new Uint8Array(fixed + 2);
		buf[0] = DISC_PROPOSAL;
		// digestCount stays 0
		const decoded = decodeProposal(buf);
		expect(decoded.status).toBe(STATUS_ACTIVE);
		expect(decoded.intentDigests.length).toBe(0);
	});
});

describe('decodeRosterChangeProposal', () => {
	test('decodes 2 additions + 1 removal with threshold change', () => {
		const fixed = 1 + 32 + 4 + MEMBER_SLOT_LEN + 32 + 2 + 2 + 1 + 2 + 1;
		// tail: 2 (add count) + 2 slots + 2 (rm count) + 1 slot
		const buf = new Uint8Array(fixed + 2 + MEMBER_SLOT_LEN * 2 + 2 + MEMBER_SLOT_LEN);
		let off = 0;
		buf[off++] = DISC_ROSTER_CHANGE_PROPOSAL;
		off = writeBytes(buf, off, pubkey(0x10).toBytes());
		off = writeU32le(buf, off, 5);
		off = writeBytes(buf, off, fillSlot(0x11));
		off = writeBytes(buf, off, new Uint8Array(32).fill(0xff)); // payloadHash
		off = writeU16le(buf, off, 0b10); // bitmap
		off = writeU16le(buf, off, 3); // newThreshold
		buf[off++] = 1; // hasNewThreshold
		off = writeU16le(buf, off, 1); // approvalCount
		buf[off++] = STATUS_APPROVED;
		off = writeU16le(buf, off, 2); // additions count
		off = writeBytes(buf, off, fillSlot(0xa1));
		off = writeBytes(buf, off, fillSlot(0xa2));
		off = writeU16le(buf, off, 1); // removals count
		off = writeBytes(buf, off, fillSlot(0xb1));

		const decoded = decodeRosterChangeProposal(buf);
		expect(decoded.recovery.equals(pubkey(0x10))).toBe(true);
		expect(decoded.rosterChangeIndex).toBe(5);
		expect(decoded.newThreshold).toBe(3);
		expect(decoded.hasNewThreshold).toBe(1);
		expect(decoded.approvalCount).toBe(1);
		expect(decoded.status).toBe(STATUS_APPROVED);
		expect(decoded.additionApproverOnlyBitmap).toBe(0b10);
		expect(decoded.additions.length).toBe(2);
		expect(decoded.removals.length).toBe(1);
		expect(Array.from(decoded.payloadHash)).toEqual(Array.from(new Uint8Array(32).fill(0xff)));
	});

	test('rejects wrong disc', () => {
		const buf = new Uint8Array(200);
		buf[0] = 99;
		expect(() => decodeRosterChangeProposal(buf)).toThrow(/disc/);
	});

	test('rejects truncated', () => {
		const buf = new Uint8Array(10);
		buf[0] = DISC_ROSTER_CHANGE_PROPOSAL;
		expect(() => decodeRosterChangeProposal(buf)).toThrow(/truncated/);
	});

	test('rejects additions count > MAX_MEMBERS', () => {
		const fixed = 1 + 32 + 4 + MEMBER_SLOT_LEN + 32 + 2 + 2 + 1 + 2 + 1;
		const buf = new Uint8Array(fixed + 4);
		buf[0] = DISC_ROSTER_CHANGE_PROPOSAL;
		writeU16le(buf, fixed, MAX_MEMBERS + 1);
		expect(() => decodeRosterChangeProposal(buf)).toThrow(/MAX_MEMBERS/);
	});
});

describe('decodeEnrollmentProposal', () => {
	test('round-trips a fresh enrollment', () => {
		const len = 1 + 32 + 4 + MEMBER_SLOT_LEN + MEMBER_SLOT_LEN + 32 + 1 + 2 + 1;
		const buf = new Uint8Array(len);
		let off = 0;
		buf[off++] = DISC_ENROLLMENT_PROPOSAL;
		off = writeBytes(buf, off, pubkey(0x21).toBytes()); // recovery
		off = writeU32le(buf, off, 11);
		off = writeBytes(buf, off, fillSlot(0x33));
		off = writeBytes(buf, off, fillSlot(0x44));
		off = writeBytes(buf, off, pubkey(0x55).toBytes()); // encryption key addr
		buf[off++] = 1; // additionApproverOnly
		off = writeU16le(buf, off, 2); // approvalCount
		buf[off++] = STATUS_APPROVED;

		const decoded = decodeEnrollmentProposal(buf);
		expect(decoded.enrollmentIndex).toBe(11);
		expect(decoded.additionApproverOnly).toBe(1);
		expect(decoded.approvalCount).toBe(2);
		expect(decoded.status).toBe(STATUS_APPROVED);
		expect(decoded.newEncryptionKeyAddress.equals(pubkey(0x55))).toBe(true);
		expect(Array.from(decoded.proposerSlot)).toEqual(Array.from(fillSlot(0x33)));
		expect(Array.from(decoded.newMember)).toEqual(Array.from(fillSlot(0x44)));
	});

	test('rejects wrong disc', () => {
		const buf = new Uint8Array(200);
		buf[0] = 99;
		expect(() => decodeEnrollmentProposal(buf)).toThrow(/EnrollmentProposal/);
	});

	test('rejects truncated', () => {
		const buf = new Uint8Array(10);
		buf[0] = DISC_ENROLLMENT_PROPOSAL;
		expect(() => decodeEnrollmentProposal(buf)).toThrow(/truncated/);
	});
});

describe('approval decoders', () => {
	function buildApproval(disc: number, parent: number, member: number, count: number): Uint8Array {
		const buf = new Uint8Array(1 + 32 + 32 + 2);
		buf[0] = disc;
		buf.set(pubkey(parent).toBytes(), 1);
		buf.set(pubkey(member).toBytes(), 33);
		writeU16le(buf, 65, count);
		return buf;
	}

	test('decodeApproval round-trips', () => {
		const buf = buildApproval(DISC_APPROVAL, 0x10, 0x20, 4);
		const a = decodeApproval(buf);
		expect(a.proposal.equals(pubkey(0x10))).toBe(true);
		expect(a.memberIdHash.equals(pubkey(0x20))).toBe(true);
		expect(a.approvedAtCount).toBe(4);
	});

	test('decodeRosterChangeApproval round-trips', () => {
		const buf = buildApproval(DISC_ROSTER_CHANGE_APPROVAL, 0x11, 0x21, 6);
		const a = decodeRosterChangeApproval(buf);
		expect(a.rosterChange.equals(pubkey(0x11))).toBe(true);
		expect(a.memberIdHash.equals(pubkey(0x21))).toBe(true);
		expect(a.approvedAtCount).toBe(6);
	});

	test('decodeEnrollmentApproval round-trips', () => {
		const buf = buildApproval(DISC_ENROLLMENT_APPROVAL, 0x12, 0x22, 9);
		const a = decodeEnrollmentApproval(buf);
		expect(a.enrollment.equals(pubkey(0x12))).toBe(true);
		expect(a.memberIdHash.equals(pubkey(0x22))).toBe(true);
		expect(a.approvedAtCount).toBe(9);
	});

	test('rejects mismatched discs across approval types', () => {
		// An EnrollmentApproval buffer should not decode as a sweep Approval.
		const buf = buildApproval(DISC_ENROLLMENT_APPROVAL, 1, 2, 3);
		expect(() => decodeApproval(buf)).toThrow(/Approval disc/);
	});

	test('rejects truncated approval', () => {
		const buf = new Uint8Array(20);
		buf[0] = DISC_APPROVAL;
		expect(() => decodeApproval(buf)).toThrow(/truncated/);
	});
});

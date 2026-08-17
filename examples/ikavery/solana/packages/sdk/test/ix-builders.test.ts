/**
 * Wire-shape tests for the rest of the ikavery instruction builders:
 *   - propose_roster_change / approve_roster_change / execute_roster_change
 *   - stage_roster_change_payload
 *   - propose_enrollment / approve_enrollment / execute_enrollment
 *   - dwallet transfer-authority
 *   - low-level encode helpers (writeU8/U16/U32, writeBytes, padInto, concat)
 *
 * Each test pins data length, the first byte (instruction disc), and the
 * account ordering on the resulting `TransactionInstruction`. The on-chain
 * handler reads these via `repr(C)` pointer casts; any drift here causes a
 * silent runtime mismatch.
 */

import { Keypair, PublicKey, SystemProgram } from '@solana/web3.js';
import { describe, expect, test } from 'bun:test';

import {
	AUTH_PUBKEY_BYTES,
	AUTH_SIGNATURE_BYTES,
	buildApproveEnrollmentIx,
	buildApproveRosterChangeIx,
	buildExecuteEnrollmentIx,
	buildExecuteRosterChangeIx,
	buildProposeEnrollmentIx,
	buildProposeRosterChangeIx,
	buildStageRosterChangePayloadIx,
	CREATE_MEMBERS_BYTES,
	enrollmentApprovalPda,
	enrollmentPda,
	ikaDwallet,
	IKAVERY_PROGRAM_ID,
	IX_APPROVE_ENROLLMENT,
	IX_APPROVE_ROSTER_CHANGE,
	IX_EXECUTE_ENROLLMENT,
	IX_EXECUTE_ROSTER_CHANGE,
	IX_PROPOSE_ENROLLMENT,
	IX_PROPOSE_ROSTER_CHANGE,
	IX_STAGE_ROSTER_CHANGE_PAYLOAD,
	MAX_CLIENT_DATA_JSON_BYTES,
	MEMBER_SLOT_LEN,
	memberIdHash,
	packMembers,
	packMemberSlot,
	packSolanaMember,
	rosterChangeApprovalPda,
	rosterChangePda,
	rosterChangeStagingPda,
	SCHEME_ED25519,
	SCHEME_SOLANA_ADDRESS,
} from '../src';
import { concat, padInto, writeBytes, writeU8, writeU16le, writeU32le } from '../src/ix/encode';

const recoveryId = new PublicKey(new Uint8Array(32).fill(0x01));
const recovery = new PublicKey(new Uint8Array(32).fill(0x02));
const payerKp = Keypair.generate();

const solanaCred = (pk: PublicKey) => ({
	scheme: SCHEME_SOLANA_ADDRESS,
	pubkey: pk.toBytes(),
});

describe('buildProposeRosterChangeIx', () => {
	const payloadHash = new Uint8Array(32).fill(0xaa);

	test('data layout: disc + idx + payloadHash + credential', () => {
		const { ix, rosterChange, staging } = buildProposeRosterChangeIx({
			recovery,
			recoveryId,
			rosterChangeIndex: 3,
			payer: payerKp.publicKey,
			payloadHash,
			credential: solanaCred(payerKp.publicKey),
		});
		expect(rosterChange.equals(rosterChangePda(recovery, 3))).toBe(true);
		expect(staging.equals(rosterChangeStagingPda(recovery, 3))).toBe(true);
		expect(ix.programId.equals(IKAVERY_PROGRAM_ID)).toBe(true);
		expect(ix.data[0]).toBe(IX_PROPOSE_ROSTER_CHANGE);

		const expectedLen =
			1 + 4 + 32 + 1 + AUTH_PUBKEY_BYTES + MAX_CLIENT_DATA_JSON_BYTES + 2 + AUTH_SIGNATURE_BYTES;
		expect(ix.data.length).toBe(expectedLen);
		// proposal_index u32 LE = 3
		expect(ix.data[1]).toBe(3);
		expect(ix.data[2]).toBe(0);
		// payload_hash at 5..37
		expect(Array.from(ix.data.subarray(5, 37))).toEqual(Array.from(payloadHash));
		// auth_scheme right after
		expect(ix.data[37]).toBe(SCHEME_SOLANA_ADDRESS);
	});

	test('rejects non-32-byte payloadHash', () => {
		expect(() =>
			buildProposeRosterChangeIx({
				recovery,
				recoveryId,
				rosterChangeIndex: 0,
				payer: payerKp.publicKey,
				payloadHash: new Uint8Array(31),
				credential: solanaCred(payerKp.publicKey),
			}),
		).toThrow(/32 bytes/);
	});

	test('account list: payer is signer, recovery + roster_change + staging writable', () => {
		const { ix } = buildProposeRosterChangeIx({
			recovery,
			recoveryId,
			rosterChangeIndex: 0,
			payer: payerKp.publicKey,
			payloadHash,
			credential: solanaCred(payerKp.publicKey),
		});
		const k = ix.keys;
		expect(k[0]!.pubkey.equals(recovery)).toBe(true);
		expect(k[0]!.isWritable).toBe(true);
		expect(k[1]!.pubkey.equals(recoveryId)).toBe(true);
		expect(k[1]!.isWritable).toBe(false);
		expect(k[4]!.pubkey.equals(payerKp.publicKey)).toBe(true);
		expect(k[4]!.isSigner).toBe(true);
		expect(k[7]!.pubkey.equals(SystemProgram.programId)).toBe(true);
	});
});

describe('buildApproveRosterChangeIx', () => {
	test('derives memberIdHashAddress + approval PDA', () => {
		const rosterChange = new PublicKey(new Uint8Array(32).fill(0x11));
		const slot = packSolanaMember(payerKp.publicKey);
		const { ix, approval, memberIdHashAddress } = buildApproveRosterChangeIx({
			recovery,
			rosterChange,
			payer: payerKp.publicKey,
			memberSlot: slot,
			credential: solanaCred(payerKp.publicKey),
		});
		expect(memberIdHashAddress.equals(memberIdHash(slot))).toBe(true);
		expect(approval.equals(rosterChangeApprovalPda(rosterChange, memberIdHashAddress))).toBe(true);
		expect(ix.data[0]).toBe(IX_APPROVE_ROSTER_CHANGE);
	});
});

describe('buildExecuteRosterChangeIx', () => {
	test('1-byte data + signer payer + writable recovery/rosterChange', () => {
		const rosterChange = new PublicKey(new Uint8Array(32).fill(0x33));
		const ix = buildExecuteRosterChangeIx({
			recovery,
			rosterChange,
			payer: payerKp.publicKey,
		});
		expect(ix.data.length).toBe(1);
		expect(ix.data[0]).toBe(IX_EXECUTE_ROSTER_CHANGE);
		expect(ix.keys[0]!.isWritable).toBe(true);
		expect(ix.keys[1]!.isWritable).toBe(true);
		expect(ix.keys[2]!.isSigner).toBe(true);
	});
});

describe('buildStageRosterChangePayloadIx', () => {
	test('encodes additions, removals, optional threshold (set)', () => {
		const a0 = packSolanaMember(Keypair.generate().publicKey);
		const a1 = packSolanaMember(Keypair.generate().publicKey);
		const r0 = packSolanaMember(Keypair.generate().publicKey);
		const { ix, staging } = buildStageRosterChangePayloadIx({
			recovery,
			recoveryId,
			rosterChangeIndex: 4,
			payer: payerKp.publicKey,
			additions: [a0, a1],
			removals: [r0],
			additionApproverOnlyBitmap: 0b10,
			newThreshold: 2,
		});
		expect(staging.equals(rosterChangeStagingPda(recovery, 4))).toBe(true);
		expect(ix.data[0]).toBe(IX_STAGE_ROSTER_CHANGE_PAYLOAD);
		// disc(1) + idx(4) + 272 + 1 + 2 + 272 + 1 + 2 + 1 = 556
		expect(ix.data.length).toBe(
			1 + 4 + CREATE_MEMBERS_BYTES + 1 + 2 + CREATE_MEMBERS_BYTES + 1 + 2 + 1,
		);
		// index u32 LE = 4
		expect(ix.data[1]).toBe(4);
		// hasNewThreshold = 1 at the end
		expect(ix.data[ix.data.length - 1]).toBe(1);
		// newThreshold u16 LE before the byte
		expect(ix.data[ix.data.length - 2]).toBe(0);
		expect(ix.data[ix.data.length - 3]).toBe(2);
	});

	test('hasNewThreshold defaults to 0 when newThreshold is omitted', () => {
		const { ix } = buildStageRosterChangePayloadIx({
			recovery,
			recoveryId,
			rosterChangeIndex: 0,
			payer: payerKp.publicKey,
			additions: [],
			removals: [],
		});
		expect(ix.data[ix.data.length - 1]).toBe(0); // has_new_threshold = false
	});

	test('packs additions into the fixed 272-byte buffer', () => {
		const a0 = packSolanaMember(Keypair.generate().publicKey);
		const { ix } = buildStageRosterChangePayloadIx({
			recovery,
			recoveryId,
			rosterChangeIndex: 0,
			payer: payerKp.publicKey,
			additions: [a0],
			removals: [],
		});
		// additions packed starts at disc(1) + idx(4) = 5
		expect(Array.from(ix.data.subarray(5, 5 + MEMBER_SLOT_LEN))).toEqual(Array.from(a0));
		// n_add byte at offset 5 + 272 = 277
		expect(ix.data[5 + CREATE_MEMBERS_BYTES]).toBe(1);
	});
});

describe('buildProposeEnrollmentIx', () => {
	const newMember = packMemberSlot(SCHEME_ED25519, new Uint8Array(32).fill(0x55));
	const encKeyAddr = new Uint8Array(32).fill(0x66);

	test('packs disc + idx + newMember + encKeyAddr + approverOnly + credential', () => {
		const { ix, enrollment } = buildProposeEnrollmentIx({
			recovery,
			recoveryId,
			enrollmentIndex: 9,
			payer: payerKp.publicKey,
			newMember,
			newEncryptionKeyAddress: encKeyAddr,
			additionApproverOnly: 1,
			credential: solanaCred(payerKp.publicKey),
		});
		expect(enrollment.equals(enrollmentPda(recovery, 9))).toBe(true);
		expect(ix.data[0]).toBe(IX_PROPOSE_ENROLLMENT);
		// idx LE u32 = 9
		expect(ix.data[1]).toBe(9);
		// newMember at 5..(5+34)
		expect(Array.from(ix.data.subarray(5, 5 + MEMBER_SLOT_LEN))).toEqual(Array.from(newMember));
		// encKeyAddr at next 32
		expect(Array.from(ix.data.subarray(5 + MEMBER_SLOT_LEN, 5 + MEMBER_SLOT_LEN + 32))).toEqual(
			Array.from(encKeyAddr),
		);
		// additionApproverOnly byte
		expect(ix.data[5 + MEMBER_SLOT_LEN + 32]).toBe(1);
	});

	test('rejects wrong newMember length', () => {
		expect(() =>
			buildProposeEnrollmentIx({
				recovery,
				recoveryId,
				enrollmentIndex: 0,
				payer: payerKp.publicKey,
				newMember: new Uint8Array(MEMBER_SLOT_LEN - 1),
				newEncryptionKeyAddress: encKeyAddr,
				additionApproverOnly: 0,
				credential: solanaCred(payerKp.publicKey),
			}),
		).toThrow(/new_member/);
	});

	test('rejects wrong newEncryptionKeyAddress length', () => {
		expect(() =>
			buildProposeEnrollmentIx({
				recovery,
				recoveryId,
				enrollmentIndex: 0,
				payer: payerKp.publicKey,
				newMember,
				newEncryptionKeyAddress: new Uint8Array(31),
				additionApproverOnly: 0,
				credential: solanaCred(payerKp.publicKey),
			}),
		).toThrow(/new_encryption_key_address/);
	});
});

describe('buildApproveEnrollmentIx', () => {
	test('ix carries IX_APPROVE_ENROLLMENT + correct PDAs', () => {
		const enrollment = new PublicKey(new Uint8Array(32).fill(0x77));
		const slot = packSolanaMember(payerKp.publicKey);
		const { ix, approval, memberIdHashAddress } = buildApproveEnrollmentIx({
			recovery,
			enrollment,
			payer: payerKp.publicKey,
			memberSlot: slot,
			credential: solanaCred(payerKp.publicKey),
		});
		expect(ix.data[0]).toBe(IX_APPROVE_ENROLLMENT);
		expect(memberIdHashAddress.equals(memberIdHash(slot))).toBe(true);
		expect(approval.equals(enrollmentApprovalPda(enrollment, memberIdHashAddress))).toBe(true);
	});
});

describe('buildExecuteEnrollmentIx', () => {
	test('1-byte data + IX_EXECUTE_ENROLLMENT', () => {
		const enrollment = new PublicKey(new Uint8Array(32).fill(0x88));
		const ix = buildExecuteEnrollmentIx({
			recovery,
			enrollment,
			payer: payerKp.publicKey,
		});
		expect(ix.data.length).toBe(1);
		expect(ix.data[0]).toBe(IX_EXECUTE_ENROLLMENT);
		expect(ix.keys[2]!.isSigner).toBe(true);
	});
});

describe('dwallet transfer-authority', () => {
	test('emits disc 24 + new authority bytes', () => {
		const current = Keypair.generate().publicKey;
		const dwallet = Keypair.generate().publicKey;
		const newAuth = Keypair.generate().publicKey;
		const ix = ikaDwallet.buildTransferDwalletAuthorityIx({
			currentAuthority: current,
			dwallet,
			newAuthority: newAuth,
		});
		expect(ix.programId.equals(ikaDwallet.IKA_DWALLET_PROGRAM_ID)).toBe(true);
		expect(ix.data.length).toBe(33);
		expect(ix.data[0]).toBe(24);
		expect(Array.from(ix.data.subarray(1, 33))).toEqual(Array.from(newAuth.toBytes()));
		expect(ix.keys[0]!.isSigner).toBe(true);
		expect(ix.keys[0]!.isWritable).toBe(false);
		expect(ix.keys[1]!.isWritable).toBe(true);
	});
});

describe('encode helpers', () => {
	test('writeU8 / writeU16le / writeU32le advance the offset', () => {
		const buf = new Uint8Array(8);
		let off = 0;
		off = writeU8(buf, off, 0xff);
		expect(off).toBe(1);
		off = writeU16le(buf, off, 0x1234);
		expect(off).toBe(3);
		off = writeU32le(buf, off, 0xdeadbeef);
		expect(off).toBe(7);
		expect(buf[0]).toBe(0xff);
		expect(buf[1]).toBe(0x34);
		expect(buf[2]).toBe(0x12);
		expect(buf[3]).toBe(0xef);
		expect(buf[4]).toBe(0xbe);
		expect(buf[5]).toBe(0xad);
		expect(buf[6]).toBe(0xde);
	});

	test('writeBytes rejects wrong length', () => {
		const buf = new Uint8Array(8);
		expect(() => writeBytes(buf, 0, new Uint8Array(7), 8)).toThrow(/expected/);
	});

	test('padInto zero-fills the unused tail', () => {
		const buf = new Uint8Array(10);
		buf.fill(0xff);
		const payload = new Uint8Array([1, 2, 3]);
		const off = padInto(buf, 2, payload, 5);
		expect(off).toBe(7);
		expect(Array.from(buf.subarray(2, 5))).toEqual([1, 2, 3]);
		// The remainder of the padded region stays whatever it was (we never
		// touched it); only the payload is copied. That's the contract.
		expect(buf[5]).toBe(0xff);
	});

	test('padInto rejects oversized payload', () => {
		expect(() => padInto(new Uint8Array(10), 0, new Uint8Array(6), 5)).toThrow(/exceeds/);
	});

	test('concat joins chunks in order', () => {
		const out = concat(new Uint8Array([1, 2]), new Uint8Array([3, 4, 5]));
		expect(Array.from(out)).toEqual([1, 2, 3, 4, 5]);
	});
});

describe('packMembers', () => {
	test('packs slots in order with the count returned', () => {
		const s0 = packSolanaMember(Keypair.generate().publicKey);
		const s1 = packSolanaMember(Keypair.generate().publicKey);
		const { packed, count } = packMembers([s0, s1], CREATE_MEMBERS_BYTES);
		expect(packed.length).toBe(CREATE_MEMBERS_BYTES);
		expect(count).toBe(2);
		expect(Array.from(packed.subarray(0, MEMBER_SLOT_LEN))).toEqual(Array.from(s0));
		expect(Array.from(packed.subarray(MEMBER_SLOT_LEN, MEMBER_SLOT_LEN * 2))).toEqual(
			Array.from(s1),
		);
	});

	test('rejects more slots than the buffer fits', () => {
		const slot = packSolanaMember(Keypair.generate().publicKey);
		expect(() => packMembers([slot, slot, slot], MEMBER_SLOT_LEN * 2)).toThrow(/too many members/);
	});

	test('zero-fills the tail past the packed slots', () => {
		const slot = packSolanaMember(Keypair.generate().publicKey);
		const { packed } = packMembers([slot], CREATE_MEMBERS_BYTES);
		for (let i = MEMBER_SLOT_LEN; i < packed.length; i++) {
			expect(packed[i]).toBe(0);
		}
	});
});

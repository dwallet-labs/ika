import { Transaction } from '@mysten/sui/transactions';
import { describe, expect, test } from 'bun:test';

import {
	buildNewMembersVec,
	isApproverOnlyMember,
	memberIdBytes,
	newMemberToMoveArg,
	type NewMemberInput,
} from '../src/move/members';

const PKG = '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';
const PK_32 = new Uint8Array(32).fill(0x01);
const PK_33_K1 = new Uint8Array(33).fill(0x02);
const PK_33_R1 = new Uint8Array(33).fill(0x03);
const PK_33_WA = new Uint8Array(33).fill(0x04);

describe('buildNewMembersVec', () => {
	test('builds N+1 commands (one per member + the makeMoveVec)', () => {
		const tx = new Transaction();
		const members: NewMemberInput[] = [
			{ scheme: 'ed25519', publicKey: PK_32 },
			{ scheme: 'secp256k1', publicKey: PK_33_K1 },
			{ scheme: 'secp256r1', publicKey: PK_33_R1 },
			{ scheme: 'webauthn', publicKey: PK_33_WA },
		];
		buildNewMembersVec(tx, PKG, members);
		const data = tx.getData();
		const moveCalls = data.commands.filter((c) => c.$kind === 'MoveCall');
		const makeVecs = data.commands.filter((c) => c.$kind === 'MakeMoveVec');
		expect(moveCalls.length).toBe(4);
		expect(makeVecs.length).toBe(1);
	});

	test('dispatches to the correct auth::new_*_member function per scheme', () => {
		const tx = new Transaction();
		buildNewMembersVec(tx, PKG, [
			{ scheme: 'ed25519', publicKey: PK_32 },
			{ scheme: 'secp256k1', publicKey: PK_33_K1 },
			{ scheme: 'secp256r1', publicKey: PK_33_R1 },
			{ scheme: 'webauthn', publicKey: PK_33_WA },
		]);
		const moveCalls = tx.getData().commands.filter((c) => c.$kind === 'MoveCall');
		const fns = moveCalls.map((c) => c.MoveCall!.function);
		expect(fns).toEqual([
			'new_ed25519_member',
			'new_secp256k1_member',
			'new_secp256r1_member',
			'new_webauthn_member',
		]);
		for (const c of moveCalls) {
			expect(c.MoveCall!.module).toBe('auth');
			expect(c.MoveCall!.package).toBe(PKG);
		}
	});

	test('uses the configured package id in the MakeMoveVec type tag', () => {
		const tx = new Transaction();
		buildNewMembersVec(tx, PKG, [{ scheme: 'ed25519', publicKey: PK_32 }]);
		const makeVec = tx.getData().commands.find((c) => c.$kind === 'MakeMoveVec');
		expect(makeVec?.MakeMoveVec?.type).toBe(`${PKG}::auth::NewMember`);
	});

	test('empty list produces an empty vec command', () => {
		const tx = new Transaction();
		buildNewMembersVec(tx, PKG, []);
		const data = tx.getData();
		const moveCalls = data.commands.filter((c) => c.$kind === 'MoveCall');
		const makeVecs = data.commands.filter((c) => c.$kind === 'MakeMoveVec');
		expect(moveCalls.length).toBe(0);
		expect(makeVecs.length).toBe(1);
	});
});

describe('memberIdBytes', () => {
	test('prefixes scheme byte to public key', () => {
		expect(Array.from(memberIdBytes({ scheme: 'ed25519', publicKey: PK_32 }))).toEqual([
			0,
			...Array.from(PK_32),
		]);
		expect(Array.from(memberIdBytes({ scheme: 'secp256k1', publicKey: PK_33_K1 }))).toEqual([
			1,
			...Array.from(PK_33_K1),
		]);
		expect(Array.from(memberIdBytes({ scheme: 'secp256r1', publicKey: PK_33_R1 }))).toEqual([
			2,
			...Array.from(PK_33_R1),
		]);
		expect(Array.from(memberIdBytes({ scheme: 'webauthn', publicKey: PK_33_WA }))).toEqual([
			3,
			...Array.from(PK_33_WA),
		]);
	});

	test('sender_address yields [4, ...address_bytes] (33 bytes)', () => {
		const addr = '0x0000000000000000000000000000000000000000000000000000000000000007';
		const id = memberIdBytes({ scheme: 'sender_address', address: addr });
		expect(id.length).toBe(33);
		expect(id[0]).toBe(4);
		// last byte should be 0x07 since address is mostly zeros + trailing 7
		expect(id[32]).toBe(0x07);
	});

	test('sender_address pads short addresses by prepending zeros', () => {
		const id = memberIdBytes({ scheme: 'sender_address', address: '0x7' });
		expect(id.length).toBe(33);
		expect(id[0]).toBe(4);
		// 0x7 padded to 64 hex chars → 32 bytes of which only the last is 0x07.
		expect(id[32]).toBe(0x07);
		for (let i = 1; i < 32; i++) expect(id[i]).toBe(0);
	});

	test('rejects address longer than 32 bytes', () => {
		// 65-hex-char string can't be left-padded to fit 32 bytes.
		const oversized = '0x' + 'ab'.repeat(33);
		expect(() => memberIdBytes({ scheme: 'sender_address', address: oversized })).toThrow(
			/invalid Sui address/,
		);
	});
});

describe('isApproverOnlyMember', () => {
	test('true for sender_address scheme', () => {
		expect(isApproverOnlyMember({ scheme: 'sender_address', address: '0x1' })).toBe(true);
	});
	test('false for every key-holding scheme', () => {
		expect(isApproverOnlyMember({ scheme: 'ed25519', publicKey: PK_32 })).toBe(false);
		expect(isApproverOnlyMember({ scheme: 'secp256k1', publicKey: PK_33_K1 })).toBe(false);
		expect(isApproverOnlyMember({ scheme: 'secp256r1', publicKey: PK_33_R1 })).toBe(false);
		expect(isApproverOnlyMember({ scheme: 'webauthn', publicKey: PK_33_WA })).toBe(false);
	});
});

describe('newMemberToMoveArg sender path', () => {
	test('dispatches to auth::new_sender_member with the address arg', () => {
		const tx = new Transaction();
		newMemberToMoveArg(tx, PKG, {
			scheme: 'sender_address',
			address: '0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
		});
		const moveCalls = tx.getData().commands.filter((c) => c.$kind === 'MoveCall');
		expect(moveCalls.length).toBe(1);
		expect(moveCalls[0]!.MoveCall!.function).toBe('new_sender_member');
		expect(moveCalls[0]!.MoveCall!.module).toBe('auth');
	});
});

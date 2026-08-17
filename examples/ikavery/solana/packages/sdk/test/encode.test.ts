import { Keypair, PublicKey } from '@solana/web3.js';
import { describe, expect, test } from 'bun:test';

import {
	AUTH_PUBKEY_BYTES,
	AUTH_SIGNATURE_BYTES,
	buildApproveIx,
	buildCreateRecoveryIx,
	buildProposeIx,
	CREATE_MEMBERS_BYTES,
	IX_APPROVE,
	IX_CREATE_RECOVERY,
	IX_PROPOSE,
	MAX_CLIENT_DATA_JSON_BYTES,
	MEMBER_SLOT_LEN,
	packMemberSlot,
	packSolanaMember,
	SCHEME_ED25519,
	SCHEME_SOLANA_ADDRESS,
} from '../src';

const dwallet32 = new Uint8Array(32).fill(0xab);
const userPubkey = new Uint8Array(32).fill(0xcd);

describe('create_recovery encoding', () => {
	test('data layout: disc + dwallet + curve + threshold + count + bitmap + members', () => {
		const creator = Keypair.generate();
		const recoveryId = Keypair.generate();
		const memberSlot = packSolanaMember(creator.publicKey);

		const { ix } = buildCreateRecoveryIx({
			creator: creator.publicKey,
			recoveryId: recoveryId.publicKey,
			dwallet: dwallet32,
			dwalletCurve: 2, // ed25519
			threshold: 1,
			members: [memberSlot],
		});

		expect(ix.data.length).toBe(1 + 32 + 2 + 2 + 1 + 2 + CREATE_MEMBERS_BYTES);
		expect(ix.data[0]).toBe(IX_CREATE_RECOVERY);
		expect(Array.from(ix.data.slice(1, 33))).toEqual(Array.from(dwallet32));
		// curve = 2 LE
		expect(ix.data[33]).toBe(2);
		expect(ix.data[34]).toBe(0);
		// threshold = 1 LE
		expect(ix.data[35]).toBe(1);
		expect(ix.data[36]).toBe(0);
		// member_count = 1
		expect(ix.data[37]).toBe(1);
		// approver_only_bitmap = 0 LE
		expect(ix.data[38]).toBe(0);
		expect(ix.data[39]).toBe(0);
		// First member slot at offset 40
		const slotStart = 40;
		expect(ix.data[slotStart]).toBe(SCHEME_SOLANA_ADDRESS);
		expect(Array.from(ix.data.slice(slotStart + 1, slotStart + 33))).toEqual(
			Array.from(creator.publicKey.toBytes()),
		);
	});

	test('rejects threshold > member count', () => {
		const creator = Keypair.generate();
		expect(() =>
			buildCreateRecoveryIx({
				creator: creator.publicKey,
				recoveryId: Keypair.generate().publicKey,
				dwallet: dwallet32,
				dwalletCurve: 0,
				threshold: 2,
				members: [packSolanaMember(creator.publicKey)],
			}),
		).toThrow();
	});

	test('rejects empty member list', () => {
		expect(() =>
			buildCreateRecoveryIx({
				creator: Keypair.generate().publicKey,
				recoveryId: Keypair.generate().publicKey,
				dwallet: dwallet32,
				dwalletCurve: 0,
				threshold: 1,
				members: [],
			}),
		).toThrow();
	});
});

describe('propose encoding', () => {
	test('data layout starts with disc + proposal_index LE + packed digests', () => {
		const proposer = Keypair.generate();
		const recovery = new PublicKey(new Uint8Array(32).fill(1));
		const recoveryId = new PublicKey(new Uint8Array(32).fill(2));
		const digest0 = new Uint8Array(32).fill(0x42);

		const { ix } = buildProposeIx({
			recovery,
			recoveryId,
			proposalIndex: 7,
			proposer: proposer.publicKey,
			intentDigests: [digest0],
			userPubkey,
			signatureScheme: 0,
			credential: {
				scheme: SCHEME_SOLANA_ADDRESS,
				pubkey: proposer.publicKey.toBytes(),
			},
		});

		expect(ix.data[0]).toBe(IX_PROPOSE);
		// proposal_index = 7 LE u32
		expect(ix.data[1]).toBe(7);
		expect(ix.data[2]).toBe(0);
		expect(ix.data[3]).toBe(0);
		expect(ix.data[4]).toBe(0);
		// digest_0 occupies bytes 5..37 of the packed digest buffer.
		expect(Array.from(ix.data.slice(5, 37))).toEqual(Array.from(digest0));
		// digest_count after the 256-byte digest buffer (offset 5+256 = 261)
		expect(ix.data[261]).toBe(1);
		// user_pubkey at 262..294
		expect(Array.from(ix.data.slice(262, 294))).toEqual(Array.from(userPubkey));
	});

	test('rejects empty bundle', () => {
		expect(() =>
			buildProposeIx({
				recovery: new PublicKey(new Uint8Array(32).fill(1)),
				recoveryId: new PublicKey(new Uint8Array(32).fill(2)),
				proposalIndex: 0,
				proposer: Keypair.generate().publicKey,
				intentDigests: [],
				userPubkey,
				signatureScheme: 0,
				credential: {
					scheme: SCHEME_SOLANA_ADDRESS,
					pubkey: new Uint8Array(32),
				},
			}),
		).toThrow(/at least one/);
	});

	test('rejects bundle > MAX_BUNDLE_PER_PROPOSAL', () => {
		const tooMany = Array.from({ length: 9 }, () => new Uint8Array(32));
		expect(() =>
			buildProposeIx({
				recovery: new PublicKey(new Uint8Array(32).fill(1)),
				recoveryId: new PublicKey(new Uint8Array(32).fill(2)),
				proposalIndex: 0,
				proposer: Keypair.generate().publicKey,
				intentDigests: tooMany,
				userPubkey,
				signatureScheme: 0,
				credential: {
					scheme: SCHEME_SOLANA_ADDRESS,
					pubkey: new Uint8Array(32),
				},
			}),
		).toThrow(/MAX_BUNDLE_PER_PROPOSAL/);
	});

	test('rejects digest with non-32-byte length', () => {
		expect(() =>
			buildProposeIx({
				recovery: new PublicKey(new Uint8Array(32).fill(1)),
				recoveryId: new PublicKey(new Uint8Array(32).fill(2)),
				proposalIndex: 0,
				proposer: Keypair.generate().publicKey,
				intentDigests: [new Uint8Array(31)],
				userPubkey,
				signatureScheme: 0,
				credential: {
					scheme: SCHEME_SOLANA_ADDRESS,
					pubkey: new Uint8Array(32),
				},
			}),
		).toThrow(/32 bytes/);
	});

	test('rejects non-32-byte userPubkey', () => {
		expect(() =>
			buildProposeIx({
				recovery: new PublicKey(new Uint8Array(32).fill(1)),
				recoveryId: new PublicKey(new Uint8Array(32).fill(2)),
				proposalIndex: 0,
				proposer: Keypair.generate().publicKey,
				intentDigests: [new Uint8Array(32)],
				userPubkey: new Uint8Array(31),
				signatureScheme: 0,
				credential: {
					scheme: SCHEME_SOLANA_ADDRESS,
					pubkey: new Uint8Array(32),
				},
			}),
		).toThrow(/user_pubkey/);
	});
});

describe('approve encoding', () => {
	test('data layout: disc + auth_scheme + auth_pubkey + cdj + cdj_len + sig', () => {
		const member = Keypair.generate();
		const recovery = new PublicKey(new Uint8Array(32).fill(1));
		const proposal = new PublicKey(new Uint8Array(32).fill(2));
		const slot = packSolanaMember(member.publicKey);

		const { ix } = buildApproveIx({
			recovery,
			proposal,
			payer: member.publicKey,
			memberSlot: slot,
			credential: {
				scheme: SCHEME_SOLANA_ADDRESS,
				pubkey: member.publicKey.toBytes(),
			},
		});

		const expectedLen =
			1 + 1 + AUTH_PUBKEY_BYTES + MAX_CLIENT_DATA_JSON_BYTES + 2 + AUTH_SIGNATURE_BYTES;
		expect(ix.data.length).toBe(expectedLen);
		expect(ix.data[0]).toBe(IX_APPROVE);
		expect(ix.data[1]).toBe(SCHEME_SOLANA_ADDRESS);
		// auth_pubkey starts at 2; first 32 bytes are the address, rest is zero pad
		expect(Array.from(ix.data.slice(2, 34))).toEqual(Array.from(member.publicKey.toBytes()));
		expect(ix.data[34]).toBe(0); // 33rd byte of pubkey buffer is pad
		// cdj_len at offset 1+1+33+256 = 291
		expect(ix.data[291]).toBe(0);
		expect(ix.data[292]).toBe(0);
	});
});

describe('credential edge cases', () => {
	test('ed25519 credential pads pubkey from 32 to 33 bytes', () => {
		const member = Keypair.generate();
		const slot = packMemberSlot(SCHEME_ED25519, member.publicKey.toBytes());
		expect(slot.length).toBe(MEMBER_SLOT_LEN);
		expect(slot[0]).toBe(SCHEME_ED25519);
	});

	test('rejects mismatched pubkey length for scheme', () => {
		expect(() => packMemberSlot(SCHEME_ED25519, new Uint8Array(33))).toThrow();
	});
});

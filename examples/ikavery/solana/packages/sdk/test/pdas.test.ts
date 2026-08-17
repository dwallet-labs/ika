/**
 * Unit tests for PDA derivation in `src/pda.ts` and `src/dwallet/pdas.ts`.
 *
 * `PublicKey.findProgramAddressSync` is deterministic but we don't ship the
 * Rust-side reference values inline, so each test asserts the two universal
 * invariants: (a) same inputs → same address (call twice), (b) different
 * inputs → different addresses (no collisions across the parameter space).
 * Off-curve membership is implicit — `findProgramAddressSync` only returns
 * off-curve points by construction.
 */

import { Keypair, PublicKey } from '@solana/web3.js';
import { describe, expect, test } from 'bun:test';

import {
	approvalPda,
	enrollmentApprovalPda,
	enrollmentPda,
	ikaDwallet,
	IKAVERY_PROGRAM_ID,
	memberIdHash,
	packMemberSlot,
	packSolanaMember,
	proposalPda,
	recoveryPda,
	rosterChangeApprovalPda,
	rosterChangePda,
	rosterChangeStagingPda,
	SCHEME_ED25519,
	SCHEME_SOLANA_ADDRESS,
} from '../src';

const {
	CURVE_CURVE25519,
	CURVE_SECP256K1,
	IKA_DWALLET_PROGRAM_ID,
	coordinatorPda,
	cpiAuthorityPda,
	dwalletPda,
	messageApprovalPda,
	packDwalletSeedPayload,
} = ikaDwallet;

const recId = new PublicKey(new Uint8Array(32).fill(0xaa));
const otherRecId = new PublicKey(new Uint8Array(32).fill(0xbb));

describe('recoveryPda', () => {
	test('deterministic across calls', () => {
		expect(recoveryPda(recId).equals(recoveryPda(recId))).toBe(true);
	});

	test('different recoveryIds yield different PDAs', () => {
		expect(recoveryPda(recId).equals(recoveryPda(otherRecId))).toBe(false);
	});
});

describe('proposalPda / rosterChangePda / rosterChangeStagingPda / enrollmentPda', () => {
	const recovery = recoveryPda(recId);

	test('proposalPda varies with index', () => {
		expect(proposalPda(recovery, 0).equals(proposalPda(recovery, 0))).toBe(true);
		expect(proposalPda(recovery, 0).equals(proposalPda(recovery, 1))).toBe(false);
	});

	test('proposalPda varies with recovery', () => {
		const other = recoveryPda(otherRecId);
		expect(proposalPda(recovery, 5).equals(proposalPda(other, 5))).toBe(false);
	});

	test('rosterChangePda independent from proposalPda for same index', () => {
		// Different seed prefixes (SEED_PROPOSAL vs SEED_ROSTER) must give
		// different PDAs — otherwise two different account kinds could collide.
		expect(proposalPda(recovery, 3).equals(rosterChangePda(recovery, 3))).toBe(false);
	});

	test('rosterChangeStagingPda independent from rosterChangePda', () => {
		expect(rosterChangePda(recovery, 0).equals(rosterChangeStagingPda(recovery, 0))).toBe(false);
	});

	test('enrollmentPda varies with index', () => {
		expect(enrollmentPda(recovery, 0).equals(enrollmentPda(recovery, 0))).toBe(true);
		expect(enrollmentPda(recovery, 0).equals(enrollmentPda(recovery, 99))).toBe(false);
	});

	test('enrollmentPda independent from proposalPda for same index', () => {
		expect(enrollmentPda(recovery, 0).equals(proposalPda(recovery, 0))).toBe(false);
	});
});

describe('memberIdHash + approval PDAs', () => {
	test('memberIdHash is deterministic per slot', () => {
		const slot = packSolanaMember(new PublicKey(new Uint8Array(32).fill(1)));
		expect(memberIdHash(slot).equals(memberIdHash(slot))).toBe(true);
	});

	test('memberIdHash differs across schemes even with same raw bytes', () => {
		const raw = new Uint8Array(32).fill(0x42);
		const a = memberIdHash(packMemberSlot(SCHEME_SOLANA_ADDRESS, raw));
		const b = memberIdHash(packMemberSlot(SCHEME_ED25519, raw));
		expect(a.equals(b)).toBe(false);
	});

	test('memberIdHash ignores zero-padding past canonical id', () => {
		// packSolanaMember zero-pads to 34 bytes; flipping a pad byte must not
		// change the hash since memberIdBytes slices to the canonical id length.
		const slot1 = packSolanaMember(new PublicKey(new Uint8Array(32).fill(7)));
		const slot2 = new Uint8Array(slot1);
		slot2[33] = 0xff;
		expect(memberIdHash(slot1).equals(memberIdHash(slot2))).toBe(true);
	});

	test('approvalPda independent from rosterChangeApprovalPda + enrollmentApprovalPda', () => {
		const parent = new PublicKey(new Uint8Array(32).fill(9));
		const member = new PublicKey(new Uint8Array(32).fill(0xcc));
		const a = approvalPda(parent, member);
		const b = rosterChangeApprovalPda(parent, member);
		const c = enrollmentApprovalPda(parent, member);
		expect(a.equals(b)).toBe(false);
		expect(a.equals(c)).toBe(false);
		expect(b.equals(c)).toBe(false);
	});

	test('approvalPda varies with proposal', () => {
		const m = new PublicKey(new Uint8Array(32).fill(0xcc));
		const p1 = new PublicKey(new Uint8Array(32).fill(1));
		const p2 = new PublicKey(new Uint8Array(32).fill(2));
		expect(approvalPda(p1, m).equals(approvalPda(p2, m))).toBe(false);
	});

	test('approvalPda varies with member', () => {
		const p = new PublicKey(new Uint8Array(32).fill(1));
		const m1 = new PublicKey(new Uint8Array(32).fill(0xcc));
		const m2 = new PublicKey(new Uint8Array(32).fill(0xdd));
		expect(approvalPda(p, m1).equals(approvalPda(p, m2))).toBe(false);
	});
});

describe('dwallet PDA helpers', () => {
	test('packDwalletSeedPayload prepends curve LE', () => {
		const pk = new Uint8Array(32).fill(0x42);
		const payload = packDwalletSeedPayload(CURVE_CURVE25519, pk);
		expect(payload.length).toBe(34);
		expect(payload[0]).toBe(CURVE_CURVE25519);
		expect(payload[1]).toBe(0);
		expect(Array.from(payload.subarray(2))).toEqual(Array.from(pk));
	});

	test('packDwalletSeedPayload masks curve to u16 LE', () => {
		const pk = new Uint8Array(2);
		const payload = packDwalletSeedPayload(0x1234, pk);
		expect(payload[0]).toBe(0x34);
		expect(payload[1]).toBe(0x12);
	});

	test('dwalletPda is deterministic + varies with curve and pubkey', () => {
		const pk = new Uint8Array(32).fill(0x01);
		const a = dwalletPda(CURVE_CURVE25519, pk);
		const b = dwalletPda(CURVE_CURVE25519, pk);
		expect(a.pda.equals(b.pda)).toBe(true);
		expect(a.bump).toBe(b.bump);

		// Different curve, same pubkey.
		const c = dwalletPda(CURVE_SECP256K1, pk);
		expect(a.pda.equals(c.pda)).toBe(false);

		// Same curve, different pubkey.
		const other = new Uint8Array(32).fill(0x02);
		const d = dwalletPda(CURVE_CURVE25519, other);
		expect(a.pda.equals(d.pda)).toBe(false);
	});

	test('dwalletPda handles SECP256K1 (33-byte pubkey: single 32+1 chunked seed)', () => {
		const pk = new Uint8Array(33).fill(0xab);
		const { pda } = dwalletPda(CURVE_SECP256K1, pk);
		// Just assert it computed something — chunking covers the payload > 32 path.
		expect(pda).toBeInstanceOf(PublicKey);
	});

	test('messageApprovalPda rejects non-32-byte digest', () => {
		expect(() =>
			messageApprovalPda(CURVE_CURVE25519, new Uint8Array(32), 0, new Uint8Array(16)),
		).toThrow(/32 bytes/);
	});

	test('messageApprovalPda varies with signatureScheme and message digest', () => {
		const pk = new Uint8Array(32).fill(0x01);
		const digest = new Uint8Array(32).fill(0xee);
		const a = messageApprovalPda(CURVE_CURVE25519, pk, 5, digest);
		const b = messageApprovalPda(CURVE_CURVE25519, pk, 6, digest);
		const otherDigest = new Uint8Array(32).fill(0xff);
		const c = messageApprovalPda(CURVE_CURVE25519, pk, 5, otherDigest);
		expect(a.pda.equals(b.pda)).toBe(false);
		expect(a.pda.equals(c.pda)).toBe(false);
	});

	test('coordinatorPda is a singleton constant', () => {
		const a = coordinatorPda();
		const b = coordinatorPda();
		expect(a.pda.equals(b.pda)).toBe(true);
		expect(a.bump).toBe(b.bump);
	});

	test('cpiAuthorityPda differs per caller program', () => {
		const callerA = Keypair.generate().publicKey;
		const callerB = Keypair.generate().publicKey;
		const a = cpiAuthorityPda(callerA);
		const b = cpiAuthorityPda(callerB);
		expect(a.pda.equals(b.pda)).toBe(false);
	});

	test('constants are stable', () => {
		expect(IKAVERY_PROGRAM_ID.toBase58()).toBe('4ZrXgy2Grv9RH3gWF7mksQvRqSUgc4atQyhcss569fw7');
		expect(IKA_DWALLET_PROGRAM_ID.toBase58()).toBe('87W54kGYFQ1rgWqMeu4XTPHWXWmXSQCcjm8vCTfiq1oY');
	});
});

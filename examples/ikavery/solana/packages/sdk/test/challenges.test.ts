/**
 * Unit tests for operation-bound challenge derivation in
 * `src/passkey/challenges.ts`. These are byte-for-byte mirrors of the Rust
 * `auth::challenges` module — any drift between TS and Rust here is a
 * silent auth bypass at signing time. We hash by hand for every tag to
 * pin the wire format and verify the helper agrees.
 */

import { sha256 } from '@noble/hashes/sha256';
import { describe, expect, test } from 'bun:test';

import {
	approveChallenge,
	bundleHash,
	bundleHashFromDigests,
	enrollApproveChallenge,
	enrollProposeChallenge,
	executeChallenge,
	MAX_BUNDLE_MESSAGES,
	proposeChallenge,
	rosterChangeApproveChallenge,
	rosterChangePayloadHash,
	rosterChangeProposeChallenge,
} from '../src/passkey/challenges';

const enc = new TextEncoder();

function u64le(n: number | bigint): Uint8Array {
	const out = new Uint8Array(8);
	new DataView(out.buffer).setBigUint64(0, BigInt(n), true);
	return out;
}

function cat(...parts: Uint8Array[]): Uint8Array {
	let total = 0;
	for (const p of parts) total += p.length;
	const out = new Uint8Array(total);
	let off = 0;
	for (const p of parts) {
		out.set(p, off);
		off += p.length;
	}
	return out;
}

const recId = new Uint8Array(32).fill(0xab);

describe('bundleHash', () => {
	test('0 messages = sha256(u64le(0))', () => {
		const expected = sha256(u64le(0));
		expect(Array.from(bundleHash([]))).toEqual(Array.from(expected));
	});

	test('1 message = sha256(u64le(1) || sha256(msg))', () => {
		const msg = enc.encode('hello world');
		const expected = sha256(cat(u64le(1), sha256(msg)));
		expect(Array.from(bundleHash([msg]))).toEqual(Array.from(expected));
	});

	test('2 messages = sha256(u64le(2) || sha256(m0) || sha256(m1))', () => {
		const m0 = enc.encode('first');
		const m1 = enc.encode('second');
		const expected = sha256(cat(u64le(2), sha256(m0), sha256(m1)));
		expect(Array.from(bundleHash([m0, m1]))).toEqual(Array.from(expected));
	});

	test('rejects bundle larger than cap', () => {
		const big = Array.from({ length: MAX_BUNDLE_MESSAGES + 1 }, () => new Uint8Array(1));
		expect(() => bundleHash(big)).toThrow(/exceeds cap/);
	});

	test('accepts exactly MAX_BUNDLE_MESSAGES', () => {
		const max = Array.from({ length: MAX_BUNDLE_MESSAGES }, () => new Uint8Array([1]));
		expect(bundleHash(max).length).toBe(32);
	});
});

describe('bundleHashFromDigests', () => {
	test('equals bundleHash when digests = sha256(msgs)', () => {
		const m0 = enc.encode('a');
		const m1 = enc.encode('b');
		const direct = bundleHash([m0, m1]);
		const fromDigests = bundleHashFromDigests([sha256(m0), sha256(m1)]);
		expect(Array.from(direct)).toEqual(Array.from(fromDigests));
	});

	test('rejects non-32-byte digest', () => {
		expect(() => bundleHashFromDigests([new Uint8Array(31)])).toThrow(/32 bytes/);
	});

	test('rejects bundle larger than cap', () => {
		const big = Array.from({ length: MAX_BUNDLE_MESSAGES + 1 }, () => new Uint8Array(32));
		expect(() => bundleHashFromDigests(big)).toThrow(/> cap/);
	});
});

describe('propose / approve / execute challenges', () => {
	test("propose: sha256('recovery::propose' || recId || bundleHash || nonce_le)", () => {
		const bh = sha256(enc.encode('bundle'));
		const expected = sha256(cat(enc.encode('recovery::propose'), recId, bh, u64le(42)));
		expect(Array.from(proposeChallenge(recId, bh, 42))).toEqual(Array.from(expected));
	});

	test("approve: sha256('recovery::approve' || recId || proposalId_le)", () => {
		const expected = sha256(cat(enc.encode('recovery::approve'), recId, u64le(7n)));
		expect(Array.from(approveChallenge(recId, 7n))).toEqual(Array.from(expected));
	});

	test("execute: sha256('recovery::execute' || recId || proposalId_le)", () => {
		const expected = sha256(cat(enc.encode('recovery::execute'), recId, u64le(11)));
		expect(Array.from(executeChallenge(recId, 11))).toEqual(Array.from(expected));
	});

	test('propose, approve, execute disagree at same recovery + counter', () => {
		const bh = new Uint8Array(32);
		const p = proposeChallenge(recId, bh, 0);
		const a = approveChallenge(recId, 0);
		const e = executeChallenge(recId, 0);
		expect(Array.from(p)).not.toEqual(Array.from(a));
		expect(Array.from(a)).not.toEqual(Array.from(e));
		expect(Array.from(p)).not.toEqual(Array.from(e));
	});

	test('approve varies with proposalId', () => {
		expect(Array.from(approveChallenge(recId, 0))).not.toEqual(
			Array.from(approveChallenge(recId, 1)),
		);
	});

	test('approve varies with recoveryId', () => {
		const otherId = new Uint8Array(32).fill(0xcd);
		expect(Array.from(approveChallenge(recId, 0))).not.toEqual(
			Array.from(approveChallenge(otherId, 0)),
		);
	});

	test('propose challenge is 32 bytes', () => {
		expect(proposeChallenge(recId, new Uint8Array(32), 0).length).toBe(32);
	});

	test('approve accepts bigint and number nonce equivalently', () => {
		expect(Array.from(approveChallenge(recId, 5))).toEqual(Array.from(approveChallenge(recId, 5n)));
	});
});

describe('enrollment challenges', () => {
	test("enroll_propose: sha256('recovery::enroll_propose' || recId || newPk || nonce_le)", () => {
		const newPk = new Uint8Array([1, 2, 3, 4]);
		const expected = sha256(cat(enc.encode('recovery::enroll_propose'), recId, newPk, u64le(99)));
		expect(Array.from(enrollProposeChallenge(recId, newPk, 99))).toEqual(Array.from(expected));
	});

	test("enroll_approve: sha256('recovery::enroll_approve' || recId || id_le)", () => {
		const expected = sha256(cat(enc.encode('recovery::enroll_approve'), recId, u64le(3n)));
		expect(Array.from(enrollApproveChallenge(recId, 3n))).toEqual(Array.from(expected));
	});

	test('enroll_propose disagrees with propose at the same nonce', () => {
		const newPk = new Uint8Array([1, 2]);
		expect(Array.from(enrollProposeChallenge(recId, newPk, 0))).not.toEqual(
			Array.from(proposeChallenge(recId, sha256(newPk), 0)),
		);
	});
});

describe('roster-change challenges', () => {
	test('payloadHash: empty removals, no threshold', () => {
		const expected = sha256(cat(u64le(0), u64le(0), new Uint8Array([0])));
		expect(Array.from(rosterChangePayloadHash([], 0, false))).toEqual(Array.from(expected));
	});

	test('payloadHash: 1 removal + threshold=2', () => {
		const id = new Uint8Array([0, 1, 2, 3, 4]);
		const expected = sha256(cat(u64le(1), u64le(id.length), id, u64le(2), new Uint8Array([1])));
		expect(Array.from(rosterChangePayloadHash([id], 2, true))).toEqual(Array.from(expected));
	});

	test('payloadHash: hasNewThreshold byte differs even when threshold value matches', () => {
		const id = new Uint8Array([7]);
		const a = rosterChangePayloadHash([id], 0, false);
		const b = rosterChangePayloadHash([id], 0, true);
		expect(Array.from(a)).not.toEqual(Array.from(b));
	});

	test('roster_change_propose: sha256(tag || recId || payloadHash || nonce_le)', () => {
		const id = new Uint8Array([1, 2]);
		const ph = rosterChangePayloadHash([id], 1, true);
		const expected = sha256(
			cat(enc.encode('recovery::roster_change_propose'), recId, ph, u64le(5n)),
		);
		expect(Array.from(rosterChangeProposeChallenge(recId, ph, 5n))).toEqual(Array.from(expected));
	});

	test('roster_change_approve: sha256(tag || recId || rosterChangeId_le)', () => {
		const expected = sha256(cat(enc.encode('recovery::roster_change_approve'), recId, u64le(8n)));
		expect(Array.from(rosterChangeApproveChallenge(recId, 8n))).toEqual(Array.from(expected));
	});

	test('roster_change_propose and roster_change_approve disagree', () => {
		const ph = new Uint8Array(32);
		expect(Array.from(rosterChangeProposeChallenge(recId, ph, 0))).not.toEqual(
			Array.from(rosterChangeApproveChallenge(recId, 0)),
		);
	});
});

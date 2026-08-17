import {
	derSigToCompactRaw64,
	spkiToCompressedP256,
	u64ToLeBytes,
} from '@fesal-packages/ikavery-core';
import { p256 } from '@noble/curves/nist.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { concatBytes, hexToBytes } from '@noble/hashes/utils.js';
import { describe, expect, test } from 'bun:test';

import {
	buildApproveChallenge,
	buildEnrollApproveChallenge,
	buildEnrollProposeChallenge,
	buildExecuteChallenge,
	buildProposeChallenge,
	buildRosterChangeApproveChallenge,
	buildRosterChangePayloadHash,
	buildRosterChangeProposeChallenge,
} from '../src/crypto/challenges';

const enc = new TextEncoder();

describe('u64ToLeBytes', () => {
	test('encodes 0', () => {
		expect(Array.from(u64ToLeBytes(0n))).toEqual([0, 0, 0, 0, 0, 0, 0, 0]);
	});
	test('encodes 1', () => {
		expect(Array.from(u64ToLeBytes(1n))).toEqual([1, 0, 0, 0, 0, 0, 0, 0]);
	});
	test('encodes 0x0807060504030201 little-endian', () => {
		expect(Array.from(u64ToLeBytes(0x0807060504030201n))).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
	});
	test('encodes max u64', () => {
		expect(Array.from(u64ToLeBytes(0xffffffffffffffffn))).toEqual([
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		]);
	});
	test('accepts number for small values', () => {
		expect(Array.from(u64ToLeBytes(5))).toEqual([5, 0, 0, 0, 0, 0, 0, 0]);
	});
});

describe('challenge builders', () => {
	const recoveryId = '0x' + 'ab'.repeat(32);
	const idBytes = new Uint8Array(32).fill(0xab);

	test('propose mirrors Move (commits to intent hash)', () => {
		const intentHash = sha256(enc.encode('intent'));
		const expected = sha256(
			concatBytes(enc.encode('recovery::propose'), idBytes, intentHash, u64ToLeBytes(5n)),
		);
		expect(Array.from(buildProposeChallenge(recoveryId, intentHash, 5n))).toEqual(
			Array.from(expected),
		);
	});
	test('approve mirrors Move', () => {
		const expected = sha256(
			concatBytes(enc.encode('recovery::approve'), idBytes, u64ToLeBytes(7n)),
		);
		expect(Array.from(buildApproveChallenge(recoveryId, 7n))).toEqual(Array.from(expected));
	});
	test('execute mirrors Move', () => {
		const expected = sha256(
			concatBytes(enc.encode('recovery::execute'), idBytes, u64ToLeBytes(11n)),
		);
		expect(Array.from(buildExecuteChallenge(recoveryId, 11n))).toEqual(Array.from(expected));
	});
	test('enroll_propose mirrors Move', () => {
		const newPk = new Uint8Array([1, 2, 3]);
		const expected = sha256(
			concatBytes(enc.encode('recovery::enroll_propose'), idBytes, newPk, u64ToLeBytes(0n)),
		);
		expect(Array.from(buildEnrollProposeChallenge(recoveryId, newPk, 0n))).toEqual(
			Array.from(expected),
		);
	});
	test('enroll_approve mirrors Move', () => {
		const expected = sha256(
			concatBytes(enc.encode('recovery::enroll_approve'), idBytes, u64ToLeBytes(3n)),
		);
		expect(Array.from(buildEnrollApproveChallenge(recoveryId, 3n))).toEqual(Array.from(expected));
	});
	test('propose, approve, and execute disagree on the same recovery+counter', () => {
		const intentHash = new Uint8Array(32);
		const propose = buildProposeChallenge(recoveryId, intentHash, 0n);
		const approve = buildApproveChallenge(recoveryId, 0n);
		const execute = buildExecuteChallenge(recoveryId, 0n);
		expect(Array.from(propose)).not.toEqual(Array.from(approve));
		expect(Array.from(approve)).not.toEqual(Array.from(execute));
		expect(Array.from(propose)).not.toEqual(Array.from(execute));
	});
	test('approve changes with proposal id', () => {
		expect(Array.from(buildApproveChallenge(recoveryId, 0n))).not.toEqual(
			Array.from(buildApproveChallenge(recoveryId, 1n)),
		);
	});
	test('approve changes with recovery id', () => {
		const otherId = '0x' + 'cd'.repeat(32);
		expect(Array.from(buildApproveChallenge(recoveryId, 0n))).not.toEqual(
			Array.from(buildApproveChallenge(otherId, 0n)),
		);
	});
	test('propose challenge is 32 bytes', () => {
		expect(buildProposeChallenge(recoveryId, new Uint8Array(32), 0n).length).toBe(32);
	});
	test('recoveryId without 0x prefix is accepted', () => {
		const a = buildApproveChallenge(recoveryId, 0n);
		const b = buildApproveChallenge(recoveryId.slice(2), 0n);
		expect(Array.from(a)).toEqual(Array.from(b));
	});
});

describe('roster-change challenges', () => {
	const recoveryId = '0x' + 'ab'.repeat(32);
	const idBytes = new Uint8Array(32).fill(0xab);

	test('payload hash with empty removals + no threshold change', () => {
		const expected = sha256(concatBytes(u64ToLeBytes(0n), u64ToLeBytes(0n), new Uint8Array([0])));
		expect(Array.from(buildRosterChangePayloadHash([], null))).toEqual(Array.from(expected));
	});

	test('payload hash with 1 removal + threshold=3', () => {
		const id = new Uint8Array([0, 1, 2, 3]);
		const expected = sha256(
			concatBytes(
				u64ToLeBytes(1n),
				u64ToLeBytes(BigInt(id.length)),
				id,
				u64ToLeBytes(3n),
				new Uint8Array([1]),
			),
		);
		expect(Array.from(buildRosterChangePayloadHash([id], 3n))).toEqual(Array.from(expected));
	});

	test('payload hash: hasNewThreshold byte differs even when threshold matches', () => {
		const id = new Uint8Array([7]);
		const a = buildRosterChangePayloadHash([id], 0n);
		const b = buildRosterChangePayloadHash([id], null);
		// null → threshold byte = 0, hasNewThreshold = 0;
		// 0n  → threshold byte = 0, hasNewThreshold = 1.
		expect(Array.from(a)).not.toEqual(Array.from(b));
	});

	test('propose-challenge bytes match sha256(tag || recId || payloadHash || nonce_le)', () => {
		const id = new Uint8Array([1, 2]);
		const payloadHash = buildRosterChangePayloadHash([id], 2n);
		const expected = sha256(
			concatBytes(
				enc.encode('recovery::roster_change_propose'),
				idBytes,
				payloadHash,
				u64ToLeBytes(0n),
			),
		);
		expect(Array.from(buildRosterChangeProposeChallenge(recoveryId, [id], 2n, 0n))).toEqual(
			Array.from(expected),
		);
	});

	test('approve-challenge bytes match sha256(tag || recId || rosterChangeId_le)', () => {
		const expected = sha256(
			concatBytes(enc.encode('recovery::roster_change_approve'), idBytes, u64ToLeBytes(7n)),
		);
		expect(Array.from(buildRosterChangeApproveChallenge(recoveryId, 7n))).toEqual(
			Array.from(expected),
		);
	});

	test('propose-challenge varies with payload', () => {
		const a = buildRosterChangeProposeChallenge(recoveryId, [], null, 0n);
		const b = buildRosterChangeProposeChallenge(recoveryId, [new Uint8Array([1])], null, 0n);
		expect(Array.from(a)).not.toEqual(Array.from(b));
	});

	test('propose-challenge and approve-challenge disagree at same nonce', () => {
		const a = buildRosterChangeProposeChallenge(recoveryId, [], null, 0n);
		const b = buildRosterChangeApproveChallenge(recoveryId, 0n);
		expect(Array.from(a)).not.toEqual(Array.from(b));
	});

	test('approve-challenge varies with rosterChangeId', () => {
		const a = buildRosterChangeApproveChallenge(recoveryId, 0n);
		const b = buildRosterChangeApproveChallenge(recoveryId, 1n);
		expect(Array.from(a)).not.toEqual(Array.from(b));
	});

	test('propose-challenge is 32 bytes', () => {
		expect(buildRosterChangeProposeChallenge(recoveryId, [], null, 0n).length).toBe(32);
	});
});

describe('derSigToCompactRaw64', () => {
	test('round-trips a real P-256 signature', () => {
		const sk = p256.utils.randomPrivateKey();
		const msg = sha256(enc.encode('hello'));
		const sigObj = p256.sign(msg, sk);
		const der = sigObj.toDERRawBytes();
		const raw = derSigToCompactRaw64(der);
		expect(raw.length).toBe(64);
		// Sui's ecdsa_r1 verifier rejects high-S signatures, so derSigToCompactRaw64
		// normalizes to low-S; compare against the same normalization.
		expect(Array.from(raw)).toEqual(Array.from(sigObj.normalizeS().toCompactRawBytes()));
	});
	test('rejects malformed DER', () => {
		expect(() => derSigToCompactRaw64(new Uint8Array([0xff, 0xff]))).toThrow();
	});
});

describe('spkiToCompressedP256', () => {
	test('round-trips a freshly-generated P-256 key', () => {
		const sk = p256.utils.randomPrivateKey();
		const compressed = p256.getPublicKey(sk, true);
		const uncompressed = p256.getPublicKey(sk, false);
		const spki = buildEs256Spki(uncompressed);
		expect(Array.from(spkiToCompressedP256(spki))).toEqual(Array.from(compressed));
	});
	test('rejects incorrect SPKI length', () => {
		expect(() => spkiToCompressedP256(new Uint8Array(90))).toThrow(/91 bytes/);
	});
	test('rejects wrong ES256 prefix', () => {
		const sk = p256.utils.randomPrivateKey();
		const uncompressed = p256.getPublicKey(sk, false);
		const spki = buildEs256Spki(uncompressed);
		spki[0] = 0x31;
		expect(() => spkiToCompressedP256(spki)).toThrow(/prefix mismatch/);
	});
	test('uncompressed point lives at bytes 26..91', () => {
		const sk = p256.utils.randomPrivateKey();
		const uncompressed = p256.getPublicKey(sk, false);
		const spki = buildEs256Spki(uncompressed);
		expect(spki[26]).toBe(0x04);
		expect(Array.from(spki.subarray(27, 91))).toEqual(Array.from(uncompressed.subarray(1)));
	});
});

/** Wrap a 65-byte uncompressed P-256 point in the canonical ES256 SPKI envelope. */
function buildEs256Spki(uncompressedPoint: Uint8Array): Uint8Array {
	if (uncompressedPoint.length !== 65 || uncompressedPoint[0] !== 0x04) {
		throw new Error('expected 65-byte uncompressed point starting with 0x04');
	}
	return concatBytes(
		hexToBytes('3059301306072a8648ce3d020106082a8648ce3d030107034200'),
		uncompressedPoint,
	);
}

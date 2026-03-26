// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { describe, expect, it } from 'vitest';

import {
	base64ToBytes,
	bytesToBase64,
	bytesToHex,
	decryptMnemonic,
	encryptMnemonic,
	hexToBytes,
} from '../crypto/index.js';

describe('hex utilities', () => {
	it('round-trips bytes through hex', () => {
		const bytes = new Uint8Array([0, 1, 15, 16, 255]);
		expect(hexToBytes(bytesToHex(bytes))).toEqual(bytes);
	});

	it('handles 0x prefix', () => {
		expect(hexToBytes('0xff')).toEqual(new Uint8Array([255]));
		expect(hexToBytes('ff')).toEqual(new Uint8Array([255]));
	});

	it('handles empty', () => {
		expect(bytesToHex(new Uint8Array([]))).toBe('');
	});
});

describe('base64 utilities', () => {
	it('round-trips bytes through base64', () => {
		const bytes = new Uint8Array([1, 2, 3, 4, 5]);
		expect(base64ToBytes(bytesToBase64(bytes))).toEqual(bytes);
	});
});

describe('mnemonic encryption', () => {
	const mnemonic =
		'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
	const passphrase = 'test-passphrase';

	it('encrypts and decrypts a mnemonic', () => {
		const { ciphertext, salt, nonce } = encryptMnemonic(mnemonic, passphrase);
		const decrypted = decryptMnemonic(ciphertext, salt, nonce, passphrase);
		expect(decrypted).toBe(mnemonic);
	});

	it('fails with wrong passphrase', () => {
		const { ciphertext, salt, nonce } = encryptMnemonic(mnemonic, passphrase);
		expect(() => decryptMnemonic(ciphertext, salt, nonce, 'wrong')).toThrow('EXPORT_FAILED');
	});

	it('produces different ciphertext each time (random salt/nonce)', () => {
		const first = encryptMnemonic(mnemonic, passphrase);
		const second = encryptMnemonic(mnemonic, passphrase);
		expect(bytesToHex(first.ciphertext)).not.toBe(bytesToHex(second.ciphertext));
		expect(bytesToHex(first.salt)).not.toBe(bytesToHex(second.salt));
	});
});

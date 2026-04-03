// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import type { DkgVaultEntry } from '../types.js';
import {
	saveVaultEntry,
	loadVaultEntry,
	listVaultEntries,
	findVaultEntry,
	deleteVaultEntry,
	updateVaultEntry,
} from '../vault/index.js';

function makeEntry(overrides: Partial<DkgVaultEntry> = {}): DkgVaultEntry {
	return {
		owsVersion: 1,
		provider: 'ika',
		id: crypto.randomUUID(),
		name: 'test-wallet',
		kind: 'dkg',
		dwalletId: '0xdwallet',
		dwalletCapId: '0xcap',
		curve: 'Secp256k1' as any,
		userShareKeysHex: 'aabb',
		encryptedUserSecretKeyShareId: '0xshare',
		publicKeyHex: 'ccdd',
		networkEncryptionKeyId: '0xkey',
		createdAt: new Date().toISOString(),
		presignIds: [],
		...overrides,
	};
}

describe('vault', () => {
	let tmpDir: string;

	beforeEach(() => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ows-vault-test-'));
	});

	afterEach(() => {
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	it('saves and loads an entry', () => {
		const entry = makeEntry();
		saveVaultEntry(entry, tmpDir);
		const loaded = loadVaultEntry(entry.id, tmpDir);
		expect(loaded.id).toBe(entry.id);
		expect(loaded.name).toBe(entry.name);
	});

	it('lists entries', () => {
		saveVaultEntry(makeEntry({ name: 'w1' }), tmpDir);
		saveVaultEntry(makeEntry({ name: 'w2' }), tmpDir);
		const entries = listVaultEntries(tmpDir);
		expect(entries.length).toBe(2);
	});

	it('finds by name', () => {
		const entry = makeEntry({ name: 'findme' });
		saveVaultEntry(entry, tmpDir);
		const found = findVaultEntry('findme', tmpDir);
		expect(found.id).toBe(entry.id);
	});

	it('finds by ID', () => {
		const entry = makeEntry();
		saveVaultEntry(entry, tmpDir);
		const found = findVaultEntry(entry.id, tmpDir);
		expect(found.name).toBe(entry.name);
	});

	it('throws on not found', () => {
		expect(() => findVaultEntry('nonexistent', tmpDir)).toThrow('WALLET_NOT_FOUND');
	});

	it('deletes by name', () => {
		const entry = makeEntry({ name: 'deleteme' });
		saveVaultEntry(entry, tmpDir);
		deleteVaultEntry('deleteme', tmpDir);
		expect(listVaultEntries(tmpDir).length).toBe(0);
	});

	it('updates an entry atomically', () => {
		const entry = makeEntry({ name: 'original' });
		saveVaultEntry(entry, tmpDir);
		updateVaultEntry(entry.id, (e) => ({ ...e, name: 'updated' }), tmpDir);
		const loaded = loadVaultEntry(entry.id, tmpDir);
		expect(loaded.name).toBe('updated');
	});

	it('vault files have restricted permissions', () => {
		const entry = makeEntry();
		saveVaultEntry(entry, tmpDir);
		const vaultFile = path.join(tmpDir, 'ika', 'wallets', `${entry.id}.json`);
		const stats = fs.statSync(vaultFile);
		// 0o600 = owner read/write only
		expect(stats.mode & 0o777).toBe(0o600);
	});
});

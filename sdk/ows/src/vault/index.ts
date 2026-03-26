// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/**
 * Local vault storage for Ika dWallet references.
 *
 * Vault layout:
 *   ~/.ows/ika/wallets/<uuid>.json   — One file per wallet (permissions 0o600)
 */

import * as fs from 'node:fs';
import * as path from 'node:path';

import { OWSError, OWSErrorCode } from '../errors.js';
import type { IkaVaultEntry } from '../types.js';

const DEFAULT_VAULT_PATH = path.join(
	process.env['HOME'] ?? process.env['USERPROFILE'] ?? '.',
	'.ows',
);
const IKA_SUBDIR = 'ika';
const WALLETS_DIR = 'wallets';

function ikaWalletsDir(vaultPath: string): string {
	return path.join(vaultPath, IKA_SUBDIR, WALLETS_DIR);
}

function ensureDir(dir: string): void {
	fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
}

function walletFilePath(vaultPath: string, id: string): string {
	return path.join(ikaWalletsDir(vaultPath), `${id}.json`);
}

/** Save a vault entry to disk. */
export function saveVaultEntry(entry: IkaVaultEntry, vaultPath?: string): void {
	const vault = vaultPath ?? DEFAULT_VAULT_PATH;
	ensureDir(ikaWalletsDir(vault));
	const filePath = walletFilePath(vault, entry.id);
	fs.writeFileSync(filePath, JSON.stringify(entry, null, '\t'), {
		encoding: 'utf-8',
		mode: 0o600,
	});
}

/** Load a vault entry by ID. */
export function loadVaultEntry(id: string, vaultPath?: string): IkaVaultEntry {
	const vault = vaultPath ?? DEFAULT_VAULT_PATH;
	const filePath = walletFilePath(vault, id);
	if (!fs.existsSync(filePath)) {
		throw new OWSError(OWSErrorCode.WALLET_NOT_FOUND, `Wallet not found: ${id}`);
	}
	return JSON.parse(fs.readFileSync(filePath, 'utf-8')) as IkaVaultEntry;
}

/** List all vault entries. */
export function listVaultEntries(vaultPath?: string): IkaVaultEntry[] {
	const vault = vaultPath ?? DEFAULT_VAULT_PATH;
	const dir = ikaWalletsDir(vault);
	if (!fs.existsSync(dir)) {
		return [];
	}
	return fs
		.readdirSync(dir)
		.filter((f) => f.endsWith('.json'))
		.map((f) => JSON.parse(fs.readFileSync(path.join(dir, f), 'utf-8')) as IkaVaultEntry);
}

/** Find a vault entry by name or ID. */
export function findVaultEntry(nameOrId: string, vaultPath?: string): IkaVaultEntry {
	const vault = vaultPath ?? DEFAULT_VAULT_PATH;

	// Try by ID first (exact file lookup).
	const filePath = walletFilePath(vault, nameOrId);
	if (fs.existsSync(filePath)) {
		return JSON.parse(fs.readFileSync(filePath, 'utf-8')) as IkaVaultEntry;
	}

	// Fall back to name search.
	const entries = listVaultEntries(vaultPath);
	const match = entries.find((e) => e.name === nameOrId || e.id === nameOrId);
	if (!match) {
		throw new OWSError(OWSErrorCode.WALLET_NOT_FOUND, `Wallet not found: ${nameOrId}`);
	}
	return match;
}

/** Delete a vault entry by name or ID. */
export function deleteVaultEntry(nameOrId: string, vaultPath?: string): void {
	const entry = findVaultEntry(nameOrId, vaultPath);
	const vault = vaultPath ?? DEFAULT_VAULT_PATH;
	const filePath = walletFilePath(vault, entry.id);
	if (fs.existsSync(filePath)) {
		fs.unlinkSync(filePath);
	}
}

/** Atomic read-modify-write of a vault entry. Used by presign pool for persistence. */
export function updateVaultEntry(
	id: string,
	updater: (entry: IkaVaultEntry) => IkaVaultEntry,
	vaultPath?: string,
): void {
	const entry = loadVaultEntry(id, vaultPath);
	const updated = updater(entry);
	saveVaultEntry(updated, vaultPath);
}

/** Export all vault entries as a JSON string (for backup). */
export function exportVault(vaultPath?: string): string {
	return JSON.stringify(listVaultEntries(vaultPath), null, '\t');
}

/** Import vault entries from a JSON string (for restore). Overwrites existing entries with same ID. */
export function importVault(json: string, vaultPath?: string): number {
	const entries = JSON.parse(json) as IkaVaultEntry[];
	for (const entry of entries) {
		saveVaultEntry(entry, vaultPath);
	}
	return entries.length;
}

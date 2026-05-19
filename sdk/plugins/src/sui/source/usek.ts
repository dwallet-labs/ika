// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { Transaction } from '@mysten/sui/transactions';
import type { Curve, IkaClient as CoreIkaClient, UserShareEncryptionKeys } from '@ika.xyz/sdk';
import { IkaTransaction, NetworkError } from '@ika.xyz/sdk';

import type { SuiSourceDefaults } from './types.js';
import type { makeExec } from './execute.js';

/**
 * Per-source-instance cache of `(usek-sui-address, curve)` pairs already
 * registered on chain. Prevents redundant on-chain registration of a USEK
 * within the same source's lifetime.
 */
export type UsekRegistrationCache = Set<string>;

export interface RegisterUsekArgs {
	readonly userShareEncryptionKeys: UserShareEncryptionKeys;
	readonly curve: Curve;
	readonly defaults: SuiSourceDefaults;
	readonly ikaClient: CoreIkaClient;
	readonly exec: ReturnType<typeof makeExec>;
	readonly cache: UsekRegistrationCache;
}

export async function ensureUsekRegistered(args: RegisterUsekArgs): Promise<void> {
	const { userShareEncryptionKeys, curve, defaults, ikaClient, exec, cache } = args;
	if (userShareEncryptionKeys.curve !== curve) {
		throw new Error(
			`UserShareEncryptionKeys curve mismatch: handle has ${userShareEncryptionKeys.curve}, requested ${curve}`,
		);
	}
	const usekAddress = userShareEncryptionKeys.getSuiAddress();
	const tag = `${usekAddress}:${curve}`;
	if (cache.has(tag)) return;

	// Check the chain first; the key may already be registered from a prior
	// run with the same USEK seed. Registering twice aborts the tx with
	// `dynamic_field::add` code 0 (field already exists).
	//
	// `NetworkError` is rethrown immediately: treating a transient RPC
	// failure as "not registered" would attempt a register that cannot
	// succeed and could poison the cache during a partial outage.
	//
	// Any other error here (parse failures, missing simulation results) is
	// interpreted as "not registered" and falls through to the register path.
	try {
		await ikaClient.getActiveEncryptionKey(usekAddress);
		cache.add(tag);
		return;
	} catch (err) {
		if (err instanceof NetworkError) throw err;
	}

	const tx = new Transaction();
	tx.setSender(defaults.signerAddress);
	const ikaTx = new IkaTransaction({
		ikaClient,
		transaction: tx,
		userShareEncryptionKeys,
	});
	await ikaTx.registerEncryptionKey({ curve });
	try {
		await exec(tx);
	} catch (err) {
		// Idempotent register: if a parallel caller (or an earlier run we
		// could not detect via `getActiveEncryptionKey`) already registered
		// the key, the Move side aborts with `dynamic_field::add` code 0.
		// Treat that as success; the key is on chain either way.
		const msg = err instanceof Error ? err.message : String(err);
		if (/dynamic_field|MoveAbort.*0|already exists/i.test(msg)) {
			cache.add(tag);
			return;
		}
		throw err;
	}
	cache.add(tag);
}

/**
 * Pick the user-share encryption keys for a call: an explicit override beats
 * the source's default. Throws if neither is available.
 */
export function resolveUsek(
	defaults: SuiSourceDefaults,
	override?: UserShareEncryptionKeys,
	context: string = 'this operation',
): UserShareEncryptionKeys {
	const keys = override ?? defaults.userShareEncryptionKeys;
	if (!keys) {
		throw new Error(
			`${context} requires user-share encryption keys. Pass one via the call, or provide a default in suiSource({ userShareEncryptionKeys }).`,
		);
	}
	return keys;
}

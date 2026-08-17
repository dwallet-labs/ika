/// <reference lib="webworker" />

import { Curve, UserShareEncryptionKeys } from '@ika.xyz/sdk';

/**
 * Off-main-thread `UserShareEncryptionKeys` derivation. The underlying
 * `fromRootSeedKey` calls into a WASM blob that takes 1–3 seconds the first
 * time and a few hundred ms thereafter — way over the 50ms budget that keeps
 * the UI responsive. Running in a worker keeps animations and input alive.
 *
 * Intentionally only handles the WASM step. Every preceding ceremony
 * (WebAuthn registration / authenticate, wallet personal-message sign) needs
 * the user's UI and stays on the main thread.
 */
export type DeriveCommand = {
	type: 'derive';
	id: number;
	seed: Uint8Array;
};

export type DeriveEvent =
	| {
			type: 'result';
			id: number;
			keysBytes: Uint8Array;
			encryptionAddress: string;
	  }
	| { type: 'error'; id: number; error: string };

const ctx = self as DedicatedWorkerGlobalScope;

ctx.addEventListener('message', async (e: MessageEvent<DeriveCommand>) => {
	const { id, seed } = e.data;
	try {
		if (!(seed instanceof Uint8Array) || seed.length !== 32) {
			throw new Error(`derive worker: expected 32-byte seed, got ${seed?.length}`);
		}
		const keys = await UserShareEncryptionKeys.fromRootSeedKey(seed, Curve.ED25519);
		const ev: DeriveEvent = {
			type: 'result',
			id,
			keysBytes: keys.toShareEncryptionKeysBytes(),
			encryptionAddress: keys.getSuiAddress(),
		};
		ctx.postMessage(ev);
	} catch (err) {
		const ev: DeriveEvent = {
			type: 'error',
			id,
			error: err instanceof Error ? err.message : String(err),
		};
		ctx.postMessage(ev);
	}
});

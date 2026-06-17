// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

// Unit tests for the sui destination's PersonalMessage signing path.
// Regression coverage: PersonalMessage MUST BCS-wrap the message before
// `messageWithIntent`, matching `@mysten/sui` `Signer.signPersonalMessage`,
// so that `publicKey.verifyPersonalMessage(message, signature)` accepts the
// resulting signature.

import { sui } from '@ika.xyz/plugins/sui/destination';
import type { SuiSupportedCurve } from '@ika.xyz/plugins/sui/destination';
import { Curve, Hash, SignatureAlgorithm } from '@ika.xyz/sdk';
import type { BaseSignResult, DWallet, IkaContext } from '@ika.xyz/sdk/plugin';
import { Ed25519PublicKey } from '@mysten/sui/keypairs/ed25519';
import { ed25519 } from '@noble/curves/ed25519.js';
import { describe, expect, it, vi } from 'vitest';

const realPubkeyByOutput = new Map<string, Uint8Array>();
const realSecretByOutput = new Map<string, Uint8Array>();

vi.mock('@ika.xyz/sdk', async () => {
	const actual = await vi.importActual<typeof import('@ika.xyz/sdk')>('@ika.xyz/sdk');
	return {
		...actual,
		publicKeyFromDWalletOutput: vi.fn(async (_curve: unknown, bytes: Uint8Array) => {
			const hit = realPubkeyByOutput.get(Array.from(bytes).join(','));
			if (!hit) throw new Error('no registered pubkey');
			return hit;
		}),
	};
});

function makeEd25519Fixture() {
	// Canonical Ed25519 secret: 32 random bytes, no clamping for noble v2.
	const secret = new Uint8Array(32);
	crypto.getRandomValues(secret);
	secret[31] &= 0x0f;
	const publicKey = ed25519.getPublicKey(secret);
	const publicOutput = new Uint8Array([1, 2, 3, ...secret.subarray(0, 8)]);
	realPubkeyByOutput.set(Array.from(publicOutput).join(','), publicKey);
	realSecretByOutput.set(Array.from(publicOutput).join(','), secret);
	return { secret, publicKey, publicOutput };
}

function fakeDWallet(publicOutput: Uint8Array): DWallet<SuiSupportedCurve> {
	return {
		id: '0xfake',
		kind: 'shared',
		curve: Curve.ED25519,
		publicOutput,
	} as unknown as DWallet<SuiSupportedCurve>;
}

function buildCtx(): IkaContext {
	const source = {
		chain: 'sui',
		async signMessage(input: { dWallet: DWallet; message: Uint8Array }): Promise<BaseSignResult> {
			const key = Array.from(input.dWallet.publicOutput).join(',');
			const secret = realSecretByOutput.get(key);
			if (!secret) throw new Error('no secret');
			// MPC EdDSA signs the raw bytes; Ed25519 internally hashes with SHA-512.
			const signature = ed25519.sign(input.message, secret);
			return {
				signature,
				curve: Curve.ED25519,
				signatureAlgorithm: SignatureAlgorithm.EdDSA,
				hash: Hash.SHA512,
			};
		},
		async getDWallet() {
			throw new Error('not used');
		},
	};
	return {
		source: source as unknown as IkaContext['source'],
		client: { decorate: async (d) => d, ready: async () => {} },
	};
}

describe('sui destination — PersonalMessage signing', () => {
	it('produces a signature that Ed25519PublicKey.verifyPersonalMessage accepts', async () => {
		const fx = makeEd25519Fixture();
		const plugin = sui();
		const ctx = buildCtx();
		await plugin.install?.(ctx);

		const dWallet = fakeDWallet(fx.publicOutput);
		const message = new TextEncoder().encode('hello sui');
		const signed = await plugin.extend.sui.sign({ dWallet, kind: 'message', message });

		expect(signed.payload.bytes).toEqual(message);
		const pk = new Ed25519PublicKey(fx.publicKey);
		const ok = await pk.verifyPersonalMessage(message, signed.payload.signature);
		expect(ok).toBe(true);
	});

	it('assembleSign rejects a wrong-length signature', async () => {
		const fx = makeEd25519Fixture();
		const plugin = sui();
		const ctx: IkaContext = {
			source: {
				chain: 'sui',
				async signMessage(): Promise<BaseSignResult> {
					return {
						signature: new Uint8Array(63), // wrong
						curve: Curve.ED25519,
						signatureAlgorithm: SignatureAlgorithm.EdDSA,
						hash: Hash.SHA512,
					};
				},
				async getDWallet() {
					throw new Error('not used');
				},
			} as unknown as IkaContext['source'],
			client: { decorate: async (d) => d, ready: async () => {} },
		};
		await plugin.install?.(ctx);
		await expect(
			plugin.extend.sui.sign({
				dWallet: fakeDWallet(fx.publicOutput),
				kind: 'message',
				message: new TextEncoder().encode('x'),
			}),
		).rejects.toThrow(/64-byte/);
	});
});

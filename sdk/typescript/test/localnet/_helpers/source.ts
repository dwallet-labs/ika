// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

// Mocked source for localnet tests. The source plugin's only contract is
// "given a message, return a signature." We back it with a real keypair so
// the produced signatures are byte-for-byte valid against the destination
// chain — the destinations sign-flow, address derivation, and publisher all
// see the same inputs they would in production.

import { ed25519 } from '@noble/curves/ed25519.js';
import { schnorr, secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { Curve, Hash, SignatureAlgorithm } from '@ika.xyz/sdk';
import type { BaseSignResult, DWallet, IkaContext } from '@ika.xyz/sdk/plugin';

function dsha256(b: Uint8Array): Uint8Array {
	return new Uint8Array(sha256(sha256(b)));
}

function applyHash(message: Uint8Array, hash: Hash): Uint8Array {
	switch (hash) {
		case Hash.SHA256:
			return new Uint8Array(sha256(message));
		case Hash.DoubleSHA256:
			return dsha256(message);
		case Hash.KECCAK256: {
			const { keccak_256 } = require('@noble/hashes/sha3.js');
			return new Uint8Array(keccak_256(message));
		}
		case Hash.SHA512: {
			const { sha512 } = require('@noble/hashes/sha2.js');
			return new Uint8Array(sha512(message));
		}
		default:
			throw new Error(`mock source: unsupported hash ${hash}`);
	}
}

export interface MockSourceFixture {
	readonly secp256k1: { secret: Uint8Array; publicKey: Uint8Array };
	readonly ed25519: { secret: Uint8Array; publicKey: Uint8Array };
}

export function makeFixture(): MockSourceFixture {
	const secp = secp256k1.utils.randomSecretKey();
	const ed = (() => {
		const seed = new Uint8Array(32);
		crypto.getRandomValues(seed);
		// Ed25519 needs canonical scalar; @noble/curves v2 expects raw 32B secret.
		seed[31] &= 0x0f;
		return seed;
	})();
	return {
		secp256k1: {
			secret: secp,
			publicKey: secp256k1.getPublicKey(secp, true),
		},
		ed25519: {
			secret: ed,
			publicKey: ed25519.getPublicKey(ed),
		},
	};
}

/**
 * Build a fake `DWallet` handle whose `publicOutput` is the public key the
 * destinations will hash for address derivation. The destination plugins
 * use `publicKeyFromDWalletOutput` — we mock that below so the dWallet's
 * `publicOutput` IS the pubkey returned to destinations.
 */
export function fakeDWallet<C extends Curve>(curve: C, pubkey: Uint8Array): DWallet<C> {
	return {
		id: '0xfake',
		kind: 'shared',
		curve,
		publicOutput: pubkey,
		raw: undefined as unknown,
	} as unknown as DWallet<C>;
}

/**
 * Build an `IkaContext` whose source signs with the registered keypair.
 * The destination's `sign` flow funnels through `ctx.source.signMessage`;
 * we apply the requested hash to the message (matching what real MPC does
 * internally) and produce a wire-format signature.
 */
export function mockSourceContext(fixture: MockSourceFixture): IkaContext {
	const source = {
		chain: 'sui',
		async signMessage(input: {
			dWallet: DWallet;
			message: Uint8Array;
			curve: Curve;
			signatureAlgorithm: SignatureAlgorithm;
			hash: Hash;
		}): Promise<BaseSignResult> {
			const sig = await signWithFixture(fixture, input);
			return {
				signature: sig,
				curve: input.curve,
				signatureAlgorithm: input.signatureAlgorithm,
				hash: input.hash,
			};
		},
		async getDWallet(): Promise<DWallet> {
			throw new Error('mock source: getDWallet not used in localnet tests');
		},
	};
	return {
		source: source as unknown as IkaContext['source'],
		client: { decorate: async (d) => d, ready: async () => {} },
	};
}

async function signWithFixture(
	fixture: MockSourceFixture,
	input: {
		message: Uint8Array;
		curve: Curve;
		signatureAlgorithm: SignatureAlgorithm;
		hash: Hash;
	},
): Promise<Uint8Array> {
	const digest = applyHash(input.message, input.hash);
	switch (input.signatureAlgorithm) {
		case SignatureAlgorithm.ECDSASecp256k1: {
			return secp256k1.sign(digest, fixture.secp256k1.secret, { prehash: false });
		}
		case SignatureAlgorithm.Taproot: {
			return schnorr.sign(digest, fixture.secp256k1.secret);
		}
		case SignatureAlgorithm.EdDSA: {
			return ed25519.sign(input.message, fixture.ed25519.secret);
		}
		default:
			throw new Error(
				`mock source: unsupported signatureAlgorithm ${input.signatureAlgorithm}`,
			);
	}
}

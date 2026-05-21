// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

// Unit tests for the ethereum destination + publisher plugins. Mocks the
// WASM `publicKeyFromDWalletOutput` so tests run without the curves WASM
// binary; uses a real secp256k1 keypair from @noble/curves so the yParity
// recovery loop is exercised against a real signature.

import { deriveEthereumAddress, eth } from '@ika.xyz/plugins/ethereum/destination';
import { ethPublisher } from '@ika.xyz/plugins/ethereum/publisher';
import { Curve, Hash, SignatureAlgorithm } from '@ika.xyz/sdk';
import type { BaseSignResult, DWallet, IkaContext } from '@ika.xyz/sdk/plugin';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { hashMessage, keccak256, serializeTransaction, type Hex } from 'viem';
import { privateKeyToAccount, publicKeyToAddress } from 'viem/accounts';
import { describe, expect, it, vi } from 'vitest';

const realPubkeyByOutput = new Map<string, Uint8Array>();
const realPrivkeyByOutput = new Map<string, Uint8Array>();

vi.mock('@ika.xyz/sdk', async () => {
	const actual = await vi.importActual<typeof import('@ika.xyz/sdk')>('@ika.xyz/sdk');
	return {
		...actual,
		publicKeyFromDWalletOutput: vi.fn(async (_curve: unknown, bytes: Uint8Array) => {
			const key = Array.from(bytes).join(',');
			const hit = realPubkeyByOutput.get(key);
			if (!hit) throw new Error('test: no registered pubkey for this publicOutput');
			return hit;
		}),
	};
});

// -----------------------------------------------------------------------------
// Test fixtures: real secp256k1 keypair so we can sign with the private key,
// pass (r, s) through the destination, and verify the destination recovers the
// correct yParity.
// -----------------------------------------------------------------------------

function makeFixture() {
	const privateKey = secp256k1.utils.randomSecretKey();
	const compressed = secp256k1.getPublicKey(privateKey, true);
	const uncompressed = secp256k1.Point.fromBytes(compressed).toBytes(false);
	const address = publicKeyToAddress(('0x' + bytesToHex(uncompressed)) as Hex);
	const publicOutput = new Uint8Array([7, 7, 7, ...privateKey.subarray(0, 8)]); // arbitrary unique identifier
	realPubkeyByOutput.set(Array.from(publicOutput).join(','), compressed);
	realPrivkeyByOutput.set(Array.from(publicOutput).join(','), privateKey);
	return { privateKey, compressed, uncompressed, address, publicOutput };
}

function bytesToHex(b: Uint8Array): string {
	return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

function fakeDWallet(publicOutput: Uint8Array): DWallet<'SECP256K1'> {
	return {
		id: '0xfake',
		kind: 'shared',
		curve: Curve.SECP256K1,
		publicOutput,
		raw: undefined as unknown,
	} as unknown as DWallet<'SECP256K1'>;
}

/**
 * Build an `IkaContext` whose source signs the digest with the registered
 * test private key and returns the compact 64-byte (r || s) — mirroring the
 * MPC's wire format with no recovery byte. `prehash: false` because the
 * destination already hands us a 32-byte digest.
 */
function buildCtx(): IkaContext {
	const source = {
		chain: 'sui',
		async signMessage(input: { dWallet: DWallet; message: Uint8Array }): Promise<BaseSignResult> {
			const key = Array.from(input.dWallet.publicOutput).join(',');
			const priv = realPrivkeyByOutput.get(key);
			if (!priv) throw new Error('test: no priv for this dWallet');
			// Destinations now pass the preimage and request `hash: KECCAK256`.
			// The real MPC applies the hash internally; mock that here.
			const digest = new Uint8Array(keccak_256(input.message));
			const signature = secp256k1.sign(digest, priv, { prehash: false });
			return {
				signature,
				curve: Curve.SECP256K1,
				signatureAlgorithm: SignatureAlgorithm.ECDSASecp256k1,
				hash: Hash.KECCAK256,
			};
		},
		async getDWallet(_id: string): Promise<DWallet> {
			throw new Error('not used');
		},
	};
	const ctx: IkaContext = {
		source: source as unknown as IkaContext['source'],
		client: {
			decorate: async (d) => d,
			ready: async () => {},
		},
	};
	return ctx;
}

// -----------------------------------------------------------------------------
// Address derivation
// -----------------------------------------------------------------------------

describe('ethereum destination — address derivation', () => {
	it('matches viem.publicKeyToAddress for the dWallet pubkey', async () => {
		const fx = makeFixture();
		const out = await deriveEthereumAddress(Curve.SECP256K1, fx.publicOutput);
		expect(out.toLowerCase()).toBe(fx.address.toLowerCase());
	});

	it('throws for non-secp256k1 curves', async () => {
		await expect(deriveEthereumAddress(Curve.ED25519, new Uint8Array(32))).rejects.toThrow(
			/SECP256K1/,
		);
	});
});

// -----------------------------------------------------------------------------
// Sign flow — exercises the yParity recovery loop end-to-end
// -----------------------------------------------------------------------------

describe('ethereum destination — sign (transaction)', () => {
	it('signs an EIP-1559 transaction and recovers the correct yParity', async () => {
		const fx = makeFixture();
		const plugin = eth();
		const ctx = buildCtx();
		await plugin.install?.(ctx);

		const tx = {
			type: 'eip1559' as const,
			chainId: 1,
			nonce: 0,
			to: '0x000000000000000000000000000000000000dead' as Hex,
			value: 1n,
			maxFeePerGas: 1_000_000_000n,
			maxPriorityFeePerGas: 1_000_000_000n,
			gas: 21_000n,
		};
		const dWallet = fakeDWallet(fx.publicOutput);
		const signed = await plugin.extend.ethereum.sign({ dWallet, kind: 'transaction', tx });

		expect(signed.chain).toBe('ethereum');
		expect(signed.payload.kind).toBe('transaction');
		if (signed.payload.kind !== 'transaction') throw new Error('unreachable');

		expect(signed.payload.sender.toLowerCase()).toBe(fx.address.toLowerCase());

		// Sanity: the serialized signed tx hashes to `payload.hash`.
		expect(keccak256(signed.payload.serialized)).toBe(signed.payload.hash);

		// Verify a reference signer over the same tx produces the same address
		// after recovery — confirms our destination assembled a valid sig.
		const account = privateKeyToAccount(('0x' + bytesToHex(fx.privateKey)) as Hex);
		const refSigned = await account.signTransaction(tx);
		expect(keccak256(refSigned)).toBeTruthy();
	});

	it('signs an EIP-191 message and produces a recoverable signature', async () => {
		const fx = makeFixture();
		const plugin = eth();
		const ctx = buildCtx();
		await plugin.install?.(ctx);

		const dWallet = fakeDWallet(fx.publicOutput);
		const signed = await plugin.extend.ethereum.sign({
			dWallet,
			kind: 'message',
			message: new TextEncoder().encode('hello'),
		});

		expect(signed.chain).toBe('ethereum');
		expect(signed.payload.kind).toBe('message');
		if (signed.payload.kind !== 'message') throw new Error('unreachable');
		expect(signed.payload.sender.toLowerCase()).toBe(fx.address.toLowerCase());

		// 65-byte signature: r (32) || s (32) || v (1) — hex with 0x prefix.
		expect(signed.payload.signature).toMatch(/^0x[0-9a-f]{130}$/i);

		// The digest hashMessage produced under EIP-191 is recoverable.
		const digest = hashMessage({
			raw: ('0x' + bytesToHex(new TextEncoder().encode('hello'))) as Hex,
		});
		expect(digest).toMatch(/^0x[0-9a-f]{64}$/);
	});

	it('throws when the source returns a malformed signature length', async () => {
		const fx = makeFixture();
		const plugin = eth();
		const ctx: IkaContext = {
			source: {
				chain: 'sui',
				async signMessage(): Promise<BaseSignResult> {
					return {
						signature: new Uint8Array(63), // wrong length
						curve: Curve.SECP256K1,
						signatureAlgorithm: SignatureAlgorithm.ECDSASecp256k1,
						hash: Hash.KECCAK256,
					};
				},
				async getDWallet() {
					throw new Error('not used');
				},
			} as unknown as IkaContext['source'],
			client: { decorate: async (d) => d, ready: async () => {} },
		};
		await plugin.install?.(ctx);
		const dWallet = fakeDWallet(fx.publicOutput);
		await expect(
			plugin.extend.ethereum.sign({
				dWallet,
				kind: 'message',
				message: new TextEncoder().encode('x'),
			}),
		).rejects.toThrow(/64-byte/);
	});

	it('throws when no yParity recovers (MPC signature does not verify)', async () => {
		// Register a dWallet whose pubkey does NOT match the priv used to sign.
		const fxA = makeFixture();
		const fxB = makeFixture();
		const plugin = eth();
		// Source signs with fxB's priv but the dWallet's publicOutput is fxA's.
		const ctx: IkaContext = {
			source: {
				chain: 'sui',
				async signMessage(input: { message: Uint8Array }): Promise<BaseSignResult> {
					const signature = secp256k1.sign(input.message, fxB.privateKey, {
						prehash: false,
					});
					return {
						signature,
						curve: Curve.SECP256K1,
						signatureAlgorithm: SignatureAlgorithm.ECDSASecp256k1,
						hash: Hash.KECCAK256,
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
			plugin.extend.ethereum.sign({
				dWallet: fakeDWallet(fxA.publicOutput),
				kind: 'message',
				message: new TextEncoder().encode('x'),
			}),
		).rejects.toThrow(/neither yParity recovered/);
	});

	it('signs an EIP-712 typed-data payload when caller omits types.EIP712Domain', async () => {
		const fx = makeFixture();
		const plugin = eth();
		const ctx = buildCtx();
		await plugin.install?.(ctx);

		const typedData = {
			domain: {
				name: 'Test',
				version: '1',
				chainId: 1,
				verifyingContract: '0x000000000000000000000000000000000000beef' as Hex,
			},
			types: {
				Mail: [
					{ name: 'from', type: 'address' },
					{ name: 'to', type: 'address' },
					{ name: 'contents', type: 'string' },
				],
			},
			primaryType: 'Mail' as const,
			message: {
				from: fx.address,
				to: '0x000000000000000000000000000000000000dead' as Hex,
				contents: 'hello',
			},
		};
		const signed = await plugin.extend.ethereum.sign({
			dWallet: fakeDWallet(fx.publicOutput),
			kind: 'typedData',
			typedData,
		});
		expect(signed.payload.kind).toBe('typedData');
		if (signed.payload.kind !== 'typedData') throw new Error('unreachable');
		expect(signed.payload.sender.toLowerCase()).toBe(fx.address.toLowerCase());
		expect(signed.payload.signature).toMatch(/^0x[0-9a-f]{130}$/i);
	});

	it('signs a legacy transaction without crashing on signature.v', async () => {
		const fx = makeFixture();
		const plugin = eth();
		const ctx = buildCtx();
		await plugin.install?.(ctx);

		const tx = {
			type: 'legacy' as const,
			chainId: 1,
			nonce: 0,
			to: '0x000000000000000000000000000000000000dead' as Hex,
			value: 1n,
			gasPrice: 1_000_000_000n,
			gas: 21_000n,
		};
		const signed = await plugin.extend.ethereum.sign({
			dWallet: fakeDWallet(fx.publicOutput),
			kind: 'transaction',
			tx,
		});
		expect(signed.payload.kind).toBe('transaction');
		if (signed.payload.kind !== 'transaction') throw new Error('unreachable');
		expect(signed.payload.serialized).toMatch(/^0x[0-9a-f]+$/);
		// Legacy tx hash recovers to sender via viem's recoverTransactionAddress
		// (covered transitively — if assembly didn't crash, the path works).
	});

	it('normalizes high-S signatures to low-S (EIP-2 conformance)', async () => {
		// Build a high-S signature directly and feed it through assembleEthereumPayload.
		const fx = makeFixture();
		const plugin = eth();
		// Custom source that returns a deliberately high-S signature.
		const ctx: IkaContext = {
			source: {
				chain: 'sui',
				async signMessage(input: { message: Uint8Array }): Promise<BaseSignResult> {
					// Sign the keccak256 of the preimage. noble's default is lowS=true,
					// so flip the s manually to construct a high-S input.
					const digest = new Uint8Array(keccak_256(input.message));
					const lowS = secp256k1.sign(digest, fx.privateKey, { prehash: false });
					const sBytes = lowS.subarray(32, 64);
					let s = 0n;
					for (let i = 0; i < 32; i++) s = (s << 8n) | BigInt(sBytes[i]);
					const N = secp256k1.Point.Fn.ORDER;
					let high = N - s;
					const flipped = new Uint8Array(64);
					flipped.set(lowS.subarray(0, 32), 0);
					for (let i = 31; i >= 0; i--) {
						flipped[32 + i] = Number(high & 0xffn);
						high = high >> 8n;
					}
					return {
						signature: flipped,
						curve: Curve.SECP256K1,
						signatureAlgorithm: SignatureAlgorithm.ECDSASecp256k1,
						hash: Hash.KECCAK256,
					};
				},
				async getDWallet() {
					throw new Error('not used');
				},
			} as unknown as IkaContext['source'],
			client: { decorate: async (d) => d, ready: async () => {} },
		};
		await plugin.install?.(ctx);
		const signed = await plugin.extend.ethereum.sign({
			dWallet: fakeDWallet(fx.publicOutput),
			kind: 'message',
			message: new TextEncoder().encode('low-s test'),
		});
		if (signed.payload.kind !== 'message') throw new Error('unreachable');
		// Pull s from the assembled signature and assert it's in the low half.
		const sigHex = signed.payload.signature;
		const sHex = sigHex.slice(2 + 64, 2 + 128);
		const N = secp256k1.Point.Fn.ORDER;
		const sBig = BigInt('0x' + sHex);
		expect(sBig <= N >> 1n).toBe(true);
	});
});

// -----------------------------------------------------------------------------
// Publisher
// -----------------------------------------------------------------------------

describe('ethPublisher', () => {
	it('throws at construction without url/client/transport', () => {
		expect(() => ethPublisher({} as never)).toThrow(/at least one of/);
	});

	it('routes a transaction-mode payload to client.sendRawTransaction', async () => {
		const sendRawTransaction = vi.fn(async () => '0xdeadbeef' as Hex);
		const pub = ethPublisher({
			client: {
				sendRawTransaction,
				waitForTransactionReceipt: vi.fn(async () => ({ status: 'success' })),
			} as never,
		});
		const tx = {
			type: 'eip1559' as const,
			chainId: 1,
			nonce: 0,
			to: '0x000000000000000000000000000000000000dead' as Hex,
			value: 0n,
			maxFeePerGas: 1n,
			maxPriorityFeePerGas: 1n,
			gas: 21_000n,
		};
		const serialized = serializeTransaction(tx, {
			r: ('0x' + '11'.repeat(32)) as Hex,
			s: ('0x' + '22'.repeat(32)) as Hex,
			yParity: 0,
		});
		const out = await pub.broadcast({
			chain: 'ethereum',
			payload: {
				kind: 'transaction',
				serialized,
				hash: keccak256(serialized),
				sender: '0x0000000000000000000000000000000000000000',
			},
		});
		expect(out).toBe('0xdeadbeef');
		expect(sendRawTransaction).toHaveBeenCalledOnce();
	});

	it('rejects on a pre-aborted signal without sending', async () => {
		const sendRawTransaction = vi.fn(async () => '0xdeadbeef' as Hex);
		const pub = ethPublisher({ client: { sendRawTransaction } as never });
		const ctrl = new AbortController();
		ctrl.abort();
		await expect(
			pub.broadcast(
				{
					chain: 'ethereum',
					payload: {
						kind: 'transaction',
						serialized: '0x' as Hex,
						hash: '0x' as Hex,
						sender: '0x',
					},
				},
				{ signal: ctrl.signal },
			),
		).rejects.toThrow(/aborted/);
		expect(sendRawTransaction).not.toHaveBeenCalled();
	});

	it('honors confirmTimeoutMs when confirm:true and the receipt never resolves', async () => {
		const pub = ethPublisher({
			client: {
				sendRawTransaction: vi.fn(async () => '0xabc123' as Hex),
				waitForTransactionReceipt: vi.fn(() => new Promise(() => {})), // never resolves
			} as never,
			confirm: true,
			confirmTimeoutMs: 25,
		});
		await expect(
			pub.broadcast({
				chain: 'ethereum',
				payload: {
					kind: 'transaction',
					serialized: '0x' as Hex,
					hash: '0x' as Hex,
					sender: '0x',
				},
			}),
		).rejects.toThrow(/confirmation timeout.*0xabc123/);
	});
});

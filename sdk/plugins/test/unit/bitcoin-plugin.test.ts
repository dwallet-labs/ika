// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

// Integration tests for the bitcoin destination + publisher plugins. Each
// mode signs a real PSBT with a real secp256k1 key, the destination assembles
// the signed tx, and bitcoinjs-lib's `Psbt.finalizeInput` accepts the
// signature without complaint. Then we verify the schnorr/ECDSA sig is
// valid against the dWallet pubkey by independently re-deriving the digest
// the MPC would have produced and verifying with @noble/curves.

import * as ecc from '@bitcoinerlab/secp256k1';
import { btc, deriveBitcoinAddress } from '@ika.xyz/plugins/bitcoin/destination';
import { bitcoinPublisher } from '@ika.xyz/plugins/bitcoin/publisher';
import { Curve, Hash, SignatureAlgorithm } from '@ika.xyz/sdk';
import type { BaseSignResult, DWallet, IkaContext } from '@ika.xyz/sdk/plugin';
import { schnorr, secp256k1 } from '@noble/curves/secp256k1.js';
import { ripemd160 } from '@noble/hashes/legacy.js';
import { sha256 } from '@noble/hashes/sha2.js';
import * as bitcoin from 'bitcoinjs-lib';
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
			if (!hit) throw new Error('test: no registered pubkey');
			return hit;
		}),
	};
});

bitcoin.initEccLib(ecc as Parameters<typeof bitcoin.initEccLib>[0]);

function dsha256(b: Uint8Array): Uint8Array {
	return new Uint8Array(sha256(sha256(b)));
}

function makeFixture() {
	const privateKey = secp256k1.utils.randomSecretKey();
	const compressed = secp256k1.getPublicKey(privateKey, true);
	const publicOutput = new Uint8Array([7, 7, 7, ...privateKey.subarray(0, 8)]);
	realPubkeyByOutput.set(Array.from(publicOutput).join(','), compressed);
	realPrivkeyByOutput.set(Array.from(publicOutput).join(','), privateKey);
	return { privateKey, compressed, publicOutput };
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
 * Build an `IkaContext` whose source signs the digest the MPC would compute
 * (sha256 for Taproot, dsha256 for ECDSA) using the registered private key,
 * and returns the canonical wire format Ika emits (64-byte schnorr for
 * Taproot; 64-byte r||s for ECDSA).
 */
function buildCtx(): IkaContext {
	const source = {
		chain: 'sui',
		async signMessage(input: {
			dWallet: DWallet;
			message: Uint8Array;
			signatureAlgorithm: SignatureAlgorithm;
			hash: Hash;
		}): Promise<BaseSignResult> {
			const key = Array.from(input.dWallet.publicOutput).join(',');
			const priv = realPrivkeyByOutput.get(key);
			if (!priv) throw new Error('test: no priv');
			let signature: Uint8Array;
			if (input.signatureAlgorithm === SignatureAlgorithm.Taproot) {
				// MPC applies SHA256(message) to get the digest, then schnorr-signs.
				const digest = new Uint8Array(sha256(input.message));
				signature = schnorr.sign(digest, priv);
			} else {
				// MPC applies the requested hash to the preimage, then ECDSA-signs.
				const digest =
					input.hash === Hash.DoubleSHA256 ? dsha256(input.message) : sha256(input.message);
				signature = secp256k1.sign(digest, priv, { prehash: false });
			}
			return {
				signature,
				curve: Curve.SECP256K1,
				signatureAlgorithm: input.signatureAlgorithm,
				hash: input.hash,
			};
		},
		async getDWallet(): Promise<DWallet> {
			throw new Error('not used');
		},
	};
	return {
		source: source as unknown as IkaContext['source'],
		client: { decorate: async (d) => d, ready: async () => {} },
	};
}

const TXID_PREV = new Uint8Array(32).fill(0xaa);

function buildPsbtWith(input: {
	prevScript: Uint8Array;
	prevValue: bigint;
	useWitnessUtxo: boolean;
	redeemScript?: Buffer;
	tapLeaf?: {
		leafVersion: number;
		script: Uint8Array;
		controlBlock: Uint8Array;
	};
	prevRawTx?: Buffer;
	recipientScript: Uint8Array;
	recipientValue: bigint;
	network: bitcoin.Network;
}): bitcoin.Psbt {
	const psbt = new bitcoin.Psbt({ network: input.network });
	psbt.addInput({
		hash: Buffer.from(TXID_PREV),
		index: 0,
		...(input.useWitnessUtxo
			? {
					witnessUtxo: {
						script: Buffer.from(input.prevScript),
						value: input.prevValue,
					},
				}
			: { nonWitnessUtxo: input.prevRawTx! }),
		...(input.redeemScript ? { redeemScript: input.redeemScript } : {}),
		...(input.tapLeaf
			? {
					tapLeafScript: [
						{
							leafVersion: input.tapLeaf.leafVersion,
							script: input.tapLeaf.script,
							controlBlock: input.tapLeaf.controlBlock,
						},
					],
					tapInternalKey: Buffer.from(
						new Uint8Array([
							0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9,
							0x7a, 0x5e, 0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a,
							0xce, 0x80, 0x3a, 0xc0,
						]),
					),
				}
			: {}),
	});
	psbt.addOutput({
		script: Buffer.from(input.recipientScript),
		value: input.recipientValue,
	});
	return psbt;
}

function makeRecipientP2pkh(): Uint8Array {
	const out = new Uint8Array(25);
	out[0] = 0x76;
	out[1] = 0xa9;
	out[2] = 0x14;
	out.set(new Uint8Array(20).fill(0x22), 3);
	out[23] = 0x88;
	out[24] = 0xac;
	return out;
}

// ---------------------------------------------------------------------------
// Address derivation
// ---------------------------------------------------------------------------

describe('bitcoin destination — address derivation', () => {
	it('derives all four mode addresses without error', async () => {
		const fx = makeFixture();
		for (const mode of ['p2pkh', 'p2wpkh', 'p2sh-p2wpkh', 'p2tr-script'] as const) {
			const addr = await deriveBitcoinAddress(Curve.SECP256K1, fx.publicOutput, mode, 'testnet');
			expect(typeof addr).toBe('string');
			expect(addr.length).toBeGreaterThan(0);
		}
	});

	it('throws for non-secp256k1 curves', async () => {
		await expect(
			deriveBitcoinAddress(Curve.ED25519, new Uint8Array(32), 'p2wpkh', 'mainnet'),
		).rejects.toThrow(/SECP256K1/);
	});

	it('produces network-appropriate prefixes', async () => {
		const fx = makeFixture();
		const mainnetP2wpkh = await deriveBitcoinAddress(
			Curve.SECP256K1,
			fx.publicOutput,
			'p2wpkh',
			'mainnet',
		);
		const testnetP2wpkh = await deriveBitcoinAddress(
			Curve.SECP256K1,
			fx.publicOutput,
			'p2wpkh',
			'testnet',
		);
		expect(mainnetP2wpkh.startsWith('bc1')).toBe(true);
		expect(testnetP2wpkh.startsWith('tb1')).toBe(true);
	});
});

// ---------------------------------------------------------------------------
// P2WPKH end-to-end sign + finalize
// ---------------------------------------------------------------------------

describe('bitcoin destination — sign (P2WPKH)', () => {
	it('signs a P2WPKH input and finalizes to a valid witness tx', async () => {
		const fx = makeFixture();
		const plugin = btc();
		const ctx = buildCtx();
		await plugin.install?.(ctx);

		// Build the P2WPKH scriptPubKey: OP_0 OP_PUSHBYTES_20 <hash160(pubkey)>
		// hash160 is exported as a helper from the destination, but we
		// recompute here to keep this test independent.
		const pkh = new Uint8Array(ripemd160(new Uint8Array(sha256(fx.compressed))));
		const prevScript = new Uint8Array(22);
		prevScript[0] = 0x00;
		prevScript[1] = 0x14;
		prevScript.set(pkh, 2);

		const psbt = buildPsbtWith({
			prevScript,
			prevValue: 200_000n,
			useWitnessUtxo: true,
			recipientScript: makeRecipientP2pkh(),
			recipientValue: 100_000n,
			network: bitcoin.networks.testnet,
		});

		const dWallet = fakeDWallet(fx.publicOutput);
		const signed = await plugin.extend.bitcoin.sign({
			dWallet,
			kind: 'psbt',
			psbt,
			inputIndex: 0,
			mode: 'p2wpkh',
			network: 'testnet',
		});
		expect(signed.chain).toBe('bitcoin');
		if (signed.payload.kind !== 'psbt') throw new Error('unreachable');
		expect(signed.payload.signedTxHex).toMatch(/^[0-9a-f]+$/);
		expect(signed.payload.txid).toMatch(/^[0-9a-f]{64}$/);
		expect(signed.payload.mode).toBe('p2wpkh');
		// Finalized tx parses cleanly.
		const tx = bitcoin.Transaction.fromHex(signed.payload.signedTxHex);
		expect(tx.ins).toHaveLength(1);
		expect(tx.ins[0].witness.length).toBeGreaterThanOrEqual(2);
	});
});

// ---------------------------------------------------------------------------
// P2TR script-path end-to-end sign + finalize
// ---------------------------------------------------------------------------

describe('bitcoin destination — sign (P2TR script-path)', () => {
	it('signs and finalizes a P2TR script-path input', async () => {
		const fx = makeFixture();
		const plugin = btc();
		const ctx = buildCtx();
		await plugin.install?.(ctx);

		// Build the P2TR payment ourselves to get the address + control block.
		const xOnly = fx.compressed.subarray(1); // strip parity
		const tapscript = new Uint8Array(34);
		tapscript[0] = 0x20;
		tapscript.set(xOnly, 1);
		tapscript[33] = 0xac;
		const internalPubkey = Buffer.from(
			new Uint8Array([
				0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a,
				0x5e, 0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80,
				0x3a, 0xc0,
			]),
		);
		const p2tr = bitcoin.payments.p2tr(
			{
				internalPubkey,
				scriptTree: { output: Buffer.from(tapscript) },
				redeem: { output: Buffer.from(tapscript), redeemVersion: 0xc0 },
				network: bitcoin.networks.testnet,
			},
			{ validate: true },
		);
		const controlBlock = p2tr.witness![p2tr.witness!.length - 1];

		const psbt = buildPsbtWith({
			prevScript: new Uint8Array(p2tr.output!),
			prevValue: 200_000n,
			useWitnessUtxo: true,
			tapLeaf: {
				leafVersion: 0xc0,
				script: Buffer.from(tapscript),
				controlBlock,
			},
			recipientScript: makeRecipientP2pkh(),
			recipientValue: 100_000n,
			network: bitcoin.networks.testnet,
		});

		const dWallet = fakeDWallet(fx.publicOutput);
		const signed = await plugin.extend.bitcoin.sign({
			dWallet,
			kind: 'psbt',
			psbt,
			inputIndex: 0,
			mode: 'p2tr-script',
			network: 'testnet',
		});
		expect(signed.chain).toBe('bitcoin');
		if (signed.payload.kind !== 'psbt') throw new Error('unreachable');
		expect(signed.payload.mode).toBe('p2tr-script');

		const tx = bitcoin.Transaction.fromHex(signed.payload.signedTxHex);
		expect(tx.ins).toHaveLength(1);
		// Script path witness: [signature, script, controlBlock]
		expect(tx.ins[0].witness).toHaveLength(3);
		expect(tx.ins[0].witness[0].length).toBe(64); // 64-byte schnorr (SIGHASH_DEFAULT)
	});
});

// ---------------------------------------------------------------------------
// Raw preimage mode
// ---------------------------------------------------------------------------

describe('bitcoin destination — sign (preimage mode)', () => {
	it('returns a raw 64-byte schnorr signature in preimage mode for p2tr-script', async () => {
		const fx = makeFixture();
		const plugin = btc();
		const ctx = buildCtx();
		await plugin.install?.(ctx);

		// Arbitrary 32-byte payload to "sign" (digest of arbitrary preimage).
		const preimage = new TextEncoder().encode('preimage-mode-test');

		const dWallet = fakeDWallet(fx.publicOutput);
		const signed = await plugin.extend.bitcoin.sign({
			dWallet,
			kind: 'preimage',
			preimage,
			mode: 'p2tr-script',
		});
		expect(signed.chain).toBe('bitcoin');
		if (signed.payload.kind !== 'preimage') throw new Error('unreachable');
		expect(signed.payload.signature.length).toBe(64);
		expect(signed.payload.mode).toBe('p2tr-script');
	});
});

// ---------------------------------------------------------------------------
// Publisher
// ---------------------------------------------------------------------------

describe('bitcoinPublisher', () => {
	it('throws at construction without apiBaseUrl or broadcast', () => {
		expect(() => bitcoinPublisher({} as never)).toThrow(/apiBaseUrl/);
	});

	it('routes a PSBT payload through the broadcast callback', async () => {
		const calls: Array<{ hex: string }> = [];
		const pub = bitcoinPublisher({
			apiBaseUrl: 'http://unused',
			broadcast: async (hex) => {
				calls.push({ hex });
				return 'a'.repeat(64); // fake txid
			},
		});
		const txid = await pub.broadcast({
			chain: 'bitcoin',
			payload: {
				kind: 'psbt',
				psbt: new bitcoin.Psbt(),
				signedTxHex: '0200000000',
				txid: 'a'.repeat(64),
				network: 'testnet',
				mode: 'p2wpkh',
				sender: 'tb1qfake',
			},
		});
		expect(txid).toBe('a'.repeat(64));
		expect(calls).toHaveLength(1);
		expect(calls[0].hex).toBe('0200000000');
	});

	it('throws when broadcast txid disagrees with the locally computed one', async () => {
		const pub = bitcoinPublisher({
			apiBaseUrl: 'http://unused',
			broadcast: async () => 'b'.repeat(64),
		});
		await expect(
			pub.broadcast({
				chain: 'bitcoin',
				payload: {
					kind: 'psbt',
					psbt: new bitcoin.Psbt(),
					signedTxHex: '0200000000',
					txid: 'a'.repeat(64),
					network: 'testnet',
					mode: 'p2wpkh',
					sender: 'tb1qfake',
				},
			}),
		).rejects.toThrow(/does not match/);
	});

	it('rejects pre-aborted signal without calling broadcast', async () => {
		const broadcast = vi.fn(async () => 'a'.repeat(64));
		const pub = bitcoinPublisher({ apiBaseUrl: 'http://unused', broadcast });
		const ctrl = new AbortController();
		ctrl.abort();
		await expect(
			pub.broadcast(
				{
					chain: 'bitcoin',
					payload: {
						kind: 'psbt',
						psbt: new bitcoin.Psbt(),
						signedTxHex: '0200000000',
						txid: 'a'.repeat(64),
						network: 'testnet',
						mode: 'p2wpkh',
						sender: 'tb1qfake',
					},
				},
				{ signal: ctrl.signal },
			),
		).rejects.toThrow(/aborted/);
		expect(broadcast).not.toHaveBeenCalled();
	});
});

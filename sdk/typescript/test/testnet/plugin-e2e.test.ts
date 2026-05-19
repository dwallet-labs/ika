// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

// Plugin-API testnet e2e. Exercises the typed `.use()` pipeline with all
// four default plugins. No `as any` casts — typed surface only.
//
// Required env:
//   IKA_TESTNET_PRIVATE_KEY  Bech32 `suiprivkey...` signer for Sui testnet

import { getJsonRpcFullnodeUrl, SuiJsonRpcClient } from '@mysten/sui/jsonRpc';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { Transaction } from '@mysten/sui/transactions';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { p256 } from '@noble/curves/nist.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { randomBytes } from '@noble/hashes/utils.js';
import { blake2b } from '@noble/hashes/blake2.js';
import { messageWithIntent } from '@mysten/sui/cryptography';
import {
	PublicKey,
	SystemProgram,
	TransactionMessage,
	VersionedTransaction,
} from '@solana/web3.js';
import { beforeAll, describe, expect, it } from 'vitest';

import {
	Curve,
	Hash,
	publicKeyFromDWalletOutput,
	SignatureAlgorithm,
	UserShareEncryptionKeys,
} from '@ika.xyz/sdk';
import { IkaClient } from '@ika.xyz/sdk/plugin';
import { SuiDWallet, suiSource } from '@ika.xyz/plugins/sui/source';
import { sui } from '@ika.xyz/plugins/sui/destination';
import { suiPublisher } from '@ika.xyz/plugins/sui/publisher';
import { solana } from '@ika.xyz/plugins/solana/destination';
import { solanaDevnet } from '@ika.xyz/plugins/solana/publisher';

const PRIVATE_KEY = process.env.IKA_TESTNET_PRIVATE_KEY;
const SHOULD_RUN = !!PRIVATE_KEY;
const TIMEOUT = 15 * 60_000;

function makeImportedKey(curve: Curve): Uint8Array {
	switch (curve) {
		case Curve.SECP256K1: {
			const scalar = secp256k1.utils.randomSecretKey();
			return new Uint8Array([0x20, ...scalar]);
		}
		case Curve.SECP256R1: {
			const scalar = p256.utils.randomSecretKey();
			return new Uint8Array([0x20, ...scalar]);
		}
		case Curve.ED25519:
		case Curve.RISTRETTO: {
			const bytes = new Uint8Array(randomBytes(32));
			bytes[31] &= 0x0f;
			return bytes;
		}
	}
}

function buildClient(
	signer: Ed25519Keypair,
	useks: UserShareEncryptionKeys,
	suiClient: SuiJsonRpcClient,
) {
	return new IkaClient()
		.use(suiSource({ network: 'testnet', signer, userShareEncryptionKeys: useks, suiClient }))
		.use(sui())
		.use(suiPublisher({ suiClient }))
		.use(solana())
		.use(solanaDevnet());
}

(SHOULD_RUN ? describe : describe.skip)('Ika plugin-API testnet e2e', () => {
	let signer: Ed25519Keypair;
	let suiClient: SuiJsonRpcClient;
	let edUseks: UserShareEncryptionKeys;
	let k1Useks: UserShareEncryptionKeys;
	let edIka: ReturnType<typeof buildClient>;
	let k1Ika: ReturnType<typeof buildClient>;

	beforeAll(async () => {
		signer = Ed25519Keypair.fromSecretKey(PRIVATE_KEY!);
		suiClient = new SuiJsonRpcClient({
			url: process.env.SUI_TESTNET_URL || getJsonRpcFullnodeUrl('testnet'),
			network: 'testnet',
		});
		edUseks = await UserShareEncryptionKeys.fromRootSeedKey(
			new TextEncoder().encode('plugin-e2e-seed-ed25519'),
			Curve.ED25519,
		);
		k1Useks = await UserShareEncryptionKeys.fromRootSeedKey(
			new TextEncoder().encode('plugin-e2e-seed-secp256k1'),
			Curve.SECP256K1,
		);
		edIka = buildClient(signer, edUseks, suiClient);
		k1Ika = buildClient(signer, k1Useks, suiClient);
		expect(edIka.source).toBeTruthy();
		expect(k1Ika.source).toBeTruthy();
	}, TIMEOUT);

	// =====================================================================
	// 1. Runtime / typed surface
	// =====================================================================

	describe('runtime', () => {
		it('client surface exposes registered plugin namespaces', () => {
			expect(edIka.source?.chain).toBe('sui');
			expect(typeof edIka.sui.createDWallet).toBe('function');
			expect(typeof edIka.sui.requestDKG).toBe('function');
			expect(typeof edIka.sui.requestDKGWithPublicShare).toBe('function');
			expect(typeof edIka.sui.requestImportedKeyVerification).toBe('function');
			expect(typeof edIka.sui.requestPresign).toBe('function');
			expect(typeof edIka.sui.requestGlobalPresign).toBe('function');
			expect(typeof edIka.sui.requestSign).toBe('function');
			expect(typeof edIka.sui.revealUserSecretShare).toBe('function');
			expect(typeof edIka.sui.sign).toBe('function');
			expect(typeof edIka.solana.sign).toBe('function');
		});

		it('publish() throws for an unregistered chain', async () => {
			// Using a string-cast — the typed publish narrows by design, but
			// we want to validate the runtime error too.
			await expect(
				(edIka.publish as (s: { chain: string; payload: unknown }) => Promise<string>)({
					chain: 'bitcoin',
					payload: {},
				}),
			).rejects.toThrow(/no publisher/);
		});
	});

	// =====================================================================
	// 2. Building-block composition (ED25519)
	// =====================================================================

	describe('source building blocks (ED25519)', () => {
		it(
			'prepareDKG output can be passed back into createDWallet',
			async () => {
				const dkgInput = await edIka.sui.prepareDKG({
					curve: Curve.ED25519,
					userShareEncryptionKeys: edUseks,
				});
				expect(dkgInput.userDKGMessage.byteLength).toBeGreaterThan(0);
				const dWallet = await edIka.sui.createDWallet({
					kind: 'shared',
					curve: Curve.ED25519,
					dkgRequestInput: dkgInput,
					sessionIdentifier: dkgInput.sessionIdentifier,
				});
				expect(dWallet.kind).toBe('shared');
				expect(dWallet.curve).toBe(Curve.ED25519);
			},
			TIMEOUT,
		);

		it(
			'requestGlobalPresign + requestSign round-trips an Ed25519 signature',
			async () => {
				const dWallet = await edIka.sui.createDWallet({
					kind: 'shared',
					curve: Curve.ED25519,
				});
				const presign = await edIka.sui.requestGlobalPresign({
					curve: Curve.ED25519,
					signatureAlgorithm: SignatureAlgorithm.EdDSA,
				});
				expect(presign.state.$kind).toBe('Completed');
				const message = new TextEncoder().encode('low-level-sign');
				const result = await edIka.sui.requestSign({
					dWallet,
					message,
					curve: Curve.ED25519,
					signatureAlgorithm: SignatureAlgorithm.EdDSA,
					hash: Hash.SHA512,
					presign,
				});
				expect(result.signature.length).toBe(64);
				const pubkey = await publicKeyFromDWalletOutput(Curve.ED25519, dWallet.publicOutput);
				expect(ed25519.verify(result.signature, message, pubkey)).toBe(true);
			},
			TIMEOUT,
		);
	});

	// =====================================================================
	// 3. Sui destination — flat-args sign, dWallet namespace, offline verify
	// =====================================================================

	describe('sui destination — ED25519 shared', () => {
		it(
			'dWallet.sui.sign({ kind, message }) verifies offline',
			async () => {
				// createDWallet now returns a DECORATED dWallet — `.sui` and
				// `.solana` are typed + attached without an explicit
				// `ika.decorate(...)` wrapping.
				const dWallet = await edIka.sui.createDWallet({
					kind: 'shared',
					curve: Curve.ED25519,
				});
				expect(typeof dWallet.sui.sign).toBe('function');
				expect(typeof dWallet.sui.getAddress).toBe('function');
				expect(typeof dWallet.solana.sign).toBe('function');

				const message = new TextEncoder().encode('hello-ika-plugin');
				const signed = await dWallet.sui.sign({ kind: 'message', message });
				expect(signed.chain).toBe('sui');
				const raw = Buffer.from(signed.payload.signature, 'base64');
				expect(raw[0]).toBe(0x00);
				expect(raw.length).toBe(1 + 64 + 32);

				const pubkey = await publicKeyFromDWalletOutput(Curve.ED25519, dWallet.publicOutput);
				const sigBytes = raw.subarray(1, 65);
				const digest = blake2b(messageWithIntent('PersonalMessage', message), {
					dkLen: 32,
				});
				expect(ed25519.verify(sigBytes, digest, pubkey)).toBe(true);
			},
			TIMEOUT,
		);

		it(
			'ika.sui.sign({ dWallet, kind, message }) (flat client-level call) works too',
			async () => {
				const dWallet = (await edIka.sui.createDWallet({
					kind: 'shared',
					curve: Curve.ED25519,
				})) as SuiDWallet<'ED25519'>;
				const signed = await edIka.sui.sign({
					dWallet,
					kind: 'message',
					message: new TextEncoder().encode('flat-args'),
				});
				expect(signed.chain).toBe('sui');
				expect(signed.payload.signature.length).toBeGreaterThan(0);
			},
			TIMEOUT,
		);
	});

	// =====================================================================
	// 4. Solana destination — flat args, offline verify
	// =====================================================================

	describe('solana destination — ED25519 shared', () => {
		it(
			'signs a VersionedTransaction whose signature verifies against the dWallet pubkey',
			async () => {
				const dWallet = await edIka.sui.createDWallet({
					kind: 'shared',
					curve: Curve.ED25519,
				});
				const pubkeyBytes = await publicKeyFromDWalletOutput(
					Curve.ED25519,
					dWallet.publicOutput,
				);
				const payer = new PublicKey(pubkeyBytes);
				const recipient = new PublicKey('11111111111111111111111111111112');
				const tx = new VersionedTransaction(
					new TransactionMessage({
						payerKey: payer,
						recentBlockhash: '11111111111111111111111111111111',
						instructions: [
							SystemProgram.transfer({
								fromPubkey: payer,
								toPubkey: recipient,
								lamports: 1_000,
							}),
						],
					}).compileToV0Message(),
				);
				const signed = await dWallet.solana.sign({ kind: 'transaction', tx });
				expect(signed.chain).toBe('solana');
				expect(signed.payload.signature.length).toBe(64);
				expect(signed.payload.sender).toBe(payer.toBase58());
				// Narrow by discriminator — `transaction` only exists on the
				// transaction-mode payload; message-mode is rejected here.
				if (signed.payload.kind !== 'transaction') {
					throw new Error('expected transaction-mode payload');
				}
				const messageBytes = signed.payload.transaction.message.serialize();
				expect(ed25519.verify(signed.payload.signature, messageBytes, pubkeyBytes)).toBe(true);
			},
			TIMEOUT,
		);
	});

	// =====================================================================
	// 5. Source building blocks (SECP256K1) — zero-trust + imported-key
	// =====================================================================

	describe('source building blocks (SECP256K1) — zero-trust + imported-key', () => {
		it(
			'createDWallet zero-trust + requestSign round-trip',
			async () => {
				const dw = await k1Ika.sui.createDWallet({
					kind: 'zero-trust',
					curve: Curve.SECP256K1,
				});
				expect(dw.kind).toBe('zero-trust');
				expect(dw.encryptedShareId).toMatch(/^0x/);
				const message = new TextEncoder().encode('zero-trust-sign');
				const presign = await k1Ika.sui.requestGlobalPresign({
					curve: Curve.SECP256K1,
					signatureAlgorithm: SignatureAlgorithm.ECDSASecp256k1,
				});
				const result = await k1Ika.sui.requestSign({
					dWallet: dw,
					message,
					curve: Curve.SECP256K1,
					signatureAlgorithm: SignatureAlgorithm.ECDSASecp256k1,
					hash: Hash.KECCAK256,
					presign,
				});
				expect(result.signature.length).toBeGreaterThan(0);
			},
			TIMEOUT,
		);

		it(
			'requestImportedKeyVerification returns dWallet + encShareId; signs with per-dWallet presign',
			async () => {
				const importedKey = makeImportedKey(Curve.SECP256K1);
				const result = await k1Ika.sui.requestImportedKeyVerification({
					importedKey,
					curve: Curve.SECP256K1,
				});
				expect(result.dWallet.kind).toBe('imported-key');
				const presign = await k1Ika.sui.requestPresign({
					dWallet: result.dWallet,
					signatureAlgorithm: SignatureAlgorithm.ECDSASecp256k1,
				});
				const signResult = await k1Ika.sui.requestSign({
					dWallet: result.dWallet,
					message: new TextEncoder().encode('imported-key-sign'),
					curve: Curve.SECP256K1,
					signatureAlgorithm: SignatureAlgorithm.ECDSASecp256k1,
					hash: Hash.SHA256,
					presign,
					encryptedShareId: result.encryptedShareId,
				});
				expect(signResult.signature.length).toBeGreaterThan(0);
			},
			TIMEOUT,
		);

		it('revealUserSecretShare without acknowledge throws', async () => {
			// We don't actually want to publish a secret share — just verify
			// the safety guard fires before any chain interaction.
			const fakeDWallet = new SuiDWallet(
				'0x0',
				'imported-key',
				Curve.SECP256K1,
				new Uint8Array(),
				{} as never,
				'0x0',
				'0xdead',
			);
			await expect(
				// @ts-expect-error — intentionally missing `acknowledge`
				k1Ika.sui.revealUserSecretShare({ dWallet: fakeDWallet }),
			).rejects.toThrow(/irreversible/);
		});
	});

	// =====================================================================
	// 6. Sui publisher — broadcast a Sui tx, validate the typed dispatch
	// =====================================================================

	describe('sui publisher — broadcast', () => {
		it(
			'broadcasts a signed Sui tx and returns a digest',
			async () => {
				const tx = new Transaction();
				tx.setSender(signer.toSuiAddress());
				const [c] = tx.splitCoins(tx.gas, [1]);
				tx.transferObjects([c], signer.toSuiAddress());
				const bytes = await tx.build({ client: suiClient });
				const { signature } = await signer.signTransaction(bytes);
				const digest = await edIka.publish({
					chain: 'sui',
					payload: { bytes, signature, sender: signer.toSuiAddress() },
				});
				expect(digest).toMatch(/^[A-Za-z0-9]+$/);
			},
			TIMEOUT,
		);
	});
});

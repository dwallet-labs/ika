// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

// Parameterized testnet e2e for IkaClient + IkaTransaction.
//
// Coverage matrix:
//   curve   ∈ { SECP256K1, SECP256R1, ED25519, RISTRETTO }
//   kind    ∈ { zero-trust, shared, imported-key, imported-key-shared }
//   sigAlgo, hash ∈ valid combinations for the curve (7 total tuples)
//   share-source ∈ { encrypted, secret+publicOutput, public } per applicable kind
//
// Plus one-off scenarios: future-sign (3 variants), sign-during-DKG, transfer,
// sync prepareDKG, hasDWallet on-chain ref.
//
// Required env:
//   IKA_TESTNET_PRIVATE_KEY  Bech32 `suiprivkey...` (sender funded with SUI + IKA)
// Optional env:
//   SUI_TESTNET_URL          Custom testnet RPC (default: public fullnode)
//   IKA_FEE_PER_OP           IKA fee budget per op in MIST (default: 100_000_000)
//
// Run: pnpm test:testnet

import { getJsonRpcFullnodeUrl, SuiJsonRpcClient } from '@mysten/sui/jsonRpc';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { coinWithBalance, Transaction } from '@mysten/sui/transactions';
import type { TransactionObjectArgument } from '@mysten/sui/transactions';
import { ed25519 } from '@noble/curves/ed25519.js';
import { p256 } from '@noble/curves/nist.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { randomBytes } from '@noble/hashes/utils.js';
import { beforeAll, describe, expect, it } from 'vitest';

import {
	createRandomSessionIdentifier,
	Curve,
	getNetworkConfig,
	Hash,
	IkaClient,
	ikaDwallet2pcMpc,
	IkaTransaction,
	prepareDKG,
	prepareDKGAsync,
	prepareImportedKeyDWalletVerification,
	publicKeyFromDWalletOutput,
	SignatureAlgorithm,
	UserShareEncryptionKeys,
} from '../../src/index.js';
import type {
	DWallet,
	IkaConfig,
	ImportedKeyDWallet,
	ImportedSharedDWallet,
	Presign,
	SharedDWallet,
	ZeroTrustDWallet,
} from '../../src/index.js';

const { CoordinatorInnerModule, SessionsManagerModule } = ikaDwallet2pcMpc;

const PRIVATE_KEY = process.env.IKA_TESTNET_PRIVATE_KEY;
const SHOULD_RUN = !!PRIVATE_KEY;

// Per-op IKA budget. Largest observed testnet fee is 250M for SECP256K1 ECDSA
// presign (protocol 5), so we default to 500M MIST (0.5 IKA) per op for slack.
const IKA_FEE = BigInt(process.env.IKA_FEE_PER_OP ?? 500_000_000);

const DKG_TIMEOUT = 10 * 60_000;
const PRESIGN_TIMEOUT = 5 * 60_000;
const SIGN_TIMEOUT = 5 * 60_000;
const SHARE_VERIFY_TIMEOUT = 5 * 60_000;

// Sleep between txs to let RPC indexing catch up before coinWithBalance polls
// the owned coins again.
const POST_TX_SLEEP_MS = 2_000;

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

// All curve / sig / hash tuples permitted by hash-signature-validation.ts
const VALID_COMBOS = [
	{ curve: Curve.SECP256K1, sigAlgo: SignatureAlgorithm.ECDSASecp256k1, hash: Hash.KECCAK256 },
	{ curve: Curve.SECP256K1, sigAlgo: SignatureAlgorithm.ECDSASecp256k1, hash: Hash.SHA256 },
	{ curve: Curve.SECP256K1, sigAlgo: SignatureAlgorithm.ECDSASecp256k1, hash: Hash.DoubleSHA256 },
	{ curve: Curve.SECP256K1, sigAlgo: SignatureAlgorithm.Taproot, hash: Hash.SHA256 },
	{ curve: Curve.SECP256R1, sigAlgo: SignatureAlgorithm.ECDSASecp256r1, hash: Hash.SHA256 },
	{ curve: Curve.ED25519, sigAlgo: SignatureAlgorithm.EdDSA, hash: Hash.SHA512 },
	{ curve: Curve.RISTRETTO, sigAlgo: SignatureAlgorithm.SchnorrkelSubstrate, hash: Hash.Merlin },
] as const;

type Combo = (typeof VALID_COMBOS)[number];

/**
 * Imported-key bytes per curve. Move-side BCS expects:
 *   - SECP256K1 / SECP256R1: vector<u8> (BCS length-prefixed) → 0x20 + 32 bytes
 *   - ED25519:               raw 32-byte seed
 *   - RISTRETTO:             raw 32-byte scalar (must be < L)
 *
 * We use @noble/curves utilities that already guarantee scalars in canonical
 * range for the SECP curves and Ed25519. For Ristretto we mask the high bits
 * so the scalar is < 2^252 < L.
 */
function generateImportedKey(curve: Curve): Uint8Array {
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
			// Mask the top 4 bits so the scalar is < 2^252 < L (canonical mod the
			// Ed25519/Ristretto group order). `randomSecretKey()` on Ed25519
			// returns a seed that is not necessarily canonical, so the WASM
			// importer rejects it.
			const bytes = new Uint8Array(randomBytes(32));
			bytes[31] &= 0x0f;
			return bytes;
		}
		default:
			throw new Error(`unsupported curve for import: ${curve}`);
	}
}

// =============================================================================
// Suite
// =============================================================================

(SHOULD_RUN ? describe : describe.skip)('Ika SDK testnet e2e (full sweep)', () => {
	let suiClient: SuiJsonRpcClient;
	let ikaClient: IkaClient;
	let ikaConfig: IkaConfig;
	let signerKeypair: Ed25519Keypair;
	let signerAddress: string;

	const useks = new Map<string, UserShareEncryptionKeys>();
	const usekRegistered = new Set<string>();
	const dwallets = new Map<string, DWallet>();
	const encryptedShareIds = new Map<string, string>();
	const importedKeySecrets = new Map<Curve, Uint8Array>();

	// -----------------------------------------------------------------------
	// Payment + tx helpers
	// -----------------------------------------------------------------------

	/**
	 * Provision an IKA coin (worth >= IKA_FEE) and a small SUI coin for the
	 * downstream Move call's `payment_ika: &mut Coin<IKA>` and
	 * `payment_sui: &mut Coin<SUI>` arguments. The Move call deducts its fee
	 * and leaves the coins in the PTB, so the leftover MUST be transferred
	 * (Sui coins have no `drop` ability). Call `finalize([...extras])` right
	 * before `exec()` to ship the leftovers + any other returned objects back
	 * to the sender in a single transferObjects.
	 */
	function pay(tx: Transaction) {
		const ika = tx.add(
			coinWithBalance({
				balance: IKA_FEE,
				type: `${ikaConfig.packages.ikaPackage}::ika::IKA`,
			}),
		);
		const sui = tx.splitCoins(tx.gas, [1_000_000]);
		const finalize = (...extras: TransactionObjectArgument[]) => {
			tx.transferObjects([...extras, ika, sui], signerAddress);
		};
		return { ika, sui, finalize };
	}

	async function exec(tx: Transaction) {
		const result = await suiClient.core.signAndExecuteTransaction({
			transaction: tx,
			signer: signerKeypair,
			include: { events: true },
		});
		// Let the RPC index the new state before the next coinWithBalance query.
		await sleep(POST_TX_SLEEP_MS);
		return result.Transaction;
	}

	function findEvent(txData: Awaited<ReturnType<typeof exec>>, partialType: string) {
		const ev = txData.events?.find((e) => e.eventType.includes(partialType));
		if (!ev) {
			throw new Error(
				`event '${partialType}' not found; got: ${txData.events
					?.map((e) => e.eventType)
					.join(', ')}`,
			);
		}
		return ev;
	}

	function parseDkgEvent(ev: { bcs?: number[] | null }) {
		return SessionsManagerModule.DWalletSessionEvent(
			CoordinatorInnerModule.DWalletDKGRequestEvent,
		).parse(new Uint8Array(ev.bcs ?? []));
	}

	function parsePresignEvent(ev: { bcs?: number[] | null }) {
		return SessionsManagerModule.DWalletSessionEvent(
			CoordinatorInnerModule.PresignRequestEvent,
		).parse(new Uint8Array(ev.bcs ?? []));
	}

	function parseSignEvent(ev: { bcs?: number[] | null }) {
		return SessionsManagerModule.DWalletSessionEvent(CoordinatorInnerModule.SignRequestEvent).parse(
			new Uint8Array(ev.bcs ?? []),
		);
	}

	function parseImportedKeyEvent(ev: { bcs?: number[] | null }) {
		return SessionsManagerModule.DWalletSessionEvent(
			CoordinatorInnerModule.DWalletImportedKeyVerificationRequestEvent,
		).parse(new Uint8Array(ev.bcs ?? []));
	}

	function parseFutureSignEvent(ev: { bcs?: number[] | null }) {
		return SessionsManagerModule.DWalletSessionEvent(
			CoordinatorInnerModule.FutureSignRequestEvent,
		).parse(new Uint8Array(ev.bcs ?? []));
	}

	function parseReEncryptEvent(ev: { bcs?: number[] | null }) {
		return SessionsManagerModule.DWalletSessionEvent(
			CoordinatorInnerModule.EncryptedShareVerificationRequestEvent,
		).parse(new Uint8Array(ev.bcs ?? []));
	}

	async function getUSEK(owner: 'alice' | 'bob', curve: Curve) {
		const key = `${owner}:${curve}`;
		let k = useks.get(key);
		if (!k) {
			k = await UserShareEncryptionKeys.fromRootSeedKey(randomBytes(32), curve);
			useks.set(key, k);
		}
		return k;
	}

	async function ensureUSEKRegistered(owner: 'alice' | 'bob', curve: Curve) {
		const key = `${owner}:${curve}`;
		if (usekRegistered.has(key)) return;
		const k = await getUSEK(owner, curve);
		const tx = new Transaction();
		tx.setSender(signerAddress);
		const ikaTx = new IkaTransaction({
			ikaClient,
			transaction: tx,
			userShareEncryptionKeys: k,
		});
		await ikaTx.registerEncryptionKey({ curve });
		await exec(tx);
		usekRegistered.add(key);
	}

	async function awaitPresignCompleted(presignId: string): Promise<Presign> {
		return ikaClient.getPresignInParticularState(presignId, 'Completed', {
			timeout: PRESIGN_TIMEOUT,
			interval: 2000,
		});
	}

	async function requestGlobalPresignFor(
		curve: Curve,
		sigAlgo: SignatureAlgorithm,
	): Promise<Presign> {
		const netKey = await ikaClient.getLatestNetworkEncryptionKey();
		const tx = new Transaction();
		tx.setSender(signerAddress);
		const p = pay(tx);
		const ikaTx = new IkaTransaction({ ikaClient, transaction: tx });
		const cap = ikaTx.requestGlobalPresign({
			dwalletNetworkEncryptionKeyId: netKey.id,
			curve,
			signatureAlgorithm: sigAlgo,
			ikaCoin: p.ika,
			suiCoin: p.sui,
		});
		p.finalize(cap);
		const result = await exec(tx);
		return awaitPresignCompleted(
			parsePresignEvent(findEvent(result, 'PresignRequestEvent')).event_data.presign_id,
		);
	}

	async function requestPerDwalletPresignFor(
		dWallet: DWallet,
		sigAlgo: SignatureAlgorithm,
	): Promise<Presign> {
		const tx = new Transaction();
		tx.setSender(signerAddress);
		const p = pay(tx);
		const ikaTx = new IkaTransaction({ ikaClient, transaction: tx });
		const cap = ikaTx.requestPresign({
			dWallet,
			signatureAlgorithm: sigAlgo,
			ikaCoin: p.ika,
			suiCoin: p.sui,
		});
		p.finalize(cap);
		const result = await exec(tx);
		return awaitPresignCompleted(
			parsePresignEvent(findEvent(result, 'PresignRequestEvent')).event_data.presign_id,
		);
	}

	// Imported-key ECDSA dWallets must use per-dWallet presign; everything else uses global.
	async function presignFor(dWallet: DWallet, sigAlgo: SignatureAlgorithm): Promise<Presign> {
		const isImportedEcdsa =
			dWallet.is_imported_key_dwallet &&
			(sigAlgo === SignatureAlgorithm.ECDSASecp256k1 ||
				sigAlgo === SignatureAlgorithm.ECDSASecp256r1);
		if (isImportedEcdsa) return requestPerDwalletPresignFor(dWallet, sigAlgo);
		return requestGlobalPresignFor(curveFromNumber(dWallet.curve), sigAlgo);
	}

	function curveFromNumber(n: number): Curve {
		switch (n) {
			case 0:
				return Curve.SECP256K1;
			case 1:
				return Curve.SECP256R1;
			case 2:
				return Curve.ED25519;
			case 3:
				return Curve.RISTRETTO;
			default:
				throw new Error(`unknown curve number ${n}`);
		}
	}

	// -----------------------------------------------------------------------
	// dWallet pool — lazy create-and-cache
	// -----------------------------------------------------------------------

	async function ensureZeroTrust(curve: Curve): Promise<ZeroTrustDWallet> {
		const key = `zero-trust:${curve}`;
		if (dwallets.has(key)) return dwallets.get(key) as ZeroTrustDWallet;

		await ensureUSEKRegistered('alice', curve);
		const aliceKeys = await getUSEK('alice', curve);
		const sessionIdBytes = createRandomSessionIdentifier();
		const dkgInput = await prepareDKGAsync(
			ikaClient,
			curve,
			aliceKeys,
			sessionIdBytes,
			signerAddress,
		);
		const netKey = await ikaClient.getLatestNetworkEncryptionKey();

		const tx = new Transaction();
		tx.setSender(signerAddress);
		const p = pay(tx);
		const ikaTx = new IkaTransaction({
			ikaClient,
			transaction: tx,
			userShareEncryptionKeys: aliceKeys,
		});
		const sessionId = ikaTx.registerSessionIdentifier(sessionIdBytes);
		const [cap] = await ikaTx.requestDWalletDKG({
			dkgRequestInput: dkgInput,
			curve,
			dwalletNetworkEncryptionKeyId: netKey.id,
			ikaCoin: p.ika,
			suiCoin: p.sui,
			sessionIdentifier: sessionId,
		});
		p.finalize(cap);
		const result = await exec(tx);
		const dkgEv = parseDkgEvent(findEvent(result, 'DWalletDKGRequestEvent'));
		const dWalletId = dkgEv.event_data.dwallet_id;
		const encShareId = dkgEv.event_data.user_secret_key_share.Encrypted!
			.encrypted_user_secret_key_share_id as string;

		const awaiting = (await ikaClient.getDWalletInParticularState(
			dWalletId,
			'AwaitingKeyHolderSignature',
			{ timeout: DKG_TIMEOUT, interval: 2000 },
		)) as ZeroTrustDWallet;

		const acceptTx = new Transaction();
		acceptTx.setSender(signerAddress);
		const acceptIka = new IkaTransaction({
			ikaClient,
			transaction: acceptTx,
			userShareEncryptionKeys: aliceKeys,
		});
		await acceptIka.acceptEncryptedUserShare({
			dWallet: awaiting,
			userPublicOutput: dkgInput.userPublicOutput,
			encryptedUserSecretKeyShareId: encShareId,
		});
		await exec(acceptTx);

		const active = (await ikaClient.getDWalletInParticularState(dWalletId, 'Active', {
			timeout: DKG_TIMEOUT,
			interval: 2000,
		})) as ZeroTrustDWallet;

		dwallets.set(key, active);
		encryptedShareIds.set(key, encShareId);
		return active;
	}

	async function ensureShared(curve: Curve): Promise<SharedDWallet> {
		const key = `shared:${curve}`;
		if (dwallets.has(key)) return dwallets.get(key) as SharedDWallet;

		await ensureUSEKRegistered('alice', curve);
		const aliceKeys = await getUSEK('alice', curve);
		const sessionIdBytes = createRandomSessionIdentifier();
		const dkgInput = await prepareDKGAsync(
			ikaClient,
			curve,
			aliceKeys,
			sessionIdBytes,
			signerAddress,
		);
		const netKey = await ikaClient.getLatestNetworkEncryptionKey();

		const tx = new Transaction();
		tx.setSender(signerAddress);
		const p = pay(tx);
		const ikaTx = new IkaTransaction({
			ikaClient,
			transaction: tx,
			userShareEncryptionKeys: aliceKeys,
		});
		const sessionId = ikaTx.registerSessionIdentifier(sessionIdBytes);
		const [cap] = await ikaTx.requestDWalletDKGWithPublicUserShare({
			publicKeyShareAndProof: dkgInput.userDKGMessage,
			publicUserSecretKeyShare: dkgInput.userSecretKeyShare,
			userPublicOutput: dkgInput.userPublicOutput,
			curve,
			dwalletNetworkEncryptionKeyId: netKey.id,
			ikaCoin: p.ika,
			suiCoin: p.sui,
			sessionIdentifier: sessionId,
		});
		p.finalize(cap);
		const result = await exec(tx);
		const dkgEv = parseDkgEvent(findEvent(result, 'DWalletDKGRequestEvent'));

		const active = (await ikaClient.getDWalletInParticularState(
			dkgEv.event_data.dwallet_id,
			'Active',
			{ timeout: DKG_TIMEOUT, interval: 2000 },
		)) as SharedDWallet;

		dwallets.set(key, active);
		return active;
	}

	async function ensureImported(curve: Curve): Promise<ImportedKeyDWallet> {
		const key = `imported-key:${curve}`;
		if (dwallets.has(key)) return dwallets.get(key) as ImportedKeyDWallet;

		await ensureUSEKRegistered('alice', curve);
		const aliceKeys = await getUSEK('alice', curve);
		let secret = importedKeySecrets.get(curve);
		if (!secret) {
			secret = generateImportedKey(curve);
			importedKeySecrets.set(curve, secret);
		}

		const sessionIdBytes = createRandomSessionIdentifier();
		const importInput = await prepareImportedKeyDWalletVerification(
			ikaClient,
			curve,
			sessionIdBytes,
			signerAddress,
			aliceKeys,
			secret,
		);

		const tx = new Transaction();
		tx.setSender(signerAddress);
		const p = pay(tx);
		const ikaTx = new IkaTransaction({
			ikaClient,
			transaction: tx,
			userShareEncryptionKeys: aliceKeys,
		});
		const sessionId = ikaTx.registerSessionIdentifier(sessionIdBytes);
		const cap = await ikaTx.requestImportedKeyDWalletVerification({
			importDWalletVerificationRequestInput: importInput,
			curve,
			signerPublicKey: aliceKeys.getSigningPublicKeyBytes(),
			sessionIdentifier: sessionId,
			ikaCoin: p.ika,
			suiCoin: p.sui,
		});
		p.finalize(cap);
		const result = await exec(tx);
		const ev = parseImportedKeyEvent(
			findEvent(result, 'DWalletImportedKeyVerificationRequestEvent'),
		);
		const dWalletId = ev.event_data.dwallet_id;
		const encShareId = ev.event_data.encrypted_user_secret_key_share_id as string;

		const awaiting = (await ikaClient.getDWalletInParticularState(
			dWalletId,
			'AwaitingKeyHolderSignature',
			{ timeout: DKG_TIMEOUT, interval: 2000 },
		)) as ImportedKeyDWallet;

		const acceptTx = new Transaction();
		acceptTx.setSender(signerAddress);
		const acceptIka = new IkaTransaction({
			ikaClient,
			transaction: acceptTx,
			userShareEncryptionKeys: aliceKeys,
		});
		await acceptIka.acceptEncryptedUserShare({
			dWallet: awaiting,
			userPublicOutput: importInput.userPublicOutput,
			encryptedUserSecretKeyShareId: encShareId,
		});
		await exec(acceptTx);

		const active = (await ikaClient.getDWalletInParticularState(dWalletId, 'Active', {
			timeout: DKG_TIMEOUT,
			interval: 2000,
		})) as ImportedKeyDWallet;

		dwallets.set(key, active);
		encryptedShareIds.set(key, encShareId);
		return active;
	}

	async function ensureImportedShared(curve: Curve): Promise<ImportedSharedDWallet> {
		const key = `imported-key-shared:${curve}`;
		if (dwallets.has(key)) return dwallets.get(key) as ImportedSharedDWallet;

		const imported = await ensureImported(curve);
		const aliceKeys = await getUSEK('alice', curve);
		const encShareId = encryptedShareIds.get(`imported-key:${curve}`)!;
		const encShare = await ikaClient.getEncryptedUserSecretKeyShare(encShareId);
		const pp = await ikaClient.getProtocolPublicParameters(imported);
		const { secretShare } = await aliceKeys.decryptUserShare(imported, encShare, pp);

		const tx = new Transaction();
		tx.setSender(signerAddress);
		const p = pay(tx);
		const ikaTx = new IkaTransaction({
			ikaClient,
			transaction: tx,
			userShareEncryptionKeys: aliceKeys,
		});
		ikaTx.makeDWalletUserSecretKeySharesPublic({
			dWallet: imported,
			secretShare,
			ikaCoin: p.ika,
			suiCoin: p.sui,
		});
		p.finalize();
		await exec(tx);

		const start = Date.now();
		let current: DWallet | undefined;
		while (Date.now() - start < SHARE_VERIFY_TIMEOUT) {
			const cur = await ikaClient.getDWallet(imported.id);
			if (cur.public_user_secret_key_share && cur.kind === 'imported-key-shared') {
				current = cur;
				break;
			}
			await sleep(2000);
		}
		if (!current) throw new Error('imported-shared never materialised');

		dwallets.set(key, current);
		return current as ImportedSharedDWallet;
	}

	// -----------------------------------------------------------------------
	// Sign helpers
	// -----------------------------------------------------------------------

	async function signZeroTrustEncrypted(
		dWallet: ZeroTrustDWallet,
		combo: Combo,
		message: Uint8Array,
	) {
		const aliceKeys = await getUSEK('alice', combo.curve);
		const presign = await presignFor(dWallet, combo.sigAlgo);
		const encShare = await ikaClient.getEncryptedUserSecretKeyShare(
			encryptedShareIds.get(`zero-trust:${combo.curve}`)!,
		);
		const tx = new Transaction();
		tx.setSender(signerAddress);
		const p = pay(tx);
		const ikaTx = new IkaTransaction({
			ikaClient,
			transaction: tx,
			userShareEncryptionKeys: aliceKeys,
		});
		const approval = ikaTx.approveMessage({
			dWalletCap: dWallet.dwallet_cap_id,
			curve: combo.curve,
			signatureAlgorithm: combo.sigAlgo,
			hashScheme: combo.hash,
			message,
		});
		await ikaTx.requestSign({
			dWallet,
			messageApproval: approval,
			verifiedPresignCap: ikaTx.verifyPresignCap({ presign }),
			hashScheme: combo.hash,
			presign,
			encryptedUserSecretKeyShare: encShare,
			message,
			signatureScheme: combo.sigAlgo,
			ikaCoin: p.ika,
			suiCoin: p.sui,
		});
		p.finalize();
		await finalizeSign(await exec(tx), combo);
	}

	async function signZeroTrustSecret(dWallet: ZeroTrustDWallet, combo: Combo, message: Uint8Array) {
		const aliceKeys = await getUSEK('alice', combo.curve);
		const encShare = await ikaClient.getEncryptedUserSecretKeyShare(
			encryptedShareIds.get(`zero-trust:${combo.curve}`)!,
		);
		const pp = await ikaClient.getProtocolPublicParameters(dWallet);
		const { secretShare, verifiedPublicOutput } = await aliceKeys.decryptUserShare(
			dWallet,
			encShare,
			pp,
		);
		const presign = await presignFor(dWallet, combo.sigAlgo);

		const tx = new Transaction();
		tx.setSender(signerAddress);
		const p = pay(tx);
		const ikaTx = new IkaTransaction({
			ikaClient,
			transaction: tx,
			userShareEncryptionKeys: aliceKeys,
		});
		const approval = ikaTx.approveMessage({
			dWalletCap: dWallet.dwallet_cap_id,
			curve: combo.curve,
			signatureAlgorithm: combo.sigAlgo,
			hashScheme: combo.hash,
			message,
		});
		await ikaTx.requestSign({
			dWallet,
			messageApproval: approval,
			verifiedPresignCap: ikaTx.verifyPresignCap({ presign }),
			hashScheme: combo.hash,
			presign,
			secretShare,
			publicOutput: verifiedPublicOutput,
			message,
			signatureScheme: combo.sigAlgo,
			ikaCoin: p.ika,
			suiCoin: p.sui,
		});
		p.finalize();
		await finalizeSign(await exec(tx), combo);
	}

	async function signSharedPublic(dWallet: SharedDWallet, combo: Combo, message: Uint8Array) {
		const presign = await presignFor(dWallet, combo.sigAlgo);
		const tx = new Transaction();
		tx.setSender(signerAddress);
		const p = pay(tx);
		const ikaTx = new IkaTransaction({ ikaClient, transaction: tx });
		const approval = ikaTx.approveMessage({
			dWalletCap: dWallet.dwallet_cap_id,
			curve: combo.curve,
			signatureAlgorithm: combo.sigAlgo,
			hashScheme: combo.hash,
			message,
		});
		await ikaTx.requestSign({
			dWallet,
			messageApproval: approval,
			verifiedPresignCap: ikaTx.verifyPresignCap({ presign }),
			hashScheme: combo.hash,
			presign,
			message,
			signatureScheme: combo.sigAlgo,
			ikaCoin: p.ika,
			suiCoin: p.sui,
		});
		p.finalize();
		await finalizeSign(await exec(tx), combo);
	}

	async function signImportedEncrypted(
		dWallet: ImportedKeyDWallet,
		combo: Combo,
		message: Uint8Array,
	) {
		const aliceKeys = await getUSEK('alice', combo.curve);
		const encShare = await ikaClient.getEncryptedUserSecretKeyShare(
			encryptedShareIds.get(`imported-key:${combo.curve}`)!,
		);
		const presign = await presignFor(dWallet, combo.sigAlgo);

		const tx = new Transaction();
		tx.setSender(signerAddress);
		const p = pay(tx);
		const ikaTx = new IkaTransaction({
			ikaClient,
			transaction: tx,
			userShareEncryptionKeys: aliceKeys,
		});
		const approval = ikaTx.approveImportedKeyMessage({
			dWalletCap: dWallet.dwallet_cap_id,
			curve: combo.curve,
			signatureAlgorithm: combo.sigAlgo,
			hashScheme: combo.hash,
			message,
		});
		await ikaTx.requestSignWithImportedKey({
			dWallet,
			importedKeyMessageApproval: approval,
			verifiedPresignCap: ikaTx.verifyPresignCap({ presign }),
			hashScheme: combo.hash,
			presign,
			encryptedUserSecretKeyShare: encShare,
			message,
			signatureScheme: combo.sigAlgo,
			ikaCoin: p.ika,
			suiCoin: p.sui,
		});
		p.finalize();
		await finalizeSign(await exec(tx), combo);
	}

	async function signImportedSecret(
		dWallet: ImportedKeyDWallet,
		combo: Combo,
		message: Uint8Array,
	) {
		const aliceKeys = await getUSEK('alice', combo.curve);
		const encShare = await ikaClient.getEncryptedUserSecretKeyShare(
			encryptedShareIds.get(`imported-key:${combo.curve}`)!,
		);
		const pp = await ikaClient.getProtocolPublicParameters(dWallet);
		const { secretShare, verifiedPublicOutput } = await aliceKeys.decryptUserShare(
			dWallet,
			encShare,
			pp,
		);
		const presign = await presignFor(dWallet, combo.sigAlgo);

		const tx = new Transaction();
		tx.setSender(signerAddress);
		const p = pay(tx);
		const ikaTx = new IkaTransaction({
			ikaClient,
			transaction: tx,
			userShareEncryptionKeys: aliceKeys,
		});
		const approval = ikaTx.approveImportedKeyMessage({
			dWalletCap: dWallet.dwallet_cap_id,
			curve: combo.curve,
			signatureAlgorithm: combo.sigAlgo,
			hashScheme: combo.hash,
			message,
		});
		await ikaTx.requestSignWithImportedKey({
			dWallet,
			importedKeyMessageApproval: approval,
			verifiedPresignCap: ikaTx.verifyPresignCap({ presign }),
			hashScheme: combo.hash,
			presign,
			secretShare,
			publicOutput: verifiedPublicOutput,
			message,
			signatureScheme: combo.sigAlgo,
			ikaCoin: p.ika,
			suiCoin: p.sui,
		});
		p.finalize();
		await finalizeSign(await exec(tx), combo);
	}

	async function signImportedSharedPublic(
		dWallet: ImportedSharedDWallet,
		combo: Combo,
		message: Uint8Array,
	) {
		const presign = await presignFor(dWallet, combo.sigAlgo);
		const tx = new Transaction();
		tx.setSender(signerAddress);
		const p = pay(tx);
		const ikaTx = new IkaTransaction({ ikaClient, transaction: tx });
		const approval = ikaTx.approveImportedKeyMessage({
			dWalletCap: dWallet.dwallet_cap_id,
			curve: combo.curve,
			signatureAlgorithm: combo.sigAlgo,
			hashScheme: combo.hash,
			message,
		});
		await ikaTx.requestSignWithImportedKey({
			dWallet,
			importedKeyMessageApproval: approval,
			verifiedPresignCap: ikaTx.verifyPresignCap({ presign }),
			hashScheme: combo.hash,
			presign,
			message,
			signatureScheme: combo.sigAlgo,
			ikaCoin: p.ika,
			suiCoin: p.sui,
		});
		p.finalize();
		await finalizeSign(await exec(tx), combo);
	}

	async function finalizeSign(
		signTx: Awaited<ReturnType<typeof exec>>,
		combo: Combo,
	): Promise<void> {
		const signEv = parseSignEvent(findEvent(signTx, 'SignRequestEvent'));
		const sign = await ikaClient.getSignInParticularState(
			signEv.event_data.sign_id,
			combo.curve,
			combo.sigAlgo,
			'Completed',
			{ timeout: SIGN_TIMEOUT, interval: 2000 },
		);
		expect(sign.state.$kind).toBe('Completed');
		expect(sign.state.Completed!.signature.length).toBeGreaterThan(0);
	}

	// -----------------------------------------------------------------------
	// Setup
	// -----------------------------------------------------------------------

	beforeAll(async () => {
		signerKeypair = Ed25519Keypair.fromSecretKey(PRIVATE_KEY!);
		signerAddress = signerKeypair.getPublicKey().toSuiAddress();

		suiClient = new SuiJsonRpcClient({
			url: process.env.SUI_TESTNET_URL || getJsonRpcFullnodeUrl('testnet'),
			network: 'testnet',
		});
		ikaClient = new IkaClient({
			suiClient,
			config: getNetworkConfig('testnet'),
			cache: true,
		});
		await ikaClient.initialize();
		ikaConfig = ikaClient.ikaConfig;
	}, DKG_TIMEOUT);

	// =======================================================================
	// 1. IkaClient read surface
	// =======================================================================

	describe('IkaClient surface', () => {
		it('initializes and exposes epoch / encryption keys / protocol params', async () => {
			const epoch = await ikaClient.getEpoch();
			expect(epoch).toBeGreaterThan(0);

			const allKeys = await ikaClient.getAllNetworkEncryptionKeys();
			expect(allKeys.length).toBeGreaterThan(0);

			const latest = await ikaClient.getLatestNetworkEncryptionKey();
			expect(latest.id).toBe(allKeys[allKeys.length - 1].id);

			const sameById = await ikaClient.getNetworkEncryptionKey(latest.id);
			expect(sameById.id).toBe(latest.id);

			const pp = await ikaClient.getProtocolPublicParameters(undefined, Curve.SECP256K1);
			expect(pp.byteLength).toBeGreaterThan(0);
			const ppCached = await ikaClient.getProtocolPublicParameters(undefined, Curve.SECP256K1);
			expect(ppCached).toBe(pp);
		});

		it('cache predicate methods round-trip', async () => {
			const latest = await ikaClient.getLatestNetworkEncryptionKey();
			await ikaClient.getProtocolPublicParameters(undefined, Curve.SECP256K1);
			expect(ikaClient.isProtocolPublicParametersCached(latest.id, Curve.SECP256K1)).toBe(true);
			const cached = ikaClient.getCachedProtocolPublicParameters(latest.id, Curve.SECP256K1);
			expect(cached?.byteLength).toBeGreaterThan(0);
			ikaClient.invalidateProtocolPublicParametersCache(latest.id, Curve.SECP256K1);
			expect(ikaClient.isProtocolPublicParametersCached(latest.id, Curve.SECP256K1)).toBe(false);
			expect(
				ikaClient.getCachedProtocolPublicParameters(latest.id, Curve.SECP256K1),
			).toBeUndefined();
		});

		it('invalidate* methods round-trip', async () => {
			ikaClient.invalidateObjectCache();
			ikaClient.invalidateEncryptionKeyCache();
			ikaClient.invalidateCache();
			await ikaClient.initialize();
			expect(await ikaClient.getEpoch()).toBeGreaterThan(0);
		});

		it('encryption-key options getter/setter round-trip', () => {
			const before = ikaClient.getEncryptionKeyOptions();
			ikaClient.setEncryptionKeyOptions({ autoDetect: false, encryptionKeyID: '0xabc' });
			expect(ikaClient.getEncryptionKeyOptions()).toEqual({
				autoDetect: false,
				encryptionKeyID: '0xabc',
			});
			ikaClient.setEncryptionKeyID('0xdef');
			expect(ikaClient.getEncryptionKeyOptions().encryptionKeyID).toBe('0xdef');
			ikaClient.setEncryptionKeyOptions(before);
		});

		it('getOwnedDWalletCaps returns paginated shape', async () => {
			const caps = await ikaClient.getOwnedDWalletCaps(signerAddress, undefined, 5);
			expect(Array.isArray(caps.dWalletCaps)).toBe(true);
			expect(typeof caps.hasNextPage).toBe('boolean');
		});
	});

	// =======================================================================
	// 2. Cross-product signing sweep
	// =======================================================================

	describe('signing sweep', () => {
		it.each(VALID_COMBOS)(
			'zero-trust / $curve / $sigAlgo / $hash / encrypted share',
			async (combo) => {
				const dWallet = await ensureZeroTrust(combo.curve);
				expect(dWallet.kind).toBe('zero-trust');
				const pubkey = await publicKeyFromDWalletOutput(
					combo.curve,
					Uint8Array.from(dWallet.state.Active!.public_output),
				);
				expect(pubkey.byteLength).toBeGreaterThan(0);
				await signZeroTrustEncrypted(
					dWallet,
					combo,
					new TextEncoder().encode(`zt-enc-${combo.curve}-${combo.sigAlgo}-${combo.hash}`),
				);
			},
			DKG_TIMEOUT + SIGN_TIMEOUT * 2,
		);

		it.each(VALID_COMBOS)(
			'zero-trust / $curve / $sigAlgo / $hash / secret share + public output',
			async (combo) => {
				const dWallet = await ensureZeroTrust(combo.curve);
				await signZeroTrustSecret(
					dWallet,
					combo,
					new TextEncoder().encode(`zt-sec-${combo.curve}-${combo.sigAlgo}-${combo.hash}`),
				);
			},
			DKG_TIMEOUT + SIGN_TIMEOUT * 2,
		);

		it.each(VALID_COMBOS)(
			'shared / $curve / $sigAlgo / $hash / public share',
			async (combo) => {
				const dWallet = await ensureShared(combo.curve);
				expect(dWallet.kind).toBe('shared');
				await signSharedPublic(
					dWallet,
					combo,
					new TextEncoder().encode(`shared-${combo.curve}-${combo.sigAlgo}-${combo.hash}`),
				);
			},
			DKG_TIMEOUT + SIGN_TIMEOUT * 2,
		);

		it.each(VALID_COMBOS)(
			'imported-key / $curve / $sigAlgo / $hash / encrypted share',
			async (combo) => {
				const dWallet = await ensureImported(combo.curve);
				expect(dWallet.kind).toBe('imported-key');
				await signImportedEncrypted(
					dWallet,
					combo,
					new TextEncoder().encode(`imp-enc-${combo.curve}-${combo.sigAlgo}-${combo.hash}`),
				);
			},
			DKG_TIMEOUT + SIGN_TIMEOUT * 2,
		);

		it.each(VALID_COMBOS)(
			'imported-key / $curve / $sigAlgo / $hash / secret share + public output',
			async (combo) => {
				const dWallet = await ensureImported(combo.curve);
				await signImportedSecret(
					dWallet,
					combo,
					new TextEncoder().encode(`imp-sec-${combo.curve}-${combo.sigAlgo}-${combo.hash}`),
				);
			},
			DKG_TIMEOUT + SIGN_TIMEOUT * 2,
		);

		it.each(VALID_COMBOS)(
			'imported-key-shared / $curve / $sigAlgo / $hash / public share',
			async (combo) => {
				const dWallet = await ensureImportedShared(combo.curve);
				expect(dWallet.kind).toBe('imported-key-shared');
				await signImportedSharedPublic(
					dWallet,
					combo,
					new TextEncoder().encode(`imps-${combo.curve}-${combo.sigAlgo}-${combo.hash}`),
				);
			},
			DKG_TIMEOUT + SIGN_TIMEOUT * 2,
		);
	});

	// =======================================================================
	// 3. Future-sign — three router variants
	// =======================================================================

	describe('future-sign variants', () => {
		it(
			'zero-trust / SECP256K1 / Taproot / SHA256 (encrypted-share router)',
			async () => {
				const combo: Combo = {
					curve: Curve.SECP256K1,
					sigAlgo: SignatureAlgorithm.Taproot,
					hash: Hash.SHA256,
				};
				const dWallet = await ensureZeroTrust(combo.curve);
				const aliceKeys = await getUSEK('alice', combo.curve);
				const encShare = await ikaClient.getEncryptedUserSecretKeyShare(
					encryptedShareIds.get(`zero-trust:${combo.curve}`)!,
				);
				const presign = await presignFor(dWallet, combo.sigAlgo);
				const message = new TextEncoder().encode('future-sign zero-trust enc');

				const reqTx = new Transaction();
				reqTx.setSender(signerAddress);
				const reqP = pay(reqTx);
				const reqIka = new IkaTransaction({
					ikaClient,
					transaction: reqTx,
					userShareEncryptionKeys: aliceKeys,
				});
				const partialCap = await reqIka.requestFutureSign({
					dWallet,
					verifiedPresignCap: reqIka.verifyPresignCap({ presign }),
					presign,
					encryptedUserSecretKeyShare: encShare,
					message,
					hashScheme: combo.hash,
					signatureScheme: combo.sigAlgo,
					ikaCoin: reqP.ika,
					suiCoin: reqP.sui,
				});
				reqP.finalize(partialCap);
				const reqResult = await exec(reqTx);
				const ev = parseFutureSignEvent(findEvent(reqResult, 'FutureSignRequestEvent'));

				const partial = await ikaClient.getPartialUserSignatureInParticularState(
					ev.event_data.partial_centralized_signed_message_id,
					'NetworkVerificationCompleted',
					{ timeout: SHARE_VERIFY_TIMEOUT, interval: 2000 },
				);

				const completeTx = new Transaction();
				completeTx.setSender(signerAddress);
				const completeP = pay(completeTx);
				const completeIka = new IkaTransaction({ ikaClient, transaction: completeTx });
				const approval = completeIka.approveMessage({
					dWalletCap: dWallet.dwallet_cap_id,
					curve: combo.curve,
					signatureAlgorithm: combo.sigAlgo,
					hashScheme: combo.hash,
					message,
				});
				completeIka.futureSign({
					partialUserSignatureCap: partial.cap_id,
					messageApproval: approval,
					ikaCoin: completeP.ika,
					suiCoin: completeP.sui,
				});
				completeP.finalize();
				await finalizeSign(await exec(completeTx), combo);
			},
			DKG_TIMEOUT + SIGN_TIMEOUT * 2,
		);

		it(
			'shared / ED25519 / EdDSA / SHA512 (public-share router)',
			async () => {
				const combo: Combo = {
					curve: Curve.ED25519,
					sigAlgo: SignatureAlgorithm.EdDSA,
					hash: Hash.SHA512,
				};
				const dWallet = await ensureShared(combo.curve);
				const presign = await presignFor(dWallet, combo.sigAlgo);
				const message = new TextEncoder().encode('future-sign shared');

				const reqTx = new Transaction();
				reqTx.setSender(signerAddress);
				const reqP = pay(reqTx);
				const reqIka = new IkaTransaction({ ikaClient, transaction: reqTx });
				const partialCap = await reqIka.requestFutureSign({
					dWallet,
					verifiedPresignCap: reqIka.verifyPresignCap({ presign }),
					presign,
					message,
					hashScheme: combo.hash,
					signatureScheme: combo.sigAlgo,
					ikaCoin: reqP.ika,
					suiCoin: reqP.sui,
				});
				reqP.finalize(partialCap);
				const reqResult = await exec(reqTx);
				const ev = parseFutureSignEvent(findEvent(reqResult, 'FutureSignRequestEvent'));
				const partial = await ikaClient.getPartialUserSignatureInParticularState(
					ev.event_data.partial_centralized_signed_message_id,
					'NetworkVerificationCompleted',
					{ timeout: SHARE_VERIFY_TIMEOUT, interval: 2000 },
				);

				const completeTx = new Transaction();
				completeTx.setSender(signerAddress);
				const completeP = pay(completeTx);
				const completeIka = new IkaTransaction({ ikaClient, transaction: completeTx });
				const approval = completeIka.approveMessage({
					dWalletCap: dWallet.dwallet_cap_id,
					curve: combo.curve,
					signatureAlgorithm: combo.sigAlgo,
					hashScheme: combo.hash,
					message,
				});
				completeIka.futureSign({
					partialUserSignatureCap: partial.cap_id,
					messageApproval: approval,
					ikaCoin: completeP.ika,
					suiCoin: completeP.sui,
				});
				completeP.finalize();
				await finalizeSign(await exec(completeTx), combo);
			},
			DKG_TIMEOUT + SIGN_TIMEOUT * 2,
		);

		it(
			'imported-key / SECP256K1 / ECDSASecp256k1 / KECCAK256 (imported-key router)',
			async () => {
				const combo: Combo = {
					curve: Curve.SECP256K1,
					sigAlgo: SignatureAlgorithm.ECDSASecp256k1,
					hash: Hash.KECCAK256,
				};
				const dWallet = await ensureImported(combo.curve);
				const aliceKeys = await getUSEK('alice', combo.curve);
				const encShare = await ikaClient.getEncryptedUserSecretKeyShare(
					encryptedShareIds.get(`imported-key:${combo.curve}`)!,
				);
				const presign = await presignFor(dWallet, combo.sigAlgo);
				const message = new TextEncoder().encode('future-sign imported');

				const reqTx = new Transaction();
				reqTx.setSender(signerAddress);
				const reqP = pay(reqTx);
				const reqIka = new IkaTransaction({
					ikaClient,
					transaction: reqTx,
					userShareEncryptionKeys: aliceKeys,
				});
				const partialCap = await reqIka.requestFutureSignWithImportedKey({
					dWallet,
					verifiedPresignCap: reqIka.verifyPresignCap({ presign }),
					presign,
					encryptedUserSecretKeyShare: encShare,
					message,
					hashScheme: combo.hash,
					signatureScheme: combo.sigAlgo,
					ikaCoin: reqP.ika,
					suiCoin: reqP.sui,
				});
				reqP.finalize(partialCap);
				const reqResult = await exec(reqTx);
				const ev = parseFutureSignEvent(findEvent(reqResult, 'FutureSignRequestEvent'));
				const partial = await ikaClient.getPartialUserSignatureInParticularState(
					ev.event_data.partial_centralized_signed_message_id,
					'NetworkVerificationCompleted',
					{ timeout: SHARE_VERIFY_TIMEOUT, interval: 2000 },
				);

				const completeTx = new Transaction();
				completeTx.setSender(signerAddress);
				const completeP = pay(completeTx);
				const completeIka = new IkaTransaction({ ikaClient, transaction: completeTx });
				const approval = completeIka.approveImportedKeyMessage({
					dWalletCap: dWallet.dwallet_cap_id,
					curve: combo.curve,
					signatureAlgorithm: combo.sigAlgo,
					hashScheme: combo.hash,
					message,
				});
				completeIka.futureSignWithImportedKey({
					partialUserSignatureCap: partial.cap_id,
					importedKeyMessageApproval: approval,
					ikaCoin: completeP.ika,
					suiCoin: completeP.sui,
				});
				completeP.finalize();
				await finalizeSign(await exec(completeTx), combo);
			},
			DKG_TIMEOUT + SIGN_TIMEOUT * 2,
		);
	});

	// =======================================================================
	// 4. Sign-during-DKG
	// =======================================================================

	describe('sign-during-DKG', () => {
		it(
			'shared / SECP256K1 / Taproot single PTB',
			async () => {
				const combo: Combo = {
					curve: Curve.SECP256K1,
					sigAlgo: SignatureAlgorithm.Taproot,
					hash: Hash.SHA256,
				};
				await ensureUSEKRegistered('alice', combo.curve);
				const aliceKeys = await getUSEK('alice', combo.curve);
				const presign = await requestGlobalPresignFor(combo.curve, combo.sigAlgo);

				const sessionIdBytes = createRandomSessionIdentifier();
				const dkgInput = await prepareDKGAsync(
					ikaClient,
					combo.curve,
					aliceKeys,
					sessionIdBytes,
					signerAddress,
				);
				const netKey = await ikaClient.getLatestNetworkEncryptionKey();
				const message = new TextEncoder().encode('sign-during-DKG shared');

				const tx = new Transaction();
				tx.setSender(signerAddress);
				const p = pay(tx);
				const ikaTx = new IkaTransaction({
					ikaClient,
					transaction: tx,
					userShareEncryptionKeys: aliceKeys,
				});
				const sessionId = ikaTx.registerSessionIdentifier(sessionIdBytes);
				const [cap] = await ikaTx.requestDWalletDKGWithPublicUserShare({
					publicKeyShareAndProof: dkgInput.userDKGMessage,
					publicUserSecretKeyShare: dkgInput.userSecretKeyShare,
					userPublicOutput: dkgInput.userPublicOutput,
					curve: combo.curve,
					dwalletNetworkEncryptionKeyId: netKey.id,
					ikaCoin: p.ika,
					suiCoin: p.sui,
					sessionIdentifier: sessionId,
					signDuringDKGRequest: {
						message,
						presign,
						verifiedPresignCap: ikaTx.verifyPresignCap({ presign }),
						hashScheme: combo.hash,
						signatureAlgorithm: combo.sigAlgo,
					},
				});
				p.finalize(cap);
				const result = await exec(tx);
				const dkgEv = parseDkgEvent(findEvent(result, 'DWalletDKGRequestEvent'));
				const signId = dkgEv.event_data.sign_during_dkg_request?.sign_id as string;
				expect(signId).toBeDefined();
				const sign = await ikaClient.getSignInParticularState(
					signId,
					combo.curve,
					combo.sigAlgo,
					'Completed',
					{ timeout: SIGN_TIMEOUT, interval: 2000 },
				);
				expect(sign.state.$kind).toBe('Completed');
			},
			DKG_TIMEOUT + SIGN_TIMEOUT,
		);

		it(
			'zero-trust / SECP256K1 / ECDSASecp256k1 single PTB',
			async () => {
				const combo: Combo = {
					curve: Curve.SECP256K1,
					sigAlgo: SignatureAlgorithm.ECDSASecp256k1,
					hash: Hash.KECCAK256,
				};
				await ensureUSEKRegistered('alice', combo.curve);
				const aliceKeys = await getUSEK('alice', combo.curve);
				const presign = await requestGlobalPresignFor(combo.curve, combo.sigAlgo);

				const sessionIdBytes = createRandomSessionIdentifier();
				const dkgInput = await prepareDKGAsync(
					ikaClient,
					combo.curve,
					aliceKeys,
					sessionIdBytes,
					signerAddress,
				);
				const netKey = await ikaClient.getLatestNetworkEncryptionKey();
				const message = new TextEncoder().encode('sign-during-DKG zero-trust');

				const tx = new Transaction();
				tx.setSender(signerAddress);
				const p = pay(tx);
				const ikaTx = new IkaTransaction({
					ikaClient,
					transaction: tx,
					userShareEncryptionKeys: aliceKeys,
				});
				const sessionId = ikaTx.registerSessionIdentifier(sessionIdBytes);
				const [cap] = await ikaTx.requestDWalletDKG({
					dkgRequestInput: dkgInput,
					curve: combo.curve,
					dwalletNetworkEncryptionKeyId: netKey.id,
					ikaCoin: p.ika,
					suiCoin: p.sui,
					sessionIdentifier: sessionId,
					signDuringDKGRequest: {
						message,
						presign,
						verifiedPresignCap: ikaTx.verifyPresignCap({ presign }),
						hashScheme: combo.hash,
						signatureAlgorithm: combo.sigAlgo,
					},
				});
				p.finalize(cap);
				const result = await exec(tx);
				const dkgEv = parseDkgEvent(findEvent(result, 'DWalletDKGRequestEvent'));
				const signId = dkgEv.event_data.sign_during_dkg_request?.sign_id as string;
				expect(signId).toBeDefined();
				const sign = await ikaClient.getSignInParticularState(
					signId,
					combo.curve,
					combo.sigAlgo,
					'Completed',
					{ timeout: SIGN_TIMEOUT, interval: 2000 },
				);
				expect(sign.state.$kind).toBe('Completed');
			},
			DKG_TIMEOUT + SIGN_TIMEOUT,
		);
	});

	// =======================================================================
	// 5. Transfer + bob signs
	// =======================================================================

	describe('transfer', () => {
		it(
			'zero-trust SECP256K1 alice -> bob, bob signs',
			async () => {
				const curve = Curve.SECP256K1;
				const sigCombo: Combo = {
					curve,
					sigAlgo: SignatureAlgorithm.Taproot,
					hash: Hash.SHA256,
				};
				await ensureUSEKRegistered('alice', curve);
				await ensureUSEKRegistered('bob', curve);

				const aliceKeys = await getUSEK('alice', curve);
				const sessionIdBytes = createRandomSessionIdentifier();
				const dkgInput = await prepareDKGAsync(
					ikaClient,
					curve,
					aliceKeys,
					sessionIdBytes,
					signerAddress,
				);
				const netKey = await ikaClient.getLatestNetworkEncryptionKey();

				const tx = new Transaction();
				tx.setSender(signerAddress);
				const p = pay(tx);
				const ikaTx = new IkaTransaction({
					ikaClient,
					transaction: tx,
					userShareEncryptionKeys: aliceKeys,
				});
				const sessionId = ikaTx.registerSessionIdentifier(sessionIdBytes);
				const [cap] = await ikaTx.requestDWalletDKG({
					dkgRequestInput: dkgInput,
					curve,
					dwalletNetworkEncryptionKeyId: netKey.id,
					ikaCoin: p.ika,
					suiCoin: p.sui,
					sessionIdentifier: sessionId,
				});
				p.finalize(cap);
				const result = await exec(tx);
				const dkgEv = parseDkgEvent(findEvent(result, 'DWalletDKGRequestEvent'));
				const dWalletId = dkgEv.event_data.dwallet_id;
				const aliceEncShareId = dkgEv.event_data.user_secret_key_share.Encrypted!
					.encrypted_user_secret_key_share_id as string;

				const awaiting = (await ikaClient.getDWalletInParticularState(
					dWalletId,
					'AwaitingKeyHolderSignature',
					{ timeout: DKG_TIMEOUT, interval: 2000 },
				)) as ZeroTrustDWallet;

				const acceptTx = new Transaction();
				acceptTx.setSender(signerAddress);
				const acceptIka = new IkaTransaction({
					ikaClient,
					transaction: acceptTx,
					userShareEncryptionKeys: aliceKeys,
				});
				await acceptIka.acceptEncryptedUserShare({
					dWallet: awaiting,
					userPublicOutput: dkgInput.userPublicOutput,
					encryptedUserSecretKeyShareId: aliceEncShareId,
				});
				await exec(acceptTx);

				const active = (await ikaClient.getDWalletInParticularState(dWalletId, 'Active', {
					timeout: DKG_TIMEOUT,
					interval: 2000,
				})) as ZeroTrustDWallet;

				const aliceEncShare = await ikaClient.getEncryptedUserSecretKeyShare(aliceEncShareId);
				const bobKeys = await getUSEK('bob', curve);
				const reTx = new Transaction();
				reTx.setSender(signerAddress);
				const reP = pay(reTx);
				const reIka = new IkaTransaction({
					ikaClient,
					transaction: reTx,
					userShareEncryptionKeys: aliceKeys,
				});
				await reIka.requestReEncryptUserShareFor({
					dWallet: active,
					destinationEncryptionKeyAddress: bobKeys.getSuiAddress(),
					sourceEncryptedUserSecretKeyShare: aliceEncShare,
					ikaCoin: reP.ika,
					suiCoin: reP.sui,
				});
				reP.finalize();
				const reResult = await exec(reTx);
				const reEv = parseReEncryptEvent(
					findEvent(reResult, 'EncryptedShareVerificationRequestEvent'),
				);
				const bobShareId = reEv.event_data.encrypted_user_secret_key_share_id as string;

				const bobShareVerified = await ikaClient.getEncryptedUserSecretKeyShareInParticularState(
					bobShareId,
					'NetworkVerificationCompleted',
					{ timeout: SHARE_VERIFY_TIMEOUT, interval: 2000 },
				);

				const aliceEK = await ikaClient.getActiveEncryptionKey(
					aliceEncShare.encryption_key_address,
				);
				const acceptTx2 = new Transaction();
				acceptTx2.setSender(signerAddress);
				const acceptIka2 = new IkaTransaction({
					ikaClient,
					transaction: acceptTx2,
					userShareEncryptionKeys: bobKeys,
				});
				await acceptIka2.acceptEncryptedUserShare({
					dWallet: active,
					sourceEncryptionKey: aliceEK,
					sourceEncryptedUserSecretKeyShare: aliceEncShare,
					destinationEncryptedUserSecretKeyShare: bobShareVerified,
				});
				await exec(acceptTx2);

				const bobShareSettled = await ikaClient.getEncryptedUserSecretKeyShareInParticularState(
					bobShareId,
					'KeyHolderSigned',
					{ timeout: SHARE_VERIFY_TIMEOUT, interval: 2000 },
				);

				const presign = await requestGlobalPresignFor(curve, sigCombo.sigAlgo);
				const message = new TextEncoder().encode('bob signs the transferred dWallet');
				const signTx = new Transaction();
				signTx.setSender(signerAddress);
				const signP = pay(signTx);
				const signIka = new IkaTransaction({
					ikaClient,
					transaction: signTx,
					userShareEncryptionKeys: bobKeys,
				});
				const approval = signIka.approveMessage({
					dWalletCap: active.dwallet_cap_id,
					curve,
					signatureAlgorithm: sigCombo.sigAlgo,
					hashScheme: sigCombo.hash,
					message,
				});
				await signIka.requestSign({
					dWallet: active,
					messageApproval: approval,
					verifiedPresignCap: signIka.verifyPresignCap({ presign }),
					hashScheme: sigCombo.hash,
					presign,
					encryptedUserSecretKeyShare: bobShareSettled,
					message,
					signatureScheme: sigCombo.sigAlgo,
					ikaCoin: signP.ika,
					suiCoin: signP.sui,
				});
				signP.finalize();
				await finalizeSign(await exec(signTx), sigCombo);
			},
			DKG_TIMEOUT + SIGN_TIMEOUT * 2,
		);

		it(
			'transfer with explicit sourceSecretShare overload',
			async () => {
				const curve = Curve.SECP256K1;
				await ensureUSEKRegistered('alice', curve);
				await ensureUSEKRegistered('bob', curve);
				const aliceKeys = await getUSEK('alice', curve);
				const bobKeys = await getUSEK('bob', curve);

				const dWallet = await ensureZeroTrust(curve);
				const aliceEncShareId = encryptedShareIds.get(`zero-trust:${curve}`)!;
				const aliceEncShare = await ikaClient.getEncryptedUserSecretKeyShare(aliceEncShareId);
				const pp = await ikaClient.getProtocolPublicParameters(dWallet);
				const { secretShare } = await aliceKeys.decryptUserShare(dWallet, aliceEncShare, pp);

				const reTx = new Transaction();
				reTx.setSender(signerAddress);
				const reP = pay(reTx);
				const reIka = new IkaTransaction({
					ikaClient,
					transaction: reTx,
					userShareEncryptionKeys: aliceKeys,
				});
				await reIka.requestReEncryptUserShareFor({
					dWallet,
					destinationEncryptionKeyAddress: bobKeys.getSuiAddress(),
					sourceEncryptedUserSecretKeyShare: aliceEncShare,
					sourceSecretShare: secretShare,
					ikaCoin: reP.ika,
					suiCoin: reP.sui,
				});
				reP.finalize();
				const reResult = await exec(reTx);
				const reEv = parseReEncryptEvent(
					findEvent(reResult, 'EncryptedShareVerificationRequestEvent'),
				);
				expect(reEv.event_data.encrypted_user_secret_key_share_id).toBeDefined();
			},
			DKG_TIMEOUT + SIGN_TIMEOUT,
		);
	});

	// =======================================================================
	// 6. Misc — sync prepareDKG, hasDWallet/getDWallet on-chain refs
	// =======================================================================

	describe('misc surface', () => {
		it('sync prepareDKG (vs prepareDKGAsync) produces a usable DKGRequestInput', async () => {
			const curve = Curve.SECP256K1;
			await ensureUSEKRegistered('alice', curve);
			const aliceKeys = await getUSEK('alice', curve);
			const pp = await ikaClient.getProtocolPublicParameters(undefined, curve);
			const sessionIdBytes = createRandomSessionIdentifier();
			const input = await prepareDKG(
				pp,
				curve,
				aliceKeys.encryptionKey,
				sessionIdBytes,
				signerAddress,
			);
			expect(input.userDKGMessage.byteLength).toBeGreaterThan(0);
			expect(input.userPublicOutput.byteLength).toBeGreaterThan(0);
			expect(input.userSecretKeyShare.byteLength).toBeGreaterThan(0);
			expect(input.encryptedUserShareAndProof.byteLength).toBeGreaterThan(0);
		}, 60_000);

		it('hasDWallet / getDWallet on-chain refs simulate cleanly', async () => {
			const dWallet = await ensureZeroTrust(Curve.SECP256K1);
			const tx = new Transaction();
			tx.setSender(signerAddress);
			const ikaTx = new IkaTransaction({ ikaClient, transaction: tx });
			ikaTx.hasDWallet({ dwalletId: dWallet.id });
			const ref = ikaTx.getDWallet({ dwalletId: dWallet.id });
			expect(ref).toBeDefined();
			const result = await suiClient.core.simulateTransaction({
				transaction: tx,
				include: { commandResults: true },
			});
			expect(result.commandResults?.length).toBeGreaterThan(0);
		});
	});
});

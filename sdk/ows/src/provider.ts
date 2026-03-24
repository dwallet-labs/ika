// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/**
 * IkaOWSProvider — Open Wallet Standard implementation backed by Ika MPC signing.
 *
 * Implements the OWS-compatible interface using Ika's 2PC-MPC protocol for
 * all signing operations. No dependency on @open-wallet-standard/core —
 * everything is implemented natively with proper policy enforcement.
 *
 * @example
 * ```ts
 * import { IkaOWSProvider, generateMnemonic } from '@ika.xyz/ows';
 * import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
 *
 * const provider = new IkaOWSProvider({
 *   network: 'mainnet',
 *   keypair: Ed25519Keypair.fromSecretKey(seed),
 * });
 * await provider.initialize();
 *
 * // Mnemonic wallet (OWS-compatible)
 * const wallet = await provider.createWallet('agent-wallet', 'passphrase');
 *
 * // Pre-fill presigns for fast signing
 * await provider.prefillPresigns('agent-wallet', 'ECDSASecp256k1', 5);
 *
 * // Sign (uses presign pool automatically)
 * const sig = await provider.signTransaction('agent-wallet', 'eip155:1', txHex);
 *
 * // Pure MPC wallet (no mnemonic, maximum security)
 * const dWallet = await provider.createDWallet('mpc-wallet');
 * ```
 */

import {
	Curve,
	getNetworkConfig,
	IkaClient,
	IkaTransaction,
	prepareDKGAsync,
	prepareImportedKeyDWalletVerification,
	publicKeyFromDWalletOutput,
	UserShareEncryptionKeys,
} from '@ika.xyz/sdk';
import type { Hash, IkaConfig, SignatureAlgorithm } from '@ika.xyz/sdk';
import type { Keypair } from '@mysten/sui/cryptography';
import { getJsonRpcFullnodeUrl, SuiJsonRpcClient } from '@mysten/sui/jsonRpc';
import type { TransactionObjectArgument } from '@mysten/sui/transactions';
import { Transaction } from '@mysten/sui/transactions';
import { sha256 } from '@noble/hashes/sha2.js';
import { randomBytes } from '@noble/hashes/utils.js';

import { deriveAccountsForCurve } from './address.js';
import { resolveChainParams } from './chains.js';
import {
	base64ToBytes,
	bytesToBase64,
	bytesToHex,
	decryptMnemonic,
	derivePrivateKeyFromMnemonic,
	encryptMnemonic,
	hexToBytes,
} from './crypto.js';
import { OWSError, OWSErrorCode } from './errors.js';
import { OWSExecutor } from './executor.js';
import { generateMnemonic } from './mnemonic.js';
import { PolicyEngine } from './policy.js';
import type { OnChainPolicy, PolicyFunction } from './policy.js';
import { PresignPool } from './presign-pool.js';
import { hashToNumber, signatureAlgorithmToNumber } from './tx/algo-numbers.js';
import * as policyEngineTx from './tx/policy-engine.js';
import type {
	ChainId,
	CreateDWalletOptions,
	CreateWalletOptions,
	DkgVaultEntry,
	IkaOWSProviderConfig,
	IkaVaultEntry,
	IkaWalletInfo,
	ImportMnemonicOptions,
	ImportPrivateKeyOptions,
	MnemonicVaultEntry,
	PolicyAccessGrantResult,
	PolicyEngineConfig,
	PolicyEngineCreateResult,
	PolicyRuleType,
	RuleConfig,
	SignOptions,
	SignResult,
} from './types.js';
import { deleteVaultEntry, findVaultEntry, listVaultEntries, saveVaultEntry } from './vault.js';

// ─── Re-exports ─────────────────────────────────────────────────────────

export { generateMnemonic, deriveAddressFromMnemonic, isValidMnemonic } from './mnemonic.js';
export { PolicyEngine } from './policy.js';
export type {
	PolicyFunction,
	PolicyContext,
	PolicyResult,
	OnChainPolicy,
	DeclarativePolicy,
	DeclarativePolicyRules,
} from './policy.js';

// ─── Provider ────────────────────────────────────────────────────────────

export class IkaOWSProvider {
	readonly #keypair: Keypair;
	readonly #vaultPath: string | undefined;
	readonly #mpcTimeout: number;
	readonly #mpcPollInterval: number;
	readonly #ikaConfig: IkaConfig;

	#suiClient: SuiJsonRpcClient;
	#ikaClient: IkaClient | null = null;
	#executor: OWSExecutor | null = null;
	#presignPool: PresignPool | null = null;
	#policyEngine: PolicyEngine;
	readonly #policyEngineConfig: PolicyEngineConfig | undefined;
	#policyEngineConfigOverride: PolicyEngineConfig | undefined;
	#initialized = false;

	/** 32-byte seed derived from the keypair for UserShareEncryptionKeys. */
	readonly #encryptionSeed: Uint8Array;

	/** Resolved policy engine config (override takes precedence). */
	get #activePolicyEngine(): PolicyEngineConfig | undefined {
		return this.#policyEngineConfigOverride ?? this.#policyEngineConfig;
	}

	/** Domain separator for encryption key derivation (must be 8 bytes). */
	static readonly #ENC_KEY_DOMAIN = new TextEncoder().encode('IKA_OWS_');

	constructor(config: IkaOWSProviderConfig) {
		this.#keypair = config.keypair;
		this.#vaultPath = config.vaultPath;
		this.#mpcTimeout = config.mpcTimeout ?? 300_000;
		this.#mpcPollInterval = config.mpcPollInterval ?? 2_000;
		this.#ikaConfig = config.ikaConfig ?? getNetworkConfig(config.network);

		// Extract 32-byte seed from ed25519 secret key.
		const secretKey = this.#keypair.getSecretKey();
		const secretKeyBytes =
			typeof secretKey === 'string'
				? new Uint8Array(Buffer.from(secretKey, 'base64')).slice(0, 32)
				: new Uint8Array(secretKey).slice(0, 32);

		// Domain-separated key derivation: SHA-256(domain || secret_key).
		const encKeyMaterial = new Uint8Array(
			IkaOWSProvider.#ENC_KEY_DOMAIN.length + secretKeyBytes.length,
		);
		encKeyMaterial.set(IkaOWSProvider.#ENC_KEY_DOMAIN, 0);
		encKeyMaterial.set(secretKeyBytes, IkaOWSProvider.#ENC_KEY_DOMAIN.length);

		this.#encryptionSeed = sha256(encKeyMaterial);

		this.#policyEngine = new PolicyEngine(config.vaultPath);
		this.#policyEngineConfig = config.policyEngine;

		const rpcUrl =
			config.suiRpcUrl ??
			getJsonRpcFullnodeUrl(config.network === 'mainnet' ? 'mainnet' : 'testnet');
		this.#suiClient = new SuiJsonRpcClient({ url: rpcUrl, network: config.network });
	}

	/** Initialize the provider. Must be called before wallet or signing operations. */
	async initialize(): Promise<void> {
		this.#ikaClient = new IkaClient({
			config: this.#ikaConfig,
			suiClient: this.#suiClient,
		});
		await this.#ikaClient.initialize();
		this.#executor = new OWSExecutor(this.#suiClient, this.#keypair);
		this.#presignPool = new PresignPool(
			this.#ikaClient,
			this.#suiClient,
			this.#keypair,
			this.#executor,
			this.#ikaConfig,
			this.#vaultPath,
		);

		// Hydrate presign pool from persisted vault entries.
		for (const entry of listVaultEntries(this.#vaultPath)) {
			this.#presignPool.hydrate(entry);
		}

		this.#initialized = true;
	}

	// ─── Mnemonic Wallets (OWS-compatible) ───────────────────────────────

	/**
	 * Create a new mnemonic-backed wallet.
	 *
	 * Generates a BIP-39 mnemonic via OWS core, derives the private key,
	 * imports it into Ika as an imported-key dWallet, and stores the
	 * encrypted mnemonic in the vault.
	 */
	async createWallet(
		name: string,
		passphrase: string,
		options?: CreateWalletOptions,
	): Promise<IkaWalletInfo> {
		this.#assertInitialized();

		const curve = options?.curve ?? Curve.SECP256K1;
		const mnemonic = generateMnemonic(options?.words);
		const privateKey = derivePrivateKeyFromMnemonic(mnemonic, curve, 0);

		const ikaInfo = await this.#importKeyIntoIka(privateKey, curve, options?.timeout);
		const { ciphertext, salt, nonce } = encryptMnemonic(mnemonic, passphrase);

		const entry: MnemonicVaultEntry = {
			owsVersion: 1,
			provider: 'ika',
			id: crypto.randomUUID(),
			name,
			kind: 'mnemonic',
			encryptedMnemonic: bytesToBase64(ciphertext),
			encryptionSalt: bytesToHex(salt),
			encryptionNonce: bytesToHex(nonce),
			dwalletId: ikaInfo.dwalletId,
			dwalletCapId: ikaInfo.dwalletCapId,
			curve,
			userShareKeysHex: ikaInfo.userShareKeysHex,
			encryptedUserSecretKeyShareId: ikaInfo.encryptedUserSecretKeyShareId,
			publicKeyHex: ikaInfo.publicKeyHex,
			networkEncryptionKeyId: ikaInfo.networkEncryptionKeyId,
			createdAt: new Date().toISOString(),
			presignIds: [],
		};

		saveVaultEntry(entry, this.#vaultPath);
		return this.#entryToWalletInfo(entry);
	}

	/**
	 * Import a wallet from a BIP-39 mnemonic.
	 *
	 * Derives the private key, imports it into Ika, and stores the
	 * encrypted mnemonic in the vault.
	 */
	async importWalletMnemonic(
		name: string,
		mnemonic: string,
		passphrase: string,
		options?: ImportMnemonicOptions,
	): Promise<IkaWalletInfo> {
		this.#assertInitialized();

		const curve = options?.curve ?? Curve.SECP256K1;
		const index = options?.index ?? 0;
		const privateKey = derivePrivateKeyFromMnemonic(mnemonic, curve, index);

		const ikaInfo = await this.#importKeyIntoIka(privateKey, curve, options?.timeout);
		const { ciphertext, salt, nonce } = encryptMnemonic(mnemonic, passphrase);

		const entry: MnemonicVaultEntry = {
			owsVersion: 1,
			provider: 'ika',
			id: crypto.randomUUID(),
			name,
			kind: 'mnemonic',
			encryptedMnemonic: bytesToBase64(ciphertext),
			encryptionSalt: bytesToHex(salt),
			encryptionNonce: bytesToHex(nonce),
			dwalletId: ikaInfo.dwalletId,
			dwalletCapId: ikaInfo.dwalletCapId,
			curve,
			userShareKeysHex: ikaInfo.userShareKeysHex,
			encryptedUserSecretKeyShareId: ikaInfo.encryptedUserSecretKeyShareId,
			publicKeyHex: ikaInfo.publicKeyHex,
			networkEncryptionKeyId: ikaInfo.networkEncryptionKeyId,
			createdAt: new Date().toISOString(),
			presignIds: [],
		};

		saveVaultEntry(entry, this.#vaultPath);
		return this.#entryToWalletInfo(entry);
	}

	/**
	 * Import a wallet from a raw private key.
	 */
	async importWalletPrivateKey(
		name: string,
		privateKeyHex: string,
		options?: ImportPrivateKeyOptions,
	): Promise<IkaWalletInfo> {
		this.#assertInitialized();

		const curve = options?.curve ?? Curve.SECP256K1;
		const privateKey = hexToBytes(privateKeyHex);
		const ikaInfo = await this.#importKeyIntoIka(privateKey, curve, options?.timeout);

		const entry: DkgVaultEntry = {
			owsVersion: 1,
			provider: 'ika',
			id: crypto.randomUUID(),
			name,
			kind: 'dkg', // No mnemonic to store; treated like a DKG entry.
			dwalletId: ikaInfo.dwalletId,
			dwalletCapId: ikaInfo.dwalletCapId,
			curve,
			userShareKeysHex: ikaInfo.userShareKeysHex,
			encryptedUserSecretKeyShareId: ikaInfo.encryptedUserSecretKeyShareId,
			publicKeyHex: ikaInfo.publicKeyHex,
			networkEncryptionKeyId: ikaInfo.networkEncryptionKeyId,
			createdAt: new Date().toISOString(),
			presignIds: [],
		};

		saveVaultEntry(entry, this.#vaultPath);
		return this.#entryToWalletInfo(entry);
	}

	// ─── DKG Wallets (Ika-specific) ──────────────────────────────────────

	/**
	 * Create a pure MPC wallet via Distributed Key Generation.
	 *
	 * No private key ever exists — the key is generated distributedly
	 * between the user and the Ika network.
	 */
	async createDWallet(name: string, options?: CreateDWalletOptions): Promise<IkaWalletInfo> {
		this.#assertInitialized();
		const ikaClient = this.#ikaClient!;

		const curve = options?.curve ?? Curve.SECP256K1;
		const timeout = options?.timeout ?? this.#mpcTimeout;

		const userShareEncryptionKeys = await UserShareEncryptionKeys.fromRootSeedKey(
			this.#encryptionSeed,
			curve,
		);
		const signerAddress = userShareEncryptionKeys.getSuiAddress();

		// Prepare DKG.
		const randomSessionIdentifier = randomBytes(32);
		const dkgData = await prepareDKGAsync(
			ikaClient,
			curve,
			userShareEncryptionKeys,
			randomSessionIdentifier,
			signerAddress,
		);

		// Execute DKG on-chain.
		const latestEncryptionKey = await ikaClient.getLatestNetworkEncryptionKey();
		const transaction = new Transaction();
		const ikaTransaction = new IkaTransaction({
			ikaClient,
			transaction,
			userShareEncryptionKeys,
		});

		await ikaTransaction.registerEncryptionKey({ curve });

		const sessionId = ikaTransaction.createSessionIdentifier();
		const ikaCoin = await this.#prepareIkaCoin(transaction);
		const [dWalletCap] = await ikaTransaction.requestDWalletDKG({
			dkgRequestInput: dkgData,
			curve,
			dwalletNetworkEncryptionKeyId: latestEncryptionKey.id,
			ikaCoin,
			suiCoin: transaction.gas,
			sessionIdentifier: sessionId,
		});

		transaction.transferObjects([dWalletCap], this.#keypair.toSuiAddress());

		const result = await this.#executor!.execute(transaction);

		const dkgEvent = (result.events ?? []).find((e: { type: string }) =>
			e.type.includes('DWalletDKGRequestEvent'),
		);
		if (!dkgEvent) {
			throw new OWSError(OWSErrorCode.DKG_FAILED, 'DKG event not found');
		}
		const eventData = dkgEvent.parsedJson as {
			dwallet_id: string;
			dwallet_cap_id: string;
			user_secret_key_share: {
				Encrypted?: { encrypted_user_secret_key_share_id: string };
			};
		};
		const encryptedShareId =
			eventData.user_secret_key_share?.Encrypted?.encrypted_user_secret_key_share_id;
		if (!encryptedShareId) {
			throw new OWSError(OWSErrorCode.DKG_FAILED, 'Encrypted share ID not found');
		}

		// Wait → accept → activate.
		const awaitingDWallet = await ikaClient.getDWalletInParticularState(
			eventData.dwallet_id,
			'AwaitingKeyHolderSignature',
			{ timeout },
		);

		const acceptTx = new Transaction();
		const acceptIkaTx = new IkaTransaction({
			ikaClient,
			transaction: acceptTx,
			userShareEncryptionKeys,
		});
		await acceptIkaTx.acceptEncryptedUserShare({
			dWallet: awaitingDWallet as any,
			userPublicOutput: dkgData.userPublicOutput,
			encryptedUserSecretKeyShareId: encryptedShareId,
		});
		await this.#executor!.execute(acceptTx);

		const activeDWallet = await ikaClient.getDWalletInParticularState(
			eventData.dwallet_id,
			'Active',
			{ timeout },
		);

		const publicOutput = Uint8Array.from(activeDWallet.state.Active?.public_output ?? []);
		const publicKey = await publicKeyFromDWalletOutput(curve, publicOutput);

		const entry: DkgVaultEntry = {
			owsVersion: 1,
			provider: 'ika',
			id: crypto.randomUUID(),
			name,
			kind: 'dkg',
			dwalletId: eventData.dwallet_id,
			dwalletCapId: eventData.dwallet_cap_id,
			curve,
			userShareKeysHex: Buffer.from(userShareEncryptionKeys.toShareEncryptionKeysBytes()).toString(
				'hex',
			),
			encryptedUserSecretKeyShareId: encryptedShareId,
			publicKeyHex: bytesToHex(publicKey),
			networkEncryptionKeyId: latestEncryptionKey.id,
			createdAt: new Date().toISOString(),
			presignIds: [],
		};

		saveVaultEntry(entry, this.#vaultPath);
		return this.#entryToWalletInfo(entry);
	}

	// ─── Wallet Management ───────────────────────────────────────────────

	listWallets(): IkaWalletInfo[] {
		return listVaultEntries(this.#vaultPath).map((e) => this.#entryToWalletInfo(e));
	}

	getWallet(nameOrId: string): IkaWalletInfo {
		return this.#entryToWalletInfo(findVaultEntry(nameOrId, this.#vaultPath));
	}

	deleteWallet(nameOrId: string): void {
		deleteVaultEntry(nameOrId, this.#vaultPath);
	}

	renameWallet(nameOrId: string, newName: string): void {
		const entry = findVaultEntry(nameOrId, this.#vaultPath);
		saveVaultEntry({ ...entry, name: newName }, this.#vaultPath);
	}

	/**
	 * Export a wallet's secret.
	 * - Mnemonic wallets: returns the decrypted mnemonic (requires passphrase).
	 * - DKG wallets: returns the serialized user share hex.
	 */
	exportWallet(nameOrId: string, passphrase?: string): string {
		const entry = findVaultEntry(nameOrId, this.#vaultPath);

		if (entry.kind === 'mnemonic') {
			if (!passphrase) {
				throw new OWSError(
					OWSErrorCode.PASSPHRASE_REQUIRED,
					'Passphrase required to export mnemonic wallet',
				);
			}
			return decryptMnemonic(
				base64ToBytes(entry.encryptedMnemonic),
				hexToBytes(entry.encryptionSalt),
				hexToBytes(entry.encryptionNonce),
				passphrase,
			);
		}

		// DKG wallet: return user share keys.
		return entry.userShareKeysHex;
	}

	// ─── Signing ─────────────────────────────────────────────────────────

	/**
	 * Sign a serialized transaction using MPC.
	 * Uses the presign pool for fast signing when presigns are available.
	 */
	async signTransaction(
		wallet: string,
		chain: ChainId,
		transactionHex: string,
		options?: SignOptions,
	): Promise<SignResult> {
		return this.#signBytes(wallet, chain, hexToBytes(transactionHex), options);
	}

	/**
	 * Sign an arbitrary message using MPC.
	 */
	async signMessage(
		wallet: string,
		chain: ChainId,
		message: string | Uint8Array,
		encoding?: 'utf8' | 'hex',
		options?: SignOptions,
	): Promise<SignResult> {
		let bytes: Uint8Array;
		if (message instanceof Uint8Array) {
			bytes = message;
		} else if (encoding === 'hex') {
			bytes = hexToBytes(message);
		} else {
			bytes = new TextEncoder().encode(message);
		}
		return this.#signBytes(wallet, chain, bytes, options);
	}

	// ─── Presign Pool ────────────────────────────────────────────────────

	/**
	 * Pre-create presigns for fast signing.
	 * @returns Created presign IDs.
	 */
	async prefillPresigns(
		wallet: string,
		signatureAlgorithm: SignatureAlgorithm,
		count: number,
	): Promise<string[]> {
		this.#assertInitialized();
		const entry = findVaultEntry(wallet, this.#vaultPath);
		return this.#presignPool!.prefill(entry, signatureAlgorithm, count);
	}

	/** Count of ready presigns for a wallet+algorithm. */
	availablePresigns(wallet: string, signatureAlgorithm: SignatureAlgorithm): number {
		const entry = findVaultEntry(wallet, this.#vaultPath);
		return this.#presignPool?.available(entry.id, signatureAlgorithm) ?? 0;
	}

	/** Direct access to the presign pool for advanced usage. */
	get presigns(): PresignPool {
		this.#assertInitialized();
		return this.#presignPool!;
	}

	// ─── Policies ────────────────────────────────────────────────────────

	/** Access the policy engine directly for advanced usage. */
	get policies(): PolicyEngine {
		return this.#policyEngine;
	}

	/**
	 * Add a custom policy function. Evaluated on every sign request.
	 *
	 * @example
	 * ```ts
	 * provider.addPolicy({
	 *   name: 'evm-only',
	 *   evaluate: (ctx) => {
	 *     if (!ctx.chain.startsWith('eip155:'))
	 *       return { allow: false, reason: 'Only EVM chains allowed' };
	 *     return { allow: true };
	 *   },
	 * });
	 * ```
	 */
	addPolicy(fn: PolicyFunction): void {
		this.#policyEngine.addPolicyFunction(fn);
	}

	/** Remove a custom policy function by name. */
	removePolicy(name: string): void {
		this.#policyEngine.removePolicyFunction(name);
	}

	/**
	 * Add an on-chain policy. Its Move function replaces the default
	 * `approve_message` during signing, adding custom on-chain validation.
	 *
	 * The Move function MUST accept the same parameters as `approve_message`
	 * plus any additional object args, and MUST return a MessageApproval.
	 *
	 * @example
	 * ```ts
	 * // Deploy a Move policy module, then register it:
	 * provider.addOnChainPolicy({
	 *   name: 'spending-limit',
	 *   approveFunction: '0xPKG::spending_limit::approve_with_limit',
	 *   objectArgs: ['0xLIMIT_CONFIG_OBJECT'],
	 * });
	 * ```
	 */
	addOnChainPolicy(policy: OnChainPolicy): void {
		this.#policyEngine.addOnChainPolicy(policy);
	}

	/** Remove an on-chain policy by name. */
	removeOnChainPolicy(name: string): void {
		this.#policyEngine.removeOnChainPolicy(name);
	}

	// ─── On-Chain Policy Engine Management ───────────────────────────────

	/**
	 * Create a policy engine that custodies a wallet's DWalletCap.
	 *
	 * The DWalletCap is transferred into the engine — the agent can no
	 * longer call `approve_message` directly. All signing must go through
	 * the engine's composable rule system.
	 *
	 * @param packageId - Package ID of the deployed ika_ows_policy contract.
	 * @param wallet - Wallet name or ID whose cap to custody.
	 * @param rules - Rules to register on the engine.
	 * @returns Engine and admin cap IDs.
	 *
	 * @example
	 * ```ts
	 * const result = await provider.createPolicyEngine('0xPKG', 'my-wallet', [
	 *   { type: 'rate_limit', maxPerWindow: 100, windowMs: 3_600_000 },
	 *   { type: 'sender_allowlist', allowed: [agentAddress] },
	 *   { type: 'spending_budget', maxPerWindow: 10000, maxPerTx: 500, windowMs: 86_400_000 },
	 * ]);
	 * ```
	 */
	async createPolicyEngine(
		packageId: string,
		wallet: string,
		rules: RuleConfig[],
	): Promise<PolicyEngineCreateResult> {
		this.#assertInitialized();

		const entry = findVaultEntry(wallet, this.#vaultPath);
		const isImportedKey = entry.kind === 'mnemonic';

		const tx = new Transaction();

		// Create engine (custodies the cap).
		const adminCap = isImportedKey
			? policyEngineTx.createWithImportedKeyCap(packageId, entry.dwalletCapId, tx)
			: policyEngineTx.createWithDkgCap(packageId, entry.dwalletCapId, tx);

		// Transfer admin cap to self.
		tx.transferObjects([adminCap], this.#keypair.toSuiAddress());

		const createResult = await this.#executor!.execute(tx);

		// Extract engine + admin cap IDs from PolicyEngineCreatedEvent.
		const createdEvent = createResult.events.find((e) =>
			e.type.includes('PolicyEngineCreatedEvent'),
		);
		if (!createdEvent) {
			throw new OWSError(
				OWSErrorCode.INVALID_INPUT,
				'PolicyEngineCreatedEvent not found in transaction result',
			);
		}
		const { engine_id: engineId, admin_cap_id: adminCapId } = createdEvent.parsedJson as {
			engine_id: string;
			admin_cap_id: string;
		};

		// Step 2: Register rules.
		if (rules.length > 0) {
			const rulesTx = new Transaction();
			for (const rule of rules) {
				this.#addRuleToTx(packageId, engineId, adminCapId, rule, rulesTx);
			}
			await this.#executor!.execute(rulesTx);
		}

		return { engineId, adminCapId, digest: createResult.digest };
	}

	/**
	 * Grant a PolicyAccessCap for an engine.
	 *
	 * @param packageId - Policy engine package ID.
	 * @param engineId - Engine object ID.
	 * @param adminCapId - Admin cap object ID.
	 * @param recipient - Address to transfer the access cap to (defaults to self).
	 */
	async grantPolicyAccess(
		packageId: string,
		engineId: string,
		adminCapId: string,
		recipient?: string,
	): Promise<PolicyAccessGrantResult> {
		this.#assertInitialized();

		const tx = new Transaction();
		const accessCap = policyEngineTx.grantAccess(packageId, engineId, adminCapId, tx);
		tx.transferObjects([accessCap], recipient ?? this.#keypair.toSuiAddress());
		const result = await this.#executor!.execute(tx);

		const grantEvent = result.events.find((e) =>
			e.type.includes('PolicyAccessGrantedEvent'),
		);
		if (!grantEvent) {
			throw new OWSError(
				OWSErrorCode.INVALID_INPUT,
				'PolicyAccessGrantedEvent not found in transaction result',
			);
		}
		const { access_cap_id: accessCapId } = grantEvent.parsedJson as {
			access_cap_id: string;
		};

		return { accessCapId, digest: result.digest };
	}

	/**
	 * Add a rule to an existing policy engine.
	 */
	async addPolicyRule(
		packageId: string,
		engineId: string,
		adminCapId: string,
		rule: RuleConfig,
	): Promise<void> {
		this.#assertInitialized();
		const tx = new Transaction();
		this.#addRuleToTx(packageId, engineId, adminCapId, rule, tx);
		await this.#executor!.execute(tx);
	}

	/**
	 * Remove a rule from an existing policy engine.
	 */
	async removePolicyRule(
		packageId: string,
		engineId: string,
		adminCapId: string,
		ruleType: PolicyRuleType,
	): Promise<void> {
		this.#assertInitialized();
		const tx = new Transaction();

		const removeFn: Record<string, () => void> = {
			rate_limit: () => policyEngineTx.removeRateLimit(packageId, engineId, adminCapId, tx),
			expiry: () => policyEngineTx.removeExpiry(packageId, engineId, adminCapId, tx),
			sender_allowlist: () => policyEngineTx.removeSenderAllowlist(packageId, engineId, adminCapId, tx),
			allowed_algorithms: () => policyEngineTx.removeAllowedAlgorithms(packageId, engineId, adminCapId, tx),
			spending_budget: () => policyEngineTx.removeSpendingBudget(packageId, engineId, adminCapId, tx),
			target_filter: () => policyEngineTx.removeTargetFilter(packageId, engineId, adminCapId, tx),
			time_delay: () => policyEngineTx.removeTimeDelay(packageId, engineId, adminCapId, tx),
		};

		removeFn[ruleType]?.();
		await this.#executor!.execute(tx);
	}

	/**
	 * Pause the policy engine. All signing blocked immediately.
	 */
	async pausePolicyEngine(packageId: string, engineId: string, adminCapId: string): Promise<void> {
		this.#assertInitialized();
		const tx = new Transaction();
		policyEngineTx.pause(packageId, engineId, adminCapId, tx);
		await this.#executor!.execute(tx);
	}

	/**
	 * Unpause the policy engine.
	 */
	async unpausePolicyEngine(packageId: string, engineId: string, adminCapId: string): Promise<void> {
		this.#assertInitialized();
		const tx = new Transaction();
		policyEngineTx.unpause(packageId, engineId, adminCapId, tx);
		await this.#executor!.execute(tx);
	}

	/**
	 * Set up a complete policy engine for a wallet in one call.
	 *
	 * Creates the engine, registers rules, grants an access cap to self,
	 * and updates the provider's policy engine config so subsequent
	 * signing calls go through the engine automatically.
	 *
	 * @returns The full PolicyEngineConfig ready for signing.
	 *
	 * @example
	 * ```ts
	 * const config = await provider.setupPolicyEngine('0xPKG', 'my-wallet', [
	 *   { type: 'rate_limit', maxPerWindow: 100, windowMs: 3_600_000 },
	 *   { type: 'spending_budget', maxPerWindow: 10000, maxPerTx: 500, windowMs: 86_400_000 },
	 * ]);
	 * // Provider now uses the policy engine for all signing.
	 * ```
	 */
	async setupPolicyEngine(
		packageId: string,
		wallet: string,
		rules: RuleConfig[],
	): Promise<PolicyEngineConfig> {
		const { engineId, adminCapId } = await this.createPolicyEngine(packageId, wallet, rules);
		const { accessCapId } = await this.grantPolicyAccess(packageId, engineId, adminCapId);

		const config: PolicyEngineConfig = {
			packageId,
			engineId,
			accessCapId,
			rules: rules.map((r) => r.type),
		};

		// Update the provider to use this engine for signing.
		this.#policyEngineConfigOverride = config;

		return config;
	}

	// ─── Utilities ───────────────────────────────────────────────────────

	getSuiAddress(): string {
		return this.#keypair.toSuiAddress();
	}

	get isInitialized(): boolean {
		return this.#initialized;
	}

	// ─── Internal: Import key into Ika ───────────────────────────────────

	async #importKeyIntoIka(
		privateKey: Uint8Array,
		curve: Curve,
		timeout?: number,
	): Promise<{
		dwalletId: string;
		dwalletCapId: string;
		encryptedUserSecretKeyShareId: string;
		publicKeyHex: string;
		userShareKeysHex: string;
		networkEncryptionKeyId: string;
	}> {
		const ikaClient = this.#ikaClient!;
		const effectiveTimeout = timeout ?? this.#mpcTimeout;

		const userShareEncryptionKeys = await UserShareEncryptionKeys.fromRootSeedKey(
			this.#encryptionSeed,
			curve,
		);
		const signerAddress = userShareEncryptionKeys.getSuiAddress();

		const sessionIdentifier = randomBytes(32);
		const importData = await prepareImportedKeyDWalletVerification(
			ikaClient,
			curve,
			sessionIdentifier,
			signerAddress,
			userShareEncryptionKeys,
			privateKey,
		);

		const transaction = new Transaction();
		const ikaTransaction = new IkaTransaction({
			ikaClient,
			transaction,
			userShareEncryptionKeys,
		});

		await ikaTransaction.registerEncryptionKey({ curve });

		const registeredSessionId = ikaTransaction.registerSessionIdentifier(sessionIdentifier);
		const ikaCoin = await this.#prepareIkaCoin(transaction);

		const importedKeyDWalletCap = await ikaTransaction.requestImportedKeyDWalletVerification({
			importDWalletVerificationRequestInput: importData,
			curve,
			signerPublicKey: userShareEncryptionKeys.getSigningPublicKeyBytes(),
			sessionIdentifier: registeredSessionId,
			ikaCoin,
			suiCoin: transaction.gas,
		});

		transaction.transferObjects([importedKeyDWalletCap], this.#keypair.toSuiAddress());

		const result = await this.#executor!.execute(transaction);

		const verificationEvent = (result.events ?? []).find((e: { type: string }) =>
			e.type.includes('DWalletImportedKeyVerificationRequestEvent'),
		);
		if (!verificationEvent) {
			throw new OWSError(OWSErrorCode.DKG_FAILED, 'Imported key verification event not found');
		}
		const eventData = verificationEvent.parsedJson as {
			dwallet_id: string;
			dwallet_cap_id: string;
			encrypted_user_secret_key_share_id: string;
		};

		// Wait → accept → activate.
		const awaitingDWallet = await ikaClient.getDWalletInParticularState(
			eventData.dwallet_id,
			'AwaitingKeyHolderSignature',
			{ timeout: effectiveTimeout },
		);

		const acceptTx = new Transaction();
		const acceptIkaTx = new IkaTransaction({
			ikaClient,
			transaction: acceptTx,
			userShareEncryptionKeys,
		});
		await acceptIkaTx.acceptEncryptedUserShare({
			dWallet: awaitingDWallet as any,
			userPublicOutput: importData.userPublicOutput,
			encryptedUserSecretKeyShareId: eventData.encrypted_user_secret_key_share_id,
		});
		await this.#executor!.execute(acceptTx);

		const activeDWallet = await ikaClient.getDWalletInParticularState(
			eventData.dwallet_id,
			'Active',
			{ timeout: effectiveTimeout },
		);

		const publicOutput = Uint8Array.from(activeDWallet.state.Active?.public_output ?? []);
		const publicKey = await publicKeyFromDWalletOutput(curve, publicOutput);
		const latestEncryptionKey = await ikaClient.getLatestNetworkEncryptionKey();

		return {
			dwalletId: eventData.dwallet_id,
			dwalletCapId: eventData.dwallet_cap_id,
			encryptedUserSecretKeyShareId: eventData.encrypted_user_secret_key_share_id,
			publicKeyHex: bytesToHex(publicKey),
			userShareKeysHex: Buffer.from(userShareEncryptionKeys.toShareEncryptionKeysBytes()).toString(
				'hex',
			),
			networkEncryptionKeyId: latestEncryptionKey.id,
		};
	}

	// ─── Internal: Sign bytes ────────────────────────────────────────────

	async #signBytes(
		walletNameOrId: string,
		chain: ChainId,
		message: Uint8Array,
		options?: SignOptions,
	): Promise<SignResult> {
		this.#assertInitialized();
		const ikaClient = this.#ikaClient!;

		const entry = findVaultEntry(walletNameOrId, this.#vaultPath);
		const chainParams = resolveChainParams(chain);

		if (entry.curve !== chainParams.curve) {
			throw new OWSError(
				OWSErrorCode.CURVE_MISMATCH,
				`Wallet curve ${entry.curve} doesn't match chain ${chain} (requires ${chainParams.curve})`,
			);
		}

		const signatureAlgorithm: SignatureAlgorithm =
			options?.signatureAlgorithmOverride ?? chainParams.signatureAlgorithm;
		const hash: Hash = options?.hashOverride ?? chainParams.hash;
		const timeout = options?.timeout ?? this.#mpcTimeout;
		const interval = options?.interval ?? this.#mpcPollInterval;

		// Layer 1: Evaluate local policies.
		await this.#policyEngine.evaluate({
			walletId: entry.id,
			walletName: entry.name,
			chain,
			operation: 'sign_transaction',
			messageHex: bytesToHex(message),
			timestamp: new Date().toISOString(),
		});

		const userShareEncryptionKeys = UserShareEncryptionKeys.fromShareEncryptionKeysBytes(
			hexToBytes(entry.userShareKeysHex),
		);

		// Fetch on-chain state.
		const activeDWallet = await ikaClient.getDWalletInParticularState(entry.dwalletId, 'Active', {
			timeout,
		});
		const encryptedShare = await ikaClient.getEncryptedUserSecretKeyShareInParticularState(
			entry.encryptedUserSecretKeyShareId,
			'KeyHolderSigned',
			{ timeout },
		);

		// Acquire presign from pool (fast) or create on-demand (slow).
		const completedPresign = await this.#presignPool!.acquire(
			entry,
			signatureAlgorithm,
			timeout,
			interval,
		);

		// Build sign transaction.
		const isImportedKey = entry.kind === 'mnemonic'; // Mnemonic wallets use imported-key protocol.
		const signTx = new Transaction();
		const signIkaTx = new IkaTransaction({
			ikaClient,
			transaction: signTx,
			userShareEncryptionKeys,
		});

		const verifiedPresignCap = signIkaTx.verifyPresignCap({ presign: completedPresign });
		const signIkaCoin = await this.#prepareIkaCoin(signTx);

		if (this.#activePolicyEngine) {
			// Layer 2: On-chain policy enforcement via PolicyEngine.
			const approval = this.#buildPolicyEngineApproval(
				signTx,
				signatureAlgorithm,
				hash,
				message,
				isImportedKey,
				options,
			);
			if (isImportedKey) {
				await signIkaTx.requestSignWithImportedKey({
					dWallet: activeDWallet as any,
					importedKeyMessageApproval: approval,
					hashScheme: hash as any,
					verifiedPresignCap,
					presign: completedPresign,
					encryptedUserSecretKeyShare: encryptedShare as any,
					message,
					signatureScheme: signatureAlgorithm as any,
					ikaCoin: signIkaCoin,
					suiCoin: signTx.gas,
				});
			} else {
				await signIkaTx.requestSign({
					dWallet: activeDWallet as any,
					messageApproval: approval,
					hashScheme: hash as any,
					verifiedPresignCap,
					presign: completedPresign,
					encryptedUserSecretKeyShare: encryptedShare as any,
					message,
					signatureScheme: signatureAlgorithm as any,
					ikaCoin: signIkaCoin,
					suiCoin: signTx.gas,
				});
			}
		} else if (isImportedKey) {
			const approval = signIkaTx.approveImportedKeyMessage({
				dWalletCap: entry.dwalletCapId,
				curve: entry.curve as any,
				signatureAlgorithm: signatureAlgorithm as any,
				hashScheme: hash as any,
				message,
			});
			await signIkaTx.requestSignWithImportedKey({
				dWallet: activeDWallet as any,
				importedKeyMessageApproval: approval,
				hashScheme: hash as any,
				verifiedPresignCap,
				presign: completedPresign,
				encryptedUserSecretKeyShare: encryptedShare as any,
				message,
				signatureScheme: signatureAlgorithm as any,
				ikaCoin: signIkaCoin,
				suiCoin: signTx.gas,
			});
		} else {
			const approval = signIkaTx.approveMessage({
				dWalletCap: entry.dwalletCapId,
				curve: entry.curve as any,
				signatureAlgorithm: signatureAlgorithm as any,
				hashScheme: hash as any,
				message,
			});
			await signIkaTx.requestSign({
				dWallet: activeDWallet as any,
				messageApproval: approval,
				hashScheme: hash as any,
				verifiedPresignCap,
				presign: completedPresign,
				encryptedUserSecretKeyShare: encryptedShare as any,
				message,
				signatureScheme: signatureAlgorithm as any,
				ikaCoin: signIkaCoin,
				suiCoin: signTx.gas,
			});
		}

		const signResult = await this.#executor!.execute(signTx);

		const signEvent = (signResult.events ?? []).find((e: { type: string }) =>
			e.type.includes('SignRequestEvent'),
		);
		if (!signEvent) {
			throw new OWSError(OWSErrorCode.SIGNING_FAILED, 'Sign event not found');
		}
		const signEventData = signEvent.parsedJson as { sign_id: string };

		const completedSign = await ikaClient.getSignInParticularState(
			signEventData.sign_id,
			entry.curve,
			signatureAlgorithm,
			'Completed',
			{ timeout, interval },
		);

		return {
			signature: bytesToHex(Uint8Array.from(completedSign.state.Completed?.signature ?? [])),
		};
	}

	// ─── Time Delay: Commit ─────────────────────────────────────────────

	/**
	 * Commit a message hash for the time_delay rule.
	 *
	 * Must be called before signing when the `time_delay` rule is active.
	 * The agent waits the configured delay, then calls `signTransaction`
	 * which will enforce the delay in the PTB.
	 *
	 * @param messageHash - blake2b256 hash of the message to sign.
	 */
	async commitTimeDelay(messageHash: Uint8Array): Promise<void> {
		this.#assertInitialized();
		const pe = this.#activePolicyEngine;
		if (!pe) {
			throw new OWSError(
				OWSErrorCode.INVALID_INPUT,
				'Policy engine not configured — commitTimeDelay requires policyEngine config',
			);
		}

		const tx = new Transaction();
		policyEngineTx.timeDelayCommit(pe.packageId, pe.engineId, pe.accessCapId, messageHash, tx);
		await this.#executor!.execute(tx);
	}

	// ─── Internal: Policy Engine Approval ────────────────────────────────

	/**
	 * Build policy engine approval within an existing transaction.
	 *
	 * Constructs the PTB calls:
	 * 1. create_request
	 * 2. enforce each registered rule → receipt
	 * 3. add_receipt for each
	 * 4. confirm_dkg / confirm_imported_key → MessageApproval
	 */
	#buildPolicyEngineApproval(
		tx: Transaction,
		signatureAlgorithm: SignatureAlgorithm,
		hash: Hash,
		message: Uint8Array,
		isImportedKey: boolean,
		options?: SignOptions,
	) {
		const pe = this.#activePolicyEngine!;

		const sigAlgoNum = signatureAlgorithmToNumber(signatureAlgorithm);
		const hashNum = hashToNumber(hash);

		// 1. Create request.
		const request = policyEngineTx.createRequest(
			pe.packageId,
			pe.engineId,
			pe.accessCapId,
			sigAlgoNum,
			hashNum,
			message,
			tx,
		);

		// 2–3. Enforce each rule and add receipt.
		for (const rule of pe.rules) {
			let receipt;
			switch (rule) {
				case 'rate_limit':
					receipt = policyEngineTx.enforceRateLimit(pe.packageId, pe.engineId, request, tx);
					break;
				case 'expiry':
					receipt = policyEngineTx.enforceExpiry(pe.packageId, pe.engineId, request, tx);
					break;
				case 'sender_allowlist':
					receipt = policyEngineTx.enforceSenderAllowlist(
						pe.packageId,
						pe.engineId,
						request,
						tx,
					);
					break;
				case 'allowed_algorithms':
					receipt = policyEngineTx.enforceAllowedAlgorithms(
						pe.packageId,
						pe.engineId,
						request,
						tx,
					);
					break;
				case 'spending_budget': {
					const value = options?.declaredValue;
					if (value === undefined) {
						throw new OWSError(
							OWSErrorCode.INVALID_INPUT,
							'spending_budget rule requires declaredValue in SignOptions',
						);
					}
					receipt = policyEngineTx.enforceSpendingBudget(
						pe.packageId,
						pe.engineId,
						request,
						value,
						tx,
					);
					break;
				}
				case 'target_filter': {
					const target = options?.declaredTarget;
					if (!target) {
						throw new OWSError(
							OWSErrorCode.INVALID_INPUT,
							'target_filter rule requires declaredTarget in SignOptions',
						);
					}
					receipt = policyEngineTx.enforceTargetFilter(
						pe.packageId,
						pe.engineId,
						request,
						target,
						tx,
					);
					break;
				}
				case 'time_delay':
					receipt = policyEngineTx.enforceTimeDelay(
						pe.packageId,
						pe.engineId,
						request,
						tx,
					);
					break;
			}

			policyEngineTx.addReceipt(pe.packageId, rule, this.#ruleTypeName(rule), request, receipt, tx);
		}

		// 4. Confirm → MessageApproval / ImportedKeyMessageApproval.
		const coordinatorId = this.#ikaConfig.objects.ikaDWalletCoordinator.objectID;
		if (isImportedKey) {
			return policyEngineTx.confirmImportedKey(
				pe.packageId,
				pe.engineId,
				coordinatorId,
				request,
				tx,
			);
		}
		return policyEngineTx.confirmDkg(pe.packageId, pe.engineId, coordinatorId, request, tx);
	}

	/** Map rule type string to Move struct name. */
	#ruleTypeName(rule: string): string {
		const map: Record<string, string> = {
			rate_limit: 'RateLimit',
			expiry: 'Expiry',
			sender_allowlist: 'SenderAllowlist',
			allowed_algorithms: 'AllowedAlgorithms',
			spending_budget: 'SpendingBudget',
			target_filter: 'TargetFilter',
			time_delay: 'TimeDelay',
		};
		return map[rule] ?? rule;
	}

	// ─── Internal: IKA Coin ──────────────────────────────────────────────

	/** The IKA coin type string: `<ikaPackage>::ika::IKA`. */
	get #ikaCoinType(): string {
		return `${this.#ikaConfig.packages.ikaPackage}::ika::IKA`;
	}

	/**
	 * Fetch the user's IKA coins and prepare a single merged coin in the
	 * transaction for protocol fee payment.
	 *
	 * If the user has multiple IKA coin objects, they are merged into one.
	 * Returns a `TransactionObjectArgument` pointing to the IKA coin.
	 */
	async #prepareIkaCoin(tx: Transaction): Promise<TransactionObjectArgument> {
		const owner = this.#keypair.toSuiAddress();
		const coins = await this.#suiClient.getCoins({
			owner,
			coinType: this.#ikaCoinType,
		});

		if (coins.data.length === 0) {
			throw new OWSError(
				OWSErrorCode.INVALID_INPUT,
				`No IKA coins found for address ${owner}. IKA tokens are required for protocol fees.`,
			);
		}

		// Use the first coin as the primary.
		const primary = tx.object(coins.data[0]!.coinObjectId);

		// Merge remaining coins into the primary if there are multiple.
		if (coins.data.length > 1) {
			const rest = coins.data.slice(1).map((c) => tx.object(c.coinObjectId));
			tx.mergeCoins(primary, rest);
		}

		return primary;
	}

	// ─── Internal: Policy Engine Helpers ─────────────────────────────────

	#addRuleToTx(
		packageId: string,
		engineId: string,
		adminCapId: string,
		rule: RuleConfig,
		tx: Transaction,
	): void {
		switch (rule.type) {
			case 'rate_limit':
				policyEngineTx.addRateLimit(
					packageId, engineId, adminCapId,
					rule.maxPerWindow, rule.windowMs, tx,
				);
				break;
			case 'expiry':
				policyEngineTx.addExpiry(packageId, engineId, adminCapId, rule.expiryMs, tx);
				break;
			case 'sender_allowlist':
				policyEngineTx.addSenderAllowlist(
					packageId, engineId, adminCapId, rule.allowed, tx,
				);
				break;
			case 'allowed_algorithms':
				policyEngineTx.addAllowedAlgorithms(
					packageId, engineId, adminCapId, rule.pairs, tx,
				);
				break;
			case 'spending_budget':
				policyEngineTx.addSpendingBudget(
					packageId, engineId, adminCapId,
					rule.maxPerWindow, rule.maxPerTx, rule.windowMs, tx,
				);
				break;
			case 'target_filter':
				policyEngineTx.addTargetFilter(
					packageId, engineId, adminCapId,
					(rule.allowedTargets ?? []).map(hexToBytes),
					(rule.blockedTargets ?? []).map(hexToBytes),
					tx,
				);
				break;
			case 'time_delay':
				policyEngineTx.addTimeDelay(packageId, engineId, adminCapId, rule.delayMs, tx);
				break;
		}
	}

	// ─── Internal: Helpers ───────────────────────────────────────────────

	#entryToWalletInfo(entry: IkaVaultEntry): IkaWalletInfo {
		const accounts = deriveAccountsForCurve(hexToBytes(entry.publicKeyHex), entry.curve);
		return {
			id: entry.id,
			name: entry.name,
			kind: entry.kind,
			accounts,
			createdAt: entry.createdAt,
			dwalletId: entry.dwalletId,
			dwalletCapId: entry.dwalletCapId,
			curve: entry.curve,
			publicKeyHex: entry.publicKeyHex,
		};
	}

	#assertInitialized(): void {
		if (!this.#initialized || !this.#ikaClient || !this.#executor || !this.#presignPool) {
			throw new OWSError(
				OWSErrorCode.NOT_INITIALIZED,
				'Provider not initialized. Call initialize() first.',
			);
		}
	}
}

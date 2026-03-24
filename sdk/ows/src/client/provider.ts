// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/**
 * IkaOWSProvider — Open Wallet Standard implementation backed by Ika MPC signing.
 *
 * Two ways to create wallets:
 * 1. **Import private key** → `createWallet(name, privateKeyHex, { curve })`
 *    The key is imported into Ika via the 2PC-MPC protocol. The raw key is
 *    only used during import and never stored. Users handle their own key
 *    derivation (HD, mnemonic, etc.) outside the SDK.
 *
 * 2. **DKG** → `createDWallet(name, { curve })`
 *    No private key ever exists. Generated distributedly via MPC.
 *
 * @example
 * ```ts
 * import { IkaOWSProvider } from '@ika.xyz/ows';
 * import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
 *
 * const provider = new IkaOWSProvider({
 *   network: 'mainnet',
 *   keypair: Ed25519Keypair.fromSecretKey(seed),
 * });
 * await provider.initialize();
 *
 * // Import a private key (secp256k1 for EVM/BTC/Cosmos)
 * const wallet = await provider.createWallet('evm-wallet', privateKeyHex, {
 *   curve: Curve.SECP256K1,
 * });
 *
 * // Sign
 * const sig = await provider.signTransaction('evm-wallet', 'eip155:1', txHex);
 *
 * // Pure MPC wallet (no private key, maximum security)
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
import { bcs as suiBcs } from '@mysten/sui/bcs';
import type { Keypair } from '@mysten/sui/cryptography';
import { getJsonRpcFullnodeUrl, SuiJsonRpcClient } from '@mysten/sui/jsonRpc';
import type { TransactionObjectArgument } from '@mysten/sui/transactions';
import { coinWithBalance, Transaction } from '@mysten/sui/transactions';
import { sha256 } from '@noble/hashes/sha2.js';
import { randomBytes } from '@noble/hashes/utils.js';

import { deriveAccountsForCurve } from '../chain/address.js';
import { resolveChainParams } from '../chain/chains.js';
import {
	base64ToBytes,
	bytesToHex,
	decryptMnemonic,
	hexToBytes,
} from '../crypto/index.js';
import { OWSError, OWSErrorCode } from '../errors.js';
import { OWSExecutor } from './executor.js';
import { PolicyEngine } from '../policy/index.js';
import type { OnChainPolicy, PolicyFunction } from '../policy/index.js';
import { PresignPool } from './presign-pool.js';
import { fromCurveAndSignatureAlgorithmAndHashToNumbers } from '../tx/algo-numbers.js';
import {
	allowedAlgorithms as allowedAlgorithmsGen,
	expiry as expiryGen,
	policyEngine as policyEngineGen,
	rateLimit as rateLimitGen,
	senderAllowlist as senderAllowlistGen,
	spendingBudget as spendingBudgetGen,
	targetFilter as targetFilterGen,
	timeDelay as timeDelayGen,
} from '../tx/policy-engine.js';
import type {
	ChainId,
	CreateDWalletOptions,
	DkgVaultEntry,
	IkaOWSProviderConfig,
	ImportedKeyVaultEntry,
	IkaVaultEntry,
	IkaWalletInfo,
	ImportPrivateKeyOptions,
	PolicyAccessGrantResult,
	PolicyEngineConfig,
	PolicyEngineCreateResult,
	PolicyRuleType,
	RuleConfig,
	SignOptions,
	SignResult,
} from '../types.js';
import { deleteVaultEntry, findVaultEntry, listVaultEntries, saveVaultEntry } from '../vault/index.js';

// ─── Re-exports ─────────────────────────────────────────────────────────

export { PolicyEngine } from '../policy/index.js';
export type {
	PolicyFunction,
	PolicyContext,
	PolicyResult,
	OnChainPolicy,
	DeclarativePolicy,
	DeclarativePolicyRules,
} from '../policy/index.js';

/** Move struct names for each rule type (used in type arguments). */
const RULE_TYPE_NAMES: Record<string, string> = {
	rate_limit: 'RateLimit',
	expiry: 'Expiry',
	sender_allowlist: 'SenderAllowlist',
	allowed_algorithms: 'AllowedAlgorithms',
	spending_budget: 'SpendingBudget',
	target_filter: 'TargetFilter',
	time_delay: 'TimeDelay',
};

// ─── Logging ─────────────────────────────────────────────────────────────

type LogLevel = 'info' | 'warn' | 'error' | 'debug';

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

	/** Tracks whether the encryption key has been registered on-chain. */
	#encryptionKeyRegistered = false;

	/** Domain separator for encryption key derivation (must be 8 bytes). */
	static readonly #ENC_KEY_DOMAIN = new TextEncoder().encode('IKA_OWS_');

	#log(level: LogLevel, msg: string, data?: Record<string, unknown>): void {
		if (level === 'debug' && !process.env.ODWS_DEBUG) return;
		const ts = new Date().toISOString();
		const suffix = data ? ' ' + JSON.stringify(data) : '';
		const fn = level === 'error' ? console.error : level === 'warn' ? console.warn : console.log;
		fn(`[OdWS] ${ts} ${level.toUpperCase()} ${msg}${suffix}`);
	}

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
		this.#log('info', 'initialize: starting');
		this.#ikaClient = new IkaClient({
			config: this.#ikaConfig,
			suiClient: this.#suiClient,
		});
		await this.#ikaClient.initialize();
		this.#executor = new OWSExecutor(this.#suiClient, this.#keypair);
		this.#presignPool = new PresignPool(
			this.#ikaClient,
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
		this.#log('info', 'initialize: complete');
	}

	// ─── Imported Key Wallets ────────────────────────────────────────────

	/**
	 * Create a wallet by importing a raw private key.
	 *
	 * The private key is imported into Ika as an imported-key dWallet.
	 * After import, all signing is done via MPC — the raw key is never
	 * stored and only used during the import protocol.
	 *
	 * **Private key format:**
	 * - secp256k1/r1: 32 bytes hex (standard ECDSA private key)
	 * - ed25519: 32 bytes hex (must be a valid canonical scalar < curve order L)
	 *
	 * For ed25519, if you're deriving from a mnemonic, do the derivation
	 * yourself (e.g., SLIP-0010) and pass the result here. If deriving
	 * from a seed, use SHA-512(seed)[0:32] reduced modulo L.
	 *
	 * @example
	 * ```ts
	 * // secp256k1 (EVM, Bitcoin, Cosmos)
	 * const wallet = await provider.createWallet('my-wallet', privateKeyHex, {
	 *   curve: Curve.SECP256K1,
	 * });
	 *
	 * // ed25519 (Solana, Sui, TON)
	 * const wallet = await provider.createWallet('sol-wallet', ed25519ScalarHex, {
	 *   curve: Curve.ED25519,
	 * });
	 * ```
	 */
	async createWallet(
		name: string,
		privateKeyHex: string,
		options?: ImportPrivateKeyOptions,
	): Promise<IkaWalletInfo> {
		this.#assertInitialized();
		this.#log('info', 'createWallet: starting', { name });

		const curve = options?.curve ?? Curve.SECP256K1;
		const privateKey = hexToBytes(privateKeyHex);
		const ikaInfo = await this.#importKeyIntoIka(privateKey, curve, options?.timeout);

		this.#log('info', 'createWallet: dWallet created', { dwalletId: ikaInfo.dwalletId });

		const entry: ImportedKeyVaultEntry = {
			owsVersion: 1,
			provider: 'ika',
			id: crypto.randomUUID(),
			name,
			kind: 'imported_key',
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
		this.#log('info', 'createWallet: complete', { name, dwalletId: ikaInfo.dwalletId });
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
		this.#log('info', 'createDWallet: starting', { name });
		const ikaClient = this.#ikaClient!;

		const curve = options?.curve ?? Curve.SECP256K1;
		const timeout = options?.timeout ?? this.#mpcTimeout;

		const userShareEncryptionKeys = await UserShareEncryptionKeys.fromRootSeedKey(
			this.#encryptionSeed,
			curve,
		);
		const signerAddress = this.#keypair.toSuiAddress();

		// Prepare DKG.
		const randomSessionIdentifier = randomBytes(32);
		const dkgData = await this.retry(() =>
			prepareDKGAsync(
				ikaClient,
				curve,
				userShareEncryptionKeys,
				randomSessionIdentifier,
				signerAddress,
			),
		);

		// Execute DKG on-chain.
		const latestEncryptionKey = await ikaClient.getLatestNetworkEncryptionKey();
		const transaction = new Transaction();
		const ikaTransaction = new IkaTransaction({
			ikaClient,
			transaction,
			userShareEncryptionKeys,
		});

		if (!this.#encryptionKeyRegistered) {
			try {
				await ikaClient.getActiveEncryptionKey(userShareEncryptionKeys.getSuiAddress());
				this.#encryptionKeyRegistered = true;
			} catch {
				await ikaTransaction.registerEncryptionKey({ curve });
				this.#encryptionKeyRegistered = true;
			}
		}

		const sessionId = ikaTransaction.registerSessionIdentifier(randomSessionIdentifier);
		const ikaCoin = this.#prepareIkaCoin(transaction);
		const [dWalletCap] = await ikaTransaction.requestDWalletDKG({
			dkgRequestInput: dkgData,
			curve,
			dwalletNetworkEncryptionKeyId: latestEncryptionKey.id,
			ikaCoin,
			suiCoin: transaction.gas,
			sessionIdentifier: sessionId,
		});

		transaction.transferObjects([dWalletCap, ikaCoin], this.#keypair.toSuiAddress());

		this.#log('info', 'createDWallet: DKG submitted');
		const result = await this.#executor!.execute(transaction);

		const dkgEvent = (result.events ?? []).find((e: { type: string }) =>
			e.type.includes('DWalletDKGRequestEvent'),
		);
		if (!dkgEvent) {
			throw new OWSError(OWSErrorCode.DKG_FAILED, 'DKG event not found');
		}
		const dkgSessionEvent = dkgEvent.parsedJson as {
			event_data: {
				dwallet_id: string;
				dwallet_cap_id: string;
				user_secret_key_share:
					| { Encrypted?: { encrypted_user_secret_key_share_id: string } }
					| { variant: string; fields: { encrypted_user_secret_key_share_id: string } };
			};
		};
		const eventData = dkgSessionEvent.event_data;
		const share = eventData.user_secret_key_share;
		const encryptedShareId =
			('Encrypted' in share ? share.Encrypted?.encrypted_user_secret_key_share_id : null) ??
			('fields' in share ? share.fields?.encrypted_user_secret_key_share_id : null);
		if (!encryptedShareId) {
			throw new OWSError(
				OWSErrorCode.DKG_FAILED,
				`Encrypted share ID not found. user_secret_key_share: ${JSON.stringify(eventData.user_secret_key_share).slice(0, 500)}`,
			);
		}

		// Wait → accept → activate.
		this.#log('info', 'createDWallet: awaiting state', { state: 'AwaitingKeyHolderSignature' });
		const awaitingDWallet = await ikaClient.getDWalletInParticularState(
			eventData.dwallet_id,
			'AwaitingKeyHolderSignature',
			{ timeout },
		);

		this.#log('info', 'createDWallet: accepted');
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
		this.#log('info', 'createDWallet: activated', { dwalletId: eventData.dwallet_id });

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
		this.#log('info', 'createDWallet: complete', { name, dwalletId: eventData.dwallet_id });
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

		// DKG / imported_key wallet: return user share keys.
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
		return this.retry(() => this.#signBytes(wallet, chain, hexToBytes(transactionHex), options));
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
		return this.retry(() => this.#signBytes(wallet, chain, bytes, options));
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
		this.#log('info', 'createPolicyEngine: starting', { wallet, rules: rules.map((r) => r.type) });

		const entry = findVaultEntry(wallet, this.#vaultPath);
		const isImportedKey = entry.kind === 'mnemonic' || entry.kind === 'imported_key';

		const tx = new Transaction();

		// Create engine (custodies the cap).
		const createFn = isImportedKey
			? policyEngineGen.createWithImportedKeyCap({
					package: packageId,
					arguments: { cap: entry.dwalletCapId },
				})
			: policyEngineGen.createWithDkgCap({
					package: packageId,
					arguments: { cap: entry.dwalletCapId },
				});
		const adminCap = tx.add(createFn);

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
		const createdData = createdEvent.parsedJson as { engine_id: string; admin_cap_id: string };
		const engineId = createdData.engine_id;
		const adminCapId = createdData.admin_cap_id;

		// Step 2: Register rules.
		if (rules.length > 0) {
			const rulesTx = new Transaction();
			for (const rule of rules) {
				this.#addRuleToTx(packageId, engineId, adminCapId, rule, rulesTx);
			}
			await this.#executor!.execute(rulesTx);
		}

		this.#log('info', 'createPolicyEngine: complete', { engineId });
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
		this.#log('info', 'grantPolicyAccess: starting', { engineId });

		const tx = new Transaction();
		const accessCap = tx.add(
			policyEngineGen.grantAccess({
				package: packageId,
				arguments: { self: engineId, adminCap: adminCapId },
			}),
		);
		tx.transferObjects([accessCap], recipient ?? this.#keypair.toSuiAddress());
		const result = await this.#executor!.execute(tx);

		const grantEvent = result.events.find((e) => e.type.includes('PolicyAccessGrantedEvent'));
		if (!grantEvent) {
			throw new OWSError(
				OWSErrorCode.INVALID_INPUT,
				'PolicyAccessGrantedEvent not found in transaction result',
			);
		}
		const grantData = grantEvent.parsedJson as { access_cap_id: string };
		const accessCapId = grantData.access_cap_id;
		this.#log('info', 'grantPolicyAccess: complete', { accessCapId });

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

		const args = { engine: engineId, adminCap: adminCapId };
		const removeFn: Record<string, () => void> = {
			rate_limit: () => tx.add(rateLimitGen.remove({ package: packageId, arguments: args })),
			expiry: () => tx.add(expiryGen.remove({ package: packageId, arguments: args })),
			sender_allowlist: () =>
				tx.add(senderAllowlistGen.remove({ package: packageId, arguments: args })),
			allowed_algorithms: () =>
				tx.add(allowedAlgorithmsGen.remove({ package: packageId, arguments: args })),
			spending_budget: () =>
				tx.add(spendingBudgetGen.remove({ package: packageId, arguments: args })),
			target_filter: () => tx.add(targetFilterGen.remove({ package: packageId, arguments: args })),
			time_delay: () => tx.add(timeDelayGen.remove({ package: packageId, arguments: args })),
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
		tx.add(
			policyEngineGen.pause({
				package: packageId,
				arguments: { self: engineId, adminCap: adminCapId },
			}),
		);
		await this.#executor!.execute(tx);
	}

	/**
	 * Unpause the policy engine.
	 */
	async unpausePolicyEngine(
		packageId: string,
		engineId: string,
		adminCapId: string,
	): Promise<void> {
		this.#assertInitialized();
		const tx = new Transaction();
		tx.add(
			policyEngineGen.unpause({
				package: packageId,
				arguments: { self: engineId, adminCap: adminCapId },
			}),
		);
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
		this.#log('info', 'setupPolicyEngine: starting', { wallet, rules: rules.map((r) => r.type) });
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
		this.#log('info', 'setupPolicyEngine: complete', { engineId });

		return config;
	}

	// ─── Utilities ───────────────────────────────────────────────────────

	getSuiAddress(): string {
		return this.#keypair.toSuiAddress();
	}

	get isInitialized(): boolean {
		return this.#initialized;
	}

	/** Execute a raw transaction through the serial executor. */
	async executeTransaction(tx: Transaction): Promise<import('./executor.js').TxResult> {
		this.#assertInitialized();
		return this.#executor!.execute(tx);
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
		this.#log('info', 'importKeyIntoIka: starting');
		const ikaClient = this.#ikaClient!;
		const effectiveTimeout = timeout ?? this.#mpcTimeout;

		const userShareEncryptionKeys = await UserShareEncryptionKeys.fromRootSeedKey(
			this.#encryptionSeed,
			curve,
		);
		const signerAddress = this.#keypair.toSuiAddress();

		// BCS-encode the private key for the WASM import function.
		// ECDSA curves: BCS vector<u8> (ULEB128 length prefix + raw bytes)
		// EdDSA/Schnorr: raw 32 bytes (no prefix)
		const encodedKey =
			curve === Curve.SECP256K1 || curve === Curve.SECP256R1
				? Uint8Array.from(suiBcs.vector(suiBcs.u8()).serialize(Array.from(privateKey)).toBytes())
				: Uint8Array.from(
						suiBcs.fixedArray(32, suiBcs.u8()).serialize(Array.from(privateKey)).toBytes(),
					);

		const sessionIdentifier = randomBytes(32);
		const importData = await this.retry(() =>
			prepareImportedKeyDWalletVerification(
				ikaClient,
				curve,
				sessionIdentifier,
				signerAddress,
				userShareEncryptionKeys,
				encodedKey,
			),
		);

		const transaction = new Transaction();
		const ikaTransaction = new IkaTransaction({
			ikaClient,
			transaction,
			userShareEncryptionKeys,
		});

		// Register encryption key in the same transaction if not yet registered.
		if (!this.#encryptionKeyRegistered) {
			try {
				await ikaClient.getActiveEncryptionKey(userShareEncryptionKeys.getSuiAddress());
				this.#encryptionKeyRegistered = true;
			} catch {
				await ikaTransaction.registerEncryptionKey({ curve });
				this.#encryptionKeyRegistered = true;
			}
		}

		const registeredSessionId = ikaTransaction.registerSessionIdentifier(sessionIdentifier);
		const ikaCoin = this.#prepareIkaCoin(transaction);

		const importedKeyDWalletCap = await ikaTransaction.requestImportedKeyDWalletVerification({
			importDWalletVerificationRequestInput: importData,
			curve,
			signerPublicKey: userShareEncryptionKeys.getSigningPublicKeyBytes(),
			sessionIdentifier: registeredSessionId,
			ikaCoin,
			suiCoin: transaction.gas,
		});

		transaction.transferObjects([importedKeyDWalletCap, ikaCoin], this.#keypair.toSuiAddress());

		this.#log('info', 'importKeyIntoIka: tx submitted');
		const result = await this.#executor!.execute(transaction);

		const verificationEvent = result.events.find((e) =>
			e.type.includes('DWalletImportedKeyVerificationRequestEvent'),
		);
		if (!verificationEvent) {
			const eventTypes = result.events.map((e) => e.type);
			throw new OWSError(
				OWSErrorCode.DKG_FAILED,
				`Imported key verification event not found. Events: ${JSON.stringify(eventTypes)}`,
			);
		}
		// Parse from BCS if parsedJson isn't available.
		// The event is DWalletSessionEvent<DWalletImportedKeyVerificationRequestEvent>.
		// The inner event data is nested under `event_data`.
		const sessionEvent = verificationEvent.parsedJson as {
			event_data: {
				dwallet_id: string;
				dwallet_cap_id: string;
				encrypted_user_secret_key_share_id: string;
			};
		};
		const eventData = sessionEvent.event_data;
		this.#log('info', 'importKeyIntoIka: verification event found', { dwalletId: eventData.dwallet_id });

		// Wait → accept → activate.
		this.#log('info', 'importKeyIntoIka: awaiting state', { state: 'AwaitingKeyHolderSignature' });
		const awaitingDWallet = await ikaClient.getDWalletInParticularState(
			eventData.dwallet_id,
			'AwaitingKeyHolderSignature',
			{ timeout: effectiveTimeout },
		);

		this.#log('info', 'importKeyIntoIka: accepted');
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
		this.#log('info', 'importKeyIntoIka: activated', { dwalletId: eventData.dwallet_id });

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
		this.#log('info', 'signBytes: starting', { wallet: walletNameOrId, chain });
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
		this.#log('info', 'signBytes: presign acquired');

		// Build sign transaction.
		const isImportedKey = entry.kind === 'mnemonic' || entry.kind === 'imported_key'; // Mnemonic wallets use imported-key protocol.
		const signTx = new Transaction();
		const signIkaTx = new IkaTransaction({
			ikaClient,
			transaction: signTx,
			userShareEncryptionKeys,
		});

		const verifiedPresignCap = signIkaTx.verifyPresignCap({ presign: completedPresign });
		const signIkaCoin = this.#prepareIkaCoin(signTx);

		if (this.#activePolicyEngine) {
			// Layer 2: On-chain policy enforcement via PolicyEngine.
			const approval = this.#buildPolicyEngineApproval(
				signTx,
				entry.curve,
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

		// Transfer residual IKA coin back to sender.
		signTx.transferObjects([signIkaCoin], this.#keypair.toSuiAddress());
		this.#log('info', 'signBytes: approval built, submitting tx');

		const signResult = await this.#executor!.execute(signTx);

		const signEvent = (signResult.events ?? []).find((e: { type: string }) =>
			e.type.includes('SignRequestEvent'),
		);
		if (!signEvent) {
			throw new OWSError(OWSErrorCode.SIGNING_FAILED, 'Sign event not found');
		}
		const signSessionEvent = signEvent.parsedJson as { event_data: { sign_id: string } };
		const signEventData = signSessionEvent.event_data;

		const completedSign = await ikaClient.getSignInParticularState(
			signEventData.sign_id,
			entry.curve,
			signatureAlgorithm,
			'Completed',
			{ timeout, interval },
		);

		this.#log('info', 'signBytes: signature received');
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
		tx.add(
			timeDelayGen.commit({
				package: pe.packageId,
				arguments: {
					engine: pe.engineId,
					accessCap: pe.accessCapId,
					messageHash: Array.from(messageHash),
				},
			}),
		);
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
		curve: Curve,
		signatureAlgorithm: SignatureAlgorithm,
		hash: Hash,
		message: Uint8Array,
		isImportedKey: boolean,
		options?: SignOptions,
	) {
		const pe = this.#activePolicyEngine!;
		const pkg = pe.packageId;

		const { signatureAlgorithmNumber: sigAlgoNum, hashNumber: hashNum } =
			fromCurveAndSignatureAlgorithmAndHashToNumbers(curve, signatureAlgorithm, hash);

		// 1. Create request.
		const request = tx.add(
			policyEngineGen.createRequest({
				package: pkg,
				arguments: {
					self: pe.engineId,
					accessCap: pe.accessCapId,
					signatureAlgorithm: sigAlgoNum,
					hashScheme: hashNum,
					message: Array.from(message),
				},
			}),
		);

		// 2–3. Enforce each rule and add receipt.
		for (const rule of pe.rules) {
			let receipt;
			switch (rule) {
				case 'rate_limit':
					receipt = tx.add(
						rateLimitGen.enforce({ package: pkg, arguments: { engine: pe.engineId, request } }),
					);
					break;
				case 'expiry':
					receipt = tx.add(
						expiryGen.enforce({ package: pkg, arguments: { engine: pe.engineId, request } }),
					);
					break;
				case 'sender_allowlist':
					receipt = tx.add(
						senderAllowlistGen.enforce({
							package: pkg,
							arguments: { engine: pe.engineId, request },
						}),
					);
					break;
				case 'allowed_algorithms':
					receipt = tx.add(
						allowedAlgorithmsGen.enforce({
							package: pkg,
							arguments: { engine: pe.engineId, request },
						}),
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
					receipt = tx.add(
						spendingBudgetGen.enforce({
							package: pkg,
							arguments: { engine: pe.engineId, request, declaredValue: value },
						}),
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
					receipt = tx.add(
						targetFilterGen.enforce({
							package: pkg,
							arguments: { engine: pe.engineId, request, declaredTarget: Array.from(target) },
						}),
					);
					break;
				}
				case 'time_delay':
					receipt = tx.add(
						timeDelayGen.enforce({ package: pkg, arguments: { engine: pe.engineId, request } }),
					);
					break;
			}

			tx.add(
				policyEngineGen.addReceipt({
					package: pkg,
					typeArguments: [`${pkg}::${rule}::${RULE_TYPE_NAMES[rule]}`],
					arguments: { self: request, receipt },
				}),
			);
		}

		// 4. Confirm → MessageApproval / ImportedKeyMessageApproval.
		const coordinatorId = this.#ikaConfig.objects.ikaDWalletCoordinator.objectID;
		if (isImportedKey) {
			return tx.add(
				policyEngineGen.confirmImportedKey({
					package: pkg,
					arguments: { self: pe.engineId, coordinator: coordinatorId, request },
				}),
			);
		}
		return tx.add(
			policyEngineGen.confirmDkg({
				package: pkg,
				arguments: { self: pe.engineId, coordinator: coordinatorId, request },
			}),
		);
	}

	// ─── Internal: IKA Coin ──────────────────────────────────────────────

	/** The IKA coin type string: `<ikaPackage>::ika::IKA`. */
	get #ikaCoinType(): string {
		return `${this.#ikaConfig.packages.ikaPackage}::ika::IKA`;
	}

	/** Minimum IKA per operation: 10 IKA (10 * 10^9 MIST). */
	static readonly #IKA_PER_OPERATION = 10n * 10n ** 9n;

	/**
	 * Add an IKA coin intent to the transaction.
	 *
	 * Allocates 10 IKA per operation for protocol fees. Uses `coinWithBalance`
	 * which resolves coins at build time — no manual coin queries, no race
	 * conditions between concurrent transactions.
	 *
	 * Minimum balance required: 10 IKA.
	 * Recommended starting balance: 1,000–10,000 IKA.
	 */
	#prepareIkaCoin(tx: Transaction): TransactionObjectArgument {
		return tx.add(
			coinWithBalance({
				type: this.#ikaCoinType,
				balance: IkaOWSProvider.#IKA_PER_OPERATION,
			}),
		);
	}

	// ─── Internal: Policy Engine Helpers ─────────────────────────────────

	#addRuleToTx(
		packageId: string,
		engineId: string,
		adminCapId: string,
		rule: RuleConfig,
		tx: Transaction,
	): void {
		const pkg = packageId;
		switch (rule.type) {
			case 'rate_limit':
				tx.add(
					rateLimitGen.add({
						package: pkg,
						arguments: {
							engine: engineId,
							adminCap: adminCapId,
							maxPerWindow: rule.maxPerWindow,
							windowMs: rule.windowMs,
						},
					}),
				);
				break;
			case 'expiry':
				tx.add(
					expiryGen.add({
						package: pkg,
						arguments: { engine: engineId, adminCap: adminCapId, expiryMs: rule.expiryMs },
					}),
				);
				break;
			case 'sender_allowlist':
				tx.add(
					senderAllowlistGen.add({
						package: pkg,
						arguments: { engine: engineId, adminCap: adminCapId, allowed: rule.allowed },
					}),
				);
				break;
			case 'allowed_algorithms': {
				const pairObjects = rule.pairs.map((p) =>
					tx.add(
						allowedAlgorithmsGen.newPair({
							package: pkg,
							arguments: { signatureAlgorithm: p.signatureAlgorithm, hashScheme: p.hashScheme },
						}),
					),
				);
				const pairsVec = tx.makeMoveVec({
					elements: pairObjects,
					type: `${pkg}::allowed_algorithms::AllowedPair`,
				});
				tx.add(
					allowedAlgorithmsGen.add({
						package: pkg,
						arguments: { engine: engineId, adminCap: adminCapId, pairs: pairsVec },
					}),
				);
				break;
			}
			case 'spending_budget':
				tx.add(
					spendingBudgetGen.add({
						package: pkg,
						arguments: {
							engine: engineId,
							adminCap: adminCapId,
							maxPerWindow: rule.maxPerWindow,
							maxPerTx: rule.maxPerTx,
							windowMs: rule.windowMs,
						},
					}),
				);
				break;
			case 'target_filter':
				tx.add(
					targetFilterGen.add({
						package: pkg,
						arguments: {
							engine: engineId,
							adminCap: adminCapId,
							allowedTargets: (rule.allowedTargets ?? []).map((h) => Array.from(hexToBytes(h))),
							blockedTargets: (rule.blockedTargets ?? []).map((h) => Array.from(hexToBytes(h))),
						},
					}),
				);
				break;
			case 'time_delay':
				tx.add(
					timeDelayGen.add({
						package: pkg,
						arguments: { engine: engineId, adminCap: adminCapId, delayMs: rule.delayMs },
					}),
				);
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

	/** Retry on transient network errors (ECONNRESET, fetch failed, etc.). */
	async retry<T>(fn: () => Promise<T>, maxAttempts: number = 3): Promise<T> {
		let lastError: unknown;
		for (let attempt = 0; attempt < maxAttempts; attempt++) {
			try {
				return await fn();
			} catch (err: unknown) {
				lastError = err;
				const msg = err instanceof Error ? err.message : String(err);
				const isTransient =
					msg.includes('ECONNRESET') ||
					msg.includes('fetch failed') ||
					msg.includes('Network error') ||
					msg.includes('Too Many Requests') ||
					msg.includes('429') ||
					msg.includes('ETIMEDOUT');
				if (!isTransient || attempt === maxAttempts - 1) throw err;
				this.#log('warn', 'retry: retrying', { attempt: attempt + 1, error: msg });
				await new Promise((r) => setTimeout(r, 1000 * 2 ** attempt));
			}
		}
		throw lastError;
	}
}

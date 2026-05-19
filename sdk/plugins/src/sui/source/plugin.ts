// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import {
	IkaClient as CoreIkaClient,
	createRandomSessionIdentifier,
	getNetworkConfig,
	IkaTransaction,
} from '@ika.xyz/sdk';
import type { IkaConfig, UserShareEncryptionKeys } from '@ika.xyz/sdk';
import type { IkaContextClient, SourcePlugin, SourceSurface } from '@ika.xyz/sdk/plugin';
import { getJsonRpcFullnodeUrl, SuiJsonRpcClient } from '@mysten/sui/jsonRpc';
import type { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { Transaction } from '@mysten/sui/transactions';
import type { TransactionObjectArgument } from '@mysten/sui/transactions';

import {
	acceptEncryptedShare,
	prepareDKG,
	requestDKG,
	requestDKGWithPublicShare,
	requestImportedKeyVerification,
	revealUserSecretShare,
} from './dkg.js';
import type { AcceptEncryptedShareInput, DKGCtx } from './dkg.js';
import type { SuiDWallet } from './dwallet.js';
import { ImportedKeySharedPartialError } from './errors.js';
import { makeExec, makePay } from './execute.js';
import { requestGlobalPresign, requestPresign } from './presign.js';
import { composeSign, requestSign, signMessage } from './sign.js';
import type { ComposeSignArgs, SignCtx } from './sign.js';
import { submitDKG, submitSign } from './submit.js';
import type { SubmitDKGArgs, SubmitSignArgs } from './submit.js';
import { isEd25519Keypair } from './types.js';
import type {
	CreateDWalletInput,
	PrepareDKGInput,
	PrepareDKGOutput,
	RequestGlobalPresignInput,
	RequestImportedKeyInput,
	RequestImportedKeyOutput,
	RequestPresignInput,
	RequestSharedDKGInput,
	RequestSignInput,
	RequestZeroTrustDKGInput,
	ResolvedTimeouts,
	RevealUserSecretShareInput,
	SuiSigner,
	SuiSignMessageInput,
	SuiSignResult,
	SuiSourceDefaults,
	SuiSourceOptions,
	SuiTxExecutionResult,
	SuiWalletSigner,
} from './types.js';
import { resolveUsek } from './usek.js';
import type { UsekRegistrationCache } from './usek.js';
import { wrapDWallet } from './wrap.js';

// Production defaults.

/**
 * Per-op IKA fee in MIST (1 IKA = 1e9 MIST). 0.5 IKA clears all current
 * testnet/mainnet presign pricing tiers. Override via `ikaFeePerOp` if your
 * deployment prices ops differently.
 */
const DEFAULT_IKA_FEE = 500_000_000n;
const DEFAULT_SUI_GAS = 1_000_000n;
/** Settling buffer between submitting a tx and querying objects it produced. */
const DEFAULT_POST_TX_SLEEP_MS = 2_000;
const DEFAULT_TIMEOUTS: ResolvedTimeouts = {
	dkg: 10 * 60_000,
	presign: 5 * 60_000,
	sign: 5 * 60_000,
	shareVerify: 5 * 60_000,
};

// `SuiSourceExtend` is the namespace merged onto `ika.sui` and exposes both
// the low-level building blocks and the high-level shortcuts.

/**
 * Builder argument passed to `ika.sui.transaction(...)`. Wraps `IkaTransaction`
 * with the source's defaults (signer, USEK) already configured.
 *
 *     await ika.sui.transaction(async ({ tx, ikaTx, pay }) => {
 *       const sessionId = ikaTx.registerSessionIdentifier(s1);
 *       await ikaTx.requestDWalletDKG({ ..., sessionIdentifier: sessionId });
 *     });
 */
export interface SuiTxBuilder {
	readonly tx: Transaction;
	readonly ikaTx: IkaTransaction;
	/** Allocate a fresh IKA+SUI fee coin pair for one coordinator operation. */
	pay(): { readonly ika: TransactionObjectArgument; readonly sui: TransactionObjectArgument };
}

export interface SuiSourceExtend {
	readonly sui: {
		readonly address: string;
		readonly config: IkaConfig;

		/**
		 * Underlying `IkaClient` from `@ika.xyz/sdk`. The plugin layer is an
		 * additive customization on top; drop down to this client for full
		 * control of multi-op transactions, custom polling, or any Move call
		 * the plugin does not expose. Throws if initialization has permanently
		 * failed so callers do not get cryptic errors deep in the core SDK.
		 *
		 * `ika.sui.transaction(...)` wires this client into an `IkaTransaction`
		 * with the source's defaults already applied.
		 */
		readonly client: CoreIkaClient;
		/** Awaits initialization and returns the core client. */
		ready(): Promise<CoreIkaClient>;

		/**
		 * Build a single Sui PTB containing one or more Ika coordinator
		 * operations: multiple DKGs, multiple signs, mixes of both. The
		 * callback receives a builder bundle. After it returns, the plugin
		 * transfers any leftover fee coins back to the signer, signs the tx,
		 * and executes it. Returns the builder's value plus the raw exec
		 * result.
		 */
		transaction<T>(
			build: (b: SuiTxBuilder) => Promise<T> | T,
			opts?: { userShareEncryptionKeys?: UserShareEncryptionKeys },
		): Promise<{ result: Awaited<T>; exec: SuiExecResult }>;

		/**
		 * Composition helpers that emit Move calls into an in-flight
		 * `IkaTransaction` without executing. Three flavours:
		 *
		 *   - `sign`        High-level: dWallet + message, plugin handles USEK,
		 *                   approval, encrypted-share fetching, sign call.
		 *                   Requires a USEK on the source.
		 *   - `submitDKG`   Non-custodial: caller supplies a DKG payload that
		 *                   was prepared elsewhere (browser, hardware wallet).
		 *                   Emits `registerEncryptionKey` (optional) +
		 *                   `requestDWalletDKG`. No USEK needed.
		 *   - `submitSign`  Non-custodial: caller supplies a precomputed
		 *                   `userSignMessage` and `userOutputSignature`. Emits
		 *                   `acceptEncryptedUserShare` + `verifyPresignCap` +
		 *                   `approveMessage` + `requestSign`. No USEK needed.
		 *
		 * The non-custodial variants drop `ikaConfig` from their public args
		 * since the plugin already has it.
		 */
		readonly compose: {
			sign(args: ComposeSignArgs): Promise<void>;
			submitDKG(args: Omit<SubmitDKGArgs, 'ikaConfig'>): ReturnType<typeof submitDKG>;
			submitSign(args: Omit<SubmitSignArgs, 'ikaConfig'>): void;
		};

		// Building blocks. Each submits its own tx; use `transaction()` to compose multiple ops.
		prepareDKG(input: PrepareDKGInput): Promise<PrepareDKGOutput>;
		requestDKG(input: RequestZeroTrustDKGInput): Promise<SuiDWallet>;
		requestDKGWithPublicShare(input: RequestSharedDKGInput): Promise<SuiDWallet>;
		requestImportedKeyVerification(
			input: RequestImportedKeyInput,
		): Promise<RequestImportedKeyOutput>;
		/** Per-dWallet presign; required for imported-key ECDSA. */
		requestPresign(input: RequestPresignInput): Promise<Awaited<ReturnType<typeof requestPresign>>>;
		/** Global per-(curve, algo) presign; faster, not bound to a specific dWallet. */
		requestGlobalPresign(
			input: RequestGlobalPresignInput,
		): Promise<Awaited<ReturnType<typeof requestGlobalPresign>>>;
		requestSign(input: RequestSignInput): Promise<SuiSignResult>;
		/** IRREVERSIBLE: publishes the user's secret share on chain. */
		revealUserSecretShare(input: RevealUserSecretShareInput): Promise<SuiDWallet>;
		/**
		 * Recovery primitive. Re-submits the user-side `acceptEncryptedUserShare`
		 * tx for a dWallet stuck in `AwaitingKeyHolderSignature`. Use when a
		 * prior `requestDKG` or `requestImportedKeyVerification` partially
		 * succeeded (network DKG completed, accept step failed).
		 */
		acceptEncryptedShare(input: AcceptEncryptedShareInput): Promise<SuiDWallet>;

		// High-level shortcuts.
		createDWallet(input: CreateDWalletInput): Promise<SuiDWallet>;
		getDWallet(id: string): Promise<SuiDWallet>;

		/**
		 * Re-bind the source's signer for follow-up calls. Returns a surface
		 * with the same shape as `ika.sui` but every tx-submitting method
		 * (DKG, presign, sign, accept, reveal, transaction) routes through
		 * the provided signer. The underlying `IkaClient`, network config,
		 * init state, and USEK registration cache are SHARED — `withSigner`
		 * is a scoping helper, not a new source.
		 *
		 * Use inline for a single call:
		 *   await ika.sui.withSigner(userWallet).signMessage({ dWallet, ... });
		 *
		 * Or bind for a whole flow:
		 *   const userView = ika.sui.withSigner(userWallet);
		 *   await userView.requestSign({ ... });
		 *
		 * Compose with `capRecipient` on DKG inputs to send the resulting
		 * cap to the user's address while a backend keypair funds the DKG:
		 *   await ika.sui.createDWallet({ kind: 'shared', curve, capRecipient: userAddress });
		 *   await ika.sui.withSigner(userWallet).requestSign({ ... });
		 */
		withSigner(signer: SuiSigner, opts?: { signerAddress?: string }): SuiSourceExtend['sui'];
	};
}

/** Resolved Sui execution result returned by `transaction()`. */
export type SuiExecResult = Awaited<ReturnType<ReturnType<typeof makeExec>>>;

// Factory.

export function suiSource(
	opts: SuiSourceOptions,
): SourcePlugin<'sui', SuiDWallet, SuiSignMessageInput, SuiSignResult, SuiSourceExtend> {
	if (opts.ikaFeePerOp !== undefined && opts.ikaFeePerOp < 0n) {
		throw new Error(`suiSource: ikaFeePerOp must be non-negative (got ${opts.ikaFeePerOp}).`);
	}
	// Zero is allowed: on a localnet / fresh deployment with default pricing
	// the coordinator accepts a zero-value IKA coin (coinWithBalance lowers
	// it to `0x2::coin::zero<IKA>`). On testnet/mainnet the on-chain pricing
	// is non-zero, so callers must pass a real budget there.
	const suiClient =
		opts.suiClient ??
		new SuiJsonRpcClient({
			url: opts.rpcUrl ?? getJsonRpcFullnodeUrl(opts.network),
			network: opts.network,
		});
	const config = opts.config ?? getNetworkConfig(opts.network);
	const ikaClient = new CoreIkaClient({ suiClient, config, cache: true });

	// Normalize the signer union into the executor + address pair the plugin
	// actually uses internally. Keypair-mode wraps
	// `suiClient.signAndExecuteTransaction` so events are always included
	// (the plugin parses Move events to extract presign/sign/dWallet ids).
	// Wallet-mode delegates to the caller's `signAndExecuteTransaction`;
	// the caller is responsible for passing `options: { showEvents: true }`
	// (or equivalent) in their wallet hook.
	function normalizeSigner(
		signer: SuiSigner,
		signerAddressOverride: string | undefined,
	): { signerAddress: string; signAndExecute: (tx: Transaction) => Promise<SuiTxExecutionResult> } {
		if (isEd25519Keypair(signer)) {
			const kp = signer as Ed25519Keypair;
			return {
				signerAddress: signerAddressOverride ?? kp.getPublicKey().toSuiAddress(),
				signAndExecute: async (tx: Transaction) => {
					const result = await suiClient.core.signAndExecuteTransaction({
						transaction: tx,
						signer: kp,
						include: { events: true },
					});
					if (!result.Transaction) {
						throw new Error('suiSource: signAndExecuteTransaction returned no Transaction payload');
					}
					return result.Transaction as SuiTxExecutionResult;
				},
			};
		}
		const wallet = signer as SuiWalletSigner;
		return {
			signerAddress: signerAddressOverride ?? wallet.address,
			signAndExecute: (tx: Transaction) => wallet.signAndExecuteTransaction(tx),
		};
	}

	const initial = normalizeSigner(opts.signer, opts.signerAddress);
	const defaults: SuiSourceDefaults = {
		signAndExecute: initial.signAndExecute,
		signerAddress: initial.signerAddress,
		userShareEncryptionKeys: opts.userShareEncryptionKeys,
		ikaFee: opts.ikaFeePerOp ?? DEFAULT_IKA_FEE,
		suiGas: opts.suiGasPerOp ?? DEFAULT_SUI_GAS,
		postTxSleepMs: opts.postTxSleepMs ?? DEFAULT_POST_TX_SLEEP_MS,
		suiClient,
		config,
		timeouts: {
			dkg: opts.timeouts?.dkg ?? DEFAULT_TIMEOUTS.dkg,
			presign: opts.timeouts?.presign ?? DEFAULT_TIMEOUTS.presign,
			sign: opts.timeouts?.sign ?? DEFAULT_TIMEOUTS.sign,
			shareVerify: opts.timeouts?.shareVerify ?? DEFAULT_TIMEOUTS.shareVerify,
		},
	};

	// USEK registration cache is shared across `withSigner` scopes: USEK
	// registration is keyed by the SUSEK's own Sui address (curve-dependent)
	// not by the tx sender, and the on-chain Move call is idempotent under
	// either path's `dynamic_field::add` retry. Sharing it avoids redundant
	// registration txs when `withSigner` is used to flip between signers
	// that all need the same USEK on chain.
	const usekCache: UsekRegistrationCache = new Set<string>();

	// Captured at install time so every dWallet returned from the extend
	// surface is auto-decorated with the destinations' namespaces. The
	// `IkaContext` is stable across the client's lifetime, so capturing once
	// is safe; `client.decorate(...)` coalesces concurrent calls and skips
	// re-decoration of an already-stamped instance.
	let pluginClient: IkaContextClient | null = null;
	const decorateIfReady = async <D extends SuiDWallet>(d: D): Promise<D> => {
		if (!pluginClient) return d;
		return (await pluginClient.decorate(d)) as D;
	};

	/**
	 * Lazy initialization with a retry cap.
	 *
	 * On first call, starts `ikaClient.initialize()` and caches the promise.
	 * Concurrent callers await the same pending promise. Success is cached
	 * forever. A transient failure clears the cache so the NEXT call retries.
	 * After `MAX_INIT_RETRIES` failures the failure is latched: every later
	 * call rejects immediately with the wrapped error.
	 *
	 * Operation methods (`apiSignMessage`, `apiCreateDWallet`, ...) each await
	 * `ensureInit()` independently, so retries happen transparently per-call.
	 * `ika.ready()` only observes the first install attempt; later retries
	 * surface on the operation method that triggered them.
	 */
	const MAX_INIT_RETRIES = 3;
	let initPromise: Promise<void> | null = null;
	let initFailures = 0;
	let permanentFailure: Error | null = null;
	const ensureInit = (): Promise<void> => {
		if (permanentFailure) return Promise.reject(permanentFailure);
		if (!initPromise) {
			initPromise = ikaClient.initialize().catch((err: unknown) => {
				initFailures++;
				initPromise = null;
				if (initFailures >= MAX_INIT_RETRIES) {
					const wrapped = new Error(
						`suiSource: ikaClient.initialize() failed ${initFailures} times. ` +
							`no further retries will be attempted. Last error: ${
								err instanceof Error ? err.message : String(err)
							}`,
					);
					(wrapped as Error & { cause?: unknown }).cause = err;
					permanentFailure = wrapped;
					throw wrapped;
				}
				throw err;
			});
		}
		return initPromise!;
	};

	/**
	 * Per-signer surface factory. `defaults` carries the signer-dependent
	 * fields (signAndExecute, signerAddress); everything else (`ikaClient`,
	 * `ensureInit`, `usekCache`, decoration) is shared via the outer scope.
	 * Called once with the configured signer to produce the default
	 * `ika.sui` surface, and again from `withSigner(...)` with a swapped
	 * `defaults` to produce a re-bound surface that submits txs through a
	 * different account.
	 */
	interface BindResult {
		readonly suiNs: SuiSourceExtend['sui'];
		readonly surface: SourceSurface<SuiDWallet, SuiSignMessageInput, SuiSignResult>;
	}

	function bind(defaults: SuiSourceDefaults): BindResult {
		const pay = makePay({
			ikaFee: defaults.ikaFee,
			suiGas: defaults.suiGas,
			ikaConfig: defaults.config,
			signerAddress: defaults.signerAddress,
		});
		const execFn = makeExec({
			signAndExecute: defaults.signAndExecute,
			postTxSleepMs: defaults.postTxSleepMs,
		});
		const dkgCtx = (): DKGCtx => ({
			defaults,
			ikaClient,
			pay,
			exec: execFn,
			usekCache,
		});
		const signCtx = (): SignCtx => ({ defaults, ikaClient, pay, exec: execFn });

		// Public functions. Each awaits `ensureInit()` first.

		const apiPrepareDKG = async (input: PrepareDKGInput) => {
			await ensureInit();
			return prepareDKG(dkgCtx(), input);
		};
		const apiRequestDKG = async (input: RequestZeroTrustDKGInput) => {
			await ensureInit();
			return decorateIfReady(await requestDKG(dkgCtx(), input));
		};
		const apiRequestDKGWithPublicShare = async (input: RequestSharedDKGInput) => {
			await ensureInit();
			return decorateIfReady(await requestDKGWithPublicShare(dkgCtx(), input));
		};
		const apiRequestImportedKeyVerification = async (input: RequestImportedKeyInput) => {
			await ensureInit();
			const out = await requestImportedKeyVerification(dkgCtx(), input);
			return { ...out, dWallet: await decorateIfReady(out.dWallet) };
		};
		const apiRevealUserSecretShare = async (input: RevealUserSecretShareInput) => {
			await ensureInit();
			return decorateIfReady(await revealUserSecretShare(dkgCtx(), input));
		};
		const apiAcceptEncryptedShare = async (input: AcceptEncryptedShareInput) => {
			await ensureInit();
			return decorateIfReady(await acceptEncryptedShare(dkgCtx(), input));
		};
		const apiRequestPresign = async (input: RequestPresignInput) => {
			await ensureInit();
			return requestPresign(signCtx(), input);
		};
		const apiRequestGlobalPresign = async (input: RequestGlobalPresignInput) => {
			await ensureInit();
			return requestGlobalPresign(signCtx(), input);
		};
		const apiRequestSign = async (input: RequestSignInput) => {
			await ensureInit();
			return requestSign(signCtx(), input);
		};
		const apiSignMessage = async (input: SuiSignMessageInput): Promise<SuiSignResult> => {
			await ensureInit();
			return signMessage(signCtx(), input);
		};

		const apiGetDWallet = async (id: string): Promise<SuiDWallet> => {
			await ensureInit();
			const raw = await ikaClient.getDWallet(id);
			return decorateIfReady(wrapDWallet(raw));
		};

		// High-level shortcut that composes the building blocks per `kind`.
		// Accepts an optional pre-computed `dkgRequestInput` so callers may run
		// prepareDKG out-of-band and submit later. The switch is exhaustive: a
		// new `DWalletKind` not handled here is a compile-time error via the
		// `never` assignment at the bottom.

		async function apiCreateDWallet(input: CreateDWalletInput): Promise<SuiDWallet> {
			await ensureInit();
			const sessionIdentifier = input.sessionIdentifier ?? createRandomSessionIdentifier();

			const inner = async (): Promise<SuiDWallet> => {
				switch (input.kind) {
					case 'shared': {
						const keys = resolveUsek(
							defaults,
							input.userShareEncryptionKeys,
							'createDWallet/shared',
						);
						const dkgInput =
							input.dkgRequestInput ??
							(await prepareDKG(dkgCtx(), {
								curve: input.curve,
								userShareEncryptionKeys: keys,
								sessionIdentifier,
								signal: input.signal,
							}));
						return requestDKGWithPublicShare(dkgCtx(), {
							publicKeyShareAndProof: dkgInput.userDKGMessage,
							publicUserSecretKeyShare: dkgInput.userSecretKeyShare,
							userPublicOutput: dkgInput.userPublicOutput,
							curve: input.curve,
							sessionIdentifier,
							networkEncryptionKeyId: input.networkEncryptionKeyId,
							userShareEncryptionKeys: keys,
							capRecipient: input.capRecipient,
							signal: input.signal,
						});
					}
					case 'zero-trust': {
						const keys = resolveUsek(
							defaults,
							input.userShareEncryptionKeys,
							'createDWallet/zero-trust',
						);
						const dkgInput =
							input.dkgRequestInput ??
							(await prepareDKG(dkgCtx(), {
								curve: input.curve,
								userShareEncryptionKeys: keys,
								sessionIdentifier,
								signal: input.signal,
							}));
						return requestDKG(dkgCtx(), {
							dkgRequestInput: dkgInput,
							curve: input.curve,
							sessionIdentifier,
							networkEncryptionKeyId: input.networkEncryptionKeyId,
							userShareEncryptionKeys: keys,
							capRecipient: input.capRecipient,
							signal: input.signal,
						});
					}
					case 'imported-key':
					case 'imported-key-shared': {
						if (!input.importedKey) {
							throw new Error(`createDWallet/${input.kind} requires an \`importedKey\` byte array`);
						}
						// Validate acknowledgement before any chain work. A late check
						// would leave the caller with a verified imported-key dWallet
						// they meant to be shared.
						if (
							input.kind === 'imported-key-shared' &&
							input.acknowledge !== 'i-understand-this-is-irreversible'
						) {
							throw new Error(
								'createDWallet/imported-key-shared is irreversible. Pass ' +
									"`acknowledge: 'i-understand-this-is-irreversible'` to confirm. " +
									'Once revealed, anyone with the dWallet cap can sign without you.',
							);
						}
						const { dWallet } = await requestImportedKeyVerification(dkgCtx(), {
							importedKey: input.importedKey,
							curve: input.curve,
							sessionIdentifier,
							userShareEncryptionKeys: input.userShareEncryptionKeys,
							capRecipient: input.capRecipient,
							signal: input.signal,
						});
						if (input.kind === 'imported-key') return dWallet;
						// On reveal failure, preserve the verified dWallet so the caller
						// can retry just the reveal via `ImportedKeySharedPartialError.retryReveal()`.
						try {
							return await revealUserSecretShare(dkgCtx(), {
								dWallet,
								acknowledge: 'i-understand-this-is-irreversible',
								userShareEncryptionKeys: input.userShareEncryptionKeys,
								signal: input.signal,
							});
						} catch (revealErr) {
							// If decoration itself fails (rare; a destination's
							// `dWalletExtend` could throw), fall back to the naked
							// handle rather than losing the partial-result path.
							let verifiedDecorated: SuiDWallet;
							try {
								verifiedDecorated = await decorateIfReady(dWallet);
							} catch {
								verifiedDecorated = dWallet;
							}
							const usek = input.userShareEncryptionKeys;
							throw new ImportedKeySharedPartialError({
								verifiedDWallet: verifiedDecorated,
								cause: revealErr,
								retryReveal: async (opts) => {
									const promoted = await revealUserSecretShare(dkgCtx(), {
										dWallet: verifiedDecorated,
										acknowledge: 'i-understand-this-is-irreversible',
										userShareEncryptionKeys: usek,
										signal: opts?.signal,
									});
									return decorateIfReady(promoted);
								},
							});
						}
					}
					default: {
						// `CreateDWalletInput` is a flat type with a literal-union
						// `kind` (not a discriminated union), so exhaustiveness is
						// checked against `input.kind`, not against `input` itself.
						const exhaustive: never = input.kind;
						throw new Error(`unknown createDWallet kind: ${exhaustive}`);
					}
				}
			};
			return decorateIfReady(await inner());
		}

		// Source surface: what destination plugins call via `ctx.source`.

		const surface: SourceSurface<SuiDWallet, SuiSignMessageInput, SuiSignResult> = {
			chain: 'sui',
			signMessage: apiSignMessage,
			getDWallet: apiGetDWallet,
		};

		const apiReady = async (): Promise<CoreIkaClient> => {
			await ensureInit();
			return ikaClient;
		};

		/**
		 * Multi-op transaction builder. Batches coordinator operations into a
		 * single Sui PTB for atomicity and lower gas. The other surface methods
		 * submit their own tx each; use this only when composition matters.
		 *
		 * USEK is not required to enter the builder. Non-custodial callers (where
		 * the user-share keys live elsewhere — typically a browser) can compose
		 * Move calls that operate on precomputed payloads. Methods on the
		 * underlying `IkaTransaction` that read USEK (e.g. `requestSign`,
		 * `requestDWalletDKG`, `registerEncryptionKey`) still throw if invoked
		 * without one — the precondition is deferred to the call site.
		 */
		const apiTransaction = async <T>(
			build: (b: SuiTxBuilder) => Promise<T> | T,
			opts?: { userShareEncryptionKeys?: UserShareEncryptionKeys },
		): Promise<{ result: Awaited<T>; exec: SuiExecResult }> => {
			await ensureInit();
			const keys = opts?.userShareEncryptionKeys ?? defaults.userShareEncryptionKeys;
			const tx = new Transaction();
			tx.setSender(defaults.signerAddress);
			const ikaTx = new IkaTransaction({
				ikaClient,
				transaction: tx,
				...(keys ? { userShareEncryptionKeys: keys } : {}),
			});
			// Sui PTB validation rejects a tx that drops a `Coin<T>` value, so
			// every `(ika, sui)` pair issued by pay() is recorded and transferred
			// back to the signer at the end of the build. Move calls take
			// `&mut Coin<T>`, so the handles remain valid after being consumed.
			const leftovers: TransactionObjectArgument[] = [];
			const builder: SuiTxBuilder = {
				tx,
				ikaTx,
				pay: () => {
					const p = pay(tx);
					leftovers.push(p.ika, p.sui);
					return { ika: p.ika, sui: p.sui };
				},
			};
			const result = await build(builder);
			if (leftovers.length > 0) {
				tx.transferObjects(leftovers, defaults.signerAddress);
			}
			const exec = await execFn(tx);
			return { result: result as Awaited<T>, exec };
		};

		const suiNs: SuiSourceExtend['sui'] = {
			address: defaults.signerAddress,
			config: defaults.config,
			// Direct access to the core `IkaClient` is part of the normal API.
			// The getter throws on permanent failure so callers do not get a
			// half-initialized client surface.
			get client(): CoreIkaClient {
				if (permanentFailure) throw permanentFailure;
				return ikaClient;
			},
			ready: apiReady,
			transaction: apiTransaction,
			compose: {
				sign: (args: ComposeSignArgs) => composeSign(ikaClient, args),
				submitDKG: (args) => submitDKG({ ...args, ikaConfig: defaults.config }),
				submitSign: (args) => submitSign({ ...args, ikaConfig: defaults.config }),
			},
			prepareDKG: apiPrepareDKG,
			requestDKG: apiRequestDKG,
			requestDKGWithPublicShare: apiRequestDKGWithPublicShare,
			requestImportedKeyVerification: apiRequestImportedKeyVerification,
			revealUserSecretShare: apiRevealUserSecretShare,
			acceptEncryptedShare: apiAcceptEncryptedShare,
			requestPresign: apiRequestPresign,
			requestGlobalPresign: apiRequestGlobalPresign,
			requestSign: apiRequestSign,
			createDWallet: apiCreateDWallet,
			getDWallet: apiGetDWallet,
			withSigner: (signer, withOpts) => {
				const swap = normalizeSigner(signer, withOpts?.signerAddress);
				return bind({
					...defaults,
					signAndExecute: swap.signAndExecute,
					signerAddress: swap.signerAddress,
				}).suiNs;
			},
		};
		return { suiNs, surface };
	} // end bind

	const { suiNs, surface } = bind(defaults);
	const extend: SuiSourceExtend = { sui: suiNs };

	return {
		kind: 'source',
		name: 'sui',
		chain: 'sui',
		surface,
		extend,
		install(ctx) {
			// Capture the IkaContext.client so the extend surface can
			// auto-decorate returned dWallets. The context is stable across
			// the client's lifetime, so a one-time capture is correct.
			pluginClient = ctx.client;
			// Returning the init promise lets `ika.ready()` observe init
			// errors at a deterministic point. Operation methods also gate
			// on `ensureInit()`, so init runs whether or not the caller
			// awaits `ready()`.
			return ensureInit();
		},
	};
}

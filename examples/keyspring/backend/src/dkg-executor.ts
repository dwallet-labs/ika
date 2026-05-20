import {
	coordinatorTransactions,
	Curve,
	Hash,
	ikaDwallet2pcMpc,
	publicKeyFromCentralizedDKGOutput,
	SignatureAlgorithm,
} from '@ika.xyz/sdk';

const { CoordinatorInnerModule, SessionsManagerModule } = ikaDwallet2pcMpc;
import { IkaClient } from '@ika.xyz/sdk/plugin';
import { suiSource } from '@ika.xyz/plugins/sui/source';
import {
	assembleEthereumPayload,
	deriveEthereumAddress,
} from '@ika.xyz/plugins/ethereum/destination';
import { ethPublisher } from '@ika.xyz/plugins/ethereum/publisher';
import { getJsonRpcFullnodeUrl, SuiJsonRpcClient } from '@mysten/sui/jsonRpc';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { Transaction } from '@mysten/sui/transactions';
import type { Hex, TransactionSerializableEIP1559 } from 'viem';
import { baseSepolia } from 'viem/chains';

import { config } from './config.js';
import { logger } from './logger.js';
import type {
	DKGRequest,
	DKGSubmitInput,
	PresignRequest,
	SignRequest,
	SignRequestInput,
} from './types.js';

const TIMEOUTS = {
	SIGN_WAIT: 120_000,
	PRESIGN_WAIT: 120_000,
} as const;

const CURVE_SECP256K1 = 0;

function withTimeout<T>(promise: Promise<T>, timeoutMs: number, operation: string): Promise<T> {
	return Promise.race([
		promise,
		new Promise<never>((_, reject) =>
			setTimeout(() => reject(new Error(`${operation} timed out after ${timeoutMs}ms`)), timeoutMs),
		),
	]);
}

const dkgRequests = new Map<string, DKGRequest>();
const presignRequests = new Map<string, PresignRequest>();
const signRequests = new Map<string, SignRequest>();

function suiRpcUrl(): string {
	return (
		process.env.SUI_RPC_URL ??
		(config.sui.network === 'mainnet'
			? 'https://ikafn-on-sui-2-mainnet.ika-network.net/'
			: getJsonRpcFullnodeUrl(config.sui.network))
	);
}

/**
 * DKG / presign / sign executor for the KeySpring demo.
 *
 * The backend is non-custodial: the USEK lives in the user's browser, the
 * frontend runs `prepareDKG` and `createUserSignMessage` locally, and the
 * backend's only job is to submit precomputed payloads to Sui and parse the
 * resulting object ids back. Because the orchestrator has no USEK, the
 * plugin's high-level USEK-needing methods (`createDWallet`, `requestSign`)
 * are not usable here — instead this module uses `ika.sui.transaction(...)`
 * for the fee-coin + execute envelope and drops down to
 * `coordinatorTransactions.*` for the precomputed-payload Move calls.
 *
 * Ethereum broadcast goes through `ika.publish({ chain: 'ethereum', ... })`
 * with the `ethPublisher` plugin; the (r, s) → serialized signed tx assembly
 * is done by the destination's `assembleEthereumPayload` helper.
 */
export class DKGExecutorService {
	private ika: ReturnType<typeof buildIka>;
	private suiClient: SuiJsonRpcClient;
	private adminKeypair: Ed25519Keypair;
	private isRunning = false;
	private pollTimeout: NodeJS.Timeout | null = null;

	constructor() {
		this.adminKeypair = Ed25519Keypair.fromSecretKey(config.sui.adminSecretKey);
		this.suiClient = new SuiJsonRpcClient({
			url: suiRpcUrl(),
			network: config.sui.network,
		});
		this.ika = buildIka(this.adminKeypair, this.suiClient);
		logger.info(
			{
				signerAddress: this.adminKeypair.toSuiAddress(),
				network: config.sui.network,
			},
			'DKG Executor initialized',
		);
	}

	getIkaClient() {
		return this.ika.sui.client;
	}

	getAdminAddress(): string {
		return this.adminKeypair.toSuiAddress();
	}

	submitRequest(data: DKGSubmitInput): DKGRequest {
		const id = crypto.randomUUID();
		const request: DKGRequest = { id, status: 'pending', data, createdAt: new Date() };
		dkgRequests.set(id, request);
		logger.info({ requestId: id, curve: data.curve ?? CURVE_SECP256K1 }, 'DKG request submitted');
		return request;
	}

	getRequest(id: string): DKGRequest | undefined {
		return dkgRequests.get(id);
	}

	submitPresignRequest(dWalletId: string): PresignRequest {
		const id = crypto.randomUUID();
		const request: PresignRequest = { id, status: 'pending', dWalletId, createdAt: new Date() };
		presignRequests.set(id, request);
		logger.info({ requestId: id, dWalletId }, 'Presign request submitted');
		return request;
	}

	getPresignRequest(id: string): PresignRequest | undefined {
		return presignRequests.get(id);
	}

	submitSignRequest(data: SignRequestInput): SignRequest {
		const id = crypto.randomUUID();
		const request: SignRequest = { id, status: 'pending', data, createdAt: new Date() };
		signRequests.set(id, request);
		logger.info(
			{ requestId: id, dWalletId: data.dWalletId, presignId: data.presignId },
			'Sign request submitted',
		);
		return request;
	}

	getSignRequest(id: string): SignRequest | undefined {
		return signRequests.get(id);
	}

	start(): void {
		if (this.isRunning) {
			logger.warn('DKG Executor is already running');
			return;
		}
		this.isRunning = true;
		logger.info('Starting DKG Executor...');
		this.poll().catch((err) => {
			logger.error({ err }, 'Error starting poll loop - will retry');
			if (this.isRunning) {
				this.pollTimeout = setTimeout(() => this.poll(), 5000);
			}
		});
	}

	stop(): void {
		this.isRunning = false;
		if (this.pollTimeout) {
			clearTimeout(this.pollTimeout);
			this.pollTimeout = null;
		}
		logger.info('Stopped DKG Executor');
	}

	private async poll(): Promise<void> {
		if (!this.isRunning) return;
		await this.safeStep('DKG', () => this.processPending(dkgRequests, (r) => this.processDKG(r)));
		await this.safeStep('presign', () =>
			this.processPending(presignRequests, (r) => this.processPresign(r)),
		);
		await this.safeStep('sign', () =>
			this.processPending(signRequests, (r) => this.processSign(r)),
		);
		await this.safeStep('cleanup', async () => this.cleanupOldRequests());
		if (this.isRunning) {
			this.pollTimeout = setTimeout(() => {
				this.poll().catch((err) => {
					logger.error({ err }, 'Fatal error in poll loop - restarting');
					if (this.isRunning) {
						this.pollTimeout = setTimeout(() => this.poll(), 5000);
					}
				});
			}, 2000);
		}
	}

	private async safeStep(label: string, fn: () => Promise<void>): Promise<void> {
		try {
			await fn();
		} catch (err) {
			logger.error({ err }, `Error in ${label} step`);
		}
	}

	private async processPending<R extends { status: string }>(
		store: Map<string, R>,
		processOne: (r: R) => Promise<void>,
	): Promise<void> {
		const pending = Array.from(store.values()).filter((r) => r.status === 'pending');
		if (pending.length === 0) return;
		logger.info({ count: pending.length }, 'Processing pending requests');
		for (const r of pending) await processOne(r);
	}

	private cleanupOldRequests(): void {
		const cutoff = Date.now() - 60 * 60 * 1000;
		for (const store of [dkgRequests, presignRequests, signRequests]) {
			for (const [id, r] of store as Map<string, { status: string; createdAt: Date }>) {
				if ((r.status === 'completed' || r.status === 'failed') && r.createdAt.getTime() < cutoff) {
					store.delete(id);
				}
			}
		}
	}

	private async processDKG(request: DKGRequest): Promise<void> {
		const log = logger.child({ requestId: request.id });
		try {
			request.status = 'processing';
			log.info('Processing DKG request');
			const result = await this.executeDKG(request.data);
			Object.assign(request, { status: 'completed', ...result });
			log.info(result, 'DKG completed');
		} catch (error) {
			request.status = 'failed';
			request.error = error instanceof Error ? error.message : String(error);
			log.error({ error: request.error }, 'DKG failed');
		}
	}

	private async processPresign(request: PresignRequest): Promise<void> {
		const log = logger.child({ requestId: request.id });
		try {
			request.status = 'processing';
			log.info('Processing presign request');
			const result = await this.executePresign();
			request.status = 'completed';
			request.presignId = result.presignId;
			log.info({ presignId: result.presignId }, 'Presign completed');
		} catch (error) {
			request.status = 'failed';
			request.error = error instanceof Error ? error.message : String(error);
			log.error({ error: request.error }, 'Presign failed');
		}
	}

	private async processSign(request: SignRequest): Promise<void> {
		const log = logger.child({ requestId: request.id });
		try {
			request.status = 'processing';
			log.info('Processing sign request');
			const result = await this.executeSign(request.data);
			Object.assign(request, { status: 'completed', ...result });
			log.info(
				{ signId: result.signId, ethTxHash: result.ethTxHash },
				'Sign completed',
			);
		} catch (error) {
			request.status = 'failed';
			request.error = error instanceof Error ? error.message : String(error);
			log.error({ error: request.error }, 'Sign failed');
		}
	}

	/**
	 * Submit a DKG with payloads precomputed by the frontend. The
	 * `registerEncryptionKey` step is conditional: if the user has registered
	 * before (a prior DKG with the same USEK), the Move call would abort with
	 * `dynamic_field::add` code 0. A `devInspect` probe reports the abort
	 * without spending gas; we skip the redundant call when detected.
	 */
	private async executeDKG(data: DKGSubmitInput): Promise<{
		dWalletCapObjectId: string;
		dWalletObjectId: string;
		ethereumAddress?: string;
		digest: string;
		encryptedUserSecretKeyShareId: string | null;
	}> {
		const ika = this.ika.sui;
		const curveNumber = data.curve ?? CURVE_SECP256K1;
		const curve = curveFromNumber(curveNumber);
		const networkKey = await ika.client.getLatestNetworkEncryptionKey();
		const alreadyRegistered = await this.encryptionKeyAlreadyRegistered(data);

		const { exec } = await ika.transaction(async ({ tx, ikaTx, pay }) => {
			const { ika: ikaCoin, sui: suiCoin } = pay();
			const sessionId = ikaTx.registerSessionIdentifier(new Uint8Array(data.sessionIdentifier));
			const dWalletCap = ika.compose.submitDKG({
				ikaTx,
				tx,
				curve,
				networkEncryptionKeyId: networkKey.id,
				userDKGMessage: new Uint8Array(data.userDkgMessage),
				encryptedUserShareAndProof: new Uint8Array(data.encryptedUserShareAndProof),
				userPublicOutput: new Uint8Array(data.userPublicOutput),
				encryptionKeyAddress: data.encryptionKeyAddress,
				signerPublicKey: new Uint8Array(data.signerPublicKey),
				sessionIdentifier: sessionId,
				ikaCoin,
				suiCoin,
				...(alreadyRegistered
					? {}
					: {
							registerEncryptionKey: {
								encryptionKey: new Uint8Array(data.encryptionKey),
								encryptionKeySignature: new Uint8Array(data.encryptionKeySignature),
							},
						}),
			});
			tx.transferObjects([dWalletCap], this.getAdminAddress());
		});

		const ids = parseDWalletIds(exec.events ?? []);
		if (!ids.dWalletCapObjectId || !ids.dWalletObjectId) {
			throw new Error('Failed to parse dWallet ids from DKG transaction events');
		}

		// Derive the Ethereum address from the centralized DKG output the
		// frontend computed. Equivalent to fetching the dWallet from chain and
		// using `deriveEthereumAddress(curve, dWallet.publicOutput)` but skips
		// the extra round-trip.
		const publicKey = await publicKeyFromCentralizedDKGOutput(
			Curve.SECP256K1,
			new Uint8Array(data.userPublicOutput),
		);
		const ethereumAddress = await deriveEthereumAddress(
			Curve.SECP256K1,
			publicKey,
		);

		return {
			dWalletCapObjectId: ids.dWalletCapObjectId,
			dWalletObjectId: ids.dWalletObjectId,
			encryptedUserSecretKeyShareId: ids.encryptedUserSecretKeyShareId,
			ethereumAddress,
			digest: exec.digest ?? '',
		};
	}

	/**
	 * `devInspectTransactionBlock` reports the `dynamic_field::add` abort code
	 * when the encryption key is already registered. The probe is run from a
	 * throwaway tx so we only emit the real `registerEncryptionKey` call when
	 * the user is a first-time submitter.
	 */
	private async encryptionKeyAlreadyRegistered(data: DKGSubmitInput): Promise<boolean> {
		const ikaConfig = this.ika.sui.config;
		const tx = new Transaction();
		tx.setSender(this.getAdminAddress());
		coordinatorTransactions.registerEncryptionKeyTx(
			ikaConfig,
			tx.object(ikaConfig.objects.ikaDWalletCoordinator.objectID),
			data.curve ?? CURVE_SECP256K1,
			new Uint8Array(data.encryptionKey),
			new Uint8Array(data.encryptionKeySignature),
			new Uint8Array(data.signerPublicKey),
			tx,
		);
		const res = await this.suiClient.devInspectTransactionBlock({
			sender: this.getAdminAddress(),
			transactionBlock: tx,
		});
		return !!res.error;
	}

	private async executePresign(): Promise<{ presignId: string }> {
		const ika = this.ika.sui;
		const networkKey = await ika.client.getLatestNetworkEncryptionKey();
		const { exec } = await ika.transaction(async ({ ikaTx, pay }) => {
			const { ika: ikaCoin, sui: suiCoin } = pay();
			ikaTx.requestGlobalPresign({
				dwalletNetworkEncryptionKeyId: networkKey.id,
				curve: Curve.SECP256K1,
				signatureAlgorithm: SignatureAlgorithm.ECDSASecp256k1,
				ikaCoin,
				suiCoin,
			});
		});
		const presignId = parsePresignId(exec.events ?? []);
		if (!presignId) throw new Error('Failed to get presign id from transaction events');
		return { presignId };
	}

	private async executeSign(data: SignRequestInput): Promise<{
		signatureHex: string;
		signId: string;
		digest: string;
		ethTxHash?: string;
	}> {
		const ika = this.ika.sui;
		const ikaClient = ika.client;

		const presign = await withTimeout(
			ikaClient.getPresignInParticularState(data.presignId, 'Completed'),
			TIMEOUTS.PRESIGN_WAIT,
			'Presign state check',
		);
		if (!presign) throw new Error(`Presign ${data.presignId} not found or not completed`);

		const message = new Uint8Array(Buffer.from(data.messageHex.replace(/^0x/, ''), 'hex'));

		// One PTB: accept the encrypted user share + verify presign cap +
		// approve the message + emit the sign request. The user's
		// `userSignMessage` was computed client-side with the decrypted secret
		// share — the backend never sees the secret.
		const { exec } = await ika.transaction(async ({ tx, ikaTx, pay }) => {
			const { ika: ikaCoin, sui: suiCoin } = pay();
			ika.compose.submitSign({
				ikaTx,
				tx,
				dWalletId: data.dWalletId,
				dWalletCapId: data.dWalletCapId,
				encryptedUserSecretKeyShareId: data.encryptedUserSecretKeyShareId,
				userOutputSignature: new Uint8Array(data.userOutputSignature),
				presign,
				message,
				userSignMessage: new Uint8Array(data.userSignMessage),
				curve: Curve.SECP256K1,
				signatureAlgorithm: SignatureAlgorithm.ECDSASecp256k1,
				hash: Hash.KECCAK256,
				ikaCoin,
				suiCoin,
			});
		});

		const signId = parseSignId(exec.events ?? []);
		if (!signId) throw new Error('Failed to get sign id from transaction events');

		const signResult = await withTimeout(
			ikaClient.getSignInParticularState(
				signId,
				Curve.SECP256K1,
				SignatureAlgorithm.ECDSASecp256k1,
				'Completed',
			),
			TIMEOUTS.SIGN_WAIT,
			'Signature from Ika network',
		);

		const signatureBytes = new Uint8Array(signResult.state.Completed.signature);
		const signatureHex = Buffer.from(signatureBytes).toString('hex');
		logger.info({ signId, signatureLength: signatureBytes.length }, 'Got signature from Ika');

		let ethTxHash: string | undefined;
		if (data.ethTx) {
			try {
				const tx: TransactionSerializableEIP1559 = {
					type: 'eip1559',
					chainId: data.ethTx.chainId,
					nonce: data.ethTx.nonce,
					to: data.ethTx.to as Hex,
					value: BigInt(data.ethTx.value),
					maxFeePerGas: BigInt(data.ethTx.maxFeePerGas),
					maxPriorityFeePerGas: BigInt(data.ethTx.maxPriorityFeePerGas),
					gas: BigInt(data.ethTx.gasLimit),
				};
				const payload = await assembleEthereumPayload(
					{ kind: 'transaction', tx },
					signatureBytes,
					data.ethTx.from as Hex,
				);
				if (payload.kind !== 'transaction') throw new Error('unreachable');
				ethTxHash = await this.ika.publish({ chain: 'ethereum', payload });
				logger.info({ ethTxHash }, 'Ethereum broadcast successful');
			} catch (err) {
				logger.error({ err }, 'Failed to broadcast to Ethereum');
			}
		}

		return { signatureHex, signId, digest: exec.digest ?? '', ethTxHash };
	}

	async getEthTxParams(address: string): Promise<{
		nonce: number;
		maxFeePerGas: string;
		maxPriorityFeePerGas: string;
		gasLimit: string;
	}> {
		// Fetch via a viem PublicClient pointed at Base Sepolia. Done lazily
		// to avoid coupling the executor to the eth chain at construction.
		const { createPublicClient, http } = await import('viem');
		const client = createPublicClient({ chain: baseSepolia, transport: http() });
		const [nonce, feeData] = await Promise.all([
			client.getTransactionCount({ address: address as Hex }),
			client.estimateFeesPerGas(),
		]);
		return {
			nonce,
			maxFeePerGas: (feeData.maxFeePerGas || BigInt('50000000000')).toString(),
			maxPriorityFeePerGas: (feeData.maxPriorityFeePerGas || BigInt('2000000000')).toString(),
			gasLimit: '21000',
		};
	}
}

/**
 * Build the plugin client. The Sui source is constructed WITHOUT a USEK — the
 * orchestrator never sees per-user encryption keys. USEK-needing plugin
 * methods (`requestSign`, `createDWallet`, ...) are off-limits; the non-USEK
 * building blocks (`requestGlobalPresign`, `verifyPresignCap`,
 * `approveMessage`, `registerSessionIdentifier`) work fine. The Ethereum
 * publisher targets Base Sepolia with confirmation polling.
 */
function buildIka(signer: Ed25519Keypair, suiClient: SuiJsonRpcClient) {
	return new IkaClient()
		.use(
			suiSource({
				network: config.sui.network,
				signer,
				suiClient,
				ikaFeePerOp: BigInt(1_000_000),
				suiGasPerOp: BigInt(10_000_000),
			}),
		)
		.use(
			ethPublisher({
				url: 'https://sepolia.base.org',
				chain: baseSepolia,
				confirm: true,
				confirmations: 1,
				confirmTimeoutMs: 60_000,
			}),
		);
}

/**
 * Convert the numeric `curve` field the frontend sends (0 = SECP256K1, etc.)
 * to the SDK's `Curve` enum value. KeySpring only uses SECP256K1 for
 * Ethereum, but the mapping covers the full enum for future use.
 */
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
			throw new Error(`unsupported curve number ${n}`);
	}
}

interface ExecEvent {
	readonly eventType: string;
	readonly bcs?: number[] | Uint8Array | null;
}

function eventBcsBytes(event: ExecEvent): Uint8Array | null {
	if (!event.bcs) return null;
	return event.bcs instanceof Uint8Array ? event.bcs : Uint8Array.from(event.bcs);
}

function parseDWalletIds(events: ExecEvent[]): {
	dWalletCapObjectId: string | null;
	dWalletObjectId: string | null;
	encryptedUserSecretKeyShareId: string | null;
} {
	const out = {
		dWalletCapObjectId: null as string | null,
		dWalletObjectId: null as string | null,
		encryptedUserSecretKeyShareId: null as string | null,
	};
	for (const event of events) {
		if (!event.eventType.includes('DWalletSessionEvent')) continue;
		const bytes = eventBcsBytes(event);
		if (!bytes) continue;
		try {
			const parsed = SessionsManagerModule.DWalletSessionEvent(
				CoordinatorInnerModule.DWalletDKGRequestEvent,
			).parse(bytes);
			out.dWalletCapObjectId = parsed.event_data.dwallet_cap_id;
			out.dWalletObjectId = parsed.event_data.dwallet_id;
			out.encryptedUserSecretKeyShareId =
				parsed.event_data.user_secret_key_share.Encrypted
					?.encrypted_user_secret_key_share_id || null;
		} catch (err) {
			logger.warn({ event: event.eventType, err }, 'Failed to parse DWalletSessionEvent');
		}
	}
	return out;
}

function parsePresignId(events: ExecEvent[]): string | null {
	for (const event of events) {
		if (!event.eventType.includes('PresignRequestEvent')) continue;
		const bytes = eventBcsBytes(event);
		if (!bytes) continue;
		try {
			const parsed = SessionsManagerModule.DWalletSessionEvent(
				CoordinatorInnerModule.PresignRequestEvent,
			).parse(bytes);
			return parsed.event_data.presign_id;
		} catch (err) {
			logger.warn({ event: event.eventType, err }, 'Failed to parse presign event');
		}
	}
	return null;
}

function parseSignId(events: ExecEvent[]): string | null {
	for (const event of events) {
		if (!event.eventType.includes('SignRequestEvent')) continue;
		const bytes = eventBcsBytes(event);
		if (!bytes) continue;
		try {
			const parsed = SessionsManagerModule.DWalletSessionEvent(
				CoordinatorInnerModule.SignRequestEvent,
			).parse(bytes);
			return parsed.event_data.sign_id;
		} catch (err) {
			logger.warn({ event: event.eventType, err }, 'Failed to parse sign event');
		}
	}
	return null;
}

export const dkgExecutor = new DKGExecutorService();

// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/**
 * Presign pool — manages pre-computed presigns for fast MPC signing.
 *
 * Presigns are single-use cryptographic pre-computations that accelerate
 * signature generation. Without a pool, every sign call must first create
 * a presign (~30-60s). With a pool of ready presigns, signing drops to
 * ~10-20s.
 *
 * Presign IDs are persisted in each wallet's vault entry so they survive
 * process restarts.
 */

import type { Keypair } from '@mysten/sui/cryptography';
import type { SuiJsonRpcClient } from '@mysten/sui/jsonRpc';
import { Transaction } from '@mysten/sui/transactions';

import type { IkaClient, IkaConfig, Presign, SignatureAlgorithm } from '@ika.xyz/sdk';
import { IkaTransaction, UserShareEncryptionKeys } from '@ika.xyz/sdk';

import { hexToBytes } from './crypto.js';
import { OWSError, OWSErrorCode } from './errors.js';
import type { OWSExecutor } from './executor.js';
import type { IkaVaultEntry, PresignPoolEntry } from './types.js';
import { updateVaultEntry } from './vault.js';

/** Composite key for the in-memory pool map. */
function poolKey(walletId: string, signatureAlgorithm: SignatureAlgorithm): string {
	return `${walletId}:${signatureAlgorithm}`;
}

/**
 * Whether a wallet+algorithm combination needs global presign vs wallet-specific.
 *
 * Wallet-specific presign (`requestPresign`) is ONLY valid for:
 * - Imported-key dWallets with ECDSA (secp256k1 or secp256r1)
 *
 * Everything else must use `requestGlobalPresign`.
 */
function needsGlobalPresign(entry: IkaVaultEntry, signatureAlgorithm: SignatureAlgorithm): boolean {
	const isImportedKey = entry.kind === 'mnemonic'; // Mnemonic wallets use imported-key protocol.
	const isEcdsa =
		signatureAlgorithm === 'ECDSASecp256k1' || signatureAlgorithm === 'ECDSASecp256r1';

	// Wallet-specific presign only for imported-key + ECDSA.
	if (isImportedKey && isEcdsa) {
		return false;
	}

	return true;
}

export class PresignPool {
	/** In-memory pool: poolKey → presignId[] */
	readonly #pool = new Map<string, string[]>();

	readonly #ikaClient: IkaClient;
	readonly #suiClient: SuiJsonRpcClient;
	readonly #keypair: Keypair;
	readonly #executor: OWSExecutor;
	readonly #vaultPath: string | undefined;
	readonly #ikaCoinType: string;

	constructor(
		ikaClient: IkaClient,
		suiClient: SuiJsonRpcClient,
		keypair: Keypair,
		executor: OWSExecutor,
		ikaConfig: IkaConfig,
		vaultPath?: string,
	) {
		this.#ikaClient = ikaClient;
		this.#suiClient = suiClient;
		this.#keypair = keypair;
		this.#executor = executor;
		this.#vaultPath = vaultPath;
		this.#ikaCoinType = `${ikaConfig.packages.ikaPackage}::ika::IKA`;
	}

	/** Fetch user's IKA coins and merge into a single coin in the transaction. */
	async #prepareIkaCoin(tx: Transaction) {
		const owner = this.#keypair.toSuiAddress();
		const coins = await this.#suiClient.getCoins({ owner, coinType: this.#ikaCoinType });

		if (coins.data.length === 0) {
			throw new OWSError(
				OWSErrorCode.INVALID_INPUT,
				`No IKA coins found for address ${owner}. IKA tokens are required for protocol fees.`,
			);
		}

		const primary = tx.object(coins.data[0]!.coinObjectId);
		if (coins.data.length > 1) {
			tx.mergeCoins(primary, coins.data.slice(1).map((c) => tx.object(c.coinObjectId)));
		}
		return primary;
	}

	/**
	 * Batch-create presigns for a wallet and persist their IDs.
	 * @returns The created presign IDs.
	 */
	async prefill(
		entry: IkaVaultEntry,
		signatureAlgorithm: SignatureAlgorithm,
		count: number,
	): Promise<string[]> {
		if (count <= 0) return [];

		const userShareEncryptionKeys = UserShareEncryptionKeys.fromShareEncryptionKeysBytes(
			hexToBytes(entry.userShareKeysHex),
		);

		const transaction = new Transaction();
		const ikaTransaction = new IkaTransaction({
			ikaClient: this.#ikaClient,
			transaction,
			userShareEncryptionKeys,
		});

		const latestEncryptionKey = await this.#ikaClient.getLatestNetworkEncryptionKey();
		const caps: ReturnType<typeof ikaTransaction.requestPresign>[] = [];

		const ikaCoin = await this.#prepareIkaCoin(transaction);

		for (let i = 0; i < count; i++) {

			if (needsGlobalPresign(entry, signatureAlgorithm)) {
				caps.push(
					ikaTransaction.requestGlobalPresign({
						dwalletNetworkEncryptionKeyId: latestEncryptionKey.id,
						curve: entry.curve as any,
						signatureAlgorithm: signatureAlgorithm as any,
						ikaCoin,
						suiCoin: transaction.gas,
					}),
				);
			} else {
				// Wallet-specific presign for imported-key ECDSA only.
				const activeDWallet = await this.#ikaClient.getDWalletInParticularState(
					entry.dwalletId,
					'Active',
				);
				caps.push(
					ikaTransaction.requestPresign({
						dWallet: activeDWallet as any,
						signatureAlgorithm,
						ikaCoin,
						suiCoin: transaction.gas,
					}),
				);
			}
		}

		transaction.transferObjects(caps, this.#keypair.toSuiAddress());

		const result = await this.#executor.execute(transaction);

		// Parse all presign events.
		const presignEvents = (result.events ?? []).filter((e: { type: string }) =>
			e.type.includes('PresignRequestEvent'),
		);

		const now = new Date().toISOString();
		const newEntries: PresignPoolEntry[] = presignEvents.map(
			(e: { parsedJson: unknown }) => ({
				presignId: (e.parsedJson as { presign_id: string }).presign_id,
				signatureAlgorithm,
				createdAt: now,
			}),
		);

		const newIds = newEntries.map((e) => e.presignId);

		// Add to in-memory pool.
		const key = poolKey(entry.id, signatureAlgorithm);
		const existing = this.#pool.get(key) ?? [];
		this.#pool.set(key, [...existing, ...newIds]);

		// Persist to vault.
		updateVaultEntry(
			entry.id,
			(e) => ({ ...e, presignIds: [...e.presignIds, ...newEntries] }),
			this.#vaultPath,
		);

		return newIds;
	}

	/**
	 * Acquire a completed presign from the pool.
	 * Falls back to on-demand creation if the pool is empty.
	 */
	async acquire(
		entry: IkaVaultEntry,
		signatureAlgorithm: SignatureAlgorithm,
		timeout: number,
		interval: number,
	): Promise<Presign> {
		const key = poolKey(entry.id, signatureAlgorithm);
		const ids = this.#pool.get(key) ?? [];

		// Try each pooled presign ID until we find a valid completed one.
		while (ids.length > 0) {
			const presignId = ids.shift()!;
			try {
				const presign = await this.#ikaClient.getPresignInParticularState(
					presignId,
					'Completed',
					{ timeout: 5000 }, // Short timeout — it should already be complete.
				);
				this.#consume(entry.id, signatureAlgorithm, presignId);
				return presign;
			} catch {
				// Stale or not yet completed — discard and try next.
				this.#consume(entry.id, signatureAlgorithm, presignId);
			}
		}

		// Pool empty — create on-demand.
		return this.#createOnDemand(entry, signatureAlgorithm, timeout, interval);
	}

	/** Count of presign IDs in memory for a wallet+algorithm. */
	available(walletId: string, signatureAlgorithm: SignatureAlgorithm): number {
		return (this.#pool.get(poolKey(walletId, signatureAlgorithm)) ?? []).length;
	}

	/** Load persisted presign IDs from a vault entry into memory. */
	hydrate(entry: IkaVaultEntry): void {
		for (const p of entry.presignIds) {
			const key = poolKey(entry.id, p.signatureAlgorithm);
			const existing = this.#pool.get(key) ?? [];
			if (!existing.includes(p.presignId)) {
				existing.push(p.presignId);
			}
			this.#pool.set(key, existing);
		}
	}

	// ─── Internal ────────────────────────────────────────────────────────

	/** Remove a presign from memory and update vault. */
	#consume(walletId: string, signatureAlgorithm: SignatureAlgorithm, presignId: string): void {
		const key = poolKey(walletId, signatureAlgorithm);
		const ids = this.#pool.get(key) ?? [];
		const filtered = ids.filter((id) => id !== presignId);
		this.#pool.set(key, filtered);

		// Persist removal.
		try {
			updateVaultEntry(
				walletId,
				(e) => ({
					...e,
					presignIds: e.presignIds.filter((p) => p.presignId !== presignId),
				}),
				this.#vaultPath,
			);
		} catch {
			// Vault write failure is non-fatal for consumption.
		}
	}

	/** Create a single presign on-demand (slow path). */
	async #createOnDemand(
		entry: IkaVaultEntry,
		signatureAlgorithm: SignatureAlgorithm,
		timeout: number,
		interval: number,
	): Promise<Presign> {
		const userShareEncryptionKeys = UserShareEncryptionKeys.fromShareEncryptionKeysBytes(
			hexToBytes(entry.userShareKeysHex),
		);

		const transaction = new Transaction();
		const ikaTransaction = new IkaTransaction({
			ikaClient: this.#ikaClient,
			transaction,
			userShareEncryptionKeys,
		});

		const latestEncryptionKey = await this.#ikaClient.getLatestNetworkEncryptionKey();
		const ikaCoin = await this.#prepareIkaCoin(transaction);

		let unverifiedPresignCap;
		if (needsGlobalPresign(entry, signatureAlgorithm)) {
			unverifiedPresignCap = ikaTransaction.requestGlobalPresign({
				dwalletNetworkEncryptionKeyId: latestEncryptionKey.id,
				curve: entry.curve as any,
				signatureAlgorithm: signatureAlgorithm as any,
				ikaCoin,
				suiCoin: transaction.gas,
			});
		} else {
			// Wallet-specific presign for imported-key ECDSA only.
			const activeDWallet = await this.#ikaClient.getDWalletInParticularState(
				entry.dwalletId,
				'Active',
			);
			unverifiedPresignCap = ikaTransaction.requestPresign({
				dWallet: activeDWallet as any,
				signatureAlgorithm,
				ikaCoin,
				suiCoin: transaction.gas,
			});
		}

		transaction.transferObjects([unverifiedPresignCap], this.#keypair.toSuiAddress());

		const result = await this.#executor.execute(transaction);

		const presignEvent = (result.events ?? []).find((e: { type: string }) =>
			e.type.includes('PresignRequestEvent'),
		);
		if (!presignEvent) {
			throw new OWSError(OWSErrorCode.PRESIGN_FAILED, 'Presign event not found');
		}

		const presignId = (presignEvent.parsedJson as { presign_id: string }).presign_id;

		return this.#ikaClient.getPresignInParticularState(presignId, 'Completed', {
			timeout,
			interval,
		});
	}
}

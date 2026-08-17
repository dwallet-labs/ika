'use client';

import { bcs } from '@mysten/sui/bcs';
import type { ClientWithCoreApi } from '@mysten/sui/client';
import { normalizeSuiAddress } from '@mysten/sui/utils';

import { buildIkaClient } from './recovery-client';

/**
 * Walk the dWallet's `encrypted_user_secret_key_shares` ObjectTable and find
 * the share encrypted to the given encryption-key address. Used to backfill
 * SavedVault.myEncryptedUserShareId for vaults imported before we started
 * persisting that field at import time.
 *
 * Stops at the first match — there's exactly one share per (dwallet,
 * encryption_key_address) in the steady state.
 *
 * Returns null when the table is empty or no share matches.
 */
export async function findMyEncryptedShareId(
	suiClient: ClientWithCoreApi,
	dwalletId: string,
	encryptionAddress: string,
): Promise<string | null> {
	const ikaClient = buildIkaClient(suiClient);
	await ikaClient.initialize();

	const dWallet = await ikaClient.getDWallet(dwalletId);
	// ObjectTable<ID, EncryptedUserSecretKeyShare> — its `id` is the table's
	// parent object id; its dynamic-field children carry one share each.
	const tableId: string = dWallet.encrypted_user_secret_key_shares.id;
	const target = normalizeSuiAddress(encryptionAddress);

	const cursor: { txDigest: string; eventSeq: string } | null | undefined = undefined;
	let pageCursor: string | null | undefined;
	void cursor; // silence unused — we only paginate dynamic fields below.

	while (true) {
		const page = await suiClient.core.listDynamicFields({
			parentId: tableId,
			cursor: pageCursor ?? null,
		});

		for (const f of page.dynamicFields) {
			// For ObjectTable<ID, V>, the dynamic-field NAME holds the share's id
			// (as a Sui address-shaped string). The wrapped V lives at that same
			// id under the table — we can fetch it directly via the SDK.
			// Core API hands back the field name as BCS rather than decoded JSON.
			const candidateId = bcs.Address.parse(f.name.bcs);
			try {
				const share = await ikaClient.getEncryptedUserSecretKeyShare(candidateId);
				const owner = normalizeSuiAddress(share.encryption_key_address);
				if (owner === target) {
					return candidateId;
				}
			} catch {}
		}

		if (!page.hasNextPage) return null;
		pageCursor = page.cursor;
	}
}

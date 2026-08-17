'use client';

import { previewProposal, type ProposalSnapshot } from '@fesal-packages/ikavery-sui-sdk';
import type { ClientWithCoreApi } from '@mysten/sui/client';

import { buildRecoveryClient } from './recovery-client';
import type { VaultState } from './recovery-state';

/**
 * Enumerate every proposal on a vault and fetch a snapshot for each. Used by
 * the dashboard's proposal-cards section. The proposal table is keyed by u64
 * so iteration is just `0..nextProposalId`.
 *
 * Snapshots reflect chain state at fetch time; the dashboard refetches on a
 * timer to keep approval counts fresh.
 */
export async function listProposalSnapshots(
	suiClient: ClientWithCoreApi,
	vault: VaultState,
): Promise<ProposalSnapshot[]> {
	const next = Number(vault.nextProposalId);
	if (next === 0) return [];

	const recClient = buildRecoveryClient(suiClient, vault.recoveryId);

	const out: ProposalSnapshot[] = [];
	for (let i = 0; i < next; i++) {
		try {
			const snap = await previewProposal(recClient, BigInt(i));
			out.push(snap);
		} catch {}
	}
	return out;
}

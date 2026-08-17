'use client';

import { ikaDwallet, readRecovery, type RecoveryAccount } from '@fesal-packages/ikavery-solana-sdk';
import { Connection, PublicKey } from '@solana/web3.js';
import { useQuery } from '@tanstack/react-query';
import * as React from 'react';

import { SOLANA_RPC } from '@/lib/env';

export interface VaultState {
	recovery: PublicKey;
	account: RecoveryAccount;
	dwalletPubkey: PublicKey;
	/** dWallet PDA on the dWallet program — the on-chain authority. */
	dwalletAccount: PublicKey;
	/** Lamports held by the dWallet — what a sweep would move. */
	dwalletBalance: number;
}

/**
 * Single-shot read of the Recovery PDA + dWallet balance, polled every 8s.
 * The poll interval matches the Sui dashboard so multi-device approval
 * shows up in roughly the same wall-clock window across both apps.
 */
export function useVaultQuery(recoveryId: string) {
	// Memoize the connection so React Query's queryFn closes over a stable ref
	// — otherwise every render rebuilds it and the dedup-by-key in
	// `connection.getAccountInfoAndContext` short-circuits.
	const connection = React.useMemo(() => new Connection(SOLANA_RPC, 'confirmed'), []);

	return useQuery<VaultState>({
		queryKey: ['solana-vault', recoveryId],
		enabled: isLikelyBase58(recoveryId),
		queryFn: async () => {
			let recovery: PublicKey;
			try {
				recovery = new PublicKey(recoveryId);
			} catch {
				throw new Error(`"${recoveryId}" is not a valid base58 Solana address.`);
			}
			const account = await readRecovery(connection, recovery);
			if (!account) {
				throw new Error(
					`Recovery PDA ${recoveryId} not found on devnet — check the network or paste the right id.`,
				);
			}
			const dwalletPubkey = account.dwallet;
			const { pda: dwalletAccount } = ikaDwallet.dwalletPda(
				account.dwalletCurve,
				dwalletPubkey.toBytes(),
			);
			// Balance read is the most informative diagnostic of a vault's state
			// beyond the on-chain threshold/roster, so we always fetch it.
			const dwalletBalance = await connection.getBalance(dwalletPubkey, 'confirmed');
			return {
				recovery,
				account,
				dwalletPubkey,
				dwalletAccount,
				dwalletBalance,
			};
		},
		refetchInterval: 8000,
		staleTime: 4000,
	});
}

/**
 * Resolve the dWallet PDA address (where the on-chain authority lives,
 * separate from the dWallet's Solana-address form).
 */
export function dwalletPdaFor(account: RecoveryAccount): PublicKey {
	const { pda } = ikaDwallet.dwalletPda(account.dwalletCurve, account.dwallet.toBytes());
	return pda;
}

function isLikelyBase58(s: string): boolean {
	// Solana addresses are 32-44 base58 chars, no zeros / O / I / l.
	return /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(s);
}

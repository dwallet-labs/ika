'use client';

import {
	decodeProposal,
	proposalPda,
	type ProposalAccount,
} from '@fesal-packages/ikavery-solana-sdk';
import { Connection, type PublicKey } from '@solana/web3.js';
import { useQuery } from '@tanstack/react-query';
import * as React from 'react';

import { SOLANA_RPC } from '@/lib/env';

export interface ProposalState {
	proposal: PublicKey;
	proposalIndex: number;
	account: ProposalAccount | null;
}

/**
 * Poll proposal state on a 4s cadence — half the dashboard's vault
 * polling interval, since approvals and the move into STATUS_APPROVED
 * are the in-flight signals the recovery flow is actively watching.
 */
export function useProposalQuery(recovery: PublicKey | null, proposalIndex: number | null) {
	const connection = React.useMemo(() => new Connection(SOLANA_RPC, 'confirmed'), []);

	const enabled = !!recovery && proposalIndex !== null && proposalIndex >= 0;
	const proposalAddress = React.useMemo(() => {
		if (!enabled) return null;
		return proposalPda(recovery as PublicKey, proposalIndex as number);
	}, [enabled, recovery, proposalIndex]);

	return useQuery<ProposalState>({
		queryKey: ['solana-proposal', recovery?.toBase58() ?? null, proposalIndex],
		enabled: enabled && !!proposalAddress,
		queryFn: async () => {
			const pda = proposalAddress as PublicKey;
			const info = await connection.getAccountInfo(pda, 'confirmed');
			const account = info ? decodeProposal(info.data) : null;
			return {
				proposal: pda,
				proposalIndex: proposalIndex as number,
				account,
			};
		},
		refetchInterval: 4000,
		staleTime: 2000,
	});
}

'use client';

import {
	decodeRosterChangeProposal,
	rosterChangePda,
	type RosterChangeProposalAccount,
} from '@fesal-packages/ikavery-solana-sdk';
import { Connection, type PublicKey } from '@solana/web3.js';
import { useQuery } from '@tanstack/react-query';
import * as React from 'react';

import { SOLANA_RPC } from '@/lib/env';

export interface RosterChangeState {
	rosterChange: PublicKey;
	rosterChangeIndex: number;
	account: RosterChangeProposalAccount | null;
}

export function useRosterChangeQuery(recovery: PublicKey | null, rosterChangeIndex: number | null) {
	const connection = React.useMemo(() => new Connection(SOLANA_RPC, 'confirmed'), []);
	const enabled = !!recovery && rosterChangeIndex !== null && rosterChangeIndex >= 0;
	const address = React.useMemo(() => {
		if (!enabled) return null;
		return rosterChangePda(recovery as PublicKey, rosterChangeIndex as number);
	}, [enabled, recovery, rosterChangeIndex]);

	return useQuery<RosterChangeState>({
		queryKey: ['solana-roster-change', recovery?.toBase58() ?? null, rosterChangeIndex],
		enabled: enabled && !!address,
		queryFn: async () => {
			const pda = address as PublicKey;
			const info = await connection.getAccountInfo(pda, 'confirmed');
			const account = info ? decodeRosterChangeProposal(info.data) : null;
			return {
				rosterChange: pda,
				rosterChangeIndex: rosterChangeIndex as number,
				account,
			};
		},
		refetchInterval: 4000,
		staleTime: 2000,
	});
}

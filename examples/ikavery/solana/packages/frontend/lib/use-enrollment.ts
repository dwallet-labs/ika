'use client';

import {
	decodeEnrollmentProposal,
	enrollmentPda,
	type EnrollmentProposalAccount,
} from '@fesal-packages/ikavery-solana-sdk';
import { Connection, type PublicKey } from '@solana/web3.js';
import { useQuery } from '@tanstack/react-query';
import * as React from 'react';

import { SOLANA_RPC } from '@/lib/env';

export interface EnrollmentState {
	enrollment: PublicKey;
	enrollmentIndex: number;
	account: EnrollmentProposalAccount | null;
}

/** Poll an enrollment proposal at the same 4s cadence as recovery proposals. */
export function useEnrollmentQuery(recovery: PublicKey | null, enrollmentIndex: number | null) {
	const connection = React.useMemo(() => new Connection(SOLANA_RPC, 'confirmed'), []);
	const enabled = !!recovery && enrollmentIndex !== null && enrollmentIndex >= 0;
	const address = React.useMemo(() => {
		if (!enabled) return null;
		return enrollmentPda(recovery as PublicKey, enrollmentIndex as number);
	}, [enabled, recovery, enrollmentIndex]);

	return useQuery<EnrollmentState>({
		queryKey: ['solana-enrollment', recovery?.toBase58() ?? null, enrollmentIndex],
		enabled: enabled && !!address,
		queryFn: async () => {
			const pda = address as PublicKey;
			const info = await connection.getAccountInfo(pda, 'confirmed');
			const account = info ? decodeEnrollmentProposal(info.data) : null;
			return {
				enrollment: pda,
				enrollmentIndex: enrollmentIndex as number,
				account,
			};
		},
		refetchInterval: 4000,
		staleTime: 2000,
	});
}

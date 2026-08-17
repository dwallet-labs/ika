'use client';

import {
	decodeEnrollmentProposal,
	decodeProposal,
	decodeRosterChangeProposal,
	enrollmentPda,
	proposalPda,
	rosterChangePda,
	type EnrollmentProposalAccount,
	type ProposalAccount,
	type RosterChangeProposalAccount,
} from '@fesal-packages/ikavery-solana-sdk';
import { Connection, type PublicKey } from '@solana/web3.js';
import { useQuery } from '@tanstack/react-query';
import * as React from 'react';

import { SOLANA_RPC } from '@/lib/env';
import { loadSweepBundle, type SweepBundle } from '@/lib/storage';

export interface ProposalSnapshot {
	index: number;
	pda: PublicKey;
	account: ProposalAccount;
	/** Saved sweep bundle from this browser (only present on the proposing device). */
	bundle: SweepBundle | null;
}

export interface EnrollmentSnapshot {
	index: number;
	pda: PublicKey;
	account: EnrollmentProposalAccount;
}

export interface RosterChangeSnapshot {
	index: number;
	pda: PublicKey;
	account: RosterChangeProposalAccount;
}

export interface DashboardActivity {
	proposals: ProposalSnapshot[];
	enrollments: EnrollmentSnapshot[];
	rosterChanges: RosterChangeSnapshot[];
}

/**
 * Single TanStack query that fetches every proposal / enrollment /
 * roster-change PDA in parallel via `getMultipleAccountsInfo`. The
 * dashboard uses this to render live cards alongside on-chain counts.
 *
 * Indexes are 0..count from the Recovery account; an empty result means
 * the vault hasn't seen any of that proposal kind. We always fetch the
 * full sequence; the on-chain count drives this and seldom climbs into
 * triple digits, so it stays in one RPC roundtrip per type.
 */
export function useDashboardActivity(params: {
	recovery: PublicKey | null;
	proposalCount: number;
	enrollmentCount: number;
	rosterChangeCount: number;
}) {
	const { recovery, proposalCount, enrollmentCount, rosterChangeCount } = params;
	const connection = React.useMemo(() => new Connection(SOLANA_RPC, 'confirmed'), []);
	const enabled = !!recovery;

	return useQuery<DashboardActivity>({
		queryKey: [
			'solana-dashboard-activity',
			recovery?.toBase58() ?? null,
			proposalCount,
			enrollmentCount,
			rosterChangeCount,
		],
		enabled,
		queryFn: async () => {
			if (!recovery) {
				return { proposals: [], enrollments: [], rosterChanges: [] };
			}
			const proposalPdas: PublicKey[] = [];
			for (let i = 0; i < proposalCount; i++) {
				proposalPdas.push(proposalPda(recovery, i));
			}
			const enrollmentPdas: PublicKey[] = [];
			for (let i = 0; i < enrollmentCount; i++) {
				enrollmentPdas.push(enrollmentPda(recovery, i));
			}
			const rosterChangePdas: PublicKey[] = [];
			for (let i = 0; i < rosterChangeCount; i++) {
				rosterChangePdas.push(rosterChangePda(recovery, i));
			}

			const [proposalInfos, enrollmentInfos, rosterChangeInfos] = await Promise.all([
				proposalPdas.length === 0
					? Promise.resolve([])
					: connection.getMultipleAccountsInfo(proposalPdas, 'confirmed'),
				enrollmentPdas.length === 0
					? Promise.resolve([])
					: connection.getMultipleAccountsInfo(enrollmentPdas, 'confirmed'),
				rosterChangePdas.length === 0
					? Promise.resolve([])
					: connection.getMultipleAccountsInfo(rosterChangePdas, 'confirmed'),
			]);

			const proposalsRaw: Array<Omit<ProposalSnapshot, 'bundle'> | null> = proposalInfos.map(
				(info, i) => {
					if (!info) return null;
					try {
						return {
							index: i,
							pda: proposalPdas[i] as PublicKey,
							account: decodeProposal(new Uint8Array(info.data)),
						};
					} catch {
						return null;
					}
				},
			);
			const enrollments: EnrollmentSnapshot[] = enrollmentInfos
				.map((info, i): EnrollmentSnapshot | null => {
					if (!info) return null;
					try {
						return {
							index: i,
							pda: enrollmentPdas[i] as PublicKey,
							account: decodeEnrollmentProposal(new Uint8Array(info.data)),
						};
					} catch {
						return null;
					}
				})
				.filter((x): x is EnrollmentSnapshot => x !== null);
			const rosterChanges: RosterChangeSnapshot[] = rosterChangeInfos
				.map((info, i): RosterChangeSnapshot | null => {
					if (!info) return null;
					try {
						return {
							index: i,
							pda: rosterChangePdas[i] as PublicKey,
							account: decodeRosterChangeProposal(new Uint8Array(info.data)),
						};
					} catch {
						return null;
					}
				})
				.filter((x): x is RosterChangeSnapshot => x !== null);

			const proposals: ProposalSnapshot[] = await Promise.all(
				proposalsRaw
					.filter((p): p is Omit<ProposalSnapshot, 'bundle'> => p !== null)
					.map(async (p) => ({
						...p,
						bundle: await loadSweepBundle(p.pda.toBase58()),
					})),
			);

			return { proposals, enrollments, rosterChanges };
		},
		refetchInterval: 8000,
		staleTime: 4000,
	});
}

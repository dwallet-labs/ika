'use client';

import { getNetworkConfig } from '@ika.xyz/sdk';
import { useQuery } from '@tanstack/react-query';
import { AlertCircle, CheckCircle2, Loader2 } from 'lucide-react';

import { env } from '@/lib/env';
import {
	compareBudget,
	fetchBalances,
	formatIka,
	formatSui,
	type CostEstimate,
} from '@/lib/gas-preflight';
import { useRecoveryClient } from '@/lib/recovery-client-context';

const IKA_COIN_TYPE = `${getNetworkConfig(env.network).packages.ikaPackage}::ika::IKA`;

/**
 * Compact "have vs need" readout for the gas-payer wallet. Polls SUI + IKA
 * balance every 12s so picking a different wallet immediately re-fetches
 * via the cache key. Returns null silently when no address is supplied —
 * callers can render this unconditionally inside their gas-payer card.
 */
export function GasBudgetRow({
	gasPayerAddress,
	estimate,
}: {
	gasPayerAddress: string | null;
	estimate: CostEstimate;
}) {
	const { suiClient } = useRecoveryClient();

	const q = useQuery({
		queryKey: ['gas-balance', gasPayerAddress?.toLowerCase() ?? null],
		queryFn: async () => {
			if (!suiClient || !gasPayerAddress) return null;
			return await fetchBalances(suiClient, gasPayerAddress, IKA_COIN_TYPE);
		},
		enabled: !!suiClient && !!gasPayerAddress,
		refetchInterval: 12_000,
		staleTime: 8_000,
	});

	if (!gasPayerAddress) return null;

	if (q.isLoading || !q.data) {
		return (
			<div className="text-[12px] text-text-3 leading-[1.5] inline-flex items-center gap-1.5">
				<Loader2 className="h-3 w-3 animate-spin" />
				Checking balance…
			</div>
		);
	}

	const r = compareBudget(q.data, estimate);
	return (
		<div className={r.ok ? 'text-text-3' : 'text-clay'} style={{ fontSize: 12, lineHeight: 1.5 }}>
			<div className="inline-flex items-center gap-1.5">
				{r.ok ? (
					<CheckCircle2 className="h-3 w-3 text-sage" />
				) : (
					<AlertCircle className="h-3 w-3 text-clay" />
				)}
				<span>
					Has{' '}
					<span className={r.suiOk ? 'text-text-2' : 'text-clay font-medium'}>
						{formatSui(r.have.sui)}
					</span>
					{estimate.ika > 0n && (
						<>
							{' · '}
							<span className={r.ikaOk ? 'text-text-2' : 'text-clay font-medium'}>
								{formatIka(r.have.ika)}
							</span>
						</>
					)}
					{' · needs ≈ '}
					<span className="text-text-2">{formatSui(estimate.sui)}</span>
					{estimate.ika > 0n && (
						<>
							{' + '}
							<span className="text-text-2">{formatIka(estimate.ika)}</span>
						</>
					)}
				</span>
			</div>
			{!r.ok && (
				<div className="mt-1 text-[11.5px] text-clay leading-[1.5]">
					{!r.suiOk && <>Top up SUI on this wallet, or pick a different gas payer.</>}
					{!r.suiOk && !r.ikaOk && <br />}
					{!r.ikaOk && <>Top up IKA — the recovery package consumes IKA fees per Solana tx.</>}
				</div>
			)}
		</div>
	);
}

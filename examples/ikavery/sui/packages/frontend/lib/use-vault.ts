'use client';

import { useQuery } from '@tanstack/react-query';

import { useRecoveryClient } from './recovery-client-context';
import { readVaultState, type VaultState } from './recovery-state';

interface UseVaultOptions {
	refetchInterval?: number | false;
	staleTime?: number;
}

export function useVaultQuery(recoveryId: string, opts: UseVaultOptions = {}) {
	const { suiClient } = useRecoveryClient();
	return useQuery<VaultState>({
		queryKey: ['vault', recoveryId, suiClient ? 'ready' : '_'],
		enabled: !!suiClient && !!recoveryId,
		queryFn: () => readVaultState(suiClient!, recoveryId),
		refetchInterval: opts.refetchInterval ?? 8_000,
		staleTime: opts.staleTime ?? 4_000,
	});
}

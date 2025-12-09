import { useCurrentAccount } from '@mysten/dapp-kit';
import { useMemo } from 'react';

import { Multisig } from '../generated/ika_btc_multisig/multisig';
import { MultisigBitcoinWallet } from '../multisig/bitcoin';
import { useMultisigOwnerships } from './useMultisigOwnerships';
import { useMultipleMultisigRequests, type RequestWithVote } from './useMultisigRequests';
import { useMultisigs, type MultisigData } from './useMultisigs';

// Re-export types for backwards compatibility
export type { RequestWithVote } from './useMultisigRequests';
export type { MultisigData } from './useMultisigs';

export interface MultisigOwnership {
	id: string;
	multisigId: string;
	multisig: typeof Multisig.$inferType;
	class: MultisigBitcoinWallet;
	requests: RequestWithVote[];
}

/**
 * Main hook that combines ownerships, multisigs, and requests
 * This is a convenience hook that maintains backwards compatibility
 * For better performance, use the individual hooks directly
 */
export const useMultisigOwnership = () => {
	const account = useCurrentAccount();

	// Step 1: Fetch ownership objects
	const {
		data: ownerships,
		isLoading: isLoadingOwnerships,
		error: ownershipsError,
		refetch: refetchOwnerships,
		isFetching: isFetchingOwnerships,
	} = useMultisigOwnerships();

	// Step 2: Get unique multisig IDs from ownerships
	const multisigIds = useMemo(() => {
		if (!ownerships) return [];
		return [...new Set(ownerships.map((ownership) => ownership.multisig_id))];
	}, [ownerships]);

	// Step 3: Fetch multisig data for all unique multisig IDs
	const {
		data: multisigs,
		isLoading: isLoadingMultisigs,
		error: multisigsError,
		refetch: refetchMultisigs,
		isFetching: isFetchingMultisigs,
	} = useMultisigs(multisigIds);

	// Step 4: Prepare data for fetching requests
	const multisigsForRequests = useMemo(() => {
		if (!multisigs) return [];
		return multisigs.map((m) => ({
			multisigId: m.id,
			requestsTableId: m.multisig.requests.id.id,
		}));
	}, [multisigs]);

	// Step 5: Fetch requests for all multisigs
	const {
		data: requestsMap,
		isLoading: isLoadingRequests,
		error: requestsError,
		refetch: refetchRequests,
		isFetching: isFetchingRequests,
	} = useMultipleMultisigRequests(multisigsForRequests);

	// Step 6: Combine all data into the final format
	const data = useMemo(() => {
		if (!ownerships || !multisigs || !requestsMap) return undefined;

		const multisigMap = new Map(multisigs.map((m) => [m.id, m]));

		return ownerships
			.map((ownership) => {
				const multisigData = multisigMap.get(ownership.multisig_id);
				if (!multisigData) return null;

				const requests = requestsMap.get(ownership.multisig_id) || [];

				return {
					id: ownership.id.id,
					multisigId: ownership.multisig_id,
					multisig: multisigData.multisig,
					class: multisigData.class,
					requests,
				};
			})
			.filter((item): item is MultisigOwnership => item !== null);
	}, [ownerships, multisigs, requestsMap]);

	const isLoading = isLoadingOwnerships || isLoadingMultisigs || isLoadingRequests;
	const isFetching = isFetchingOwnerships || isFetchingMultisigs || isFetchingRequests;
	const error = ownershipsError || multisigsError || requestsError;

	// Combined refetch function
	const refetch = async () => {
		await Promise.all([refetchOwnerships(), refetchMultisigs(), refetchRequests()]);
	};

	return {
		data,
		isLoading,
		isFetching,
		error,
		refetch,
	};
};

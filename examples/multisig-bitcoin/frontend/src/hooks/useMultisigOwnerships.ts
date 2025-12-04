import { objResToBcs } from '@ika.xyz/sdk';
import { useCurrentAccount, useSuiClient } from '@mysten/dapp-kit';
import { useQuery } from '@tanstack/react-query';
import invariant from 'tiny-invariant';

import { MultisigOwnership } from '../generated/ika_btc_multisig/multisig';
import { useIds } from './useObjects';

/**
 * Hook to fetch the user's MultisigOwnership objects
 * These are lightweight objects that link a user to multisigs they're part of
 */
export const useMultisigOwnerships = () => {
	const { multisigPackageId } = useIds();
	const account = useCurrentAccount();
	const suiClient = useSuiClient();

	return useQuery({
		queryKey: ['multisigOwnerships', account?.address, multisigPackageId],
		queryFn: async () => {
			invariant(account, 'Account not found');

			const multisigOwnershipResponse = await suiClient.getOwnedObjects({
				owner: account.address,
				options: {
					showBcs: true,
				},
				filter: {
					StructType: `${multisigPackageId}::multisig::MultisigOwnership`,
				},
			});

			const ownerships = multisigOwnershipResponse.data.map((obj) =>
				MultisigOwnership.fromBase64(objResToBcs(obj)),
			);

			return ownerships;
		},
		enabled: !!account,
		// Ownership objects rarely change, so we can refetch less frequently
		refetchInterval: 30000, // 30 seconds
		staleTime: 20000, // 20 seconds
	});
};

import { objResToBcs } from '@ika.xyz/sdk';
import { useCurrentAccount, useCurrentClient } from '@mysten/dapp-kit-react';
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
	const suiClient = useCurrentClient();

	return useQuery({
		queryKey: ['multisigOwnerships', account?.address, multisigPackageId],
		queryFn: async () => {
			invariant(account, 'Account not found');

			const multisigOwnershipResponse = await suiClient.listOwnedObjects({
				owner: account.address,
				include: { content: true },
				type: `${multisigPackageId}::multisig::MultisigOwnership`,
			});

			const ownerships = multisigOwnershipResponse.objects.map((obj) =>
				MultisigOwnership.parse(objResToBcs(obj)),
			);

			return ownerships;
		},
		enabled: !!account,
		// Ownership objects rarely change, so we can refetch less frequently
		refetchInterval: 30000, // 30 seconds
		staleTime: 20000, // 20 seconds
	});
};

import { Curve, DWalletWithState, objResToBcs, publicKeyFromDWalletOutput } from '@ika.xyz/sdk';
import { useCurrentAccount, useSuiClient } from '@mysten/dapp-kit';
import { useQuery } from '@tanstack/react-query';
import invariant from 'tiny-invariant';

import { Multisig } from '../generated/ika_btc_multisig/multisig';
import { MultisigBitcoinWallet } from '../multisig/bitcoin';
import { useIkaClient } from './useIkaClient';
import { useIds } from './useObjects';

export interface MultisigData {
	id: string;
	multisig: typeof Multisig.$inferType;
	dWallet: DWalletWithState<'Active'>;
	class: MultisigBitcoinWallet;
	publicKey: Uint8Array;
}

/**
 * Hook to fetch full multisig data including dWallet info
 * @param multisigIds - Array of multisig object IDs to fetch
 */
export const useMultisigs = (multisigIds: string[]) => {
	const { multisigPackageId, coordinator } = useIds();
	const account = useCurrentAccount();
	const suiClient = useSuiClient();
	const { ikaClient } = useIkaClient();

	return useQuery({
		queryKey: ['multisigs', multisigIds.sort().join(',')],
		queryFn: async (): Promise<MultisigData[]> => {
			invariant(account, 'Account not found');

			if (multisigIds.length === 0) {
				return [];
			}

			// Fetch all multisig objects in parallel
			const multisigsObjects = await suiClient.multiGetObjects({
				ids: multisigIds,
				options: {
					showBcs: true,
				},
			});

			const multisigs = multisigsObjects.map((obj) => Multisig.fromBase64(objResToBcs(obj)));

			// Filter to only include multisigs where the user is a member
			const userMultisigs = multisigs.filter((multisig) =>
				multisig.members.includes(account.address),
			);

			if (userMultisigs.length === 0) {
				return [];
			}

			// Fetch dWallets for all multisigs
			const dWalletIds = userMultisigs.map((multisig) => multisig.dwallet_cap.dwallet_id);
			const dWallets = await ikaClient.getMultipleDWallets(dWalletIds);
			const dWalletMap = new Map(
				dWallets.map((dWallet) => [dWallet.id.id, dWallet as DWalletWithState<'Active'>]),
			);

			// Create MultisigData objects with all necessary info
			const multisigDataPromises = userMultisigs.map(async (multisig) => {
				const dWallet = dWalletMap.get(multisig.dwallet_cap.dwallet_id);
				invariant(dWallet, 'dWallet not found');

				// Get public key
				const publicKey = await publicKeyFromDWalletOutput(
					Curve.SECP256K1,
					Uint8Array.from(dWallet.state.Active?.public_output ?? []),
				);

				// Create the MultisigBitcoinWallet instance
				const multisigClass = new MultisigBitcoinWallet(
					'testnet',
					publicKey,
					ikaClient,
					suiClient,
					multisigPackageId,
					{
						multisig: multisig.id.id,
						coordinator,
						dWallet,
					},
				);

				return {
					id: multisig.id.id,
					multisig,
					dWallet,
					class: multisigClass,
					publicKey,
				};
			});

			return Promise.all(multisigDataPromises);
		},
		enabled: !!account && multisigIds.length > 0,
		// Multisig data changes less frequently than requests
		refetchInterval: 20000, // 20 seconds
		staleTime: 15000, // 15 seconds
	});
};

/**
 * Hook to fetch a single multisig's data
 * @param multisigId - The multisig object ID
 */
export const useMultisig = (multisigId: string | null) => {
	const result = useMultisigs(multisigId ? [multisigId] : []);

	return {
		...result,
		data: result.data?.[0] ?? null,
	};
};

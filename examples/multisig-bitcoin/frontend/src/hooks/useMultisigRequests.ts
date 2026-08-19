import { useCurrentAccount, useCurrentClient } from '@mysten/dapp-kit-react';
import { bcs } from '@mysten/sui/bcs';
import type { SuiGrpcClient } from '@mysten/sui/grpc';
import { useQuery } from '@tanstack/react-query';
import invariant from 'tiny-invariant';

import { Request } from '../generated/ika_btc_multisig/multisig_request';

export type RequestWithVote = typeof Request.$inferType & {
	voted?: boolean;
	userVote?: boolean;
	requestId: number;
};

/**
 * Reads every request in a multisig's requests table, plus this account's vote
 * on each.
 *
 * The Core API returns a dynamic field's value inline, so listing the table
 * yields the requests themselves — where the JSON-RPC flow had to list the
 * fields, fetch each `Field<u64, Request>` object, and unwrap the envelope by
 * hand.
 */
/** Kept separate so the paginated `cursor` never feeds its own inference. */
function listRequestFields(suiClient: SuiGrpcClient, parentId: string, cursor: string | null) {
	return suiClient.listDynamicFields<{ value: true }>({
		parentId,
		cursor,
		include: { value: true },
	});
}

async function fetchRequests(
	suiClient: SuiGrpcClient,
	requestsTableId: string,
	voterAddress: string,
): Promise<RequestWithVote[]> {
	const requests: RequestWithVote[] = [];
	let cursor: string | null = null;

	do {
		const response = await listRequestFields(suiClient, requestsTableId, cursor);

		for (const field of response.dynamicFields) {
			try {
				requests.push({
					...Request.parse(field.value!.bcs),
					voted: false,
					userVote: undefined,
					requestId: Number(bcs.u64().parse(field.name.bcs)),
				});
			} catch (error) {
				// Skip invalid requests
				console.error('Failed to parse request:', error);
			}
		}

		cursor = response.hasNextPage ? response.cursor : null;
	} while (cursor);

	if (requests.length === 0) {
		return [];
	}

	// A missing vote field means this account has not voted, which the Core API
	// reports as a failed lookup rather than an empty result.
	const voteChecks = await Promise.allSettled(
		requests.map(async (request) => {
			try {
				const { dynamicField } = await suiClient.getDynamicField({
					parentId: request.votes.id.id,
					name: {
						type: 'address',
						bcs: bcs.Address.serialize(voterAddress).toBytes(),
					},
				});

				if (dynamicField) {
					request.voted = true;
					request.userVote = bcs.bool().parse(dynamicField.value.bcs);
				}
			} catch {
				request.voted = false;
			}

			return request;
		}),
	);

	return voteChecks
		.filter((result) => result.status === 'fulfilled')
		.map((result) => (result as PromiseFulfilledResult<RequestWithVote>).value);
}

/**
 * Hook to fetch requests for a specific multisig
 * @param multisigId - The multisig object ID
 * @param requestsTableId - The ID of the requests table (from multisig.requests.id.id)
 */
export const useMultisigRequests = (multisigId: string | null, requestsTableId: string | null) => {
	const account = useCurrentAccount();
	const suiClient = useCurrentClient();

	return useQuery({
		queryKey: ['multisigRequests', multisigId, requestsTableId, account?.address],
		queryFn: async (): Promise<RequestWithVote[]> => {
			invariant(account, 'Account not found');
			invariant(requestsTableId, 'Requests table ID not found');

			return fetchRequests(suiClient, requestsTableId, account.address);
		},
		enabled: !!account && !!multisigId && !!requestsTableId,
		// Requests change frequently, so we refetch more often
		refetchInterval: 10000, // 10 seconds
		staleTime: 5000, // 5 seconds
	});
};

/**
 * Hook to fetch requests for multiple multisigs
 * @param multisigs - Array of objects with multisigId and requestsTableId
 */
export const useMultipleMultisigRequests = (
	multisigs: Array<{ multisigId: string; requestsTableId: string }>,
) => {
	const account = useCurrentAccount();
	const suiClient = useCurrentClient();

	return useQuery({
		queryKey: [
			'multipleMultisigRequests',
			multisigs
				.map((m) => m.multisigId)
				.sort()
				.join(','),
			account?.address,
		],
		queryFn: async (): Promise<Map<string, RequestWithVote[]>> => {
			invariant(account, 'Account not found');

			if (multisigs.length === 0) {
				return new Map();
			}

			const results = await Promise.all(
				multisigs.map(async ({ multisigId, requestsTableId }) => ({
					multisigId,
					requests: await fetchRequests(suiClient, requestsTableId, account.address),
				})),
			);

			return new Map(results.map(({ multisigId, requests }) => [multisigId, requests]));
		},
		enabled: !!account && multisigs.length > 0,
		// Requests change frequently
		refetchInterval: 10000, // 10 seconds
		staleTime: 5000, // 5 seconds
	});
};

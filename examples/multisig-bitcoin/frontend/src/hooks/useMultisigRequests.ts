import { objResToBcs } from '@ika.xyz/sdk';
import { useCurrentAccount, useSuiClient } from '@mysten/dapp-kit';
import { bcs } from '@mysten/sui/bcs';
import { useQuery } from '@tanstack/react-query';
import invariant from 'tiny-invariant';

import { Request } from '../generated/ika_btc_multisig/multisig_request';

export type RequestWithVote = typeof Request.$inferType & {
	voted?: boolean;
	userVote?: boolean;
	requestId: number;
};

/**
 * Hook to fetch requests for a specific multisig
 * @param multisigId - The multisig object ID
 * @param requestsTableId - The ID of the requests table (from multisig.requests.id.id)
 */
export const useMultisigRequests = (multisigId: string | null, requestsTableId: string | null) => {
	const account = useCurrentAccount();
	const suiClient = useSuiClient();

	return useQuery({
		queryKey: ['multisigRequests', multisigId, requestsTableId, account?.address],
		queryFn: async (): Promise<RequestWithVote[]> => {
			invariant(account, 'Account not found');
			invariant(requestsTableId, 'Requests table ID not found');

			// Fetch all dynamic fields from requests table with pagination
			const allDynamicFields: Array<{ objectId: string; name: { type: string; value: any } }> = [];
			let cursor: string | null = null;

			do {
				const response = await suiClient.getDynamicFields({
					parentId: requestsTableId,
					cursor,
				});

				if (response.data) {
					allDynamicFields.push(...response.data);
				}

				cursor = response.nextCursor || null;
				if (!response.hasNextPage || !cursor) {
					break;
				}
			} while (cursor);

			if (allDynamicFields.length === 0) {
				return [];
			}

			// Fetch all request objects in parallel
			const requestObjects = await suiClient.multiGetObjects({
				ids: allDynamicFields.map((field) => field.objectId),
				options: {
					showBcs: true,
				},
			});

			// Parse requests and prepare vote checks
			const parsedRequests: Array<{
				request: RequestWithVote;
				votesTableId: string;
			}> = [];

			requestObjects.forEach((obj, idx) => {
				try {
					// Parse the Field<u64, Request> wrapper
					const fieldBcs = objResToBcs(obj);
					const fieldBytes = Buffer.from(fieldBcs, 'base64');

					// Create BCS struct for Field<u64, Request>
					const fieldStruct = bcs.struct('Field', {
						id: bcs.Address,
						name: bcs.u64(),
						value: Request,
					});

					const parsedField = fieldStruct.parse(fieldBytes);

					// Extract the Request from the Field's value
					const request = parsedField.value;
					const key = allDynamicFields[idx]?.name?.value;
					const requestIdNum = typeof key === 'string' ? Number(key) : Number(key ?? 0);
					parsedRequests.push({
						request: {
							...request,
							voted: false,
							userVote: undefined,
							requestId: requestIdNum,
						},
						votesTableId: request.votes.id.id,
					});
				} catch (error) {
					// Skip invalid requests
					console.error('Failed to parse request:', error);
				}
			});

			// Batch check votes for all requests in parallel
			// Use Promise.allSettled to prevent one failed vote check from failing entire query
			const voteCheckResults = await Promise.allSettled(
				parsedRequests.map(async ({ request, votesTableId }) => {
					try {
						const voteField = await suiClient.getDynamicFieldObject({
							parentId: votesTableId,
							name: {
								type: 'address',
								value: account.address,
							},
						});

						if (voteField.data) {
							const voteObject = await suiClient.getObject({
								id: voteField.data.objectId,
								options: {
									showBcs: true,
									showContent: true,
								},
							});

							request.voted = true;
							// @ts-expect-error - content is not typed
							request.userVote = voteObject.data?.content?.fields?.value;
						}
					} catch {
						// User hasn't voted
						request.voted = false;
					}

					return request;
				}),
			);

			// Extract successful results
			const requestsWithVotes = voteCheckResults
				.filter((result) => result.status === 'fulfilled')
				.map((result) => (result as PromiseFulfilledResult<RequestWithVote>).value);

			return requestsWithVotes;
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
	const suiClient = useSuiClient();

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

			// Fetch requests for each multisig in parallel
			const requestsPromises = multisigs.map(async ({ multisigId, requestsTableId }) => {
				// Fetch all dynamic fields from requests table with pagination
				const allDynamicFields: Array<{ objectId: string; name: { type: string; value: any } }> =
					[];
				let cursor: string | null = null;

				do {
					const response = await suiClient.getDynamicFields({
						parentId: requestsTableId,
						cursor,
					});

					if (response.data) {
						allDynamicFields.push(...response.data);
					}

					cursor = response.nextCursor || null;
					if (!response.hasNextPage || !cursor) {
						break;
					}
				} while (cursor);

				if (allDynamicFields.length === 0) {
					return { multisigId, requests: [] };
				}

				// Fetch all request objects in parallel
				const requestObjects = await suiClient.multiGetObjects({
					ids: allDynamicFields.map((field) => field.objectId),
					options: {
						showBcs: true,
					},
				});

				// Parse requests
				const parsedRequests: Array<{
					request: RequestWithVote;
					votesTableId: string;
				}> = [];

				requestObjects.forEach((obj, idx) => {
					try {
						const fieldBcs = objResToBcs(obj);
						const fieldBytes = Buffer.from(fieldBcs, 'base64');

						const fieldStruct = bcs.struct('Field', {
							id: bcs.Address,
							name: bcs.u64(),
							value: Request,
						});

						const parsedField = fieldStruct.parse(fieldBytes);
						const request = parsedField.value;
						const key = allDynamicFields[idx]?.name?.value;
						const requestIdNum = typeof key === 'string' ? Number(key) : Number(key ?? 0);

						parsedRequests.push({
							request: {
								...request,
								voted: false,
								userVote: undefined,
								requestId: requestIdNum,
							},
							votesTableId: request.votes.id.id,
						});
					} catch (error) {
						console.error('Failed to parse request:', error);
					}
				});

				// Check votes for all requests
				const voteCheckResults = await Promise.allSettled(
					parsedRequests.map(async ({ request, votesTableId }) => {
						try {
							const voteField = await suiClient.getDynamicFieldObject({
								parentId: votesTableId,
								name: {
									type: 'address',
									value: account.address,
								},
							});

							if (voteField.data) {
								const voteObject = await suiClient.getObject({
									id: voteField.data.objectId,
									options: {
										showBcs: true,
										showContent: true,
									},
								});

								request.voted = true;
								// @ts-expect-error - content is not typed
								request.userVote = voteObject.data?.content?.fields?.value;
							}
						} catch {
							request.voted = false;
						}

						return request;
					}),
				);

				const requestsWithVotes = voteCheckResults
					.filter((result) => result.status === 'fulfilled')
					.map((result) => (result as PromiseFulfilledResult<RequestWithVote>).value);

				return { multisigId, requests: requestsWithVotes };
			});

			const results = await Promise.all(requestsPromises);

			// Convert to Map for easy lookup
			const requestsMap = new Map<string, RequestWithVote[]>();
			results.forEach(({ multisigId, requests }) => {
				requestsMap.set(multisigId, requests);
			});

			return requestsMap;
		},
		enabled: !!account && multisigs.length > 0,
		// Requests change frequently
		refetchInterval: 10000, // 10 seconds
		staleTime: 5000, // 5 seconds
	});
};

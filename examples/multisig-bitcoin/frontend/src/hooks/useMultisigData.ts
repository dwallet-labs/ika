import { Curve, objResToBcs, publicKeyFromDWalletOutput } from '@ika.xyz/sdk';
import { useCurrentAccount, useSuiClient } from '@mysten/dapp-kit';
import { bcs } from '@mysten/sui/bcs';
import { useQuery } from '@tanstack/react-query';
import invariant from 'tiny-invariant';

import { Multisig, MultisigOwnership } from '../generated/ika_btc_multisig/multisig';
import { Request } from '../generated/ika_btc_multisig/multisig_request';
import { MultisigBitcoinWallet } from '../multisig/bitcoin';
import { useIkaClient } from './useIkaClient';
import { useIds } from './useObjects';

export type RequestWithVote = typeof Request.$inferType & {
	voted?: boolean;
	userVote?: boolean;
	requestId: number;
};

export interface MultisigOwnership {
	id: string;
	multisigId: string;
	multisig: typeof Multisig.$inferType;
	class: MultisigBitcoinWallet;
	requests: RequestWithVote[];
}

export const useMultisigOwnership = () => {
	const { multisigPackageId, coordinator } = useIds();
	const account = useCurrentAccount();
	const suiClient = useSuiClient();
	const { ikaClient } = useIkaClient();

	return useQuery({
		queryKey: ['multisigOwnership', account?.address],
		queryFn: async () => {
			invariant(account, 'Account not found');

			// Step 1: Fetch ownership objects
			const multisigOwnership = await suiClient.getOwnedObjects({
				owner: account.address,
				options: {
					showBcs: true,
				},
				filter: {
					StructType: `${multisigPackageId}::multisig::MultisigOwnership`,
				},
			});

			const ownerships = multisigOwnership.data.map((obj) =>
				MultisigOwnership.fromBase64(objResToBcs(obj)),
			);

			if (ownerships.length === 0) {
				return [];
			}

			// Step 2: Fetch all multisig objects in parallel
			const unDuplicatedMultisigIds = [
				...new Set(ownerships.map((ownership) => ownership.multisig_id)),
			];
			const multisigsObjects = await suiClient.multiGetObjects({
				ids: unDuplicatedMultisigIds,
				options: {
					showBcs: true,
				},
			});

			const multisigs = multisigsObjects.map((obj) => Multisig.fromBase64(objResToBcs(obj)));

			// Step 3: Create lookup maps for O(1) access
			const multisigMap = new Map(multisigs.map((multisig) => [multisig.id.id, multisig]));
			const dWalletIds = multisigs.map((multisig) => multisig.dwallet_cap.dwallet_id);
			const dWallets = await ikaClient.getMultipleDWallets(dWalletIds);
			const dWalletMap = new Map(dWallets.map((dWallet) => [dWallet.id.id, dWallet]));

			// Step 4: Filter and process multisigs in parallel
			const multisigDataPromises = ownerships
				.map((ownership) => {
					const multisig = multisigMap.get(ownership.multisig_id);
					if (!multisig || !multisig.members.includes(account.address)) {
						return null;
					}
					return { ownership, multisig };
				})
				.filter(
					(item): item is { ownership: (typeof ownerships)[0]; multisig: (typeof multisigs)[0] } =>
						item !== null,
				)
				.map(async ({ ownership, multisig }) => {
					const dWallet = dWalletMap.get(multisig.dwallet_cap.dwallet_id);

					// Get public key
					const encodedPublicKey = await publicKeyFromDWalletOutput(
						Curve.SECP256K1,
						Uint8Array.from(dWallet?.state.Active?.public_output ?? []),
					);
					const publicKey = new Uint8Array(bcs.vector(bcs.u8()).parse(encodedPublicKey));

					// Fetch all dynamic fields from requests table with pagination
					const allDynamicFields: Array<{ objectId: string; name: { type: string; value: any } }> =
						[];
					let cursor: string | null = null;

					do {
						const response = await suiClient.getDynamicFields({
							parentId: multisig.requests.id.id,
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
						return {
							id: ownership.id.id,
							multisigId: ownership.multisig_id,
							multisig,
							class: new MultisigBitcoinWallet(
								'testnet',
								publicKey,
								ikaClient,
								// @todo(fesal): fix this
								// @ts-expect-error - suiClient is not typed
								suiClient,
								multisigPackageId,
								{
									multisig: multisig.id.id,
									coordinator,
									dWallet: dWallet,
								},
							),
							requests: [],
						};
					}

					// Fetch all request objects in parallel
					const requestObjects = await suiClient.multiGetObjects({
						ids: allDynamicFields.map((field) => field.objectId),
						options: {
							showBcs: true,
						},
					});

					// Parse requests and prepare vote checks (preserve requestId from dynamic field key)
					// The dynamic field is wrapped in Field<u64, Request>, so we need to parse the Field first
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
					const requestsWithVotes = await Promise.all(
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

					return {
						id: ownership.id.id,
						multisigId: ownership.multisig_id,
						multisig,
						class: new MultisigBitcoinWallet(
							'testnet',
							publicKey,
							ikaClient,
							// @todo(fesal): fix this
							// @ts-expect-error - suiClient is not typed
							suiClient,
							multisigPackageId,
							{
								multisig: multisig.id.id,
								coordinator,
								dWallet: dWallet,
							},
						),
						requests: requestsWithVotes,
					};
				});

			return Promise.all(multisigDataPromises);
		},
		enabled: !!account,
	});
};

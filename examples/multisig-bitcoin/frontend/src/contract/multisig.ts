import {
	CoordinatorInnerModule,
	createUserSignMessageWithPublicOutput,
	Curve,
	DynamicField,
	Hash,
	IkaTransaction,
	objResToBcs,
	prepareDKGSecondRoundAsync,
	publicKeyFromDWalletOutput,
	SessionsManagerModule,
	UserShareEncryptionKeys,
} from '@ika.xyz/sdk';
import { useCurrentAccount, useSignTransaction, useSuiClient } from '@mysten/dapp-kit';
import { bcs } from '@mysten/sui/bcs';
import { Transaction } from '@mysten/sui/transactions';
import { useCallback, useEffect, useState } from 'react';

import { useIkaClient } from '@/hooks/ika-client';
import {
	BitcoinUtils,
	btcToSatoshis,
	fetchUTXOs,
	getNetworkFeeRates,
	validateAddress,
} from '@/lib/bitcoin-utils';

import { SignRequestEvent } from '../../../../../sdk/typescript/dist/esm/generated/ika_dwallet_2pc_mpc/coordinator_inner';
import * as EventWrapperModule from '../generated/ika_btc_multisig/event_wrapper';
import * as MultisigModule from '../generated/ika_btc_multisig/multisig';
import * as MultisigEventsModule from '../generated/ika_btc_multisig/multisig_events';
import * as RequestModule from '../generated/ika_btc_multisig/multisig_request';

export const useMultisig = () => {
	const { ikaClient } = useIkaClient();
	const suiClient = useSuiClient();
	const { mutateAsync: signTransaction } = useSignTransaction();
	const currentAccount = useCurrentAccount();
	const getUserShareEncryptionKeys = useCallback(async () => {
		return await UserShareEncryptionKeys.fromRootSeedKey(
			new TextEncoder().encode('bitcoin_multisig_ika'),
			Curve.SECP256K1,
		);
	}, []);
	const MULTISIG_PACKAGE = '0x31055e1145f91fa6c119fc1637ab7ba4f27d745a9bb58e61b4ce1f1785bb63b8';

	const executeTransaction = async (tx: Transaction) => {
		const signedTransaction = await signTransaction({
			transaction: tx,
			chain: 'sui:mainnet',
		});

		// Execute
		const res1 = await suiClient.executeTransactionBlock({
			transactionBlock: signedTransaction.bytes,
			signature: signedTransaction.signature,
		});

		// Wait
		const res2 = await suiClient.waitForTransaction({
			digest: res1.digest,
			options: {
				showEffects: true,
				showBalanceChanges: true,
				showEvents: true,
			},
		});

		return res2;
	};

	const createMultisig = async (
		params: {
			members: string[];
			approvalThreshold: number;
			rejectionThreshold: number;
			expirationDuration: number;
		},
		onStateUpdate?: (
			stateId: string,
			status: 'pending' | 'in_progress' | 'completed' | 'error',
			error?: string,
		) => void,
	) => {
		if (!ikaClient) {
			throw new Error('IKA client not initialized');
		}

		try {
			onStateUpdate?.('encryption_key', 'in_progress');
			const userShareEncryptionKeys = await getUserShareEncryptionKeys();

			const activeEncryptionKey = await ikaClient
				.getActiveEncryptionKey(userShareEncryptionKeys.getSuiAddress())
				.catch((_) => {
					return null;
				});

			if (!activeEncryptionKey) {
				console.log('No active encryption key found, registering one');

				const registertx = new Transaction();
				const ikaregistertx = new IkaTransaction({
					ikaClient,
					transaction: registertx as any,
					userShareEncryptionKeys,
				});
				await ikaregistertx.registerEncryptionKey({
					curve: Curve.SECP256K1,
				});

				await executeTransaction(registertx);
			}

			onStateUpdate?.('encryption_key', 'completed');

			onStateUpdate?.('create_multisig', 'in_progress');
			const tx = new Transaction();

			const emptyIkaCoin = tx.moveCall({
				target: `0x2::coin::zero`,
				arguments: [],
				typeArguments: [`${ikaClient.ikaConfig.packages.ikaPackage}::ika::IKA`],
			});

			tx.moveCall({
				target: `${MULTISIG_PACKAGE}::multisig::new_multisig`,
				arguments: [
					tx.object(ikaClient.ikaConfig.objects.ikaDWalletCoordinator.objectID),
					emptyIkaCoin,
					tx.splitCoins(tx.gas, [1_000_000_000]),
					tx.pure.id((await ikaClient.getLatestNetworkEncryptionKey()).id),
					tx.pure.vector('address', params.members),
					tx.pure.u64(params.members.length),
					tx.pure.u64(params.approvalThreshold),
					tx.pure.u64(params.expirationDuration),
				],
			});

			const createMultisigResult = await executeTransaction(tx);
			onStateUpdate?.('create_multisig', 'completed');

			const startDKGFirstRoundEvents = createMultisigResult.events
				?.map((event) =>
					event.type.includes('DWalletDKGFirstRoundRequestEvent') &&
					event.type.includes('DWalletSessionEvent')
						? SessionsManagerModule.DWalletSessionEvent(
								CoordinatorInnerModule.DWalletDKGFirstRoundRequestEvent,
							).fromBase64(event.bcs)
						: null,
				)
				.filter(Boolean);

			if (!startDKGFirstRoundEvents?.[0]) {
				throw new Error('Failed to get DKG first round request event');
			}

			const multisigCreatedEvent = createMultisigResult.events?.find((event) =>
				event.type.includes('MultisigCreated')
					? EventWrapperModule.Event(MultisigEventsModule.MultisigCreated).fromBase64(event.bcs)
					: null,
			);

			const dwalletID = startDKGFirstRoundEvents?.[0]?.event_data.dwallet_id;

			const multisigID = (
				(multisigCreatedEvent?.parsedJson as any)
					.pos0 as typeof MultisigEventsModule.MultisigCreated.$inferType
			).multisig_id;

			onStateUpdate?.('dkg_second_round', 'in_progress');
			const dWallet = await ikaClient.getDWalletInParticularState(
				dwalletID,
				'AwaitingUserDKGVerificationInitiation',
			);

			const dkgSecondRoundInput = await prepareDKGSecondRoundAsync(
				ikaClient,
				dWallet,
				userShareEncryptionKeys,
			);

			const secondRoundTx = new Transaction();

			secondRoundTx.moveCall({
				target: `${MULTISIG_PACKAGE}::multisig::multisig_dkg_second_round`,
				arguments: [
					secondRoundTx.object(multisigID),
					secondRoundTx.object(ikaClient.ikaConfig.objects.ikaDWalletCoordinator.objectID),
					secondRoundTx.pure.vector('u8', dkgSecondRoundInput.userDKGMessage),
					secondRoundTx.pure.vector('u8', dkgSecondRoundInput.encryptedUserShareAndProof),
					secondRoundTx.pure.vector('u8', dkgSecondRoundInput.userPublicOutput),
				],
			});

			const secondRoundResult = await executeTransaction(secondRoundTx);
			onStateUpdate?.('dkg_second_round', 'completed');

			const dkgSecondRoundRequestEvent = secondRoundResult.events?.find((event) => {
				return (
					event.type.includes('DWalletDKGSecondRoundRequestEvent') &&
					event.type.includes('DWalletSessionEvent')
				);
			});

			const dkgSecondRoundEvent = SessionsManagerModule.DWalletSessionEvent(
				CoordinatorInnerModule.DWalletDKGSecondRoundRequestEvent,
			).fromBase64(dkgSecondRoundRequestEvent?.bcs as string);

			onStateUpdate?.('accept_and_share', 'in_progress');
			const awaitingKeyHolderSignatureDWallet = await ikaClient.getDWalletInParticularState(
				dwalletID!,
				'AwaitingKeyHolderSignature',
			);

			const acceptAndShareTx = new Transaction();

			acceptAndShareTx.moveCall({
				target: `${MULTISIG_PACKAGE}::multisig::multisig_accept_and_share`,
				arguments: [
					acceptAndShareTx.object(multisigID),
					acceptAndShareTx.object(ikaClient.ikaConfig.objects.ikaDWalletCoordinator.objectID),
					acceptAndShareTx.pure.id(
						dkgSecondRoundEvent.event_data.encrypted_user_secret_key_share_id,
					),
					acceptAndShareTx.pure.vector(
						'u8',
						await userShareEncryptionKeys.getUserOutputSignature(
							awaitingKeyHolderSignatureDWallet,
							dkgSecondRoundInput.userPublicOutput,
						),
					),
					acceptAndShareTx.pure.vector('u8', dkgSecondRoundInput.userSecretKeyShare),
				],
			});

			await executeTransaction(acceptAndShareTx);
			onStateUpdate?.('accept_and_share', 'completed');

			onStateUpdate?.('generate_address', 'in_progress');
			const publickey = await publicKeyFromDWalletOutput(
				Uint8Array.from(
					awaitingKeyHolderSignatureDWallet.state.AwaitingKeyHolderSignature
						?.public_output as number[],
				),
			);

			const bitcoinAddress = await BitcoinUtils.getAddressFromPublicKey(publickey);
			onStateUpdate?.('generate_address', 'completed');

			console.log('=== MULTISIG CREATION RESULT ===');
			console.log('Multisig ID:', multisigID);
			console.log('DWallet ID:', dwalletID);
			console.log('Bitcoin Address:', bitcoinAddress);
			console.log('Address validation in multisig:', BitcoinUtils.validateAddress(bitcoinAddress));
			console.log('=================================');

			return {
				multisigID,
				dwalletID,
				bitcoinAddress,
			};
		} catch (error) {
			// Update all states to error if something goes wrong
			onStateUpdate?.(
				'encryption_key',
				'error',
				error instanceof Error ? error.message : 'Unknown error',
			);
			onStateUpdate?.(
				'create_multisig',
				'error',
				error instanceof Error ? error.message : 'Unknown error',
			);
			onStateUpdate?.(
				'dkg_second_round',
				'error',
				error instanceof Error ? error.message : 'Unknown error',
			);
			onStateUpdate?.(
				'accept_and_share',
				'error',
				error instanceof Error ? error.message : 'Unknown error',
			);
			onStateUpdate?.(
				'generate_address',
				'error',
				error instanceof Error ? error.message : 'Unknown error',
			);
			throw error;
		}
	};

	const fetchMultisig = async (multisigID: string) => {
		if (!ikaClient) {
			throw new Error('IKA client not initialized');
		}

		try {
			const multisig = await suiClient
				.getObject({
					id: multisigID,
					options: {
						showBcs: true,
					},
				})
				.then((obj) => MultisigModule.Multisig.fromBase64(objResToBcs(obj)));

			// Get dWallet information if available
			let bitcoinAddress = null;
			let dwalletState = null;

			if (multisig.ready && multisig.dwallet_cap) {
				try {
					const dWallet = await ikaClient.getDWalletInParticularState(
						multisig.dwallet_cap.dwallet_id,
						'Active',
					);
					dwalletState = dWallet.state;

					if (dWallet.state.Active?.public_output) {
						const publicKey = await publicKeyFromDWalletOutput(
							Uint8Array.from(dWallet.state.Active.public_output as number[]),
						);
						bitcoinAddress = await BitcoinUtils.getAddressFromPublicKey(publicKey);
					}
				} catch (error) {
					console.warn('Could not fetch dWallet information:', error);
				}
			}

			// Get pending requests count
			let pendingRequests = 0;
			try {
				// For now, we'll just return the request counter
				// In a production app, you'd want to iterate through the table properly
				pendingRequests = parseInt(multisig.request_id_counter.toString());
			} catch (error) {
				console.warn('Could not count pending requests:', error);
			}

			return {
				id: multisigID,
				members: multisig.members,
				approvalThreshold: multisig.approval_threshold,
				rejectionThreshold: multisig.rejection_threshold,
				ready: multisig.ready,
				expirationDuration: multisig.expiration_duration,
				requestCount: multisig.request_id_counter,
				pendingRequests,
				ikaBalance: multisig.ika_balance,
				suiBalance: multisig.sui_balance,
				bitcoinAddress,
				dwalletState,
				dwalletId: multisig.dwallet_cap?.dwallet_id || null,
			};
		} catch (error) {
			throw new Error(`Failed to fetch multisig ${multisigID}: ${error}`);
		}
	};

	const createTransaction = async (
		multisigID: string,
		btcAmount: number,
		toAddress: string,
		changeAddress: string,
		walletAddress: string,
	) => {
		if (!ikaClient) {
			throw new Error('IKA client not initialized');
		}

		if (!validateAddress(toAddress)) {
			throw new Error('Invalid recipient Bitcoin address');
		}

		if (!validateAddress(changeAddress)) {
			throw new Error('Invalid change Bitcoin address');
		}

		if (!validateAddress(walletAddress)) {
			throw new Error('Invalid wallet Bitcoin address');
		}

		const multisig = await suiClient
			.getObject({
				id: multisigID,
				options: {
					showBcs: true,
				},
			})
			.then((obj) => MultisigModule.Multisig.fromBase64(objResToBcs(obj)));

		const dWallet = await ikaClient.getDWalletInParticularState(
			multisig.dwallet_cap.dwallet_id,
			'Active',
		);
		const presignId = multisig.presigns[0].presign_id;

		const presign = await ikaClient.getPresignInParticularState(presignId, 'Completed');

		if (!presign.state.Completed?.presign) {
			throw new Error('Presign not completed');
		}

		// Fetch real UTXOs and fee estimates
		console.log('Fetching UTXOs for address:', walletAddress);
		const utxos = await fetchUTXOs(walletAddress);

		if (utxos.length === 0) {
			throw new Error(
				'No UTXOs found for the wallet address. Please ensure you have funds in this address.',
			);
		}

		console.log(
			`Found ${utxos.length} UTXOs with total value: ${utxos.reduce((sum, utxo) => sum + utxo.value, 0)} satoshis`,
		);

		// Get current fee estimates
		const feeRates = await getNetworkFeeRates();
		const satoshisAmount = btcToSatoshis(btcAmount);

		// Use more conservative fee rate (between halfHour and hour rates, minimum 2 sats/vB)
		const conservativeFeeRate = Math.min(feeRates.halfHour, Math.max(feeRates.hour, 2));

		// Calculate fee based on transaction size
		const estimatedFee = BitcoinUtils.calculateFee(utxos.length, 2, conservativeFeeRate); // 2 outputs: recipient + change

		// Debug: Log transaction parameters
		console.log('Transaction parameters:', {
			btcAmount,
			satoshisAmount,
			estimatedFee,
			originalFeeRate: feeRates.halfHour,
			conservativeFeeRate,
			allFeeRates: feeRates,
			utxoTotal: utxos.reduce((sum, utxo) => sum + utxo.value, 0),
			utxoCount: utxos.length,
			utxoValues: utxos.map((u) => u.value),
			requiredTotal: satoshisAmount + estimatedFee,
		});

		// Create Bitcoin PSBT with real data
		const psbtHex = BitcoinUtils.createTransaction(
			utxos,
			toAddress,
			satoshisAmount,
			estimatedFee,
			changeAddress,
		);

		console.log('Created Bitcoin transaction:', {
			amount: btcAmount,
			satoshis: satoshisAmount,
			toAddress,
			changeAddress,
			walletAddress,
			utxoCount: utxos.length,
			estimatedFee,
			feeRate: feeRates.halfHour,
			psbtHex,
		});

		const tx = new Transaction();

		tx.moveCall({
			target: `${MULTISIG_PACKAGE}::multisig::transaction_request`,
			arguments: [
				tx.object(multisigID),
				tx.object(ikaClient.ikaConfig.objects.ikaDWalletCoordinator.objectID),
				tx.pure.vector('u8', psbtHex),
				tx.pure.vector(
					'u8',
					await createUserSignMessageWithPublicOutput(
						await ikaClient.getProtocolPublicParameters(dWallet),
						Uint8Array.from(dWallet.state.Active?.public_output as number[]),
						Uint8Array.from(dWallet.public_user_secret_key_share as number[]),
						Uint8Array.from(presign.state.Completed?.presign as number[]),
						psbtHex,
						Hash.SHA256,
					),
				),
				tx.object.clock(),
			],
		});

		const result = await executeTransaction(tx);

		const transactionRequestEvent = result.events?.find((event) => {
			return event.type.includes('RequestCreated');
		});

		const requestId = MultisigEventsModule.RequestCreated.fromBase64(
			transactionRequestEvent?.bcs as string,
		).request_id;

		return {
			requestId,
			psbtHex,
			amount: btcAmount,
			recipient: toAddress,
		};
	};

	const fetchPendingRequests = async (multisigID: string) => {
		if (!ikaClient) {
			throw new Error('IKA client not initialized');
		}

		try {
			const multisig = await suiClient
				.getObject({
					id: multisigID,
					options: {
						showBcs: true,
					},
				})
				.then((obj) => MultisigModule.Multisig.fromBase64(objResToBcs(obj)));

			const pendingRequests = [];

			// Iterate through all requests to find pending ones
			const requestList = multisig.requests.id.id;

			let requestDynamicFields = await suiClient.getDynamicFields({
				parentId: requestList,
			});

			const requests = await suiClient.multiGetObjects({
				ids: requestDynamicFields.data.map((df) => df.objectId),
				options: {
					showBcs: true,
				},
			});

			for (const request of requests) {
				pendingRequests.push(DynamicField(RequestModule.Request).fromBase64(objResToBcs(request)));
			}

			const multisigRequests = pendingRequests.map((df) => ({
				...df.value,
				request_id: df.name,
			}));

			for (const request of multisigRequests) {
				let votes: { [key: string]: boolean } = {};
				const votesDF = await suiClient.getDynamicFields({
					parentId: request.votes.id.id,
				});

				const votesObjects = await suiClient.multiGetObjects({
					ids: votesDF.data.map((df) => df.objectId),
					options: {
						showContent: true,
					},
				});

				for (const vote of votesObjects) {
					console.log(vote);
					// @ts-ignore
					votes[vote.data?.content.fields.name] = vote.data?.content.fields.value;
				}

				// @ts-ignore
				request.parsed_votes = votes;
			}

			return multisigRequests;
		} catch (error) {
			throw new Error(`Failed to fetch pending requests for ${multisigID}: ${error}`);
		}
	};

	const voteOnRequest = async (multisigID: string, requestId: number, approve: boolean) => {
		if (!ikaClient) {
			throw new Error('IKA client not initialized');
		}

		const tx = new Transaction();

		tx.moveCall({
			target: `${MULTISIG_PACKAGE}::multisig::vote_request`,
			arguments: [
				tx.object(multisigID),
				tx.pure.u64(requestId),
				tx.pure.bool(approve),
				tx.object.clock(),
			],
		});

		const result = await executeTransaction(tx);
		return result;
	};

	const fetchSingleRequest = async (multisigID: string, requestId: number) => {
		if (!ikaClient) {
			throw new Error('IKA client not initialized');
		}

		try {
			const multisig = await suiClient
				.getObject({
					id: multisigID,
					options: {
						showBcs: true,
					},
				})
				.then((obj) => MultisigModule.Multisig.fromBase64(objResToBcs(obj)));

			const requestList = multisig.requests.id.id;
			let requestDynamicFields = await suiClient.getDynamicFields({
				parentId: requestList,
			});

			const targetRequest = requestDynamicFields.data.find(
				(df) => df.name.value === requestId.toString(),
			);
			if (!targetRequest) {
				throw new Error(`Request ${requestId} not found`);
			}

			const request = await suiClient.getObject({
				id: targetRequest.objectId,
				options: {
					showBcs: true,
				},
			});

			return DynamicField(RequestModule.Request).fromBase64(objResToBcs(request)).value;
		} catch (error) {
			throw new Error(`Failed to fetch request ${requestId}: ${error}`);
		}
	};

	const executeRequest = async (multisigID: string, requestId: number) => {
		if (!ikaClient) {
			throw new Error('IKA client not initialized');
		}

		const tx = new Transaction();

		tx.moveCall({
			target: `${MULTISIG_PACKAGE}::multisig::execute_request`,
			arguments: [
				tx.object(multisigID),
				tx.object(ikaClient.ikaConfig.objects.ikaDWalletCoordinator.objectID),
				tx.pure.u64(requestId),
				tx.object.clock(),
			],
		});

		const result = await executeTransaction(tx);

		const signEvent = result.events?.find((event) => {
			return event.type.includes('SignRequestEvent');
		});

		const parsedSignEvent = SessionsManagerModule.DWalletSessionEvent(SignRequestEvent).fromBase64(
			signEvent?.bcs as string,
		);

		const sign = await ikaClient.getSignInParticularState(
			parsedSignEvent.event_data.sign_id,
			'Completed',
		);

		// Extract the signature and broadcast to Bitcoin network
		if (sign.state.Completed?.signature) {
			try {
				const signature = Uint8Array.from(sign.state.Completed.signature as number[]);

				// Get the original request to extract the PSBT
				const request = await fetchSingleRequest(multisigID, requestId);
				if (request && request.request_type.Transaction) {
					// Convert the transaction data (which is stored as a vector<u8> in Move)
					const psbtHex = request.request_type.Transaction as unknown as Buffer;

					// Create the signed transaction by applying the signature to the PSBT
					const signedTxHex = await BitcoinUtils.applySignatureToPSBT(psbtHex, signature);

					// Broadcast the transaction to the Bitcoin network
					const txid = await BitcoinUtils.broadcastTransaction(signedTxHex);

					console.log('=== BITCOIN TRANSACTION BROADCAST ===');
					console.log('Transaction ID:', txid);
					console.log('Explorer URL:', `https://mempool.space/testnet/tx/${txid}`);
					console.log('=====================================');

					return {
						...result,
						bitcoinTxid: txid,
						explorerUrl: `https://mempool.space/testnet/tx/${txid}`,
					};
				}
			} catch (error) {
				console.error('Failed to broadcast Bitcoin transaction:', error);
				// Don't throw here - the signing was successful, broadcasting is additional
			}
		}

		return result;
	};

	return {
		createMultisig,
		fetchMultisig,
		createTransaction,
		fetchPendingRequests,
		voteOnRequest,
		executeRequest,
	};
};

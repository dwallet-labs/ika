import {
	CoordinatorInnerModule,
	createRandomSessionIdentifier,
	Curve,
	objResToBcs,
	SessionsManagerModule,
	SignatureAlgorithm,
} from '@ika.xyz/sdk';
import { useCurrentAccount, useSuiClient } from '@mysten/dapp-kit';
import { bcs } from '@mysten/sui/bcs';
import { coinWithBalance, Transaction } from '@mysten/sui/transactions';
import * as bitcoin from 'bitcoinjs-lib';
import invariant from 'tiny-invariant';

import {
	addIkaBalance,
	addMemberRequest,
	addPresign,
	addSuiBalance,
	changeApprovalThresholdRequest,
	changeExpirationDurationRequest,
	changeRejectionThresholdRequest,
	executeRequest,
	newMultisig,
	removeMemberRequest,
	voteRequest,
} from '../generated/ika_btc_multisig/multisig';
import * as MultisigModule from '../generated/ika_btc_multisig/multisig';
import { Request } from '../generated/ika_btc_multisig/multisig_request';
import { MultisigBitcoinWallet, UTXO } from '../multisig/bitcoin';
import { prepareDKGWithWorker } from '../workers/api';
import { useExecuteTransaction } from './useExecuteTransaction';
import { useIkaClient } from './useIkaClient';
import { useIds } from './useObjects';
import { useUserShareEncryptionKeys } from './useUserShareEncryptionKeys';

export const useMultisigFunctions = () => {
	const account = useCurrentAccount();
	const suiClient = useSuiClient();
	const { coordinator, multisigPackageId, ikaPackageId } = useIds();
	const { ikaClient } = useIkaClient();
	const { data: userShareEncryptionKeys, isLoading: isLoadingKeys } = useUserShareEncryptionKeys();
	const { executeTransaction } = useExecuteTransaction();

	const createMultisig = async ({
		members,
		approvalThreshold,
		rejectionThreshold,
		expirationDuration,
	}: {
		members: string[];
		approvalThreshold: number;
		rejectionThreshold: number;
		expirationDuration: number;
	}) => {
		invariant(account, 'Account not found');
		invariant(
			userShareEncryptionKeys,
			'User share encryption keys are not ready yet. Please wait...',
		);

		const transaction = new Transaction();

		const initialIkaCoinForBalance = transaction.add(
			coinWithBalance({
				type: `${ikaPackageId}::ika::IKA`,
				balance: 10_000_000_000,
			}),
		);

		const initialSuiCoinForBalance = transaction.splitCoins(transaction.gas, [1_000_000_000]);

		const randomSessionIdentifier = createRandomSessionIdentifier();

		// Use worker for DKG computatio
		const result = await prepareDKGWithWorker({
			protocolPublicParameters: Array.from(await ikaClient.getProtocolPublicParameters()),
			curve: Curve.SECP256K1,
			userShareEncryptionKeysBytes: Array.from(
				userShareEncryptionKeys.toShareEncryptionKeysBytes(),
			),
			sessionIdentifier: Array.from(randomSessionIdentifier),
			userAddress: account.address,
		});

		// Deserialize results
		const userPublicOutput = new Uint8Array(result?.userPublicOutput ?? []);
		const publicUserSecretKeyShare = new Uint8Array(result?.userSecretKeyShare ?? []);
		const centralizedPublicKeyShareAndProof = new Uint8Array(result?.userDKGMessage ?? []);

		const byteVector = bcs.vector(bcs.u8());

		transaction.add(
			newMultisig({
				package: multisigPackageId,
				arguments: {
					coordinator: coordinator,
					initialIkaCoinForBalance: initialIkaCoinForBalance,
					initialSuiCoinForBalance: initialSuiCoinForBalance,
					dwalletNetworkEncryptionKeyId: (await ikaClient.getLatestNetworkEncryptionKey()).id,
					centralizedPublicKeyShareAndProof: byteVector
						.serialize(centralizedPublicKeyShareAndProof)
						.parse(),
					userPublicOutput: byteVector.serialize(userPublicOutput).parse(),
					publicUserSecretKeyShare: byteVector.serialize(publicUserSecretKeyShare).parse(),
					members,
					approvalThreshold,
					rejectionThreshold,
					expirationDuration,
					sessionIdentifier: byteVector.serialize(randomSessionIdentifier).parse(),
				},
			}),
		);

		await executeTransaction(transaction);
	};

	const addIkaBalanceToMultisig = async ({
		multisig,
		amount,
	}: {
		multisig: MultisigBitcoinWallet;
		amount: bigint;
	}) => {
		invariant(account, 'Account not found');

		const transaction = new Transaction();

		transaction.add(
			addIkaBalance({
				package: multisigPackageId,
				arguments: {
					self: multisig.object.multisig,
					ikaCoin: transaction.add(
						coinWithBalance({
							type: `${ikaPackageId}::ika::IKA`,
							balance: amount,
						}),
					),
				},
			}),
		);

		await executeTransaction(transaction);
	};

	const addSuiBalanceToMultisig = async ({
		multisig,
		amount,
	}: {
		multisig: MultisigBitcoinWallet;
		amount: bigint;
	}) => {
		invariant(account, 'Account not found');

		const transaction = new Transaction();

		const suiCoin = transaction.splitCoins(transaction.gas, [amount]);

		transaction.add(
			addSuiBalance({
				package: multisigPackageId,
				arguments: {
					self: multisig.object.multisig,
					suiCoin: suiCoin,
				},
			}),
		);

		await executeTransaction(transaction);
	};

	const addPresignToMultisig = async ({ multisig }: { multisig: MultisigBitcoinWallet }) => {
		invariant(account, 'Account not found');

		const transaction = new Transaction();

		transaction.add(
			addPresign({
				package: multisigPackageId,
				arguments: {
					self: multisig.object.multisig,
					coordinator: coordinator,
				},
			}),
		);

		await executeTransaction(transaction);
	};

	const voteOnRequest = async ({
		multisig,
		requestId,
		vote,
	}: {
		multisig: MultisigBitcoinWallet;
		requestId: number | bigint;
		vote: boolean;
	}) => {
		invariant(account, 'Account not found');

		const transaction = new Transaction();

		transaction.add(
			voteRequest({
				package: multisigPackageId,
				arguments: {
					self: multisig.object.multisig,
					requestId: requestId,
					vote: vote,
				},
			}),
		);

		await executeTransaction(transaction);
	};

	const executeMultisigRequest = async ({
		multisig,
		requestId,
	}: {
		multisig: MultisigBitcoinWallet;
		requestId: number;
	}) => {
		invariant(account, 'Account not found');

		const transaction = new Transaction();

		transaction.add(
			executeRequest({
				package: multisigPackageId,
				arguments: {
					self: multisig.object.multisig,
					coordinator: coordinator,
					requestId: requestId,
				},
			}),
		);

		const transactionResult = await executeTransaction(transaction);

		const signEvent = transactionResult.events?.find((event) =>
			event.type.includes('SignRequestEvent'),
		);

		const signEventData = SessionsManagerModule.DWalletSessionEvent(
			CoordinatorInnerModule.SignRequestEvent,
		).fromBase64(signEvent?.bcs as string);

		const sign = await ikaClient.getSignInParticularState(
			signEventData.event_data.sign_id,
			Curve.SECP256K1,
			SignatureAlgorithm.Taproot,
			'Completed',
			{ timeout: 60000, interval: 1000 },
		);

		// Get the multisig object to access the requests table
		const multisigObject = await suiClient
			.getObject({
				id: multisig.object.multisig,
				options: {
					showBcs: true,
				},
			})
			.then((obj) => MultisigModule.Multisig.fromBase64(objResToBcs(obj)));

		// Get the table ID from the requests table
		const tableId = multisigObject.requests.id.id;

		// Get the request from the requests table using getDynamicFieldObject
		const requestFieldResponse = await suiClient.getDynamicFieldObject({
			parentId: tableId,
			name: {
				type: 'u64',
				value: String(requestId),
			},
		});

		// Get the actual Request object from the dynamic field
		// The dynamic field contains a Field object, we need to get the value object
		invariant(requestFieldResponse.data, 'Request not found');

		const requestObject = await suiClient.getObject({
			id: requestFieldResponse.data.objectId,
			options: {
				showBcs: true,
			},
		});

		// Parse the Field<u64, Request> wrapper first
		const fieldBcs = objResToBcs(requestObject);
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

		// Extract PSBT from request_type if it's a Transaction type
		let psbt: Uint8Array | null = null;

		if (request.request_type && 'Transaction' in request.request_type) {
			const transactionData = request.request_type.Transaction;
			// Transaction is a tuple of [sighash, message_centralized_signature, psbt]
			// Each element is a vector<u8> which should be a Uint8Array when parsed
			if (transactionData && Array.isArray(transactionData) && transactionData.length >= 3) {
				// The PSBT is the third element, convert to Uint8Array if needed
				const psbtData = transactionData[2];
				psbt = psbtData instanceof Uint8Array ? psbtData : new Uint8Array(psbtData);
			}
		}

		invariant(psbt, 'PSBT not found');

		const finalizedTransaction = multisig.finalizeTransaction(
			bitcoin.Psbt.fromBuffer(psbt),
			Buffer.from(sign.state.Completed.signature),
			0,
		);

		const txid = await multisig.broadcastTransaction(finalizedTransaction);

		return {
			transactionResult,
			sign,
			request,
			psbt,
			txid,
		};
	};

	const createTransactionRequest = async ({
		multisig,
		toAddress,
		amount,
		feeRate,
		utxo,
	}: {
		multisig: MultisigBitcoinWallet;
		toAddress: string;
		amount: bigint;
		feeRate: number;
		utxo: UTXO;
	}) => {
		invariant(account, 'Account not found');

		const { transaction } = await multisig.sendTransactionSui(toAddress, amount, feeRate, utxo);

		await executeTransaction(transaction);
	};

	const createAddMemberRequest = async ({
		multisig,
		memberAddress,
	}: {
		multisig: MultisigBitcoinWallet;
		memberAddress: string;
	}) => {
		invariant(account, 'Account not found');

		const transaction = new Transaction();

		transaction.add(
			addMemberRequest({
				package: multisigPackageId,
				arguments: {
					self: multisig.object.multisig,
					memberAddress: memberAddress,
				},
			}),
		);

		await executeTransaction(transaction);
	};

	const createRemoveMemberRequest = async ({
		multisig,
		memberAddress,
	}: {
		multisig: MultisigBitcoinWallet;
		memberAddress: string;
	}) => {
		invariant(account, 'Account not found');

		const transaction = new Transaction();

		transaction.add(
			removeMemberRequest({
				package: multisigPackageId,
				arguments: {
					self: multisig.object.multisig,
					memberAddress: memberAddress,
				},
			}),
		);

		await executeTransaction(transaction);
	};

	const createChangeApprovalThresholdRequest = async ({
		multisig,
		newThreshold,
	}: {
		multisig: MultisigBitcoinWallet;
		newThreshold: number | bigint;
	}) => {
		invariant(account, 'Account not found');

		const transaction = new Transaction();

		transaction.add(
			changeApprovalThresholdRequest({
				package: multisigPackageId,
				arguments: {
					self: multisig.object.multisig,
					newThreshold: newThreshold,
				},
			}),
		);

		await executeTransaction(transaction);
	};

	const createChangeRejectionThresholdRequest = async ({
		multisig,
		newThreshold,
	}: {
		multisig: MultisigBitcoinWallet;
		newThreshold: number | bigint;
	}) => {
		invariant(account, 'Account not found');

		const transaction = new Transaction();

		transaction.add(
			changeRejectionThresholdRequest({
				package: multisigPackageId,
				arguments: {
					self: multisig.object.multisig,
					newThreshold: newThreshold,
				},
			}),
		);

		await executeTransaction(transaction);
	};

	const createChangeExpirationDurationRequest = async ({
		multisig,
		newDuration,
	}: {
		multisig: MultisigBitcoinWallet;
		newDuration: number | bigint;
	}) => {
		invariant(account, 'Account not found');

		const transaction = new Transaction();

		transaction.add(
			changeExpirationDurationRequest({
				package: multisigPackageId,
				arguments: {
					self: multisig.object.multisig,
					newDuration: newDuration,
				},
			}),
		);

		await executeTransaction(transaction);
	};

	const broadcastApprovedTransaction = async ({
		multisig,
		requestId,
	}: {
		multisig: MultisigBitcoinWallet;
		requestId: number;
	}) => {
		invariant(account, 'Account not found');

		// Get the multisig object to access the requests table
		const multisigObject = await suiClient
			.getObject({
				id: multisig.object.multisig,
				options: {
					showBcs: true,
				},
			})
			.then((obj) => MultisigModule.Multisig.fromBase64(objResToBcs(obj)));

		// Get the table ID from the requests table
		const tableId = multisigObject.requests.id.id;

		// Get the request from the requests table using getDynamicFieldObject
		const requestFieldResponse = await suiClient.getDynamicFieldObject({
			parentId: tableId,
			name: {
				type: 'u64',
				value: String(requestId),
			},
		});

		// Get the actual Request object from the dynamic field
		invariant(requestFieldResponse.data, 'Request not found');

		const requestObject = await suiClient.getObject({
			id: requestFieldResponse.data.objectId,
			options: {
				showBcs: true,
			},
		});

		// Parse the Field<u64, Request> wrapper first
		const fieldBcs = objResToBcs(requestObject);
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

		// Check if request is approved and is a Transaction type
		const statusObj = request.status as any;
		const isApproved =
			statusObj &&
			typeof statusObj === 'object' &&
			(statusObj.$kind === 'Approved' || ('Approved' in statusObj && statusObj.Approved));

		invariant(isApproved, 'Request is not approved');

		// Extract sign_id from Approved status
		// Status structure: Approved(RequestResult::Transaction(sign_id))
		// When deserialized, it might be:
		// - { Approved: { Transaction: sign_id } }
		// - { $kind: 'Approved', Approved: { $kind: 'Transaction', Transaction: sign_id } }
		// - { Approved: { $kind: 'Transaction', Transaction: sign_id } }
		let signId: string | null = null;

		if (statusObj.Approved) {
			const approvedResult = statusObj.Approved;
			if (approvedResult && typeof approvedResult === 'object') {
				// Try different possible structures
				if (approvedResult.Transaction) {
					signId = String(approvedResult.Transaction);
				} else if (approvedResult.$kind === 'Transaction' && approvedResult.value) {
					signId = String(approvedResult.value);
				} else if (approvedResult.$kind === 'Transaction') {
					// The value might be directly in the object
					const keys = Object.keys(approvedResult);
					const transactionKey = keys.find((k) => k !== '$kind');
					if (transactionKey && approvedResult[transactionKey as keyof typeof approvedResult]) {
						signId = String(approvedResult[transactionKey as keyof typeof approvedResult]);
					}
				}
			}
		} else if (statusObj.$kind === 'Approved' && statusObj.Approved) {
			const approvedResult = statusObj.Approved;
			if (approvedResult && typeof approvedResult === 'object') {
				if (approvedResult.Transaction) {
					signId = String(approvedResult.Transaction);
				} else if (approvedResult.$kind === 'Transaction') {
					const keys = Object.keys(approvedResult);
					const transactionKey = keys.find((k) => k !== '$kind');
					if (transactionKey && approvedResult[transactionKey as keyof typeof approvedResult]) {
						signId = String(approvedResult[transactionKey as keyof typeof approvedResult]);
					}
				}
			}
		}

		invariant(signId, 'Sign ID not found in approved request');

		// Get the sign from IKA client
		const sign = await ikaClient.getSignInParticularState(
			signId,
			Curve.SECP256K1,
			SignatureAlgorithm.Taproot,
			'Completed',
			{ timeout: 60000, interval: 1000 },
		);

		// Extract PSBT from request_type if it's a Transaction type
		let psbt: Uint8Array | null = null;

		if (request.request_type && 'Transaction' in request.request_type) {
			const transactionData = request.request_type.Transaction;
			// Transaction is a tuple of [sighash, message_centralized_signature, psbt]
			if (transactionData && Array.isArray(transactionData) && transactionData.length >= 3) {
				// The PSBT is the third element, convert to Uint8Array if needed
				const psbtData = transactionData[2];
				psbt = psbtData instanceof Uint8Array ? psbtData : new Uint8Array(psbtData);
			}
		}

		invariant(psbt, 'PSBT not found');

		const finalizedTransaction = multisig.finalizeTransaction(
			bitcoin.Psbt.fromBuffer(psbt),
			Buffer.from(sign.state.Completed.signature),
			0,
		);

		const txid = await multisig.broadcastTransaction(finalizedTransaction);

		return {
			sign,
			request,
			psbt,
			txid,
		};
	};

	return {
		createMultisig,
		addIkaBalanceToMultisig,
		addSuiBalanceToMultisig,
		addPresignToMultisig,
		voteOnRequest,
		executeMultisigRequest,
		broadcastApprovedTransaction,
		createTransactionRequest,
		createAddMemberRequest,
		createRemoveMemberRequest,
		createChangeApprovalThresholdRequest,
		createChangeRejectionThresholdRequest,
		createChangeExpirationDurationRequest,
		isKeysReady: !isLoadingKeys && !!userShareEncryptionKeys,
		isLoadingKeys,
	};
};

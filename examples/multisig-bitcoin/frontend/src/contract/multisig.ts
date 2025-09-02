import {
	CoordinatorInnerModule,
	Curve,
	IkaTransaction,
	prepareDKGSecondRoundAsync,
	SessionsManagerModule,
	UserShareEncryptionKeys,
} from '@ika.xyz/sdk';
import { useSignTransaction, useSuiClient } from '@mysten/dapp-kit';
import { Transaction } from '@mysten/sui/transactions';
import { useCallback } from 'react';

import { useIkaClient } from '@/hooks/ika-client';

import * as EventWrapperModule from '../generated/ika_btc_multisig/event_wrapper';
import * as MultisigEventsModule from '../generated/ika_btc_multisig/multisig_events';

export const useMultisig = () => {
	const { ikaClient } = useIkaClient();
	const suiClient = useSuiClient();
	const { mutateAsync: signTransaction } = useSignTransaction();
	const getUserShareEncryptionKeys = useCallback(async () => {
		return await UserShareEncryptionKeys.fromRootSeedKey(
			new TextEncoder().encode('bitcoin_multisig_ika'),
			Curve.SECP256K1,
		);
	}, []);
	const MULTISIG_PACKAGE = '0xbec6799dea6c1ccde6b58d277e5124dea3367b5b18214c2996dbac87d15cb198';

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

	const createMultisig = async () => {
		if (!ikaClient) {
			throw new Error('IKA client not initialized');
		}

		const userShareEncryptionKeys = await getUserShareEncryptionKeys();

		console.log(
			Buffer.from(userShareEncryptionKeys.getPublicKey().toRawBytes()).toString('hex'),
			userShareEncryptionKeys.getSuiAddress(),
		);

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
				tx.pure.vector('address', [
					'0xa5b1611d756c1b2723df1b97782cacfd10c8f94df571935db87b7f54ef653d66',
					'0x0c96b48925580099ddb1e9398ed51f3e8504b7793ffd7cee7b7f5b2c8c0e9271',
					'0x2c1507b83627174a0b561cc3747511a29dcca2d6839897e9ebb3367e9c7699b5',
				]),
				tx.pure.u64(3),
				tx.pure.u64(2),
				tx.pure.u64(1000000000000000),
			],
		});

		const createMultisigResult = await executeTransaction(tx);

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

		const dkgSecondRoundRequestEvent = secondRoundResult.events?.find((event) => {
			return (
				event.type.includes('DWalletDKGSecondRoundRequestEvent') &&
				event.type.includes('DWalletSessionEvent')
			);
		});

		const dkgSecondRoundEvent = SessionsManagerModule.DWalletSessionEvent(
			CoordinatorInnerModule.DWalletDKGSecondRoundRequestEvent,
		).fromBase64(dkgSecondRoundRequestEvent?.bcs as string);

		const awaitingKeyHolderSignatureDWallet = await ikaClient.getDWalletInParticularState(
			dwalletID!,
			'AwaitingKeyHolderSignature',
		);

		const acceptAndShareTx = new Transaction();

		const encryptedUserSecretKeyShare = await ikaClient.getEncryptedUserSecretKeyShare(
			dkgSecondRoundEvent.event_data.encrypted_user_secret_key_share_id,
		);

		const { secretShare, verifiedPublicOutput } = await userShareEncryptionKeys.decryptUserShare(
			awaitingKeyHolderSignatureDWallet,
			encryptedUserSecretKeyShare,
			await ikaClient.getProtocolPublicParameters(awaitingKeyHolderSignatureDWallet),
		);

		acceptAndShareTx.moveCall({
			target: `${MULTISIG_PACKAGE}::multisig::multisig_accept_and_share`,
			arguments: [
				acceptAndShareTx.object(multisigID),
				acceptAndShareTx.object(ikaClient.ikaConfig.objects.ikaDWalletCoordinator.objectID),
				acceptAndShareTx.pure.id(dkgSecondRoundEvent.event_data.encrypted_user_secret_key_share_id),
				acceptAndShareTx.pure.vector(
					'u8',
					await userShareEncryptionKeys.getUserOutputSignature(
						awaitingKeyHolderSignatureDWallet,
						verifiedPublicOutput,
					),
				),
				acceptAndShareTx.pure.vector('u8', secretShare),
			],
		});

		await executeTransaction(acceptAndShareTx);

		return {
			multisigID,
			dwalletID,
		};
	};

	return {
		createMultisig,
	};
};

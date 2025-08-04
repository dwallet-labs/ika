import { Transaction, TransactionObjectArgument } from '@mysten/sui/transactions';

import * as coordinatorTx from '../tx/coordinator';
import { IkaClient } from './ika-client';

export type IkaTransactionParams = {
	ikaClient: IkaClient;
	transaction: Transaction;
};

export class IkaTransaction {
	private ikaClient: IkaClient;
	private transaction: Transaction;

	constructor({ ikaClient, transaction }: IkaTransactionParams) {
		this.ikaClient = ikaClient;
		this.transaction = transaction;
	}

	/**
	 * Request the DKG first round.
	 * @param params - The parameters for the DKG first round.
	 * @param params.curve - The curve to use for the DKG first round.
	 * @param params.ikaCoin - The IKA coin to use for payment of the DKG first round.
	 * @param params.suiCoin - The SUI coin to use for payment of the DKG first round.
	 * @returns DWalletCap
	 */
	async requestDWalletDKGFirstRound({
		curve,
		ikaCoin,
		suiCoin,
	}: {
		curve: number;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
	}): Promise<TransactionObjectArgument> {
		return coordinatorTx.requestDWalletDKGFirstRound(
			this.ikaClient.ikaConfig,
			await this.ikaClient.getDecryptionKeyID(),
			curve,
			this.createSessionIdentifier(),
			ikaCoin,
			suiCoin,
			this.transaction,
		);
	}

	/**
	 * Request the DKG first round and keep the DWalletCap.
	 * @param params - The parameters for the DKG first round.
	 * @param params.curve - The curve to use for the DKG first round.
	 * @param params.ikaCoin - The IKA coin to use for payment of the DKG first round.
	 * @param params.suiCoin - The SUI coin to use for payment of the DKG first round.
	 * @param params.receiver - The receiver of the DWalletCap.
	 */
	async requestDWalletDKGFirstRoundAndKeep({
		curve,
		ikaCoin,
		suiCoin,
		receiver,
	}: {
		curve: number;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
		receiver: string;
	}) {
		let cap = coordinatorTx.requestDWalletDKGFirstRound(
			this.ikaClient.ikaConfig,
			await this.ikaClient.getDecryptionKeyID(),
			curve,
			this.createSessionIdentifier(),
			ikaCoin,
			suiCoin,
			this.transaction,
		);

		this.transaction.transferObjects([cap], receiver);
	}

	private createSessionIdentifier() {
		const freshObjectAddress = this.transaction.moveCall({
			target: `0x2::tx_context::fresh_object_address`,
			arguments: [],
			typeArguments: [],
		});

		const freshObjectAddressBytes = this.transaction.moveCall({
			target: `0x2::address::to_bytes`,
			arguments: [freshObjectAddress],
			typeArguments: [],
		});

		return coordinatorTx.registerSessionIdentifier(
			this.ikaClient.ikaConfig,
			freshObjectAddressBytes,
			this.transaction,
		);
	}
}

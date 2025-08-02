import { Transaction } from '@mysten/sui/transactions';

import { IkaClient } from './ika-client';

export type IkaTransactionParams = {
	ikaClient: IkaClient;
	transaction: Transaction;
	dWallet?: {
		dWalletID: string;
		dWalletCap: string;
	};
};

export class IkaTransaction {
	private ikaClient: IkaClient;
	private transaction: Transaction;
	private dWallet?: {
		dWalletID: string;
		dWalletCap: string;
	};

	constructor({ ikaClient, transaction, dWallet }: IkaTransactionParams) {
		this.ikaClient = ikaClient;
		this.transaction = transaction;
		this.dWallet = dWallet;
	}
}

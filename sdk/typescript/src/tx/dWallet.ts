import { bcs } from '@mysten/bcs';
import type {
	Transaction,
	TransactionArgument,
	TransactionObjectArgument,
} from '@mysten/sui/transactions';

import { IkaConfig } from '../client/types';

export async function registerEncryptionKey(
	ikaConfig: IkaConfig,
	encryption: {
		encryptionKey: Uint8Array;
		encryptionKeySignature: Uint8Array;
		encryptionKeyAddress: Uint8Array;
	},
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::register_encryption_key`,
		arguments: [
			tx.sharedObjectRef({
				objectId: ikaConfig.objects.ikaDWalletCoordinator.objectID,
				initialSharedVersion: ikaConfig.objects.ikaDWalletCoordinator.initialSharedVersion,
				mutable: true,
			}),
			tx.pure.u32(0),
			tx.pure(bcs.vector(bcs.u8()).serialize(encryption.encryptionKey)),
			tx.pure(bcs.vector(bcs.u8()).serialize(encryption.encryptionKeySignature)),
			tx.pure(bcs.vector(bcs.u8()).serialize(encryption.encryptionKeyAddress)),
		],
	});
}

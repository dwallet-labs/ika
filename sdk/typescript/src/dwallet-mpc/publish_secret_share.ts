import { bcs } from '@mysten/bcs';
import { Transaction } from '@mysten/sui/transactions';

import type { Config } from './globals.js';
import {
	createSessionIdentifier,
	DWALLET_COORDINATOR_MOVE_MODULE_NAME,
	getDWalletSecpState,
	getObjectWithType,
	SUI_PACKAGE_ID,
} from './globals.js';

export async function makeDWalletUserSecretKeySharesPublicRequestEvent(
	conf: Config,
	dwallet_id: string,
	secret_share: Uint8Array,
	sui_coin_id?: string,
	ika_coin_id: string = '0x9df87437f4f0fb73bffe6fc6291f568da6e59ad4ad0770743b21cd4e1c030914',
) {
	const tx = new Transaction();
	let ikaCoinArg;
	let suiCoinArg;
	let destroyZero = false;
	if (sui_coin_id) {
		ikaCoinArg = tx.object(ika_coin_id);
		suiCoinArg = tx.object(sui_coin_id);
	} else {
		ikaCoinArg = tx.moveCall({
			target: `${SUI_PACKAGE_ID}::coin::zero`,
			arguments: [],
			typeArguments: [`${conf.ikaConfig.packages.ika_package_id}::ika::IKA`],
		});
		suiCoinArg = tx.gas;
		destroyZero = true;
	}
	const dWalletStateData = await getDWalletSecpState(conf);
	const dwalletStateArg = tx.sharedObjectRef({
		objectId: dWalletStateData.object_id,
		initialSharedVersion: dWalletStateData.initial_shared_version,
		mutable: true,
	});
	const sessionIdentifier = await createSessionIdentifier(
		tx,
		dwalletStateArg,
		conf.ikaConfig.packages.ika_dwallet_2pc_mpc_package_id,
	);
	tx.moveCall({
		target: `${conf.ikaConfig.packages.ika_dwallet_2pc_mpc_package_id}::${DWALLET_COORDINATOR_MOVE_MODULE_NAME}::request_make_dwallet_user_secret_key_shares_public`,
		arguments: [
			dwalletStateArg,
			tx.pure.id(dwallet_id),
			tx.pure(bcs.vector(bcs.u8()).serialize(secret_share)),
			sessionIdentifier,
			ikaCoinArg,
			suiCoinArg,
		],
	});

	if (destroyZero) {
		tx.moveCall({
			target: `${SUI_PACKAGE_ID}::coin::destroy_zero`,
			arguments: [ikaCoinArg],
			typeArguments: [`${conf.ikaConfig.packages.ika_package_id}::ika::IKA`],
		});
	}

	await conf.client.signAndExecuteTransaction({
		signer: conf.suiClientKeypair,
		transaction: tx,
		options: {
			showEffects: true,
			showEvents: true,
		},
	});
	await getObjectWithType(conf, dwallet_id, isDWalletWithPublicUserSecretKeyShares);
}

interface DWalletWithPublicUserSecretKeyShares {
	public_user_secret_key_share: Uint8Array;
	id: { id: string };
	dwallet_cap_id: string;
}

export function isDWalletWithPublicUserSecretKeyShares(
	obj: any,
): obj is DWalletWithPublicUserSecretKeyShares {
	return (
		obj &&
		Array.isArray(obj.public_user_secret_key_share) &&
		obj.public_user_secret_key_share.length > 0
	);
}

// Copyright (c) dWallet Labs, Ltd..
// SPDX-License-Identifier: BSD-3-Clause-Clear
import { Transaction } from '@mysten/sui/transactions';

import {
	createSessionIdentifier,
	DWALLET_COORDINATOR_MOVE_MODULE_NAME,
	getDWalletSecpState,
	getObjectWithType,
	SUI_PACKAGE_ID,
} from './globals.js';
import type { Config } from './globals.ts';

export interface CompletedPresign {
	state: {
		fields: {
			presign: Uint8Array;
		};
	};
	id: { id: string };
}

interface StartPresignEvent {
	event_data: {
		presign_id: string;
	};
}

function isCompletedPresign(event: any): event is CompletedPresign {
	return (
		event.state !== undefined &&
		event.state.fields !== undefined &&
		event.state.fields.presign !== undefined
	);
}

export async function presign(
	conf: Config,
	dwallet_id: string,
	sui_coin_id?: string,
	ika_coin_id: string = '0x9df87437f4f0fb73bffe6fc6291f568da6e59ad4ad0770743b21cd4e1c030914',
): Promise<CompletedPresign> {
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
	const presignCap = tx.moveCall({
		target: `${conf.ikaConfig.packages.ika_dwallet_2pc_mpc_package_id}::${DWALLET_COORDINATOR_MOVE_MODULE_NAME}::request_presign`,
		arguments: [
			dwalletStateArg,
			tx.pure.id(dwallet_id),
			tx.pure.u32(0),
			sessionIdentifier,
			ikaCoinArg,
			suiCoinArg,
		],
	});

	tx.transferObjects([presignCap], conf.suiClientKeypair.toSuiAddress());
	if (destroyZero) {
		tx.moveCall({
			target: `${SUI_PACKAGE_ID}::coin::destroy_zero`,
			arguments: [ikaCoinArg],
			typeArguments: [`${conf.ikaConfig.packages.ika_package_id}::ika::IKA`],
		});
	}

	const result = await conf.client.signAndExecuteTransaction({
		signer: conf.suiClientKeypair,
		transaction: tx,
		options: {
			showEffects: true,
			showEvents: true,
		},
	});
	const startSessionEvent = result.events?.at(1)?.parsedJson;
	if (!isStartPresignEvent(startSessionEvent)) {
		throw new Error('invalid start session event');
	}

	return await getObjectWithType(conf, startSessionEvent.event_data.presign_id, isCompletedPresign);
}

function isStartPresignEvent(event: any): event is StartPresignEvent {
	return event.event_data !== undefined && event.event_data.presign_id !== undefined;
}

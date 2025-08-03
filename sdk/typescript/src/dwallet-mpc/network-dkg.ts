import { bcs } from '@mysten/bcs';
import { Transaction } from '@mysten/sui/transactions';

import type { Config } from './globals.js';
import {
	DWALLET_COORDINATOR_MOVE_MODULE_NAME,
	DWALLET_SYSTEM_MOVE_MODULE_NAME,
	getInitialSharedVersion,
	getObjectWithType,
} from './globals.js';

export async function createNetworkKey(c: Config, protocolCapID: string): Promise<string> {
	const tx = new Transaction();
	const coordinatorStateArg = tx.sharedObjectRef({
		objectId: c.ikaConfig.objects.ika_dwallet_coordinator_object_id,
		initialSharedVersion: await getInitialSharedVersion(
			c,
			c.ikaConfig.objects.ika_dwallet_coordinator_object_id,
		),
		mutable: true,
	});
	const systemStateArg = tx.sharedObjectRef({
		objectId: c.ikaConfig.objects.ika_system_object_id,
		initialSharedVersion: await getInitialSharedVersion(
			c,
			c.ikaConfig.objects.ika_system_object_id,
		),
		mutable: false,
	});
	const verifiedProtocolCap = tx.moveCall({
		target: `${c.ikaConfig.packages.ika_system_package_id}::${DWALLET_SYSTEM_MOVE_MODULE_NAME}::verify_protocol_cap`,
		arguments: [systemStateArg, tx.object(protocolCapID)],
	});
	tx.moveCall({
		target: `${c.ikaConfig.packages.ika_dwallet_2pc_mpc_package_id}::${DWALLET_COORDINATOR_MOVE_MODULE_NAME}::request_dwallet_network_encryption_key_dkg_by_cap`,
		arguments: [
			coordinatorStateArg,
			tx.pure(bcs.vector(bcs.u8()).serialize([])),
			verifiedProtocolCap,
		],
	});
	const result = await c.client.signAndExecuteTransaction({
		signer: c.suiClientKeypair,
		transaction: tx,
		options: {
			showEffects: true,
			showEvents: true,
		},
	});
	const startDKGEvent = result.events?.at(0)?.parsedJson;
	if (!isStartNetworkDKGEvent(startDKGEvent)) {
		throw new Error(
			`Unexpected event type: ${JSON.stringify(startDKGEvent)}. Expected StartNetworkDKGEvent.`,
		);
	}
	await getObjectWithType(
		c,
		startDKGEvent.event_data.dwallet_network_encryption_key_id,
		isActiveNetworkKey,
	);
	return startDKGEvent.event_data.dwallet_network_encryption_key_id;
}

interface StartNetworkDKGEvent {
	event_data: {
		dwallet_network_encryption_key_id: string;
		params_for_network: string;
	};
}

function isStartNetworkDKGEvent(obj: any): obj is StartNetworkDKGEvent {
	return (
		!!obj?.event_data?.dwallet_network_encryption_key_id && !!obj?.event_data.params_for_network
	);
}

export interface ActiveNetworkKey {
	state: {
		variant: 'NetworkDKGCompleted';
	};
	id: { id: string };
}

function isActiveNetworkKey(obj: any): obj is ActiveNetworkKey {
	return obj?.state?.variant === 'NetworkDKGCompleted';
}

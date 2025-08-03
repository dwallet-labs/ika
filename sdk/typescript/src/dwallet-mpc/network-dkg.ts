import { bcs } from '@mysten/bcs';
import { Transaction } from '@mysten/sui/transactions';

import {
	Config,
	createSessionIdentifier,
	DWALLET_COORDINATOR_MOVE_MODULE_NAME,
	DWALLET_SYSTEM_MOVE_MODULE_NAME,
	getInitialSharedVersion,
	getNetworkDecryptionKeyID,
	SUI_PACKAGE_ID,
} from './globals';

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
	return '';
}

interface StartNetworkDKGEvent {
	event_data: {
		dwallet_id: string;
		dwallet_cap_id: string;
		dwallet_network_encryption_key_id: string;
	};
	session_identifier_preimage: Uint8Array;
}

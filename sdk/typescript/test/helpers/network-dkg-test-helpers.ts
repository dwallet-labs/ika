import { bcs } from '@mysten/bcs';
import { SuiClient } from '@mysten/sui/client';
import { Transaction } from '@mysten/sui/transactions';

import { ActiveNetworkKey } from '../../src/dwallet-mpc/network-dkg';
import { requestDwalletNetworkEncryptionKeyDkgByCap } from '../../src/tx/coordinator';
import { verifyProtocolCap } from '../../src/tx/system';
import {
	Config,
	createTestIkaClient,
	createTestIkaTransaction,
	DWALLET_COORDINATOR_MOVE_MODULE_NAME,
	DWALLET_SYSTEM_MOVE_MODULE_NAME,
	executeTestTransaction,
	getInitialSharedVersion,
	getObjectWithType,
} from './test-utils';

export async function testCreateNetworkKey(
	suiClient: SuiClient,
	protocolCapID: string,
	testName: string,
): Promise<string> {
	const ikaClient = createTestIkaClient(suiClient);
	const tx = new Transaction();
	const coordinatorStateArg = tx.sharedObjectRef({
		objectId: ikaClient.ikaConfig.objects.ikaDWalletCoordinator.objectID,
		initialSharedVersion: ikaClient.ikaConfig.objects.ikaDWalletCoordinator.initialSharedVersion,
		mutable: true,
	});
	const systemStateArg = tx.sharedObjectRef({
		objectId: ikaClient.ikaConfig.objects.ikaSystemObject.objectID,
		initialSharedVersion: ikaClient.ikaConfig.objects.ikaSystemObject.initialSharedVersion,
		mutable: false,
	});
	const verifiedProtocolCap = verifyProtocolCap(
		ikaClient.ikaConfig,
		systemStateArg,
		protocolCapID,
		tx,
	);
	requestDwalletNetworkEncryptionKeyDkgByCap(
		ikaClient.ikaConfig,
		coordinatorStateArg,
		Uint8Array.from([]),
		verifiedProtocolCap,
		tx
	);
	const result = await executeTestTransaction(suiClient, tx, testName);
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

function isStartNetworkDKGEvent(obj: any): obj is StartNetworkDKGEvent {
	return (
		!!obj?.event_data?.dwallet_network_encryption_key_id && !!obj?.event_data.params_for_network
	);
}

function isActiveNetworkKey(obj: any): obj is ActiveNetworkKey {
	return obj?.state?.variant === 'NetworkDKGCompleted';
}

interface StartNetworkDKGEvent {
	event_data: {
		dwallet_network_encryption_key_id: string;
		params_for_network: string;
	};
}

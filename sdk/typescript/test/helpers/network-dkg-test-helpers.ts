import { SuiClient } from '@mysten/sui/client';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { Transaction } from '@mysten/sui/transactions';

import { requestDwalletNetworkEncryptionKeyDkgByCap } from '../../src/tx/coordinator';
import { verifyProtocolCap } from '../../src/tx/system';
import {
	createTestIkaClient,
	executeTestTransaction,
	executeTestTransactionWithKeypair,
	getObjectWithType,
} from './test-utils';

interface ActiveNetworkKey {
	state: {
		variant: 'NetworkDKGCompleted';
	};
	id: { id: string };
}

export async function testCreateNetworkKey(
	suiClient: SuiClient,
	protocolCapID: string,
	publisherKeypair: Ed25519Keypair,
): Promise<string> {
	const ikaClient = createTestIkaClient(suiClient);
	await ikaClient.initialize();
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
		tx,
	);
	const result = await executeTestTransactionWithKeypair(suiClient, tx, publisherKeypair);
	const startDKGEvent = result.events?.at(0)?.parsedJson;
	if (!isStartNetworkDKGEvent(startDKGEvent)) {
		throw new Error(
			`Unexpected event type: ${JSON.stringify(startDKGEvent)}. Expected StartNetworkDKGEvent.`,
		);
	}
	console.log('Start DKG Event:', startDKGEvent);
	console.log('Network Key ID:', startDKGEvent.event_data.dwallet_network_encryption_key_id);
	await getObjectWithType(
		suiClient,
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

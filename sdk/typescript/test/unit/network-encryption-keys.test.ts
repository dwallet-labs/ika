// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { bcs } from '@mysten/sui/bcs';
import { describe, expect, it, vi } from 'vitest';

import { IkaClient } from '../../src/client/ika-client';
import { getNetworkConfig } from '../../src/client/network-configs';
import { DWalletNetworkEncryptionKey } from '../../src/generated/ika_dwallet_2pc_mpc/coordinator_inner';

const hexId = (byte: string) => '0x' + byte.repeat(32);

const KEYS_TABLE_ID = hexId('aa');

// Listed deliberately out of epoch order, with the highest epoch neither first nor last.
const NETWORK_KEYS = [
	{ id: hexId('01'), objectId: hexId('b1'), outputsId: hexId('c1'), epoch: 5 },
	{ id: hexId('02'), objectId: hexId('b2'), outputsId: hexId('c2'), epoch: 9 },
	{ id: hexId('03'), objectId: hexId('b3'), outputsId: hexId('c3'), epoch: 1 },
	{ id: hexId('04'), objectId: hexId('b4'), outputsId: hexId('c4'), epoch: 3 },
];

function serializeNetworkKeyObject(key: (typeof NETWORK_KEYS)[number]) {
	return DWalletNetworkEncryptionKey.serialize({
		id: key.objectId,
		dkg_at_epoch: BigInt(key.epoch),
		network_dkg_public_output: { contents: { id: key.outputsId, size: 0n } },
		// Same table id for reconfiguration outputs; the mock lists it as empty.
		reconfiguration_public_outputs: { id: key.outputsId, size: 0n },
		dkg_params_for_network: [],
		supported_curves: [0],
		state: { NetworkDKGCompleted: true },
	}).toBytes();
}

/**
 * An IkaClient over a mocked Sui client that serves NETWORK_KEYS. `getObject` calls
 * for a key object wait for `beforeKeyObject` (if set) before answering.
 */
function createClient(beforeKeyObject?: (objectId: string) => Promise<void>) {
	const getObject = vi.fn(async ({ objectId }: { objectId: string }) => {
		const key = NETWORK_KEYS.find((k) => k.objectId === objectId);
		if (!key) {
			throw new Error(`unexpected getObject(${objectId})`);
		}
		await beforeKeyObject?.(objectId);
		return { object: { content: serializeNetworkKeyObject(key) } };
	});

	const listDynamicFields = vi.fn(async ({ parentId }: { parentId: string }) => {
		if (parentId === KEYS_TABLE_ID) {
			return {
				dynamicFields: NETWORK_KEYS.map((k) => ({
					name: { bcs: bcs.Address.serialize(k.id).toBytes() },
					childId: k.objectId,
				})),
				hasNextPage: false,
				cursor: null,
			};
		}
		// A key's reconfiguration-outputs table: no reconfigurations yet.
		return { dynamicFields: [], hasNextPage: false, cursor: null };
	});

	const ikaClient = new IkaClient({
		suiClient: { core: { getObject, listDynamicFields } } as any,
		config: getNetworkConfig('testnet'),
	});
	vi.spyOn(ikaClient, 'ensureInitialized').mockResolvedValue({
		coordinatorInner: { dwallet_network_encryption_keys: { id: KEYS_TABLE_ID } },
		systemInner: {},
	} as any);

	return { ikaClient, getObject };
}

const sortedKeyIds = [...NETWORK_KEYS].sort((a, b) => a.epoch - b.epoch).map((k) => k.id);

describe('IkaClient network encryption key cache', () => {
	it('returns every key after a fetch that failed partway', async () => {
		let failOnThirdKey = true;
		const { ikaClient } = createClient(async (objectId) => {
			if (failOnThirdKey && objectId === NETWORK_KEYS[2].objectId) {
				failOnThirdKey = false;
				throw new Error('transient RPC failure');
			}
		});

		await expect(ikaClient.getAllNetworkEncryptionKeys()).rejects.toThrow(
			'Failed to fetch encryption keys',
		);

		const keys = await ikaClient.getAllNetworkEncryptionKeys();
		expect(keys.map((k) => k.id)).toEqual(sortedKeyIds);
	});

	it('gives a caller that arrives during an in-progress fetch the complete list', async () => {
		let releaseSecondKey!: () => void;
		const secondKeyReleased = new Promise<void>((resolve) => (releaseSecondKey = resolve));
		let secondKeyRequested!: () => void;
		const secondKeyWasRequested = new Promise<void>((resolve) => (secondKeyRequested = resolve));
		const { ikaClient } = createClient(async (objectId) => {
			if (objectId === NETWORK_KEYS[1].objectId) {
				secondKeyRequested();
				await secondKeyReleased;
			}
		});

		const firstCall = ikaClient.getAllNetworkEncryptionKeys();
		// The first key has been processed; the fetch is now blocked on the second one.
		await secondKeyWasRequested;
		const secondCall = ikaClient.getAllNetworkEncryptionKeys();
		releaseSecondKey();

		const [firstKeys, secondKeys] = await Promise.all([firstCall, secondCall]);
		expect(secondKeys.map((k) => k.id)).toEqual(sortedKeyIds);
		expect(firstKeys.map((k) => k.id)).toEqual(sortedKeyIds);
	});

	it('getLatestNetworkEncryptionKey returns the highest-epoch key', async () => {
		const { ikaClient } = createClient();

		const latest = await ikaClient.getLatestNetworkEncryptionKey();

		expect(latest.epoch).toBe(9);
		expect(latest.id).toBe(NETWORK_KEYS[1].id);
	});
});

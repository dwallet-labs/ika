// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

// Build an IkaConfig pointing at the local Ika network. The Ika container
// publishes its package + object IDs to `./ika-state/ika_config.json`
// (bind-mounted from the ika service). The shared objects' initialSharedVersion
// is not in that file — we query Sui for it here.

import { readFile } from 'node:fs/promises';
import { resolve as resolvePath } from 'node:path';
import type { IkaConfig } from '@ika.xyz/sdk';
import type { ClientWithCoreApi } from '@mysten/sui/client';

// Shape of `ika_config.json` written by crates/ika-swarm-config/src/sui_client.rs.
// serde renames the Rust fields to snake_case.
interface RawIkaConfigJson {
	packages: {
		ika_package_id: string;
		ika_common_package_id: string;
		ika_dwallet_2pc_mpc_package_id: string;
		ika_dwallet_2pc_mpc_package_id_v2?: string | null;
		ika_system_package_id: string;
	};
	objects: {
		ika_system_object_id: string;
		ika_dwallet_coordinator_object_id: string;
	};
}

export interface LocalIkaConfig extends IkaConfig {
	/** Echoed path so test failures can point at the actual file consulted. */
	readonly sourcePath: string;
}

const DEFAULT_CONFIG_PATH = resolvePath(
	new URL('../ika-state/ika_config.json', import.meta.url).pathname,
);

/**
 * Read the local Ika network config (written by `ika start` in the docker
 * container) and resolve it into an `IkaConfig` consumable by the SDK.
 *
 * The Rust side persists package + object IDs but not the
 * `initialSharedVersion` of the system / coordinator shared objects, so we
 * query Sui for them here. Both objects are guaranteed to exist by the time
 * the Ika container's healthcheck flips green.
 */
export async function loadLocalnetIkaConfig(
	suiClient: ClientWithCoreApi,
	opts: { configPath?: string } = {},
): Promise<LocalIkaConfig> {
	const path = opts.configPath ?? DEFAULT_CONFIG_PATH;
	const raw = (await readFile(path, 'utf8').then((b) => JSON.parse(b))) as RawIkaConfigJson;

	const ikaSystemObjectVersion = await fetchInitialSharedVersion(
		suiClient,
		raw.objects.ika_system_object_id,
	);
	const ikaDWalletCoordinatorVersion = await fetchInitialSharedVersion(
		suiClient,
		raw.objects.ika_dwallet_coordinator_object_id,
	);

	return {
		sourcePath: path,
		packages: {
			ikaPackage: raw.packages.ika_package_id,
			ikaCommonPackage: raw.packages.ika_common_package_id,
			ikaSystemOriginalPackage: raw.packages.ika_system_package_id,
			ikaSystemPackage: raw.packages.ika_system_package_id,
			ikaDwallet2pcMpcOriginalPackage: raw.packages.ika_dwallet_2pc_mpc_package_id,
			ikaDwallet2pcMpcPackage:
				raw.packages.ika_dwallet_2pc_mpc_package_id_v2 ??
				raw.packages.ika_dwallet_2pc_mpc_package_id,
		},
		objects: {
			ikaSystemObject: {
				objectID: raw.objects.ika_system_object_id,
				initialSharedVersion: ikaSystemObjectVersion,
			},
			ikaDWalletCoordinator: {
				objectID: raw.objects.ika_dwallet_coordinator_object_id,
				initialSharedVersion: ikaDWalletCoordinatorVersion,
			},
		},
	};
}

async function fetchInitialSharedVersion(
	suiClient: ClientWithCoreApi,
	objectId: string,
): Promise<number> {
	const obj = await suiClient.core.getObject({ objectId });
	const owner = obj.object?.owner as unknown;
	if (!owner || typeof owner !== 'object' || !('Shared' in owner)) {
		throw new Error(
			`loadLocalnetIkaConfig: object ${objectId} is not shared (owner=${JSON.stringify(owner)})`,
		);
	}
	const shared = (owner as { Shared: { initialSharedVersion?: number | string } }).Shared;
	const ver = shared.initialSharedVersion;
	if (ver === undefined) {
		throw new Error(
			`loadLocalnetIkaConfig: shared object ${objectId} missing initialSharedVersion`,
		);
	}
	return typeof ver === 'string' ? Number(ver) : ver;
}

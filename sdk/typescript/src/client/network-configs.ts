// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import fs from 'fs';
import path from 'path';

import type { IkaConfig, Network } from './types.js';

/**
 * Find the ika_config.json file by searching in multiple possible locations
 * @returns The path to the found ika_config.json file
 * @throws {Error} If no ika_config.json file can be found
 */
function findIkaConfigFile(): string {
	const possiblePaths = [
		// Current working directory
		'ika_config.json',
		// One level up
		'../ika_config.json',
		// Two levels up (current hardcoded path)
		'../../ika_config.json',
		// Three levels up
		'../../../ika_config.json',
		// From environment variable if set
		...(process.env.IKA_CONFIG_PATH ? [process.env.IKA_CONFIG_PATH] : []),
		// From project root (assuming we're in sdk/typescript/src/client/)
		path.resolve(__dirname, '../../../../ika_config.json'),
		// From workspace root (assuming we're in sdk/typescript/)
		path.resolve(__dirname, '../../../ika_config.json'),
	];

	for (const configPath of possiblePaths) {
		try {
			const resolvedPath = path.resolve(configPath);
			if (fs.existsSync(resolvedPath)) {
				return resolvedPath;
			}
		} catch {
			// Continue to next path if this one fails
			continue;
		}
	}

	throw new Error(
		`Could not find ika_config.json file. Tried the following locations:\n` +
			`${possiblePaths.map((p) => `  - ${p}`).join('\n')}\n\n` +
			`Please ensure the file exists in one of these locations, or set the IKA_CONFIG_PATH environment variable.`,
	);
}

/**
 * Get the network configuration for a specific Ika network.
 * This function returns the appropriate package IDs, object IDs, and shared versions
 * for the specified network environment.
 *
 * @param network - The network environment to get configuration for ('localnet', 'testnet', or 'mainnet')
 * @param ikaConfigPath - The path to the ika_config.json file to use. If not provided, the function will search for the file in the default locations. Only used for localnet.
 * @returns The complete Ika configuration object for the specified network
 * @throws {Error} If reading the localnet config file fails
 *
 * @example
 * ```typescript
 * const config = getNetworkConfig('mainnet');
 * console.log(config.packages.ikaSystemPackage);
 * ```
 */
export function getNetworkConfig(network: Network, ikaConfigPath?: string): IkaConfig {
	switch (network) {
		case 'localnet': {
			try {
				const configPath = ikaConfigPath ?? findIkaConfigFile();
				const parsedJson = JSON.parse(fs.readFileSync(configPath, 'utf8'));

				return {
					packages: {
						ikaPackage: parsedJson.packages.ika_package_id,
						ikaCommonPackage: parsedJson.packages.ika_common_package_id,
						ikaSystemPackage: parsedJson.packages.ika_system_package_id,
						ikaDwallet2pcMpcPackage: parsedJson.packages.ika_dwallet_2pc_mpc_package_id,
					},
					objects: {
						ikaSystemObject: {
							objectID: parsedJson.objects.ika_system_object_id,
							initialSharedVersion: 0,
						},
						ikaDWalletCoordinator: {
							objectID: parsedJson.objects.ika_dwallet_coordinator_object_id,
							initialSharedVersion: 0,
						},
					},
				};
			} catch (error) {
				throw new Error(
					`Failed to load localnet configuration: ${error instanceof Error ? error.message : String(error)}`,
				);
			}
		}
		case 'testnet':
			return {
				packages: {
					ikaPackage: '0x1f26bb2f711ff82dcda4d02c77d5123089cb7f8418751474b9fb744ce031526a',
					ikaCommonPackage: '0x96fc75633b6665cf84690587d1879858ff76f88c10c945e299f90bf4e0985eb0',
					ikaSystemPackage: '0xae71e386fd4cff3a080001c4b74a9e485cd6a209fa98fb272ab922be68869148',
					ikaDwallet2pcMpcPackage:
						'0xf02f5960c94fce1899a3795b5d11fd076bc70a8d0e20a2b19923d990ed490730',
				},
				objects: {
					ikaSystemObject: {
						objectID: '0x2172c6483ccd24930834e30102e33548b201d0607fb1fdc336ba3267d910dec6',
						initialSharedVersion: 508060325,
					},
					ikaDWalletCoordinator: {
						objectID: '0x4d157b7415a298c56ec2cb1dcab449525fa74aec17ddba376a83a7600f2062fc',
						initialSharedVersion: 510819272,
					},
				},
			};
		case 'mainnet':
			return {
				packages: {
					ikaPackage: '0x7262fb2f7a3a14c888c438a3cd9b912469a58cf60f367352c46584262e8299aa',
					ikaCommonPackage: '0x9e1e9f8e4e51ee2421a8e7c0c6ab3ef27c337025d15333461b72b1b813c44175',
					ikaSystemPackage: '0xb874c9b51b63e05425b74a22891c35b8da447900e577667b52e85a16d4d85486',
					ikaDwallet2pcMpcPackage:
						'0xdd24c62739923fbf582f49ef190b4a007f981ca6eb209ca94f3a8eaf7c611317',
				},
				objects: {
					ikaSystemObject: {
						objectID: '0x215de95d27454d102d6f82ff9c54d8071eb34d5706be85b5c73cbd8173013c80',
						initialSharedVersion: 595745916,
					},
					ikaDWalletCoordinator: {
						objectID: '0x5ea59bce034008a006425df777da925633ef384ce25761657ea89e2a08ec75f3',
						initialSharedVersion: 595876492,
					},
				},
			};
	}
}

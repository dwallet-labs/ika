// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import type { IkaConfig, Network } from './types.js';

/**
 * Get the network configuration for a specific Ika network.
 * This function returns the appropriate package IDs, object IDs, and shared versions
 * for the specified network environment.
 *
 * @param network - The network environment to get configuration for ('testnet', or 'mainnet')
 * @returns The complete Ika configuration object for the specified network
 *
 * @example
 * ```typescript
 * const config = getNetworkConfig('mainnet');
 * console.log(config.packages.ikaSystemPackage);
 * ```
 */
export function getNetworkConfig(network: Network): IkaConfig {
	switch (network) {
		case 'testnet':
			return {
				packages: {
					ikaPackage: '0x1f26bb2f711ff82dcda4d02c77d5123089cb7f8418751474b9fb744ce031526a',
					ikaCommonPackage: '0x96fc75633b6665cf84690587d1879858ff76f88c10c945e299f90bf4e0985eb0',
					ikaSystemOriginalPackage:
						'0xae71e386fd4cff3a080001c4b74a9e485cd6a209fa98fb272ab922be68869148',
					ikaSystemPackage: '0xde05f49e5f1ee13ed06c1e243c0a8e8fe858e1d8689476fdb7009af8ddc3c38b',
					ikaDwallet2pcMpcOriginalPackage:
						'0xf02f5960c94fce1899a3795b5d11fd076bc70a8d0e20a2b19923d990ed490730',
					ikaDwallet2pcMpcPackage:
						'0x6573a6c13daf26a64eb8a37d3c7a4391b353031e223072ca45b1ff9366f59293',
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
					ikaSystemOriginalPackage:
						'0xb874c9b51b63e05425b74a22891c35b8da447900e577667b52e85a16d4d85486',
					ikaSystemPackage: '0xd69f947d7ee6f224dd0dd31ec3ec30c0dd0f713a1de55d564e8e98910c4f9553',
					ikaDwallet2pcMpcOriginalPackage:
						'0xdd24c62739923fbf582f49ef190b4a007f981ca6eb209ca94f3a8eaf7c611317',
					ikaDwallet2pcMpcPackage:
						'0x23b5bd96051923f800c3a2150aacdcdd8d39e1df2dce4dac69a00d2d8c7f7e77',
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

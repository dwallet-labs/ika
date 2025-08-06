import fs from 'fs';
import path from 'path';

import { IkaConfig, Network } from './types';

export function getNetworkConfig(network: Network): IkaConfig {
	switch (network) {
		case 'localnet':
			let parsedJson = JSON.parse(
				fs.readFileSync(path.resolve(process.cwd(), '../../ika_config.json'), 'utf8'),
			);
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

// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { describe, expect, it } from 'vitest';

import { getNetworkConfig } from '../../src/client/network-configs';
import type { Network } from '../../src/client/types';

describe('Network Configuration', () => {
	it('should load mainnet configuration with expected hardcoded values', async () => {
		const config = getNetworkConfig('mainnet');

		expect(config).toBeDefined();
		expect(config.packages).toBeDefined();
		expect(config.objects).toBeDefined();

		// Test exact expected mainnet package addresses
		expect(config.packages.ikaPackage).toBe(
			'0x7262fb2f7a3a14c888c438a3cd9b912469a58cf60f367352c46584262e8299aa',
		);
		expect(config.packages.ikaCommonPackage).toBe(
			'0x9e1e9f8e4e51ee2421a8e7c0c6ab3ef27c337025d15333461b72b1b813c44175',
		);
		expect(config.packages.ikaDwallet2pcMpcPackage).toBe(
			'0xdd24c62739923fbf582f49ef190b4a007f981ca6eb209ca94f3a8eaf7c611317',
		);
		expect(config.packages.ikaSystemPackage).toBe(
			'0xb874c9b51b63e05425b74a22891c35b8da447900e577667b52e85a16d4d85486',
		);

		// Test exact expected mainnet object IDs and versions
		expect(config.objects.ikaSystemObject.objectID).toBe(
			'0x215de95d27454d102d6f82ff9c54d8071eb34d5706be85b5c73cbd8173013c80',
		);
		expect(config.objects.ikaSystemObject.initialSharedVersion).toBe(595745916);

		expect(config.objects.ikaDWalletCoordinator.objectID).toBe(
			'0x5ea59bce034008a006425df777da925633ef384ce25761657ea89e2a08ec75f3',
		);
		expect(config.objects.ikaDWalletCoordinator.initialSharedVersion).toBe(595876492);

		// Verify format requirements are still met
		expect(config.packages.ikaPackage).toMatch(/^0x[a-f0-9]+$/);
		expect(config.packages.ikaCommonPackage).toMatch(/^0x[a-f0-9]+$/);
		expect(config.packages.ikaDwallet2pcMpcPackage).toMatch(/^0x[a-f0-9]+$/);
		expect(config.packages.ikaSystemPackage).toMatch(/^0x[a-f0-9]+$/);
		expect(config.objects.ikaSystemObject.objectID).toMatch(/^0x[a-f0-9]+$/);
		expect(config.objects.ikaDWalletCoordinator.objectID).toMatch(/^0x[a-f0-9]+$/);
	});

	it('should load testnet configuration with expected hardcoded values', async () => {
		const config = getNetworkConfig('testnet');

		expect(config).toBeDefined();
		expect(config.packages).toBeDefined();
		expect(config.objects).toBeDefined();

		// Test exact expected testnet package addresses
		expect(config.packages.ikaPackage).toBe(
			'0x1f26bb2f711ff82dcda4d02c77d5123089cb7f8418751474b9fb744ce031526a',
		);
		expect(config.packages.ikaCommonPackage).toBe(
			'0x96fc75633b6665cf84690587d1879858ff76f88c10c945e299f90bf4e0985eb0',
		);
		expect(config.packages.ikaDwallet2pcMpcPackage).toBe(
			'0xf02f5960c94fce1899a3795b5d11fd076bc70a8d0e20a2b19923d990ed490730',
		);
		expect(config.packages.ikaSystemPackage).toBe(
			'0xae71e386fd4cff3a080001c4b74a9e485cd6a209fa98fb272ab922be68869148',
		);

		// Test exact expected testnet object IDs and versions
		expect(config.objects.ikaSystemObject.objectID).toBe(
			'0x2172c6483ccd24930834e30102e33548b201d0607fb1fdc336ba3267d910dec6',
		);
		expect(config.objects.ikaSystemObject.initialSharedVersion).toBe(508060325);

		expect(config.objects.ikaDWalletCoordinator.objectID).toBe(
			'0x4d157b7415a298c56ec2cb1dcab449525fa74aec17ddba376a83a7600f2062fc',
		);
		expect(config.objects.ikaDWalletCoordinator.initialSharedVersion).toBe(510819272);

		// Verify format requirements are still met
		expect(config.packages.ikaPackage).toMatch(/^0x[a-f0-9]+$/);
		expect(config.packages.ikaCommonPackage).toMatch(/^0x[a-f0-9]+$/);
		expect(config.packages.ikaDwallet2pcMpcPackage).toMatch(/^0x[a-f0-9]+$/);
		expect(config.packages.ikaSystemPackage).toMatch(/^0x[a-f0-9]+$/);
		expect(config.objects.ikaSystemObject.objectID).toMatch(/^0x[a-f0-9]+$/);
		expect(config.objects.ikaDWalletCoordinator.objectID).toMatch(/^0x[a-f0-9]+$/);
	});

	it('should load localnet configuration', async () => {
		const config = getNetworkConfig('localnet');

		expect(config).toBeDefined();
		expect(config.packages).toBeDefined();
		expect(config.objects).toBeDefined();

		// Test that localnet config has the same structure as other networks
		expect(config.packages.ikaPackage).toBeDefined();
		expect(config.packages.ikaCommonPackage).toBeDefined();
		expect(config.packages.ikaDwallet2pcMpcPackage).toBeDefined();
		expect(config.packages.ikaSystemPackage).toBeDefined();

		expect(config.objects.ikaSystemObject).toBeDefined();
		expect(config.objects.ikaDWalletCoordinator).toBeDefined();
	});

	it('should have different configurations for different networks with specific expected differences', async () => {
		const mainnetConfig = getNetworkConfig('mainnet');
		const testnetConfig = getNetworkConfig('testnet');
		const localnetConfig = getNetworkConfig('localnet');

		// Verify exact differences between mainnet and testnet
		expect(mainnetConfig.packages.ikaPackage).toBe(
			'0x7262fb2f7a3a14c888c438a3cd9b912469a58cf60f367352c46584262e8299aa',
		);
		expect(testnetConfig.packages.ikaPackage).toBe(
			'0x1f26bb2f711ff82dcda4d02c77d5123089cb7f8418751474b9fb744ce031526a',
		);
		expect(mainnetConfig.packages.ikaPackage).not.toBe(testnetConfig.packages.ikaPackage);

		// Verify mainnet vs testnet object IDs are different
		expect(mainnetConfig.objects.ikaSystemObject.objectID).toBe(
			'0x215de95d27454d102d6f82ff9c54d8071eb34d5706be85b5c73cbd8173013c80',
		);
		expect(testnetConfig.objects.ikaSystemObject.objectID).toBe(
			'0x2172c6483ccd24930834e30102e33548b201d0607fb1fdc336ba3267d910dec6',
		);
		expect(mainnetConfig.objects.ikaSystemObject.objectID).not.toBe(
			testnetConfig.objects.ikaSystemObject.objectID,
		);

		// Verify initial shared versions are different and reasonable
		expect(mainnetConfig.objects.ikaSystemObject.initialSharedVersion).toBe(595745916);
		expect(testnetConfig.objects.ikaSystemObject.initialSharedVersion).toBe(508060325);
		expect(mainnetConfig.objects.ikaSystemObject.initialSharedVersion).not.toBe(
			testnetConfig.objects.ikaSystemObject.initialSharedVersion,
		);

		// Localnet should be different from both mainnet and testnet
		expect(localnetConfig.packages.ikaPackage).not.toBe(mainnetConfig.packages.ikaPackage);
		expect(localnetConfig.packages.ikaPackage).not.toBe(testnetConfig.packages.ikaPackage);
		expect(localnetConfig.objects.ikaSystemObject.objectID).not.toBe(
			mainnetConfig.objects.ikaSystemObject.objectID,
		);
		expect(localnetConfig.objects.ikaSystemObject.objectID).not.toBe(
			testnetConfig.objects.ikaSystemObject.objectID,
		);
	});

	it('should provide consistent results for repeated calls', async () => {
		// Test that repeated calls return the same configuration
		const config1 = getNetworkConfig('mainnet');
		const config2 = getNetworkConfig('mainnet');

		expect(config1).toEqual(config2);

		// Test with different networks
		const testnetConfig1 = getNetworkConfig('testnet');
		const testnetConfig2 = getNetworkConfig('testnet');

		expect(testnetConfig1).toEqual(testnetConfig2);
	});

	it('should handle network type validation', async () => {
		// Test valid network types
		const validNetworks: Network[] = ['mainnet', 'testnet', 'localnet'];

		validNetworks.forEach((network) => {
			const config = getNetworkConfig(network);
			expect(config).toBeDefined();
			expect(config.packages).toBeDefined();
			expect(config.objects).toBeDefined();
		});
	});

	it('should have consistent configuration structure', async () => {
		const networks: Network[] = ['mainnet', 'testnet', 'localnet'];

		networks.forEach((network) => {
			const config = getNetworkConfig(network);

			// Test required package fields
			const requiredPackageFields = [
				'ikaPackage',
				'ikaCommonPackage',
				'ikaDwallet2pcMpcPackage',
				'ikaSystemPackage',
			];

			requiredPackageFields.forEach((field) => {
				expect(config.packages).toHaveProperty(field);
				expect(typeof config.packages[field as keyof typeof config.packages]).toBe('string');
				expect(config.packages[field as keyof typeof config.packages].length).toBeGreaterThan(0);
			});

			// Test required object fields
			expect(config.objects).toHaveProperty('ikaSystemObject');
			expect(config.objects).toHaveProperty('ikaDWalletCoordinator');

			expect(config.objects.ikaSystemObject).toHaveProperty('objectID');
			expect(config.objects.ikaSystemObject).toHaveProperty('initialSharedVersion');
			expect(config.objects.ikaDWalletCoordinator).toHaveProperty('objectID');
			expect(config.objects.ikaDWalletCoordinator).toHaveProperty('initialSharedVersion');
		});
	});

	it('should have valid Sui address formats', async () => {
		const networks: Network[] = ['mainnet', 'testnet', 'localnet'];

		networks.forEach((network) => {
			const config = getNetworkConfig(network);

			// All package addresses should be valid Sui addresses
			Object.values(config.packages).forEach((packageAddress) => {
				expect(packageAddress).toMatch(/^0x[a-f0-9]{1,64}$/);
			});

			// All object IDs should be valid Sui object IDs
			expect(config.objects.ikaSystemObject.objectID).toMatch(/^0x[a-f0-9]{1,64}$/);
			expect(config.objects.ikaDWalletCoordinator.objectID).toMatch(/^0x[a-f0-9]{1,64}$/);
		});
	});

	it('should have logical initial shared versions', async () => {
		const networks: Network[] = ['mainnet', 'testnet', 'localnet'];

		networks.forEach((network) => {
			const config = getNetworkConfig(network);

			// Initial shared versions should be non-negative integers
			expect(config.objects.ikaSystemObject.initialSharedVersion).toBeGreaterThanOrEqual(0);
			expect(config.objects.ikaDWalletCoordinator.initialSharedVersion).toBeGreaterThanOrEqual(0);

			// Should be reasonable values (not too large)
			expect(config.objects.ikaSystemObject.initialSharedVersion).toBeLessThan(1000000000);
			expect(config.objects.ikaDWalletCoordinator.initialSharedVersion).toBeLessThan(1000000000);

			// Should be integers
			expect(Number.isInteger(config.objects.ikaSystemObject.initialSharedVersion)).toBe(true);
			expect(Number.isInteger(config.objects.ikaDWalletCoordinator.initialSharedVersion)).toBe(
				true,
			);

			// For mainnet and testnet, should be positive (localnet can be 0)
			if (network === 'mainnet' || network === 'testnet') {
				expect(config.objects.ikaSystemObject.initialSharedVersion).toBeGreaterThan(0);
				expect(config.objects.ikaDWalletCoordinator.initialSharedVersion).toBeGreaterThan(0);
			}
		});
	});

	it('should be immutable configuration objects', async () => {
		const config = getNetworkConfig('mainnet');
		const originalPackage = config.packages.ikaPackage;

		// Try to modify the configuration (this should not affect the original)
		try {
			(config.packages as any).ikaPackage = 'modified';
		} catch (error) {
			// If it throws, that's good - it means the object is frozen/immutable
		}

		// Get a fresh configuration to verify it wasn't modified
		const freshConfig = getNetworkConfig('mainnet');
		expect(freshConfig.packages.ikaPackage).toBe(originalPackage);
	});

	describe('Edge Cases', () => {
		it('should handle network parameter validation', () => {
			// Test all valid network types work
			expect(() => getNetworkConfig('mainnet')).not.toThrow();
			expect(() => getNetworkConfig('testnet')).not.toThrow();
			expect(() => getNetworkConfig('localnet')).not.toThrow();
		});

		it('should maintain consistent network type behavior', () => {
			// Test that the same network returns the same configuration
			const config1 = getNetworkConfig('mainnet');
			const config2 = getNetworkConfig('mainnet');

			expect(config1).toEqual(config2);
		});
	});
});

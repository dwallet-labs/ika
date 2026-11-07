// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { bcs } from '@mysten/bcs';
import { Transaction } from '@mysten/sui/transactions';
import { describe, expect, it } from 'vitest';

import { IkaClient } from '../../src/client/ika-client';
import { IkaTransaction } from '../../src/client/ika-transaction';
import { getNetworkConfig } from '../../src/client/network-configs';
import { SignatureAlgorithm } from '../../src/client/types';

// Mirrors the Rust `VersionedDwalletDKGPublicOutput` enum, whose BCS variant
// index is the first byte of a dWallet's on-chain `public_output`.
const VersionedDwalletDKGPublicOutput = bcs.enum('VersionedDwalletDKGPublicOutput', {
	V1: bcs.vector(bcs.u8()),
	V2: bcs.struct('V2', {
		public_key_bytes: bcs.vector(bcs.u8()),
		dkg_output: bcs.vector(bcs.u8()),
	}),
});

function createZeroTrustSecp256k1DWallet(publicOutput: Uint8Array) {
	return {
		id: '0x' + '11'.repeat(32),
		curve: 0, // secp256k1
		is_imported_key_dwallet: false,
		kind: 'zero-trust',
		dwallet_network_encryption_key_id: '0x' + '22'.repeat(32),
		state: {
			$kind: 'Active',
			Active: { public_output: Array.from(publicOutput) },
		},
	} as any;
}

function createIkaTransaction() {
	const ikaClient = new IkaClient({
		suiClient: {} as any,
		config: getNetworkConfig('testnet'),
	});
	const transaction = new Transaction();
	const ikaTransaction = new IkaTransaction({ ikaClient, transaction });

	return { transaction, ikaTransaction };
}

describe('IkaTransaction.requestPresign', () => {
	it('allows an ECDSA presign for a V1 zero-trust secp256k1 dWallet', () => {
		const dWallet = createZeroTrustSecp256k1DWallet(
			VersionedDwalletDKGPublicOutput.serialize({ V1: [1, 2, 3] }).toBytes(),
		);
		const { transaction, ikaTransaction } = createIkaTransaction();

		const presignCap = ikaTransaction.requestPresign({
			dWallet,
			signatureAlgorithm: SignatureAlgorithm.ECDSASecp256k1,
			ikaCoin: transaction.object('0x' + '33'.repeat(32)),
			suiCoin: transaction.gas,
		});

		expect(presignCap).toBeDefined();
		const moveCalls = transaction
			.getData()
			.commands.flatMap((command) => (command.MoveCall ? [command.MoveCall.function] : []));
		expect(moveCalls).toContain('request_presign');
	});

	it('refuses an ECDSA presign for a V2 zero-trust secp256k1 dWallet', () => {
		const dWallet = createZeroTrustSecp256k1DWallet(
			VersionedDwalletDKGPublicOutput.serialize({
				V2: { public_key_bytes: [4, 5, 6], dkg_output: [1, 2, 3] },
			}).toBytes(),
		);
		const { transaction, ikaTransaction } = createIkaTransaction();

		expect(() =>
			ikaTransaction.requestPresign({
				dWallet,
				signatureAlgorithm: SignatureAlgorithm.ECDSASecp256k1,
				ikaCoin: transaction.object('0x' + '33'.repeat(32)),
				suiCoin: transaction.gas,
			}),
		).toThrow('You can call this function for ecdsa signatures only');
	});
});

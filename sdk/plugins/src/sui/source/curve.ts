// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { Curve } from '@ika.xyz/sdk';

/** Map the BCS-encoded `u32` curve from the Move side back to the `Curve` enum. */
export function curveFromNumber(n: number): Curve {
	switch (n) {
		case 0:
			return Curve.SECP256K1;
		case 1:
			return Curve.SECP256R1;
		case 2:
			return Curve.ED25519;
		case 3:
			return Curve.RISTRETTO;
		default:
			throw new Error(`unknown curve number ${n}`);
	}
}

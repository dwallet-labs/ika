// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import type { Curve, DWallet as RawDWallet } from '@ika.xyz/sdk';
import { DWallet, type DWalletKind } from '@ika.xyz/sdk/plugin';

/**
 * Sui-source dWallet handle. Holds the BCS-decoded Move object on `raw`
 * alongside the fields users actually touch.
 *
 * `encryptedShareId` is captured at DKG or imported-key creation time when
 * relevant (zero-trust and imported-key kinds). To override it for a single
 * sign call, pass `SuiSignMessageInput.encryptedShareId` rather than
 * constructing a new handle.
 */
export class SuiDWallet<C extends Curve = Curve> extends DWallet<C, RawDWallet> {
	constructor(
		readonly id: string,
		readonly kind: DWalletKind,
		readonly curve: C,
		readonly publicOutput: Uint8Array,
		readonly raw: RawDWallet,
		readonly dWalletCapId: string,
		readonly encryptedShareId?: string,
	) {
		super();
	}
}

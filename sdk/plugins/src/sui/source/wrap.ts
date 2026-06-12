// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import type { DWallet as RawDWallet } from '@ika.xyz/sdk';
import type { DWalletKind } from '@ika.xyz/sdk/plugin';

import { curveFromNumber } from './curve.js';
import { SuiDWallet } from './dwallet.js';

/**
 * Wrap a BCS-decoded Move dWallet into the public `SuiDWallet` handle. The
 * returned handle is NAKED; destination namespaces (`dWallet.sui.sign(...)`
 * etc.) are added by `client.decorate(dWallet)` or by the extend-surface
 * methods that wrap their results in `decorateIfReady`.
 *
 * Decoration is kept distinct from wrapping so that:
 *   - the type system reflects whether a handle is decorated, instead of a
 *     globally-augmented `DWallet` interface lying about it;
 *   - decoration runs against the destinations registered at call time, not
 *     a snapshot from when this function ran.
 */
export function wrapDWallet(raw: RawDWallet, encryptedShareId?: string): SuiDWallet {
	if (raw.state.$kind !== 'Active') {
		throw new Error(`dWallet ${raw.id} is not active (state=${raw.state.$kind})`);
	}
	return new SuiDWallet(
		raw.id,
		raw.kind as DWalletKind,
		curveFromNumber(raw.curve),
		Uint8Array.from(raw.state.Active.public_output),
		raw,
		raw.dwallet_cap_id,
		encryptedShareId,
	);
}

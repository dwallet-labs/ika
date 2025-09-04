// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { toHex } from '@mysten/bcs';
import { describe, expect, it } from 'vitest';

import { sessionIdentifierDigest } from '../../src';

describe('sessionIdentifierDigest', () => {
	it('should return the correct digest', () => {
		const sessionIdentifier = new Uint8Array(32);
		sessionIdentifier.fill(42);
		const digest = sessionIdentifierDigest(sessionIdentifier);

		expect(toHex(digest)).toBe('369df3310b6a3e225c5c6b43fe444a4155494d452650a80b3695ec6c625cdae7');
	});
});

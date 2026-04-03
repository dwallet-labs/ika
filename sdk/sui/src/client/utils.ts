// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { InvalidObjectError } from '@ika.xyz/core';
import type { ClientWithCoreApi, SuiClientTypes } from '@mysten/sui/client';

/**
 * Extract BCS (Binary Canonical Serialization) bytes from a Sui object response.
 */
export function objResToBcs(
	resp:
		| SuiClientTypes.Object<{
				content: true;
		  }>
		| SuiClientTypes.GetObjectResponse<{
				content: true;
		  }>
		| Error,
): Uint8Array<ArrayBuffer> {
	if (resp instanceof Error) {
		throw resp;
	}

	if ('object' in resp) {
		resp = resp.object;
	}

	if (!resp.content) {
		throw new InvalidObjectError(`Response bcs missing: ${JSON.stringify(resp.type, null, 2)}`);
	}

	return new Uint8Array(resp.content);
}

export async function fetchAllDynamicFields(
	suiClient: ClientWithCoreApi,
	parentId: string,
): Promise<SuiClientTypes.DynamicFieldEntry[]> {
	const allFields: any[] = [];
	let cursor: string | null = null;

	while (true) {
		const response = await suiClient.core.listDynamicFields({
			parentId,
			cursor,
		});

		allFields.push(...response.dynamicFields);

		if (response.cursor === cursor) {
			break;
		}

		cursor = response.cursor;
	}

	return allFields;
}

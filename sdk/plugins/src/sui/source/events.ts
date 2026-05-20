// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { ikaDwallet2pcMpc } from '@ika.xyz/sdk';

const { CoordinatorInnerModule, SessionsManagerModule } = ikaDwallet2pcMpc;

export type EventLike = { eventType: string; bcs?: number[] | Uint8Array | null };
export type TxLike = { events?: ReadonlyArray<EventLike> | null } | undefined;

export function findEvent(txData: TxLike, partialType: string): EventLike {
	const events = txData?.events ?? [];
	const ev = events.find((e) => e.eventType.includes(partialType));
	if (!ev) {
		throw new Error(
			`event '${partialType}' not found; got: ${events.map((e) => e.eventType).join(', ')}`,
		);
	}
	return ev;
}

function parse<T>(parser: { parse: (bytes: Uint8Array) => T }, ev: EventLike): T {
	return parser.parse(new Uint8Array(ev.bcs ?? []));
}

export const parseDkgEvent = (ev: EventLike) =>
	parse(
		SessionsManagerModule.DWalletSessionEvent(CoordinatorInnerModule.DWalletDKGRequestEvent),
		ev,
	);

export const parsePresignEvent = (ev: EventLike) =>
	parse(SessionsManagerModule.DWalletSessionEvent(CoordinatorInnerModule.PresignRequestEvent), ev);

export const parseSignEvent = (ev: EventLike) =>
	parse(SessionsManagerModule.DWalletSessionEvent(CoordinatorInnerModule.SignRequestEvent), ev);

export const parseImportedKeyEvent = (ev: EventLike) =>
	parse(
		SessionsManagerModule.DWalletSessionEvent(
			CoordinatorInnerModule.DWalletImportedKeyVerificationRequestEvent,
		),
		ev,
	);

export const parseFutureSignEvent = (ev: EventLike) =>
	parse(
		SessionsManagerModule.DWalletSessionEvent(CoordinatorInnerModule.FutureSignRequestEvent),
		ev,
	);

// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { ikaDwallet2pcMpc } from '@ika.xyz/sdk';

const { CoordinatorInnerModule, SessionsManagerModule } = ikaDwallet2pcMpc;

export type EventLike = { eventType: string; bcs?: number[] | Uint8Array | null };
export type TxLike = { events?: ReadonlyArray<EventLike> | null } | undefined;

/**
 * Match by the canonical inner module path (e.g. `::coordinator_inner::SignRequestEvent`)
 * rather than a bare struct-name substring. This anchors the match to the
 * coordinator's module path so a malicious wallet returning fabricated
 * events whose type happens to end in the bare struct name (or a foreign
 * package emitting a same-named struct) cannot satisfy the find.
 *
 * The `>` terminator in the matched suffix prevents a foreign struct
 * starting with the same name (e.g. `SignRequestEventExt`) from matching.
 */
export function findEvent(txData: TxLike, innerEventName: string): EventLike {
	const events = txData?.events ?? [];
	const needle = `::coordinator_inner::${innerEventName}>`;
	const ev = events.find((e) => e.eventType.endsWith(needle));
	if (!ev) {
		throw new Error(
			`event ending in '${needle}' not found; got: ${events.map((e) => e.eventType).join(', ')}`,
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

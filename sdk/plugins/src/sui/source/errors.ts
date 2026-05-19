// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import type { SuiDWallet } from './dwallet.js';

/**
 * Thrown by `createDWallet({ kind: 'imported-key-shared' })` when the verify
 * step succeeds but the subsequent reveal step fails. The verified
 * imported-key dWallet is preserved on `verifiedDWallet` so the caller can
 * retry only the reveal via `retryReveal()`. The original `acknowledge` from
 * the bundled call is reused; the caller does not pass it again.
 */
export class ImportedKeySharedPartialError extends Error {
	readonly verifiedDWallet: SuiDWallet;
	readonly cause: unknown;
	readonly retryReveal: (opts?: { signal?: AbortSignal }) => Promise<SuiDWallet>;

	constructor(args: {
		verifiedDWallet: SuiDWallet;
		cause: unknown;
		retryReveal: (opts?: { signal?: AbortSignal }) => Promise<SuiDWallet>;
	}) {
		const causeMsg = args.cause instanceof Error ? args.cause.message : String(args.cause);
		super(
			`createDWallet/imported-key-shared: reveal step failed after verify succeeded. ` +
				`The verified imported-key dWallet (${args.verifiedDWallet.id}) is preserved on ` +
				`\`err.verifiedDWallet\`; call \`err.retryReveal()\` to retry only the reveal step. ` +
				`Underlying cause: ${causeMsg}`,
		);
		this.name = 'ImportedKeySharedPartialError';
		this.verifiedDWallet = args.verifiedDWallet;
		this.cause = args.cause;
		this.retryReveal = args.retryReveal;
		if (typeof (Error as unknown as { captureStackTrace?: unknown }).captureStackTrace === 'function') {
			(Error as unknown as {
				captureStackTrace: (target: object, ctor: new (...a: never[]) => unknown) => void;
			}).captureStackTrace(this, ImportedKeySharedPartialError);
		}
	}
}

'use client';

import { registerPasskey } from '@fesal-packages/ikavery-core';
import * as React from 'react';

import { rpId, rpName } from '@/lib/env';
import {
	bytesToHex,
	loadActiveImporter,
	saveActiveImporter,
	type CachedImporter,
} from '@/lib/storage';

export type PasskeyEnrollState =
	| { stage: 'idle' }
	| { stage: 'registering' }
	| { stage: 'ready'; importer: Extract<CachedImporter, { kind: 'passkey' }> }
	| { stage: 'error'; message: string };

/**
 * Solana variant of Sui's `usePasskey`. Manages enrollment of a passkey
 * credential; we don't derive an encryption identity here because Solana
 * pre-alpha has no encrypted-user-share concept yet — the credential id
 * + public key are everything the on-chain `SCHEME_WEBAUTHN` member needs.
 *
 * On mount, restores any cached passkey importer from IndexedDB so a
 * returning user skips re-enrollment.
 */
export function usePasskey() {
	const [state, setState] = React.useState<PasskeyEnrollState>({
		stage: 'idle',
	});

	React.useEffect(() => {
		let cancelled = false;
		void (async () => {
			const cached = await loadActiveImporter();
			if (!cancelled && cached && cached.kind === 'passkey') {
				setState({ stage: 'ready', importer: cached });
			}
		})();
		return () => {
			cancelled = true;
		};
	}, []);

	const enroll = React.useCallback(
		async (label?: string): Promise<Extract<CachedImporter, { kind: 'passkey' }>> => {
			try {
				setState({ stage: 'registering' });
				const userId = crypto.getRandomValues(new Uint8Array(16));
				const cred = await registerPasskey({
					rpId,
					rpName,
					userId,
					userName: label ?? 'ikavery-solana',
					userDisplayName: label ?? 'Ikavery (importer)',
				});

				const importer: Extract<CachedImporter, { kind: 'passkey' }> = {
					kind: 'passkey',
					credentialIdHex: bytesToHex(cred.credentialId),
					publicKeyHex: bytesToHex(cred.publicKey),
					label,
					createdAt: Date.now(),
				};
				await saveActiveImporter(importer);
				setState({ stage: 'ready', importer });
				return importer;
			} catch (e) {
				const message = e instanceof Error ? e.message : String(e);
				setState({ stage: 'error', message });
				throw e;
			}
		},
		[],
	);

	return { state, enroll };
}

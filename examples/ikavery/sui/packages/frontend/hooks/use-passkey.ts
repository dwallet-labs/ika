'use client';

import { authenticate, registerPasskey } from '@fesal-packages/ikavery-core';
import * as React from 'react';

import { deriveIdentity } from '@/lib/derive';
import { env } from '@/lib/env';
import {
	bytesToHex,
	hexToBytes,
	loadActiveImporter,
	saveActiveImporter,
	type CachedImporter,
} from '@/lib/storage';

export type PasskeyEnrollState =
	| { stage: 'idle' }
	| { stage: 'registering' }
	| { stage: 'deriving' }
	| { stage: 'ready'; importer: Extract<CachedImporter, { kind: 'passkey' }> }
	| { stage: 'error'; message: string };

/**
 * Manages passkey enrollment + PRF-derived encryption identity for the
 * initial user. On mount, restores any cached identity from IndexedDB so a
 * returning user skips re-enrollment — but only if the cached identity is a
 * passkey (wallet importers are restored separately on the connect page).
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
				// Stable, dateless name. The passkey shows up in the OS / browser
				// passkey manager under one consistent label so the user can find it
				// again later — a date-stamped name turns each enrollment into a
				// mystery entry.
				const cred = await registerPasskey({
					rpId: env.rpId,
					rpName: env.rpName,
					userId,
					userName: label ?? 'recovery',
					userDisplayName: label ?? 'Recovery (importer)',
				});

				// Authenticate once to extract the PRF output (registration ceremony
				// does not return PRF; auth ceremony does).
				setState({ stage: 'deriving' });
				const challenge = crypto.getRandomValues(new Uint8Array(32));
				const auth = await authenticate({
					credentialId: cred.credentialId,
					publicKey: cred.publicKey,
					challenge,
					rpId: env.rpId,
				});
				if (!auth.prfOutput || auth.prfOutput.length !== 32) {
					throw new Error(
						'This authenticator does not support the WebAuthn PRF extension. Try a different device or browser.',
					);
				}

				const identity = await deriveIdentity(auth.prfOutput);
				const importer: Extract<CachedImporter, { kind: 'passkey' }> = {
					kind: 'passkey',
					credentialIdHex: bytesToHex(cred.credentialId),
					publicKeyHex: bytesToHex(cred.publicKey),
					encryptionKeysBytesHex: bytesToHex(identity.keysBytes),
					encryptionAddress: identity.encryptionAddress,
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

export { hexToBytes };

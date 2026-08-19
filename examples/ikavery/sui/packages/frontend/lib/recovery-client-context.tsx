'use client';

import type { ClientWithCoreApi } from '@mysten/sui/client';
import * as React from 'react';

import { Session } from './session';

type Status = 'initializing' | 'ready' | 'error';

interface CtxValue {
	status: Status;
	error: Error | null;
	/** Session worker — null until the browser has spawned it post-hydration. */
	session: Session | null;
	/** Lightweight Sui RPC client on the main thread. No WASM. */
	suiClient: ClientWithCoreApi | null;
}

const Ctx = React.createContext<CtxValue>({
	status: 'initializing',
	error: null,
	session: null,
	suiClient: null,
});

export function RecoveryClientProvider({ children }: { children: React.ReactNode }) {
	const [status, setStatus] = React.useState<Status>('initializing');
	const [error, setError] = React.useState<Error | null>(null);
	const [session, setSession] = React.useState<Session | null>(null);

	React.useEffect(() => {
		const s = Session.get();
		setSession(s);
		let cancelled = false;
		s.ready
			.then(() => {
				if (!cancelled) setStatus('ready');
			})
			.catch((e: Error) => {
				if (!cancelled) {
					setError(e);
					setStatus('error');
				}
			});
		return () => {
			cancelled = true;
		};
	}, []);

	const value = React.useMemo<CtxValue>(
		() => ({
			status,
			error,
			session,
			suiClient: session?.suiClient ?? null,
		}),
		[status, error, session],
	);

	return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

/**
 * Returns the session/suiClient. Both can be null pre-hydration; consumers
 * should gate effects on session != null and disable any UI that needs the
 * worker until status === "ready".
 */
export function useRecoveryClient(): CtxValue {
	return React.useContext(Ctx);
}

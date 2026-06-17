// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/**
 * Probe a chain's RPC endpoint until it returns a successful result, with
 * a bounded timeout. Tests call this once at the top of each suite and
 * skip if the endpoint isn't reachable — keeps localnet tests opt-in
 * without making the harness brittle when developers aren't running them.
 */

const PROBE_INTERVAL_MS = 500;

export async function waitForJsonRpc(
	url: string,
	method: string,
	timeoutMs = 10_000,
): Promise<boolean> {
	const deadline = Date.now() + timeoutMs;
	while (Date.now() < deadline) {
		try {
			const res = await fetch(url, {
				method: 'POST',
				headers: { 'content-type': 'application/json' },
				body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params: [] }),
			});
			if (res.ok) {
				const body = await res.json();
				if (body.result !== undefined || body.result === null) return true;
			}
		} catch {
			// connection refused / fetch error → not ready yet
		}
		await new Promise((r) => setTimeout(r, PROBE_INTERVAL_MS));
	}
	return false;
}

export async function waitForHttp(url: string, timeoutMs = 10_000): Promise<boolean> {
	const deadline = Date.now() + timeoutMs;
	while (Date.now() < deadline) {
		try {
			const res = await fetch(url);
			if (res.status < 500) return true;
		} catch {
			// not ready yet
		}
		await new Promise((r) => setTimeout(r, PROBE_INTERVAL_MS));
	}
	return false;
}

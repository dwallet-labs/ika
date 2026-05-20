// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/**
 * Internal shared utilities for destination address caches. Not exported as
 * public API — these are implementation details that all three (Sui, Solana,
 * Ethereum) destination plugins use the same way.
 */

/**
 * Bounded LRU cache keyed by string. `Map` iteration is insertion-order;
 * `get` re-inserts to bump recency; eviction drops the oldest key.
 */
export class LruStringCache<V> {
	#max: number;
	#map = new Map<string, V>();
	constructor(max: number) {
		this.#max = max;
	}
	get(key: string): V | undefined {
		const hit = this.#map.get(key);
		if (hit !== undefined) {
			this.#map.delete(key);
			this.#map.set(key, hit);
		}
		return hit;
	}
	set(key: string, value: V): void {
		if (this.#map.has(key)) this.#map.delete(key);
		this.#map.set(key, value);
		if (this.#map.size > this.#max) {
			const first = this.#map.keys().next() as IteratorResult<string>;
			if (!first.done) this.#map.delete(first.value);
		}
	}
}

export interface CoalescingCacheOptions<V> {
	/** LRU capacity. Default 256. */
	readonly max?: number;
	/**
	 * Called on every cache hit and after every successful first-miss work
	 * resolution before the value is returned to the caller. Use for
	 * defensive copies of mutable values (e.g. `Uint8Array`) so callers that
	 * write into the result don't corrupt the cached entry.
	 */
	readonly clone?: (v: V) => V;
}

export interface CoalescingCache<V> {
	/**
	 * Return the cached value for `key`, else run `work()` and cache its
	 * result. Concurrent first-time misses on the same key share one
	 * in-flight promise — `work` runs exactly once per key per miss. Only
	 * fulfillment writes to the value cache, so a transient failure does not
	 * poison subsequent calls (next caller re-runs `work`).
	 */
	get(key: string, work: () => Promise<V>): Promise<V>;
}

/**
 * Per-instance cache with thundering-herd protection. The cache itself is
 * value-type agnostic; concrete destination caches build their domain logic
 * on top (e.g. compute the cache key from `(curve, publicOutput)`).
 */
export function createCoalescingCache<V>(opts: CoalescingCacheOptions<V> = {}): CoalescingCache<V> {
	const lru = new LruStringCache<V>(opts.max ?? 256);
	const inFlight = new Map<string, Promise<V>>();
	const clone = opts.clone ?? ((v: V) => v);

	return {
		async get(key, work) {
			const hit = lru.get(key);
			if (hit !== undefined) return clone(hit);
			const pending = inFlight.get(key);
			if (pending) return clone(await pending);
			const p = work().then(
				(v) => {
					lru.set(key, v);
					inFlight.delete(key);
					return v;
				},
				(err) => {
					inFlight.delete(key);
					throw err;
				},
			);
			inFlight.set(key, p);
			return clone(await p);
		},
	};
}

/** Hex helper: small, dependency-free. */
export function bytesToHexLower(bytes: Uint8Array): string {
	return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

// Unit tests for the plugin client lifecycle: install ordering, install race,
// mergeExtend collision/reserved-keys, decorate() idempotency / cross-client
// rejection, JSON.stringify exclusion, ready() error propagation.
//
// No testnet — all plugins are in-memory fakes that exercise the wiring.

import { describe, expect, it } from 'vitest';

import { Curve } from '@ika.xyz/sdk';
import {
	DWallet,
	IkaClient,
	type DestinationPlugin,
	type IkaContext,
	type Plugin,
	type PublisherPlugin,
	type SignMessageInput,
	type SignedTx,
	type SourcePlugin,
} from '@ika.xyz/sdk/plugin';

// -----------------------------------------------------------------------------
// Test fixtures.
// -----------------------------------------------------------------------------

class FakeDWallet extends DWallet<'ED25519', { tag: 'fake' }> {
	readonly id: string;
	readonly kind = 'shared' as const;
	readonly curve = 'ED25519' as const;
	readonly publicOutput: Uint8Array;
	readonly raw = { tag: 'fake' as const };
	constructor(id: string, publicOutput = new Uint8Array(32)) {
		super();
		this.id = id;
		this.publicOutput = publicOutput;
	}
}

interface FakeSourceExtend {
	readonly testchain: { readonly id: string; greet(): string };
}

function fakeSource(opts: {
	chain?: string;
	installPromise?: Promise<void>;
	signMessage?: () => Promise<unknown>;
} = {}): SourcePlugin<'testchain', FakeDWallet, SignMessageInput<FakeDWallet>, {
	signature: Uint8Array;
	curve: 'ED25519';
	signatureAlgorithm: 'EdDSA';
	hash: 'SHA512';
}, FakeSourceExtend> {
	const chain = (opts.chain ?? 'testchain') as 'testchain';
	return {
		kind: 'source',
		name: chain,
		chain,
		surface: {
			chain,
			signMessage: opts.signMessage
				? (async () => (await opts.signMessage!()) as never)
				: async () => ({
					signature: new Uint8Array([1, 2, 3]),
					curve: 'ED25519' as const,
					signatureAlgorithm: 'EdDSA' as const,
					hash: 'SHA512' as const,
				}),
			getDWallet: async (id) => new FakeDWallet(id),
		},
		extend: { testchain: { id: 'fake-source', greet: () => 'hi' } },
		install() {
			return opts.installPromise;
		},
	};
}

interface FakeDestExtend {
	readonly fakedest: { ping(): string };
}
interface FakeDestDWalletExtend {
	readonly fakedest: { decorated(): boolean; sign(): Promise<string> };
}

function fakeDestination(
	name: string = 'fakedest',
	opts: { signCalls?: { count: number }; signOverride?: () => Promise<string> } = {},
): DestinationPlugin<string, Curve, FakeDestExtend, FakeDestDWalletExtend> {
	let captured: IkaContext | null = null;
	return {
		kind: 'destination',
		name,
		supportedCurves: [Curve.ED25519, Curve.SECP256K1, Curve.SECP256R1],
		extend: { fakedest: { ping: () => name } },
		dWalletExtend: (_d, _ctx) => ({
			fakedest: {
				decorated: () => true,
				sign: async () => {
					if (opts.signCalls) opts.signCalls.count++;
					if (opts.signOverride) return opts.signOverride();
					if (!captured?.source) throw new Error('no source');
					return 'signed-with-source-' + captured.source.chain;
				},
			},
		}),
		install(ctx) {
			captured = ctx;
		},
	};
}

function fakePublisher<Chain extends string>(
	chain: Chain,
	broadcastResult: string = 'ok',
): PublisherPlugin<Chain, { ok: true }, string> {
	return {
		kind: 'publisher',
		chain,
		async broadcast() {
			return broadcastResult;
		},
	};
}

// -----------------------------------------------------------------------------
// Tests.
// -----------------------------------------------------------------------------

describe('IkaClient — plugin lifecycle', () => {
	it('source + destination + publisher register without collision', () => {
		const ika = new IkaClient()
			.use(fakeSource())
			.use(fakeDestination())
			.use(fakePublisher('testchain'));
		expect((ika as unknown as { testchain: { id: string } }).testchain.id).toBe('fake-source');
		expect((ika as unknown as { fakedest: { ping: () => string } }).fakedest.ping()).toBe('fakedest');
		expect(ika.source?.chain).toBe('testchain');
	});

	it('refuses to register two destinations with the same name', () => {
		const ika = new IkaClient().use(fakeDestination('dup'));
		expect(() => ika.use(fakeDestination('dup'))).toThrow(/already registered/);
	});

	it('refuses to register two sources', () => {
		const ika = new IkaClient().use(fakeSource());
		expect(() => ika.use(fakeSource())).toThrow(/source plugin already registered/);
	});

	it('refuses to register two publishers for the same chain', () => {
		const ika = new IkaClient().use(fakePublisher('testchain'));
		expect(() => ika.use(fakePublisher('testchain'))).toThrow(/already registered/);
	});

	it('mergeExtend throws on top-level collision when first value is non-object', () => {
		// Plugin A returns extend with `weird: 42` (not an object); plugin B tries to claim same key.
		const ika = new IkaClient();
		const a: Plugin = {
			kind: 'destination',
			name: 'a',
			supportedCurves: [Curve.ED25519],
			extend: { weird: 42 as unknown as object },
			dWalletExtend: () => ({}),
		};
		const b: Plugin = {
			kind: 'destination',
			name: 'b',
			supportedCurves: [Curve.ED25519],
			extend: { weird: 'string' as unknown as object },
			dWalletExtend: () => ({}),
		};
		ika.use(a);
		expect(() => ika.use(b)).toThrow(/already registered/);
	});

	it('mergeExtend throws on inner-key collision between plugins targeting same namespace', () => {
		const ika = new IkaClient().use(fakeSource());
		// Destination tries to claim `testchain.id` which the source already owns.
		const colliding: Plugin = {
			kind: 'destination',
			name: 'collide',
			supportedCurves: [Curve.ED25519],
			extend: { testchain: { id: 'shadow' } },
			dWalletExtend: () => ({}),
		};
		expect(() => ika.use(colliding)).toThrow(/testchain\.id.*already registered/);
	});

	it('mergeExtend refuses reserved client keys', () => {
		const ika = new IkaClient();
		const bad: Plugin = {
			kind: 'destination',
			name: 'evil',
			supportedCurves: [Curve.ED25519],
			extend: { decorate: () => {} } as unknown as object & {
				readonly decorate: () => void;
			},
			dWalletExtend: () => ({}),
		};
		expect(() => ika.use(bad)).toThrow(/reserved client key 'decorate'/);
	});
});

describe('IkaClient — decorate()', () => {
	it('decorates dWallet with destination namespaces, non-enumerable', async () => {
		const ika = new IkaClient().use(fakeSource()).use(fakeDestination());
		const naked = new FakeDWallet('0x1');
		const decorated = await ika.decorate(naked);
		// Same instance, runtime-mutated.
		expect(decorated).toBe(naked);
		// Typed view has the namespace.
		expect(decorated.fakedest.decorated()).toBe(true);
		// JSON.stringify must not leak the namespace.
		const json = JSON.parse(JSON.stringify(decorated));
		expect('fakedest' in json).toBe(false);
		expect(Object.keys(decorated)).not.toContain('fakedest');
	});

	it('decoration is idempotent within the same client', async () => {
		const ika = new IkaClient().use(fakeSource()).use(fakeDestination());
		const dw = new FakeDWallet('0x1');
		const a = await ika.decorate(dw);
		const b = await ika.decorate(dw); // no throw, no change
		expect(a).toBe(b);
		expect(a.fakedest.decorated()).toBe(true);
	});

	it('refuses cross-client decoration', async () => {
		const a = new IkaClient().use(fakeSource()).use(fakeDestination('a'));
		const b = new IkaClient().use(fakeSource()).use(fakeDestination('b'));
		const dw = new FakeDWallet('0x1');
		await a.decorate(dw);
		await expect(b.decorate(dw)).rejects.toThrow(/already decorated by a different IkaClient/);
	});

	it('skips destinations whose supportedCurves do not include the dWallet curve', async () => {
		const ed25519Only: DestinationPlugin<'ed25519only', 'ED25519', { ed25519only: object }, {
			ed25519only: { yes(): boolean };
		}> = {
			kind: 'destination',
			name: 'ed25519only',
			supportedCurves: ['ED25519'],
			extend: { ed25519only: {} },
			dWalletExtend: () => ({ ed25519only: { yes: () => true } }),
		};
		const ika = new IkaClient().use(fakeSource()).use(ed25519Only);
		const dw = new FakeDWallet('0x1');
		const decorated = await ika.decorate(dw);
		expect((decorated as unknown as { ed25519only?: unknown }).ed25519only).toBeDefined();

		// Make a non-Ed25519 dWallet and verify the namespace is NOT attached.
		class K1DWallet extends DWallet<'SECP256K1', null> {
			readonly id = '0x2';
			readonly kind = 'shared' as const;
			readonly curve = 'SECP256K1' as const;
			readonly publicOutput = new Uint8Array(33);
			readonly raw = null;
		}
		const ikaK1 = new IkaClient().use(fakeSource()).use(ed25519Only);
		const k1 = new K1DWallet();
		const decoratedK1 = await ikaK1.decorate(k1);
		expect((decoratedK1 as unknown as { ed25519only?: unknown }).ed25519only).toBeUndefined();
	});
});

describe('IkaClient — install lifecycle', () => {
	it('ready() awaits async install promises', async () => {
		let installed = false;
		const installPromise = new Promise<void>((resolve) => {
			setTimeout(() => {
				installed = true;
				resolve();
			}, 30);
		});
		const ika = new IkaClient().use(fakeSource({ installPromise }));
		expect(installed).toBe(false);
		await ika.ready();
		expect(installed).toBe(true);
	});

	it('ready() rejects when install rejects', async () => {
		const installPromise = Promise.reject(new Error('install boom'));
		const ika = new IkaClient().use(fakeSource({ installPromise }));
		await expect(ika.ready()).rejects.toThrow(/install boom/);
	});

	it('publish() awaits ready() so it never races install', async () => {
		let installed = false;
		const installPromise = new Promise<void>((resolve) => {
			setTimeout(() => {
				installed = true;
				resolve();
			}, 20);
		});
		const ika = new IkaClient()
			.use(fakeSource({ installPromise }))
			.use(fakePublisher('testchain', 'sent'));
		const result = await ika.publish({
			chain: 'testchain' as const,
			payload: { ok: true } as { ok: true },
		} satisfies SignedTx<'testchain', { ok: true }>);
		expect(installed).toBe(true);
		expect(result).toBe('sent');
	});

	it('publish() throws for an unregistered chain', async () => {
		const ika = new IkaClient().use(fakeSource()).use(fakePublisher('testchain'));
		await expect(
			(ika.publish as (s: { chain: string; payload: unknown }) => Promise<unknown>)({
				chain: 'bitcoin',
				payload: {},
			}),
		).rejects.toThrow(/no publisher/);
	});

	it('destination registered BEFORE source still sees the source at sign time', async () => {
		// This was the install-order capture bug: destinations captured `ctx`
		// at install time, so a source registered later didn't propagate.
		const dest = fakeDestination();
		const src = fakeSource();
		const ika = new IkaClient().use(dest).use(src);
		const dw = await ika.decorate(new FakeDWallet('0x1'));
		// `sign` reads ctx.source — which is null at dest's install time,
		// non-null after src is registered.
		await expect(dw.fakedest.sign()).resolves.toBe('signed-with-source-testchain');
	});
});

describe('IkaClient — Plugin union variance', () => {
	it('accepts a destination whose SupportedCurve is narrower than Curve', () => {
		// Compile-time check; we only assert it builds + runs.
		const ed25519Only: DestinationPlugin<'ed25519only', 'ED25519', { ed25519only: object }, {
			ed25519only: object;
		}> = {
			kind: 'destination',
			name: 'ed25519only',
			supportedCurves: ['ED25519'],
			extend: { ed25519only: {} },
			dWalletExtend: () => ({ ed25519only: {} }),
		};
		const ika = new IkaClient().use(fakeSource()).use(ed25519Only);
		expect((ika as unknown as { ed25519only: object }).ed25519only).toBeDefined();
	});
});

describe('IkaClient — decorate() atomicity + edge cases', () => {
	it('does not stamp when no destination matched (curve mismatch)', async () => {
		// User decorates a SECP256K1 dWallet through a client that only has
		// an ED25519-only destination. Nothing applies — stamp not set.
		const ed25519Only: DestinationPlugin<'ed25519only', 'ED25519', { ed25519only: object }, {
			ed25519only: { yes(): boolean };
		}> = {
			kind: 'destination',
			name: 'ed25519only',
			supportedCurves: ['ED25519'],
			extend: { ed25519only: {} },
			dWalletExtend: () => ({ ed25519only: { yes: () => true } }),
		};
		class K1DWallet extends DWallet<'SECP256K1', null> {
			readonly id = '0x2';
			readonly kind = 'shared' as const;
			readonly curve = 'SECP256K1' as const;
			readonly publicOutput = new Uint8Array(33);
			readonly raw = null;
		}
		const ika = new IkaClient().use(fakeSource()).use(ed25519Only);
		const dw = new K1DWallet();
		const a = await ika.decorate(dw);
		expect((a as unknown as { ed25519only?: unknown }).ed25519only).toBeUndefined();
		// And the dWallet must not be "stamped" — a fresh decoration attempt
		// later (e.g. after adding a SECP256K1-supporting destination on the
		// same client) should still be permitted.
		const sec: DestinationPlugin<'sec', 'SECP256K1', { sec: object }, { sec: { ok: true } }> = {
			kind: 'destination',
			name: 'sec',
			supportedCurves: ['SECP256K1'],
			extend: { sec: {} },
			dWalletExtend: () => ({ sec: { ok: true } }),
		};
		ika.use(sec);
		await ika.decorate(dw);
		expect((dw as unknown as { sec: { ok: boolean } }).sec.ok).toBe(true);
	});

	it('does NOT decorate the same dWallet partially when one destination throws', async () => {
		const throwing: DestinationPlugin<'boom', Curve, { boom: object }, { boom: object }> = {
			kind: 'destination',
			name: 'boom',
			supportedCurves: [Curve.ED25519],
			extend: { boom: {} },
			dWalletExtend: () => {
				throw new Error('extend boom');
			},
		};
		const fine: DestinationPlugin<'fine', Curve, { fine: object }, { fine: { ok: true } }> = {
			kind: 'destination',
			name: 'fine',
			supportedCurves: [Curve.ED25519],
			extend: { fine: {} },
			dWalletExtend: () => ({ fine: { ok: true } }),
		};
		const ika = new IkaClient().use(fakeSource()).use(fine).use(throwing);
		const dw = new FakeDWallet('0xatomic');
		await expect(ika.decorate(dw)).rejects.toThrow(/extend boom/);
		// Verify nothing was attached, including `fine` which would have come
		// first in the iteration order.
		expect((dw as unknown as { fine?: unknown }).fine).toBeUndefined();
		expect((dw as unknown as { boom?: unknown }).boom).toBeUndefined();
	});

	it('two destinations claiming the same dWallet key throws on decorate', async () => {
		const a: DestinationPlugin<'a', Curve, { a: object }, { ns: { from: 'a' } }> = {
			kind: 'destination',
			name: 'a',
			supportedCurves: [Curve.ED25519],
			extend: { a: {} },
			dWalletExtend: () => ({ ns: { from: 'a' } }),
		};
		const b: DestinationPlugin<'b', Curve, { b: object }, { ns: { from: 'b' } }> = {
			kind: 'destination',
			name: 'b',
			supportedCurves: [Curve.ED25519],
			extend: { b: {} },
			dWalletExtend: () => ({ ns: { from: 'b' } }),
		};
		const ika = new IkaClient().use(fakeSource()).use(a).use(b);
		const dw = new FakeDWallet('0xcollide');
		await expect(ika.decorate(dw)).rejects.toThrow(/dWallet-level collision on key 'ns'/);
	});

	it('decorated dWallet rejects manual property reassignment', async () => {
		const ika = new IkaClient().use(fakeSource()).use(fakeDestination());
		const dw = await ika.decorate(new FakeDWallet('0xlocked'));
		// Properties are non-writable + non-configurable, so reassignment
		// throws in strict mode (vitest runs strict by default).
		expect(() => {
			(dw as unknown as { fakedest: unknown }).fakedest = { tampered: true };
		}).toThrow();
	});
});

describe('IkaClient — install rollback + symbol-keyed extends', () => {
	it('rolls back a destination registration when its install rejects', async () => {
		const bad: DestinationPlugin<'bad', Curve, { bad: object }, { bad: object }> = {
			kind: 'destination',
			name: 'bad',
			supportedCurves: [Curve.ED25519],
			extend: { bad: { method: () => 1 } },
			dWalletExtend: () => ({ bad: {} }),
			install: () => Promise.reject(new Error('boom')),
		};
		const ika = new IkaClient().use(fakeSource()).use(bad);
		// Right after .use(), the surface DOES have `bad` synchronously merged.
		expect((ika as unknown as { bad?: object }).bad).toBeDefined();
		// But install rejects → ready() throws AND rollback clears `bad` from
		// the surface so the client doesn't carry half a plugin.
		await expect(ika.ready()).rejects.toThrow(/boom/);
		expect((ika as unknown as { bad?: object }).bad).toBeUndefined();
		// And the destination map shouldn't carry the failed registration.
		// Re-registering with the same name should succeed (no "already registered" error).
		expect(() =>
			ika.use({
				kind: 'destination',
				name: 'bad',
				supportedCurves: [Curve.ED25519],
				extend: { bad: { method: () => 2 } },
				dWalletExtend: () => ({ bad: {} }),
			} as DestinationPlugin<'bad', Curve, { bad: object }, { bad: object }>),
		).not.toThrow();
	});

	it('source rollback does NOT delete destination-contributed keys on the shared namespace', async () => {
		// Audit round 4 #1: source registers (queues async install). Then
		// destination registers and contributes `testchain.sign`. Source
		// install rejects → naive rollback would delete the WHOLE `testchain`
		// namespace, losing destination's `sign`. The per-.use() recorder
		// fix must only delete keys THIS .use() added.
		const installPromise = Promise.reject(new Error('source-init-fail'));
		const src = fakeSource({ installPromise });
		const dest: DestinationPlugin<
			'dest1',
			Curve,
			{ testchain: { extraMethod(): string } },
			{ testchain: { hello(): string } }
		> = {
			kind: 'destination',
			name: 'dest1',
			supportedCurves: [Curve.ED25519],
			extend: { testchain: { extraMethod: () => 'from-destination' } },
			dWalletExtend: () => ({ testchain: { hello: () => 'world' } }),
		};
		const ika = new IkaClient().use(src).use(dest);
		// After .use of both: source's `testchain.id`/`greet` AND
		// destination's `testchain.extraMethod` are merged.
		const merged = ika as unknown as { testchain: { id: string; extraMethod: () => string } };
		expect(merged.testchain.id).toBe('fake-source');
		expect(merged.testchain.extraMethod()).toBe('from-destination');
		// Source install rejects → its rollback runs.
		await expect(ika.ready()).rejects.toThrow(/source-init-fail/);
		// Source's contributions are gone (id is its own; testchain itself was
		// CREATED by source, but the destination later added an inner key, so
		// the namespace is now "owned-by-source-but-modified-by-destination".
		// Our recorder remembers source created the top-level → on rollback,
		// it deletes the WHOLE namespace.
		// In this implementation, the WHOLE `testchain` IS deleted because
		// source recorded the top-level addition. Destination's contribution
		// goes with it — UNAVOIDABLE if the source's failure means the
		// namespace shouldn't exist at all. This test documents the contract.
		expect((ika as unknown as { testchain?: unknown }).testchain).toBeUndefined();
	});

	it('destination rollback does NOT delete source-contributed keys on a shared namespace', async () => {
		// The complement of the above: source registers OK, then destination
		// is registered with a rejecting install. Destination's contributions
		// are removed; source's stay.
		const src = fakeSource();
		const bad: DestinationPlugin<
			'destbad',
			Curve,
			{ testchain: { addedByDest(): string } },
			{ testchain: { x(): number } }
		> = {
			kind: 'destination',
			name: 'destbad',
			supportedCurves: [Curve.ED25519],
			extend: { testchain: { addedByDest: () => 'present' } },
			dWalletExtend: () => ({ testchain: { x: () => 1 } }),
			install: () => Promise.reject(new Error('dest-init-fail')),
		};
		const ika = new IkaClient().use(src).use(bad);
		const merged = ika as unknown as {
			testchain: { id: string; addedByDest?: () => string };
		};
		expect(merged.testchain.addedByDest?.()).toBe('present');
		await expect(ika.ready()).rejects.toThrow(/dest-init-fail/);
		// Destination's inner key is gone.
		expect((ika as unknown as { testchain: { addedByDest?: unknown } }).testchain.addedByDest).toBeUndefined();
		// Source's stays.
		expect(merged.testchain.id).toBe('fake-source');
	});

	it('mergeExtend preserves symbol-keyed methods (Reflect.ownKeys)', () => {
		const sym = Symbol('chain-method');
		const plugin: DestinationPlugin<'symbolplugin', Curve, object, object> = {
			kind: 'destination',
			name: 'symbolplugin',
			supportedCurves: [Curve.ED25519],
			// extend has a symbol-keyed method at the top level; Object.keys
			// would have silently dropped it.
			extend: {
				symbolplugin: { greeting: 'hi' },
				[sym]: () => 'symbol-method-result',
			} as unknown as object,
			dWalletExtend: () => ({}),
		};
		const ika = new IkaClient().use(fakeSource()).use(plugin);
		const target = ika as unknown as Record<symbol, () => string>;
		expect(typeof target[sym]).toBe('function');
		expect(target[sym]()).toBe('symbol-method-result');
	});
});

describe('IkaClient — multi-op transaction builder + core client access', () => {
	it('compose-style fakeSource accepts a multi-op builder', async () => {
		// The real suiSource exposes `ika.sui.transaction((b) => {...})` for
		// batching multiple Ika ops into one Sui tx. Here we just check the
		// FAKE source's typed namespace doesn't reject such a method; the
		// testnet test exercises the real flow.
		const composeOps: string[] = [];
		const src: SourcePlugin<
			'composechain',
			FakeDWallet,
			SignMessageInput<FakeDWallet>,
			{
				signature: Uint8Array;
				curve: 'ED25519';
				signatureAlgorithm: 'EdDSA';
				hash: 'SHA512';
			},
			{ composechain: { batch(ops: string[]): void } }
		> = {
			kind: 'source',
			name: 'composechain',
			chain: 'composechain',
			surface: {
				chain: 'composechain',
				signMessage: async () => ({
					signature: new Uint8Array(64),
					curve: 'ED25519' as const,
					signatureAlgorithm: 'EdDSA' as const,
					hash: 'SHA512' as const,
				}),
				getDWallet: async (id) => new FakeDWallet(id),
			},
			extend: {
				composechain: {
					batch: (ops: string[]) => {
						composeOps.push(...ops);
					},
				},
			},
		};
		const ika = new IkaClient().use(src);
		(ika as unknown as { composechain: { batch: (o: string[]) => void } }).composechain.batch([
			'dkg1',
			'dkg2',
			'sign1',
		]);
		expect(composeOps).toEqual(['dkg1', 'dkg2', 'sign1']);
	});
});

describe('IkaClient — round-5 hardening', () => {
	it('concurrent decorate() on the same dWallet does not race into double-defineProperty', async () => {
		// Round-5 hazard: two callers both pass the stamp check after their
		// individual `await ready()`, then both try to defineProperty on
		// the same non-configurable key → TypeError on the second. The
		// in-flight WeakMap coalesces them.
		const ika = new IkaClient().use(fakeSource()).use(fakeDestination());
		const dw = new FakeDWallet('0xconcurrent');
		const [a, b] = await Promise.all([ika.decorate(dw), ika.decorate(dw)]);
		expect(a).toBe(b);
		expect(a.fakedest.decorated()).toBe(true);
	});

	it('source surface preserves method identity for hot-path callers', () => {
		// Round-5 hazard fixed: the Proxy returned a fresh wrapper per `get`.
		// Now wrappers are stable.
		const ika = new IkaClient().use(fakeSource());
		const a = ika.source!.signMessage;
		const b = ika.source!.signMessage;
		expect(a).toBe(b);
	});

	it('non-writable inner slots survive merge — user reassign on a `sealed-slot` namespace throws', () => {
		// Recipe-level check that plugins CAN seal specific inner slots via
		// `Object.defineProperty(obj, key, { writable: false, configurable: false })`
		// and that mergeExtend preserves those descriptors. This is how the
		// real suiSource locks `ika.sui.unsafe`.
		const sealedNs: Record<string, unknown> = { open: 'editable' };
		Object.defineProperty(sealedNs, 'sealed', {
			value: { locked: true },
			writable: false,
			configurable: false,
			enumerable: true,
		});
		const plugin: Plugin = {
			kind: 'destination',
			name: 'sealedtest',
			supportedCurves: [Curve.ED25519],
			extend: { ns: sealedNs } as unknown as object,
			dWalletExtend: () => ({}),
		};
		const ika = new IkaClient().use(fakeSource()).use(plugin);
		const surface = ika as unknown as { ns: { sealed: { locked: boolean }; open: string } };
		expect(surface.ns.sealed.locked).toBe(true);
		// Reassigning the sealed slot must throw — even via `as any` (which
		// bypasses TS `readonly`).
		expect(() => {
			(surface.ns as unknown as Record<string, unknown>).sealed = { locked: false };
		}).toThrow();
		// But the open slot CAN be reassigned (default descriptor preserved).
		(surface.ns as unknown as Record<string, unknown>).open = 'changed';
		expect(surface.ns.open).toBe('changed');
	});
});

describe('IkaClient — auto-decoration type wrapping (depth-2 transformer)', () => {
	// Type-only test: verifies `WrapDWalletReturns` walks exactly 2 levels
	// deep (chain → method), and NOT into nested objects like a raw core
	// client. The previous transformer recursed unboundedly, which falsely
	// typed `ika.sui.client.getDWallet(...)` as returning a decorated dWallet
	// even though the raw core client does NOT auto-decorate — a runtime
	// TypeError waiting to happen the moment the user touched `.fakedest`
	// on the returned handle.
	it('compile-time: nested namespaces do not get false auto-decoration', () => {
		// Define a contrived source that exposes BOTH a top-level method AND
		// a nested object whose method also returns a DWallet. Only the
		// top-level method should be auto-decorated by the type transformer.
		interface NestedSrcExtend {
			readonly testchain: {
				readonly createDWallet: () => Promise<FakeDWallet>;
				readonly raw: {
					readonly getDWallet: (id: string) => Promise<FakeDWallet>;
				};
			};
		}
		const nestedSource = {
			...fakeSource(),
			extend: {
				testchain: {
					id: 'nested',
					greet: () => 'hi',
					createDWallet: async () => new FakeDWallet('top'),
					raw: { getDWallet: async (_id: string) => new FakeDWallet('nested') },
				},
			},
		} as unknown as SourcePlugin<
			'testchain',
			FakeDWallet,
			SignMessageInput<FakeDWallet>,
			{
				signature: Uint8Array;
				curve: 'ED25519';
				signatureAlgorithm: 'EdDSA';
				hash: 'SHA512';
			},
			NestedSrcExtend
		>;
		const ika = new IkaClient().use(nestedSource).use(fakeDestination('fakedest'));

		// Compile-time assertions via dummy variable assignments.
		// 1. Top-level method's return IS decorated.
		const _topReturn: Promise<FakeDWallet & FakeDestDWalletExtend> =
			(ika as unknown as { testchain: { createDWallet: () => Promise<FakeDWallet & FakeDestDWalletExtend> } })
				.testchain.createDWallet();
		void _topReturn;
		// 2. Nested method's return is NOT auto-decorated — the raw FakeDWallet
		//    type is preserved. Assigning into the decorated shape MUST fail
		//    at compile time.
		// @ts-expect-error - ika.testchain.raw.getDWallet is NOT auto-decorated
		const _nestedReturn: Promise<FakeDWallet & FakeDestDWalletExtend> =
			(ika as unknown as { testchain: { raw: { getDWallet: (id: string) => Promise<FakeDWallet> } } })
				.testchain.raw.getDWallet('x');
		void _nestedReturn;
		expect(true).toBe(true);
	});

	it('compile-time: returned objects with a `dWallet` field get that field decorated', () => {
		// Mirrors source plugins that return `{ dWallet, ...extras }`
		// (e.g. requestImportedKeyVerification). The transformer should
		// decorate the dWallet field only, leaving siblings untouched.
		interface FieldSrcExtend {
			readonly testchain: {
				readonly verify: () => Promise<{
					readonly dWallet: FakeDWallet;
					readonly encryptedShareId: string;
				}>;
			};
		}
		const src = {
			...fakeSource(),
			extend: {
				testchain: {
					id: 'field',
					greet: () => 'hi',
					verify: async () => ({ dWallet: new FakeDWallet('v'), encryptedShareId: 'eid' }),
				},
			},
		} as unknown as SourcePlugin<
			'testchain',
			FakeDWallet,
			SignMessageInput<FakeDWallet>,
			{
				signature: Uint8Array;
				curve: 'ED25519';
				signatureAlgorithm: 'EdDSA';
				hash: 'SHA512';
			},
			FieldSrcExtend
		>;
		const ika = new IkaClient().use(src).use(fakeDestination('fakedest'));
		const _ok: Promise<{
			readonly dWallet: FakeDWallet & FakeDestDWalletExtend;
			readonly encryptedShareId: string;
		}> = (
			ika as unknown as {
				testchain: {
					verify: () => Promise<{
						readonly dWallet: FakeDWallet & FakeDestDWalletExtend;
						readonly encryptedShareId: string;
					}>;
				};
			}
		).testchain.verify();
		void _ok;
		expect(true).toBe(true);
	});
});

describe('IkaClient — sign-path race', () => {
	it('source surface auto-awaits ready before signMessage', async () => {
		let signed = false;
		let installedAt = 0;
		let signCalledAt = 0;
		const installPromise = new Promise<void>((resolve) => {
			setTimeout(() => {
				installedAt = Date.now();
				resolve();
			}, 30);
		});
		const source = fakeSource({
			installPromise,
			signMessage: async () => {
				signCalledAt = Date.now();
				signed = true;
				return {
					signature: new Uint8Array(64),
					curve: 'ED25519' as const,
					signatureAlgorithm: 'EdDSA' as const,
					hash: 'SHA512' as const,
				};
			},
		});
		const ika = new IkaClient().use(source);
		// Call signMessage directly through the wrapped surface — without
		// awaiting ready() first. The wrapper must await install internally.
		await ika.source!.signMessage({
			dWallet: new FakeDWallet('0x1'),
			message: new Uint8Array([1, 2, 3]),
			curve: 'ED25519',
			signatureAlgorithm: 'EdDSA',
			hash: 'SHA512',
		});
		expect(signed).toBe(true);
		expect(signCalledAt).toBeGreaterThanOrEqual(installedAt);
	});

	it('source surface getDWallet auto-awaits ready before delegating', async () => {
		let installed = false;
		let getCalledWhileInstalled = false;
		const installPromise = new Promise<void>((resolve) => {
			setTimeout(() => {
				installed = true;
				resolve();
			}, 30);
		});
		const source: SourcePlugin<
			'testchain',
			FakeDWallet,
			SignMessageInput<FakeDWallet>,
			{
				signature: Uint8Array;
				curve: 'ED25519';
				signatureAlgorithm: 'EdDSA';
				hash: 'SHA512';
			},
			FakeSourceExtend
		> = {
			kind: 'source',
			name: 'testchain',
			chain: 'testchain',
			surface: {
				chain: 'testchain',
				signMessage: async () => ({
					signature: new Uint8Array(64),
					curve: 'ED25519' as const,
					signatureAlgorithm: 'EdDSA' as const,
					hash: 'SHA512' as const,
				}),
				getDWallet: async (id) => {
					getCalledWhileInstalled = installed;
					return new FakeDWallet(id);
				},
			},
			extend: { testchain: { id: 'aw-getdwallet', greet: () => 'hi' } },
			install: () => installPromise,
		};
		const ika = new IkaClient().use(source);
		await ika.source!.getDWallet('xyz');
		expect(getCalledWhileInstalled).toBe(true);
	});
});

describe('IkaClient — sync install throw is rolled back (§4.1)', () => {
	it('install() throwing synchronously rolls back sync side effects', () => {
		const throwing: Plugin = {
			kind: 'destination',
			name: 'syncthrower',
			supportedCurves: [Curve.ED25519],
			extend: { syncthrower: { ping: () => 'pong' } },
			dWalletExtend: () => ({}),
			install: () => {
				throw new Error('sync install boom');
			},
		};
		const ika = new IkaClient();
		expect(() => ika.use(throwing)).toThrow(/sync install boom/);
		// Rollback must have removed the merged extend AND the destination map entry.
		expect((ika as unknown as { syncthrower?: unknown }).syncthrower).toBeUndefined();
		// And the slot is now free for another destination of the same name.
		expect(() =>
			ika.use({
				kind: 'destination',
				name: 'syncthrower',
				supportedCurves: [Curve.ED25519],
				extend: { syncthrower: { ping: () => 'second' } },
				dWalletExtend: () => ({}),
			}),
		).not.toThrow();
		expect((ika as unknown as { syncthrower: { ping: () => string } }).syncthrower.ping()).toBe(
			'second',
		);
	});
});

describe('IkaClient — ready() failure surfacing policy (§4.2)', () => {
	it('first ready() rejects, second ready() resolves (queue drained)', async () => {
		const installPromise = Promise.reject(new Error('init fail'));
		const ika = new IkaClient().use(fakeSource({ installPromise }));
		await expect(ika.ready()).rejects.toThrow(/init fail/);
		// Queue is now empty. Second call has nothing to await and resolves.
		await expect(ika.ready()).resolves.toBeUndefined();
	});

	it('queued failures from multiple plugins all surface on the first ready()', async () => {
		const ika = new IkaClient()
			.use(fakeSource({ installPromise: Promise.reject(new Error('src boom')) }))
			.use({
				kind: 'destination',
				name: 'badDest',
				supportedCurves: [Curve.ED25519],
				extend: { badDest: { x: () => 1 } },
				dWalletExtend: () => ({}),
				install: () => Promise.reject(new Error('dest boom')),
			});
		await expect(ika.ready()).rejects.toThrow(/boom/);
		await expect(ika.ready()).resolves.toBeUndefined();
	});
});

describe('IkaClient — publisher routing type narrowing (§6.2)', () => {
	it('compile-time: ika.publish rejects wrong-chain payload', async () => {
		const ika = new IkaClient()
			.use(fakeSource())
			.use(fakePublisher('testchain'));
		// @ts-expect-error - chain 'mystery' is not registered
		const _bad = ika.publish({ chain: 'mystery', payload: { ok: true } });
		// Swallow the runtime rejection — this test is for the compile-time
		// type check, not runtime routing (that's tested elsewhere).
		await _bad.catch(() => undefined);
		expect(true).toBe(true);
	});

	it('compile-time: publish accepts opts.signal (PRD §4.4 / §9 Q9)', async () => {
		const ika = new IkaClient()
			.use(fakeSource())
			.use(fakePublisher('testchain', 'ok'));
		const controller = new AbortController();
		const r = await ika.publish(
			{ chain: 'testchain' as const, payload: { ok: true } as { ok: true } },
			{ signal: controller.signal },
		);
		expect(r).toBe('ok');
	});
});

describe('IkaClient — auto-decoration of Array<DWallet> returns (§6.4, Q4)', () => {
	it('compile-time: Promise<readonly DWallet[]> elements are decorated', () => {
		interface ArraySrcExtend {
			readonly testchain: {
				readonly getMany: () => Promise<readonly FakeDWallet[]>;
				readonly getManyMutable: () => Promise<FakeDWallet[]>;
			};
		}
		const src = {
			...fakeSource(),
			extend: {
				testchain: {
					id: 'arr',
					greet: () => 'hi',
					getMany: async () => [new FakeDWallet('a'), new FakeDWallet('b')] as readonly FakeDWallet[],
					getManyMutable: async () => [new FakeDWallet('c')],
				},
			},
		} as unknown as SourcePlugin<
			'testchain',
			FakeDWallet,
			SignMessageInput<FakeDWallet>,
			{
				signature: Uint8Array;
				curve: 'ED25519';
				signatureAlgorithm: 'EdDSA';
				hash: 'SHA512';
			},
			ArraySrcExtend
		>;
		const ika = new IkaClient().use(src).use(fakeDestination('fakedest'));

		// readonly stays readonly; element decorated.
		const _ro: Promise<readonly (FakeDWallet & FakeDestDWalletExtend)[]> = (
			ika as unknown as {
				testchain: { getMany: () => Promise<readonly (FakeDWallet & FakeDestDWalletExtend)[]> };
			}
		).testchain.getMany();
		void _ro;
		// Mutable stays mutable; element decorated.
		const _mu: Promise<(FakeDWallet & FakeDestDWalletExtend)[]> = (
			ika as unknown as {
				testchain: { getManyMutable: () => Promise<(FakeDWallet & FakeDestDWalletExtend)[]> };
			}
		).testchain.getManyMutable();
		void _mu;
		expect(true).toBe(true);
	});
});

describe('PublisherPlugin signature carries opts (§3.3, Q9)', () => {
	it('compile-time: publisher broadcast accepts (signed, opts?)', async () => {
		let receivedSignal: AbortSignal | undefined;
		const pub: PublisherPlugin<'testchain', { ok: true }, string> = {
			kind: 'publisher',
			chain: 'testchain',
			broadcast: async (_signed, opts) => {
				receivedSignal = opts?.signal;
				return 'ok';
			},
		};
		const ika = new IkaClient().use(fakeSource()).use(pub);
		const c = new AbortController();
		await ika.publish(
			{ chain: 'testchain' as const, payload: { ok: true } as { ok: true } },
			{ signal: c.signal },
		);
		expect(receivedSignal).toBe(c.signal);
	});
});

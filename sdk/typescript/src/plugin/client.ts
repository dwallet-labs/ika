// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import type { Curve } from '../client/types.js';
import type {
	BaseSignResult,
	DestinationPlugin,
	DWallet,
	IkaContext,
	IkaContextClient,
	Plugin,
	PublisherPlugin,
	PublishOptions,
	SignedTx,
	SignMessageInput,
	SourcePlugin,
	SourceSurface,
} from './types.js';

// =============================================================================
// Type-level helpers — propagate plugin metadata through `.use()` chains.
// =============================================================================

type PublisherChainOf<P> = P extends PublisherPlugin<infer C, unknown, unknown> ? C : never;
type PublisherPayloadOf<P> = P extends PublisherPlugin<string, infer Pay, unknown> ? Pay : never;
type PublisherResultOf<P> = P extends PublisherPlugin<string, unknown, infer R> ? R : never;

/** Pull the client-level `extend` namespace out of a source/destination plugin. */
type ExtendOf<P> =
	P extends DestinationPlugin<string, Curve, infer CE, object>
		? CE
		: P extends SourcePlugin<string, DWallet, SignMessageInput, BaseSignResult, infer SE>
			? SE
			: object;

/** Pull the dWallet-level extension shape (output of `dWalletExtend`). */
type DWalletNsOf<P> = P extends DestinationPlugin<string, Curve, object, infer DE> ? DE : object;

/**
 * Wrap a single returned value at the type level (PRD §6.4).
 *   1. If it IS a DWallet, intersect with `DWalletNs`.
 *   2. If it has a `dWallet: DWallet` field (e.g. `RequestImportedKeyOutput`),
 *      intersect that field.
 *   3. If it's a `readonly DWallet[]` or `DWallet[]`, element-wise wrap each
 *      entry while preserving the array's `readonly`-ness.
 *   4. Otherwise leave it alone.
 *
 * Deliberately narrow: only these three shapes are covered because they're
 * the ones whose runtime DOES get auto-decorated by the source plugin. Other
 * shapes (Maps, nested containers like `{ items: D[] }`) keep their original
 * types — callers must `await ika.decorate(...)` manually.
 *
 * Order matters: the `readonly D[]` check has to come BEFORE the `{ dWallet }`
 * check, because arrays in TS have an `indexer` shape that doesn't match
 * `{ dWallet }` but otherwise we want array detection ahead of the generic
 * "object with a `dWallet` field" path for clarity.
 *
 * The mapped-type rewrite for the `{ dWallet, ... }` case is homomorphic
 * (`{ [K in keyof R]: ... }`), so `readonly` and optional modifiers on every
 * other field of R are preserved exactly. A naïve `Omit<R, 'dWallet'> & { ... }`
 * would silently drop those modifiers on the reconstructed field.
 */
type WrapReturnValue<R, DWalletNs extends object> = R extends DWallet
	? R & DWalletNs
	: R extends readonly (infer E)[]
		? E extends DWallet
			? // Preserve readonly-ness: a `readonly E[]` input produces `readonly (E & DWalletNs)[]`,
				// a mutable `E[]` input produces `(E & DWalletNs)[]`. The trick is to branch on
				// whether the original was `readonly` by checking against the mutable form.
				R extends E[]
				? (E & DWalletNs)[]
				: readonly (E & DWalletNs)[]
			: R
		: R extends { dWallet: infer D }
			? D extends DWallet
				? { [K in keyof R]: K extends 'dWallet' ? D & DWalletNs : R[K] }
				: R
			: R;

/** Wrap a single method's return type. Non-function values pass through unchanged. */
type WrapDWalletMethod<F, DWalletNs extends object> = F extends (...a: infer A) => Promise<infer P>
	? (...a: A) => Promise<WrapReturnValue<P, DWalletNs>>
	: F extends (...a: infer A) => infer R
		? (...a: A) => WrapReturnValue<R, DWalletNs>
		: F;

/**
 * Walk a client `extend` namespace exactly two levels deep:
 *   1. Top-level chain namespaces (e.g. `sui`, `solana`).
 *   2. Direct methods/values on each chain namespace.
 *
 * Stops at depth 2 — deeper nesting (e.g. `ika.sui.client.getDWallet`) is
 * NOT auto-transformed. That's intentional: `ika.sui.client` is the raw
 * core `IkaClient`, which does not run through the source plugin's
 * `decorateIfReady` wrapper. Walking into it would FALSELY type its
 * methods' returns as decorated, hiding a runtime crash where the user
 * touches `.sui` on an undecorated handle. Users reaching for the raw
 * client must call `await ika.decorate(...)` themselves.
 *
 * Function types at level 1 pass through unchanged — chain namespaces are
 * always objects in practice. The explicit guard keeps TS from walking a
 * function's own properties (`.name`, `.length`, `.bind`, ...).
 */
type WrapDWalletReturns<T, DWalletNs extends object> = {
	[K in keyof T]: T[K] extends (...args: never) => unknown
		? T[K]
		: T[K] extends object
			? { [M in keyof T[K]]: WrapDWalletMethod<T[K][M], DWalletNs> }
			: T[K];
};

type PublisherRecord = { chain: string; payload: unknown; result: unknown };

type PublisherMetaOf<P> =
	P extends PublisherPlugin<string, unknown, unknown>
		? { chain: PublisherChainOf<P>; payload: PublisherPayloadOf<P>; result: PublisherResultOf<P> }
		: never;

type PublisherChainsOf<Pub extends PublisherRecord> = Pub extends { chain: infer C } ? C : never;
type PublisherPayloadByChain<Pub extends PublisherRecord, Chain extends string> = Pub extends {
	chain: Chain;
	payload: infer Payload;
}
	? Payload
	: never;
type PublisherResultByChain<Pub extends PublisherRecord, Chain extends string> = Pub extends {
	chain: Chain;
	result: infer R;
}
	? R
	: never;

/**
 * `PluginIkaClient` carries three pieces of metadata in its generics:
 *   - `Ext`: the merged client-extension namespaces (`ika.sui.*`, `ika.solana.*`, ...).
 *   - `Pub`: the union of registered publisher records, used to narrow `publish()`
 *     so misroutes are caught at compile time.
 *   - `DWalletNs`: the merged dWallet-level decoration shape, exposed via `decorate()`.
 *
 * `.use()` returns a new typed view widened with the new plugin's metadata.
 */
export interface PluginIkaClient<
	Ext extends object = object,
	Pub extends PublisherRecord = never,
	DWalletNs extends object = object,
> {
	readonly source: SourceSurface | null;

	/**
	 * Awaits every queued plugin install. The client also auto-awaits this
	 * before `publish()` and before any source-surface call routed through
	 * the client, but `await ika.ready()` lets you choose a deterministic
	 * point to surface install errors (otherwise async install rejections
	 * surface on first use).
	 */
	ready(): Promise<void>;

	use<P extends Plugin>(
		plugin: P,
	): PluginIkaClient<Ext & ExtendOf<P>, Pub | PublisherMetaOf<P>, DWalletNs & DWalletNsOf<P>> &
		WrapDWalletReturns<Ext & ExtendOf<P>, DWalletNs & DWalletNsOf<P>>;

	/**
	 * Attach all registered destinations' dWallet namespaces to `dWallet` in
	 * place (as non-enumerable own properties), and return it with the merged
	 * type. Throws if a different `IkaClient` already decorated this instance.
	 *
	 * Async — awaits `ready()` first so destinations with deferred-init are
	 * fully installed before `dWalletExtend` runs.
	 */
	decorate<D extends DWallet>(dWallet: D): Promise<D & DWalletNs>;

	publish<Chain extends PublisherChainsOf<Pub>>(
		signed: SignedTx<Chain, PublisherPayloadByChain<Pub, Chain>>,
		opts?: PublishOptions,
	): Promise<PublisherResultByChain<Pub, Chain>>;
}

// =============================================================================
// Implementation. Internal — users only see the typed PluginIkaClient.
// =============================================================================

type AnyDestination = DestinationPlugin<string, Curve, object, object>;
type AnySource = SourcePlugin<string, DWallet, SignMessageInput, BaseSignResult, object>;
type AnyPublisher = PublisherPlugin<string, unknown, unknown>;

/**
 * Reserved keys cannot be claimed by plugins via `extend`. Protects the
 * client's own surface from being shadowed by a buggy or malicious plugin.
 */
const RESERVED_KEYS = new Set<string>(['use', 'ready', 'decorate', 'publish', 'source']);

/**
 * Symbol stamped on each dWallet to track which client decorated it.
 *
 * Uses `Symbol.for` with a VERSION-TAGGED key so:
 *   - Two copies of the SDK at the same version share the registry
 *     (cross-bundle dedup works as intended).
 *   - Two copies at DIFFERENT versions get distinct keys, so a v1 client
 *     and a v2 client can both decorate the same dWallet without one
 *     mistaking the other's stamp for a "different IkaClient".
 *
 * Bump the suffix when changing the decoration contract (e.g. if we ever
 * allow re-decoration semantics).
 */
const DECORATED_BY = Symbol.for('@ika.xyz/sdk/plugin@v1:decorated-by');

class IkaClientImpl {
	#source: { plugin: AnySource; surface: SourceSurface } | null = null;
	#destinations: Map<string, AnyDestination> = new Map();
	#publishers: Map<string, AnyPublisher> = new Map();
	#installPromises: Promise<void>[] = [];
	#context: IkaContext;
	#contextClient: IkaContextClient;
	#wrappedSourceSurface: SourceSurface | null = null;
	// Track in-flight decorate calls per dWallet so two concurrent
	// `decorate(d)` invocations don't race after `await ready()` and end up
	// both trying to `defineProperty` on the same key (the second would
	// throw TypeError on the now-non-configurable property).
	#decoratingInFlight: WeakMap<DWallet, Promise<unknown>> = new WeakMap();

	constructor() {
		this.#contextClient = Object.freeze({
			decorate: <D extends DWallet>(d: D): Promise<D> => this.decorate(d) as Promise<D>,
			ready: () => this.ready(),
		});
		// Live context — captured via arrow functions so the getters below
		// resolve `this` to the IkaClient instance rather than the literal
		// object frozen by `Object.freeze`.
		const getSource = (): SourceSurface | null => this.#wrappedSourceSurface;
		const getClient = (): IkaContextClient => this.#contextClient;
		this.#context = Object.freeze({
			get source() {
				return getSource();
			},
			get client() {
				return getClient();
			},
		}) as IkaContext;
	}

	get source(): SourceSurface | null {
		return this.#wrappedSourceSurface;
	}

	async ready(): Promise<void> {
		// Drain queue. New installs may be queued while we await (e.g. from
		// a plugin's install side-effects), so loop until quiet.
		while (this.#installPromises.length > 0) {
			const pending = this.#installPromises.splice(0);
			await Promise.all(pending);
		}
	}

	use(plugin: Plugin): IkaClientImpl {
		switch (plugin.kind) {
			case 'source': {
				if (this.#source) {
					throw new Error(
						`source plugin already registered ('${this.#source.plugin.name}'); ` +
							`cannot also register '${plugin.name}'`,
					);
				}
				const source = plugin as AnySource;
				const rec = this.#beginRecording();
				try {
					this.#source = { plugin: source, surface: source.surface };
					this.#wrappedSourceSurface = this.#wrapSourceSurface(source.surface);
					rec.setSource();
					this.#mergeExtend(source.extend ?? {}, rec);
				} catch (err) {
					rec.rollback();
					throw err;
				}
				// A plugin's `install` may throw SYNCHRONOUSLY before returning
				// the promise (e.g. argument validation). Catch and roll back
				// here — otherwise the sync throw escapes `use()` while the
				// merged extend + maps stay populated, leaving the client in a
				// half-installed state.
				let installResult: void | Promise<void> | undefined;
				try {
					installResult = source.install?.({ client: this.#contextClient });
				} catch (err) {
					rec.rollback();
					throw err;
				}
				this.#queueInstall(installResult, rec.rollback, `source '${source.name}'`);
				break;
			}
			case 'destination': {
				if (this.#destinations.has(plugin.name)) {
					throw new Error(`destination plugin '${plugin.name}' already registered`);
				}
				const dest = plugin as AnyDestination;
				const rec = this.#beginRecording();
				try {
					this.#destinations.set(dest.name, dest);
					rec.addDestination(dest.name);
					this.#mergeExtend(dest.extend, rec);
				} catch (err) {
					rec.rollback();
					throw err;
				}
				let installResult: void | Promise<void> | undefined;
				try {
					installResult = dest.install?.(this.#context);
				} catch (err) {
					rec.rollback();
					throw err;
				}
				this.#queueInstall(installResult, rec.rollback, `destination '${dest.name}'`);
				break;
			}
			case 'publisher': {
				if (this.#publishers.has(plugin.chain)) {
					throw new Error(`publisher plugin for chain '${plugin.chain}' already registered`);
				}
				const pub = plugin as AnyPublisher;
				const rec = this.#beginRecording();
				this.#publishers.set(pub.chain, pub);
				rec.addPublisher(pub.chain);
				let installResult: void | Promise<void> | undefined;
				try {
					installResult = pub.install?.(this.#context);
				} catch (err) {
					rec.rollback();
					throw err;
				}
				this.#queueInstall(installResult, rec.rollback, `publisher '${pub.chain}'`);
				break;
			}
			default: {
				const exhaustive: never = plugin;
				throw new Error(`unknown plugin kind: ${(exhaustive as { kind?: string }).kind}`);
			}
		}
		return this;
	}

	async publish(signed: SignedTx<string, unknown>, opts?: PublishOptions): Promise<unknown> {
		await this.ready();
		const publisher = this.#publishers.get(signed.chain);
		if (!publisher) {
			throw new Error(
				`no publisher registered for chain '${signed.chain}'. ` +
					`Did you forget \`.use(${signed.chain}Publisher(...))\`?`,
			);
		}
		return publisher.broadcast(signed, opts);
	}

	/**
	 * Decorate `dWallet` with each compatible destination's namespace.
	 *
	 * - Awaits `ready()` so all queued plugin installs have settled.
	 * - Idempotent within a single client; throws on cross-client decoration.
	 * - Two-phase atomic: builds the full namespace map FIRST, then installs
	 *   every property — so a destination throwing from `dWalletExtend`
	 *   doesn't leave the dWallet partially mutated.
	 * - Stamps only when at least one destination contributed, so a user who
	 *   calls `decorate(d)` before any destination is registered isn't
	 *   permanently locked out of decoration on that instance.
	 */
	async decorate<D extends DWallet>(dWallet: D): Promise<D> {
		// Coalesce concurrent decorate(d) calls on the same instance so
		// they don't race after `ready()` and both try to defineProperty
		// the same non-configurable key.
		const inFlight = this.#decoratingInFlight.get(dWallet);
		if (inFlight) return inFlight as Promise<D>;
		const work = this.#decorateImpl(dWallet);
		this.#decoratingInFlight.set(dWallet, work);
		try {
			return await work;
		} finally {
			this.#decoratingInFlight.delete(dWallet);
		}
	}

	async #decorateImpl<D extends DWallet>(dWallet: D): Promise<D> {
		await this.ready();
		const stamp = (dWallet as unknown as Record<symbol, unknown>)[DECORATED_BY];
		if (stamp === this) return dWallet;
		if (stamp !== undefined) {
			throw new Error(
				'dWallet was already decorated by a different IkaClient. ' +
					'Each dWallet instance can only be decorated once.',
			);
		}

		// Phase 1: gather all namespaces. Validate first so phase 2 can't
		// throw partway and leave the dWallet half-mutated.
		const pending: Record<string, unknown> = Object.create(null);
		const target = dWallet as unknown as Record<string | symbol, unknown>;
		for (const dest of this.#destinations.values()) {
			if (!dest.supportedCurves.includes(dWallet.curve)) continue;
			const namespace = dest.dWalletExtend(dWallet, this.#context);
			if (namespace == null || typeof namespace !== 'object') {
				throw new Error(
					`decorate: destination plugin '${dest.name}' returned ${typeof namespace} ` +
						`from dWalletExtend; expected an object of namespace key → method maps.`,
				);
			}
			for (const key of Reflect.ownKeys(namespace)) {
				if (typeof key !== 'string') {
					throw new Error(
						`decorate: destination plugin '${dest.name}' contributed a non-string ` +
							`key (${String(key)}). dWalletExtend keys must be strings.`,
					);
				}
				const value = (namespace as Record<string, unknown>)[key];
				if (key in pending) {
					throw new Error(
						`decorate: dWallet-level collision on key '${key}' between ` +
							`two destination plugins. Each destination must contribute a ` +
							`unique top-level dWallet namespace key.`,
					);
				}
				// Reject keys that already exist on the dWallet — would either
				// shadow user data or fail in phase 2 if they're non-configurable.
				if (Object.prototype.hasOwnProperty.call(target, key)) {
					throw new Error(
						`decorate: cannot install '${key}' — dWallet already has a property at ` +
							`this key. Destination plugin '${dest.name}' must pick a different name.`,
					);
				}
				pending[key] = value;
			}
		}

		// No destination contributed — leave dWallet untouched so a future
		// `decorate()` call (after a destination is registered) can succeed.
		if (Object.keys(pending).length === 0) return dWallet;

		// Phase 2: install properties + stamp. Locked forever (non-configurable,
		// non-writable) so:
		//   - Accidental `dWallet.sui = {...}` from user code fails loudly.
		//   - Decoration is one-shot per dWallet — re-running with a different
		//     destination set on the same dWallet is intentionally forbidden;
		//     to retry, fetch a fresh handle via `ika.sui.getDWallet(id)`.
		for (const [key, value] of Object.entries(pending)) {
			Object.defineProperty(target, key, {
				value,
				enumerable: false,
				configurable: false,
				writable: false,
			});
		}
		Object.defineProperty(target, DECORATED_BY, {
			value: this,
			enumerable: false,
			configurable: false,
			writable: false,
		});
		return dWallet;
	}

	// ---------------------------------------------------------------------
	// Private helpers.
	// ---------------------------------------------------------------------

	#queueInstall(
		result: void | Promise<void> | undefined,
		rollback: () => void,
		label: string,
	): void {
		if (result === undefined || result === null) return;
		const p = Promise.resolve(result).then(
			() => undefined,
			(err: unknown) => {
				// Roll back the synchronous side effects (merged extend, maps)
				// so the client surface doesn't carry half a plugin after an
				// async install rejection.
				try {
					rollback();
				} catch (rollbackErr) {
					// Rollback should not throw, but if it does, surface both.
					const wrapped = new Error(`install of ${label} failed AND rollback failed`);
					(wrapped as Error & { cause?: unknown }).cause = err;
					(wrapped as Error & { rollbackCause?: unknown }).rollbackCause = rollbackErr;
					throw wrapped;
				}
				throw err;
			},
		);
		// Suppress unhandled-rejection warnings — `ready()` is the official
		// place to observe install failures. A no-op catch doesn't consume
		// the rejection for awaiters; it just marks the chain as "handled".
		p.catch(() => undefined);
		this.#installPromises.push(p);
	}

	/**
	 * Build a rollback closure that records EXACTLY which keys this single
	 * `.use()` added and reverts only those — never a diff of "all state
	 * since registration", which would erroneously delete keys added by a
	 * LATER `.use()` whose snapshot included them.
	 *
	 * Usage:
	 *   const rec = this.#beginRecording();
	 *   <mutate state>
	 *   if (success) -> queue install; on async failure, call rec.rollback()
	 *
	 * The recorder is connected to `#mergeExtend` and the source/dest/pub
	 * setters so it tracks specifically what THIS .use() touched.
	 */
	#beginRecording(): {
		setSource: () => void;
		addDestination: (name: string) => void;
		addPublisher: (chain: string) => void;
		rollback: () => void;
		// Called by #mergeExtend to record the keys IT added so the rollback
		// can revert them without diffing.
		recordTopKey: (k: string | symbol) => void;
		recordInnerKey: (top: string | symbol, inner: string | symbol) => void;
	} {
		const self = this as unknown as Record<string | symbol, unknown>;
		const addedTopKeys: (string | symbol)[] = [];
		const addedInner = new Map<string | symbol, Set<string | symbol>>();
		let setSourceFlag = false;
		let addedDestName: string | null = null;
		let addedPubChain: string | null = null;

		const rollback = (): void => {
			// Remove top-level keys we added.
			for (const k of addedTopKeys) {
				Reflect.deleteProperty(self, k);
			}
			// Remove inner keys we added to namespaces we did NOT create.
			// (If we created the top-level, it's already gone from the loop above.)
			for (const [topKey, innerSet] of addedInner.entries()) {
				if (addedTopKeys.includes(topKey)) continue; // namespace removed wholesale
				const val = self[topKey];
				if (val !== null && typeof val === 'object' && !Array.isArray(val)) {
					for (const inner of innerSet) {
						Reflect.deleteProperty(val, inner);
					}
				}
			}
			if (setSourceFlag && this.#source !== null) {
				this.#source = null;
				this.#wrappedSourceSurface = null;
			}
			if (addedDestName !== null) {
				this.#destinations.delete(addedDestName);
			}
			if (addedPubChain !== null) {
				this.#publishers.delete(addedPubChain);
			}
		};

		return {
			setSource: () => {
				setSourceFlag = true;
			},
			addDestination: (name: string) => {
				addedDestName = name;
			},
			addPublisher: (chain: string) => {
				addedPubChain = chain;
			},
			recordTopKey: (k: string | symbol) => {
				addedTopKeys.push(k);
			},
			recordInnerKey: (top: string | symbol, inner: string | symbol) => {
				let s = addedInner.get(top);
				if (!s) {
					s = new Set();
					addedInner.set(top, s);
				}
				s.add(inner);
			},
			rollback,
		};
	}

	/**
	 * Wrap the source surface so every call from destinations or end-users
	 * awaits `ready()` first. This is the gate that prevents the install-race
	 * bug where `ika.sui.sign(...)` fires before `ikaClient.initialize()`
	 * settles.
	 *
	 * Explicit wrapping (vs. a Proxy) — Proxy variants had three problems:
	 *   - `Reflect.get(target, prop, receiver)` with `receiver=Proxy` causes
	 *     getter recursion if any property is an accessor.
	 *   - Allocating a fresh wrapper on every `get` breaks identity comparison
	 *     and bloats GC on hot signing loops.
	 *   - A Proxy can't distinguish sync vs async source methods, so it
	 *     silently coerces sync returns into Promises.
	 *
	 * Trade-off: extending `SourceSurface` with a new method now requires
	 * updating this wrapper. That's a small price for predictable semantics.
	 */
	#wrapSourceSurface(raw: SourceSurface): SourceSurface {
		const ready = () => this.ready();
		return {
			chain: raw.chain,
			signMessage: async (input) => {
				await ready();
				return raw.signMessage(input);
			},
			getDWallet: async (id) => {
				await ready();
				return raw.getDWallet(id);
			},
		};
	}

	/**
	 * Merge a plugin's `extend` namespace onto the client instance.
	 *
	 * Two-level deep merge: top-level keys (chain names like `sui`) and the
	 * single nested level beneath them (methods on the chain namespace).
	 *
	 * Strict rules:
	 *   - Top-level key in `RESERVED_KEYS` ⇒ throw (no shadowing internal API).
	 *   - Top-level key exists with non-object value ⇒ throw (collision).
	 *   - Inner key already registered on the same chain namespace ⇒ throw
	 *     (silent overwrite was the source of the order-dependent `mergeExtend`
	 *     bug). Source and destination plugins MUST not register overlapping
	 *     method names on `ika.<chain>`.
	 *   - Property descriptors are preserved via `Object.defineProperty`, so
	 *     getters keep their getter semantics (no auto-materialization).
	 */
	#mergeExtend(
		extend: object,
		recorder?: {
			recordTopKey: (k: string | symbol) => void;
			recordInnerKey: (top: string | symbol, inner: string | symbol) => void;
		},
	): void {
		const self = this as unknown as Record<string | symbol, unknown>;
		// `Reflect.ownKeys` returns string AND symbol keys, including non-
		// enumerable ones. Plugins that ship namespaces as class instances
		// (prototype methods) or that use symbol keys are fully supported.
		for (const topKey of Reflect.ownKeys(extend)) {
			if (typeof topKey === 'string' && RESERVED_KEYS.has(topKey)) {
				throw new Error(
					`plugin tried to register reserved client key '${topKey}'. ` +
						`This name is owned by the IkaClient surface.`,
				);
			}
			const existing = self[topKey];
			const topDescriptor = Object.getOwnPropertyDescriptor(extend, topKey);
			if (!topDescriptor) continue;
			const incoming = topDescriptor.get ? topDescriptor.get.call(extend) : topDescriptor.value;
			if (
				existing != null &&
				typeof existing === 'object' &&
				!Array.isArray(existing) &&
				incoming != null &&
				typeof incoming === 'object' &&
				!Array.isArray(incoming)
			) {
				// Inner walk — also via Reflect.ownKeys.
				const merged = existing as Record<string | symbol, unknown>;
				for (const innerKey of Reflect.ownKeys(incoming as object)) {
					if (innerKey in merged) {
						throw new Error(
							`plugin collision: '${String(topKey)}.${String(innerKey)}' already ` +
								`registered. Source and destination plugins targeting the same ` +
								`namespace must not declare overlapping method names.`,
						);
					}
					const innerDescriptor = Object.getOwnPropertyDescriptor(incoming as object, innerKey);
					if (innerDescriptor) {
						Object.defineProperty(merged, innerKey, innerDescriptor);
						recorder?.recordInnerKey(topKey, innerKey);
					}
				}
			} else if (existing === undefined) {
				Object.defineProperty(self, topKey, topDescriptor);
				recorder?.recordTopKey(topKey);
				// Per PRD §4.1 / Q11: wholesale-nuke on top-level rollback.
				// The owning plugin's rollback deletes the whole namespace,
				// including inner keys merged in by subsequent plugins. We do
				// NOT record per-inner-key ownership here because rollback
				// removes the top-level wholesale.
			} else {
				throw new Error(
					`plugin collision: client key '${String(topKey)}' already registered with ` +
						`a non-object value`,
				);
			}
		}
	}
}

// =============================================================================
// Public class export. `new IkaClient()` returns a typed PluginIkaClient.
// =============================================================================

export const IkaClient = IkaClientImpl as unknown as {
	new (): PluginIkaClient<object, never, object>;
};
export type IkaClient<
	Ext extends object = object,
	Pub extends PublisherRecord = never,
	DWalletNs extends object = object,
> = PluginIkaClient<Ext, Pub, DWalletNs>;

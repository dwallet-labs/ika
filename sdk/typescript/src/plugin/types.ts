// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import type { Curve, Hash, SignatureAlgorithm } from '../client/types.js';

// =============================================================================
// DWallet — the user-facing handle.
//
// `C` is the cryptographic curve, carried in the type so destinations can be
// type-filtered by `supportedCurves`. `Raw` is the source-specific payload —
// on Sui it's the BCS-decoded Move object. End users rarely touch it.
//
// IMPORTANT: this class is NEVER augmented globally via `declare module`.
// Destination namespaces (e.g. `dWallet.sui`, `dWallet.solana`) appear ONLY
// on the result of `client.decorate(dWallet)`, never on a naked instance.
// The typed name for the merged shape is `Decorated<D, DWalletNs>`, which
// the client surface returns from `decorate(...)` and from any source method
// the client wraps for decoration.
// =============================================================================

export type DWalletKind = 'zero-trust' | 'shared' | 'imported-key' | 'imported-key-shared';

export abstract class DWallet<C extends Curve = Curve, Raw = unknown> {
	abstract readonly id: string;
	abstract readonly kind: DWalletKind;
	abstract readonly curve: C;
	/** Active public output (DKG result), curve-encoded. Used for address derivation. */
	abstract readonly publicOutput: Uint8Array;
	/**
	 * Source-specific representation. **Advanced use only** — destinations
	 * should treat this as opaque; reading from it bypasses the plugin contract.
	 */
	abstract readonly raw: Raw;
}

/** Typed view of a dWallet that has been decorated with destination namespaces. */
export type Decorated<D extends DWallet, DWalletNs extends object> = D & DWalletNs;

// =============================================================================
// SignedTx — wire format. `chain` is the discriminator that routes
// `ika.publish(signed)` to the right publisher plugin.
// =============================================================================

export type SignedTx<Chain extends string = string, Payload = unknown> = {
	readonly chain: Chain;
	readonly payload: Payload;
};

// =============================================================================
// SignMessageInput — base shape every source's signMessage accepts. Source
// plugins are expected to extend this with their own optional overrides
// (e.g. `encryptedShareId`, custom `presign`, alternate user-share keys).
// =============================================================================

export interface SignMessageInput<DW extends DWallet = DWallet> {
	readonly dWallet: DW;
	readonly message: Uint8Array;
	readonly curve: Curve;
	readonly signatureAlgorithm: SignatureAlgorithm;
	readonly hash: Hash;
	/** Optional cooperative cancellation — sources should honor it during polling. */
	readonly signal?: AbortSignal;
}

// =============================================================================
// BaseSignResult — minimum shape every source plugin's sign output must
// carry. Sources extend this with chain-specific extras.
// =============================================================================

export interface BaseSignResult {
	readonly signature: Uint8Array;
	readonly curve: Curve;
	readonly signatureAlgorithm: SignatureAlgorithm;
	readonly hash: Hash;
}

// =============================================================================
// SourceSurface — what the active source exposes to destination plugins.
// Generic over the source's DWallet, SignMessageInput, and SignResult shapes
// so each chain's source can carry the customization it needs.
// =============================================================================

/**
 * Minimal options shape destination plugins use when forwarding a
 * chain-led `createDWallet` call (e.g. `ika.bitcoin.createDWallet({ kind })`)
 * to the active source. The destination supplies the curve; the caller
 * supplies `kind` and any source-specific extras as a flat record.
 */
export interface SourceCreateDWalletInput {
	readonly curve: Curve;
	readonly kind: 'zero-trust' | 'shared' | 'imported-key' | 'imported-key-shared';
	readonly [key: string]: unknown;
}

export interface SourceSurface<
	DW extends DWallet = DWallet,
	In extends SignMessageInput<DW> = SignMessageInput<DW>,
	Out extends BaseSignResult = BaseSignResult,
> {
	/** Identifier of the chain where dWallets live (e.g. 'sui'). */
	readonly chain: string;

	/** Sign `message` with `dWallet`. Source orchestrates presign+sign internally. */
	signMessage(input: In): Promise<Out>;

	/** Fetch a dWallet by id. Returned naked — call `client.decorate(...)` if you want namespaces. */
	getDWallet(id: string): Promise<DW>;

	/**
	 * Create a fresh dWallet bound to the given curve. Optional because
	 * legacy / minimal sources may not implement it. Destination plugins
	 * that expose chain-led sugar (e.g. `ika.bitcoin.createDWallet`)
	 * forward to this; if it's missing they throw a clear error pointing
	 * the caller at the source's own `createDWallet`.
	 */
	createDWallet?(input: SourceCreateDWalletInput): Promise<DW>;
}

// =============================================================================
// IkaContextClient — subset of the IkaClient surface plugins see at install.
// =============================================================================

export interface IkaContextClient {
	/**
	 * Decorate `dWallet` with all registered destinations' namespaces.
	 * Returns the SAME instance (decoration is in-place via non-enumerable
	 * properties) so it doesn't leak into JSON.stringify. Throws if a
	 * different IkaClient already decorated this instance.
	 *
	 * Async because it awaits `ready()` first — so destinations with
	 * deferred-init can rely on `dWalletExtend` running only after their
	 * `install()` has settled.
	 *
	 * Type-level: the typed `IkaClient.decorate` returns `Promise<D & DWalletNs>`.
	 * The plugin-facing `IkaContextClient.decorate` returns `Promise<D>` —
	 * plugins don't need to see the merged shape (it exists only so end-user
	 * code can call `dWallet.sui.sign(...)`).
	 */
	decorate<D extends DWallet>(dWallet: D): Promise<D>;

	/**
	 * Awaits every queued plugin install. Use before issuing the first call
	 * that depends on plugin state being ready. Most surface methods on the
	 * client auto-await this — explicit calls are only needed when the
	 * caller wants a deterministic point at which init has settled.
	 */
	ready(): Promise<void>;
}

export interface IkaContext<
	DW extends DWallet = DWallet,
	In extends SignMessageInput<DW> = SignMessageInput<DW>,
	Out extends BaseSignResult = BaseSignResult,
> {
	/**
	 * LIVE reference — accessing `ctx.source` returns whatever source is
	 * currently registered. Plugins that captured `ctx` at install time still
	 * see the latest source, so destination plugins can be registered before
	 * source plugins without breaking.
	 */
	readonly source: SourceSurface<DW, In, Out> | null;
	readonly client: IkaContextClient;
}

// =============================================================================
// Plugins.
//
// A plugin is a discriminated union over `kind`. Source plugins contribute
// dWallet primitives; destination plugins add chain-native signing helpers
// (and namespaces on dWallet instances); publishers broadcast signed txs.
// =============================================================================

export interface SourcePlugin<
	Chain extends string = string,
	DW extends DWallet = DWallet,
	In extends SignMessageInput<DW> = SignMessageInput<DW>,
	Out extends BaseSignResult = BaseSignResult,
	Extend extends object = object,
> {
	readonly kind: 'source';
	readonly name: Chain;
	readonly chain: Chain;
	readonly surface: SourceSurface<DW, In, Out>;
	readonly extend: Extend;
	install?(ctx: Omit<IkaContext<DW, In, Out>, 'source'>): void | Promise<void>;
}

export interface DestinationPlugin<
	Name extends string = string,
	SupportedCurve extends Curve = Curve,
	ClientExtend extends object = object,
	DWalletExtend extends object = object,
> {
	readonly kind: 'destination';
	readonly name: Name;
	readonly supportedCurves: readonly SupportedCurve[];
	readonly extend: ClientExtend;
	/**
	 * Per-dWallet decoration factory. Accepts the abstract `DWallet` so
	 * destinations work against any source. The runtime guarantees
	 * `dWallet.curve ∈ supportedCurves` when this is invoked — destinations
	 * with unsupported curves are filtered out by the client.
	 */
	readonly dWalletExtend: (dWallet: DWallet, ctx: IkaContext) => DWalletExtend;
	install?(ctx: IkaContext): void | Promise<void>;
}

/**
 * PublisherPlugin — broadcast a signed transaction. `chain` is the routing
 * key (matches `SignedTx.chain`). The payload type is generic so consumers
 * get compile-time safety that the payload matches the publisher's
 * expectations.
 *
 * `broadcast` accepts an optional `{ signal }` (PRD §3.3/§4.4/§9 Q9). The
 * publisher MUST honor the signal during confirmation polling and reject
 * promptly on abort. `opts` is optional and backward-compatible — older
 * publishers that ignore it still type-check, but new publishers SHOULD
 * thread `signal` through.
 */
export interface PublishOptions {
	readonly signal?: AbortSignal;
}

export interface PublisherPlugin<
	Chain extends string = string,
	Payload = unknown,
	BroadcastResult = string,
> {
	readonly kind: 'publisher';
	readonly chain: Chain;
	broadcast(signed: SignedTx<Chain, Payload>, opts?: PublishOptions): Promise<BroadcastResult>;
	install?(ctx: IkaContext): void | Promise<void>;
}

export type Plugin =
	| SourcePlugin<string, DWallet, SignMessageInput, BaseSignResult, object>
	| DestinationPlugin<string, Curve, object, object>
	| PublisherPlugin<string, unknown, unknown>;

// =============================================================================
// Type helpers.
// =============================================================================

/** Extract the client-level `extend` shape from any plugin. */
export type ClientExtensionOf<P> = P extends { readonly extend: infer E } ? E : object;

/** Extract the dWallet-level extension shape (return type of dWalletExtend). */
export type DWalletExtensionOf<P> = P extends {
	readonly dWalletExtend: (...args: never[]) => infer E;
}
	? E
	: object;

/** Extract supported curves of a destination plugin (or `never`). */
export type SupportedCurvesOf<P> =
	P extends DestinationPlugin<string, infer SC, object, object> ? SC : never;

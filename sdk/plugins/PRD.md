# Ika SDK Plugin System — PRD

**Audience:** Internal engineering (us + delegated subagents). **Scope:** The plugin system only —
`@ika.xyz/sdk/plugin` core abstractions + `@ika.xyz/plugins` implementations. Core SDK internals
(cryptography, IkaClient mechanics) are out of scope. **Status:** Draft for grilling.

---

## 1. Goals & Non-Goals

### Goals

1. **Additive customization layer** on top of `@ika.xyz/sdk`'s `IkaClient`. Users can keep using the
   core directly; plugins are an opt-in convenience.
2. **Type-safe multi-chain composition.** A single `ika` instance routes sign requests to the right
   source, signing intent to the right destination, and broadcast to the right publisher — with
   mismatches caught at compile time.
3. **Hide chain-specific details on destinations.** A user signing for Solana never picks the hash,
   sigAlgo, or intent prefix; the plugin does. A user signing for Sui never picks blake2b or the
   intent scope.
4. **Preserve full source-side customization parity with core.** Every knob the user has via
   `IkaTransaction` directly (custom approvals, pre-verified presign caps, per-call USEK override,
   custom dWalletCap) must remain reachable through the plugin layer.
5. **Decorated dWallet handles by default.** Anywhere a source returns a dWallet, the result is
   auto-decorated with every registered destination's per-dWallet namespace, so users can call
   `dWallet.solana.sign(...)` without manual `await ika.decorate(...)`.
6. **Multi-op transactions.** A single Sui PTB must be able to contain N coordinator ops (multiple
   DKGs, signs, presigns) for atomicity + fee savings.
7. **Predictable lifecycle.** Plugin installs are async-tolerant but never observable in a
   half-installed state. Sync or async install failure rolls back all sync side effects.
8. **Multi-tenant safety.** Two `IkaClient` instances in the same process must not share caches,
   decorate stamps, or other per-instance state.

### Non-Goals

- Replace the core `IkaClient` API or hide it from users. Plugins layer on top.
- Cryptographic protocol changes (2PC-MPC, class-groups encryption). The plugin layer only
  orchestrates.
- Custom RPC transports, connection pooling, retry policies — the core client owns those.
- Browser-only or Node-only features. The plugin system runs in both environments.
- A formal extension marketplace, plugin discovery, version negotiation between plugins. Plugins are
  first-party today.
- Hot-swapping plugins after install (no `unuse()` API).

### Design principles (tie-breakers when goals conflict)

Ranked. Higher item wins.

1. **Security.** No silent data loss, no lost handles after partial success, no hangs that exhaust
   caller resources. Irreversible operations require explicit acknowledgement.
2. **Predictable failure modes.** A user looking at an error message should be able to act on it.
   Half-broken state visible at the API surface is worse than clean unavailability.
3. **Type-level guarantees over runtime checks.** When the compiler can prove a misuse impossible,
   prefer that. Runtime checks are a fallback, not a substitute.
4. **Customization parity with core.** Anything possible against the raw `IkaClient` MUST be
   reachable through the plugin layer — possibly with more steps, never with fewer capabilities.
5. **Ergonomics for the happy path.** The 80% case (sign a tx for one chain via one source) should
   be one call. Customization paths can be more verbose.
6. **Predictable abstraction depth.** Type and runtime behavior should agree about what's
   auto-handled. No silent recursion into raw client surfaces; no type lies about decoration.
7. **YAGNI.** Don't design for hypothetical future architecture (multi-source, plugin marketplaces).
   Add when there's a concrete use case.

---

## 2. Core Concepts

### 2.1 Plugin kinds

Three discriminated kinds. Each `.use(plugin)` call routes by `plugin.kind`.

| Kind          | Contributes                                                                                          | Cardinality per client  |
| ------------- | ---------------------------------------------------------------------------------------------------- | ----------------------- |
| `source`      | dWallet lifecycle primitives (DKG, presign, sign); the `signMessage` surface destinations call into. | Exactly one\*           |
| `destination` | Chain-specific signing helpers (`ika.<chain>.sign(...)`); per-dWallet namespace (`dWallet.<chain>`). | Many, unique by `name`  |
| `publisher`   | Broadcast a signed payload of a specific chain.                                                      | Many, unique by `chain` |

\*Single source per client is the **permanent** model for this iteration (see §9 Q10). When a second
source plugin ships, a parallel client class will be introduced rather than retrofitting
multi-source onto this one.

### 2.2 Decoration

The merged dWallet shape. A "decorated" dWallet is one where each compatible destination has
installed its per-dWallet namespace (e.g. `dWallet.solana.sign(...)`). Decoration:

- happens in-place on the original object (non-enumerable own properties);
- is one-shot per dWallet handle;
- is keyed by client identity — a different `IkaClient` instance MUST NOT re-decorate.

### 2.3 IkaContext (what plugins see)

A small, stable object passed to `install()` and to per-dWallet `dWalletExtend()`:

```
{
  source: SourceSurface | null   // live getter, reflects current source
  client: IkaContextClient        // { decorate, ready }
}
```

- `source` is a getter so a destination that captures `ctx` at install time still sees the latest
  source registration.
- `client.decorate(d)` and `client.ready()` are the only client-surface methods plugins may call.

**Important — source-install context is narrowed.** `SourcePlugin.install` receives
`Omit<IkaContext, 'source'>` (the `source` field is removed from its context type). Rationale: at
the moment `source.install(ctx)` runs, the source's own surface is the thing being installed;
exposing `ctx.source` to itself is either undefined or self-referential. Destination and publisher
installs receive the full `IkaContext` with a live source getter — they need it to call back into
the source.

---

## 3. Plugin Contracts

### 3.1 SourcePlugin

Owns:

- `surface`: `{ chain, signMessage(input), getDWallet(id) }`. This is what destination plugins call
  via `ctx.source`.
- `extend`: an object merged onto the client surface as `ika.<chain>.*`. Provides the source's
  customization API (DKG, presign, sign, transaction builder, direct core access).
- `install?(ctx)`: optional. Returns `void | Promise<void>`. Used to bind the source to the client's
  `decorate` so source-returned dWallets are auto-decorated.

Required behaviors:

- `signMessage(input)` accepts a **whitelisted set of fields** defined by the source's input type.
  Destination plugins pass source-specific overrides through a structural cast
  (`input as Parameters<typeof source.signMessage>[0]`); the source destructures named fields and
  ignores the rest. Sources MUST NOT throw on unknown fields — strict-validating sources (e.g. Zod
  `.strict()`) would break the destination → source channel. The protocol is: "extra fields silently
  dropped at the source boundary."
- `getDWallet(id)` on the **source surface** (the one destinations consume via
  `ctx.source.getDWallet`) MUST return a naked (undecorated) dWallet. Callers that want decoration
  call `ctx.client.decorate(d)`.
- Source-returned dWallets from the **`extend` surface** (e.g. `ika.<chain>.getDWallet`,
  `ika.<chain>.createDWallet`) SHOULD be auto-decorated. The source captures `ctx.client` in install
  and calls `decorate` before returning. Naming overlap is intentional: the source-surface method is
  consumed by other plugins; the extend-surface method is consumed by end users.

### 3.2 DestinationPlugin

Owns:

- `supportedCurves: readonly Curve[]`. Decoration is skipped for dWallets whose curve isn't in this
  list.
- `extend`: object merged onto `ika.<destination-chain>.*`. Exposes high-level sign helpers.
- `dWalletExtend(dWallet, ctx)`: factory returning the per-dWallet namespace (e.g.
  `{ solana: { sign, getAddress } }`). Invoked by `decorate()`.
- `install?(ctx)`: optional. Typically captures `ctx` so `dWalletExtend` factories close over the
  source.

Required behaviors:

- Destinations MUST NOT mutate the dWallet directly inside `dWalletExtend` — only return the
  namespace; the client installs it.
- Destinations MAY assume that when `dWalletExtend` is called, `dWallet.curve ∈ supportedCurves`.
  The client filters.
- Destinations targeting the same chain MUST NOT register overlapping `extend` method names with the
  source.

### 3.3 PublisherPlugin

Owns:

- `chain: string`. Routing key — `ika.publish(signed, opts?)` looks up by `signed.chain`.
- `broadcast(signed, opts?: { signal?: AbortSignal }): Promise<Result>`. Returns the chain-native
  result type (signature, digest, etc.).

Required behaviors:

- A publisher MUST only accept signed payloads whose runtime `chain` matches its own. (Compile-time
  enforced via the `PluginIkaClient.publish` overload.)
- Publishers MAY confirm on-chain inclusion before resolving (opt-in via plugin options) but MUST
  NOT loop indefinitely without a bounded exit condition. Each chain-specific publisher MUST expose
  a `confirmTimeoutMs` option (default 180_000ms / 3 minutes for Solana; chain-appropriate defaults
  elsewhere). On timeout, the publisher throws with a message that includes the chain-native
  transaction identifier (signature, digest, etc.) so the user can manually verify on chain.
- Publishers MUST honor `opts.signal` during confirmation polling and resolve/reject promptly on
  abort.

---

## 4. Lifecycle Requirements

### 4.1 `use(plugin)`

Synchronous from the caller's perspective. Returns the same client typed-widened to include the new
plugin's contributions.

Order of operations:

1. Validate uniqueness (one source; unique destination names; unique publisher chains).
2. Begin a per-`use()` recorder.
3. Mutate state (set source / add to destinations map / add to publishers map; merge `extend` into
   client surface).
4. Invoke `install(ctx)`.
5. Queue the install result onto the client's pending-install list.

Step 4/5 transitions:

- If `install` returns a Promise → step 5 queues it.
- If `install` returns `void` or `undefined` → step 5 is a no-op.
- If `install` throws synchronously → step 4 invokes rollback per the sync-failure invariant below;
  step 5 never runs.
- If `install` is not provided on the plugin → both step 4 and 5 are no-ops.

Invariants:

- **Sync failure → rollback.** A throw from steps 3 or 4 MUST roll back all sync side effects from
  step 3 before propagating. This includes synchronous throws from `install()` itself (an `install`
  that throws before returning its promise).
- **Async failure → rollback.** A rejected promise from step 5 MUST roll back all sync side effects
  of THIS `use()` call before the rejection becomes observable to `ready()` callers.
- **Rollback granularity — subsequent use() isolation.** A rollback from THIS `use()` MUST NOT touch
  state added by ANY subsequent `use()` whose mutations don't share keys with this one. Each call
  gets its own recorder that tracks exactly what THIS call added.
- **Rollback granularity — top-level ownership (wholesale-nuke).** A plugin that creates a top-level
  namespace (`ika.<chain>`) owns it. If that plugin's install fails and rolls back, the entire
  namespace is deleted — including inner keys merged in by subsequent plugins. Subsequent plugins
  MAY assume the namespace persists across THEIR OWN rollbacks but MUST NOT assume it persists
  across the creating plugin's rollback. See Q11 in §9 for the decision rationale.

### 4.2 `ready()`

Awaits every queued install. Drains the queue under a loop so that installs which themselves trigger
further installs settle correctly.

**Failure surfacing policy.** `ready()` reports each failure **exactly once**, then forgets. The
queue is drained on each call: a rejection propagates to the awaiter, the queue is now empty, and a
subsequent `ready()` resolves successfully. This is deliberate — latching a permanent failure makes
recovery harder (e.g. user can't `.use()` a replacement plugin after a failed `.use()` of a similar
one). Callers that need durable "did init succeed?" semantics should track this themselves.

Per-failure cleanup is still guaranteed via the rollback contract (§4.1) — synchronous state is
consistent regardless of how the awaiter handles the rejection.

### 4.3 `decorate(dWallet)`

1. `await ready()`.
2. If `dWallet` is stamped by THIS client, return as-is (idempotent).
3. If stamped by a DIFFERENT client, throw.
4. Phase 1 — gather every compatible destination's namespace into a pending map. Throw on key
   collisions BEFORE mutating the dWallet. **Collisions checked:** both inter-destination keys (two
   destinations claiming the same top-level dWallet field) AND collisions with the dWallet's own
   existing properties (`id`, `kind`, `curve`, `publicOutput`, `raw`, plus anything added by future
   fields). A destination claiming any existing key throws — pick a different namespace name.
5. Phase 2 — install all properties as non-enumerable, non-configurable, non-writable, then stamp.

`decorate(d)` mutates `d` in place and returns the same reference (with the type widened). Users may
keep using the original handle; capturing the return value is for type narrowing only.

Invariants:

- **Atomicity.** A throw during Phase 1 leaves the dWallet untouched.
- **Concurrency.** Two concurrent `decorate(d)` calls on the same instance share one in-flight
  promise (no double-install attempts).
- **No-op when no destinations.** Decorating with zero destinations leaves the dWallet untouched (no
  stamp), so a later `decorate()` after a destination is registered still works.

### 4.4 `publish(signed, opts?)`

Signature: `publish(signed, opts?: { signal?: AbortSignal }): Promise<Result>`.

- Awaits `ready()`.
- Routes by `signed.chain` to the matching publisher.
- Throws if no publisher is registered for that chain.
- Forwards `opts.signal` to the publisher's `broadcast(signed, { signal })` so confirmation polling
  can be cancelled by the caller.

---

## 5. Customization Knobs

### 5.1 Source-side (Sui today)

Per-call overrides available on the appropriate source methods. Not every override applies to every
method — the column **Used by** is the canonical scope.

| Override                  | Used by                                                                            | Purpose                                                                                     |
| ------------------------- | ---------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| `userShareEncryptionKeys` | every method that touches a USEK (DKG, sign, reveal)                               | Override the source's default USEK (multi-tenant servers, per-user keys).                   |
| `presign`                 | `requestSign`, destination `sign`                                                  | Skip auto-fetch; reuse a pre-computed presign.                                              |
| `encryptedShareId`        | `requestSign`, `acceptEncryptedShare`, `revealUserSecretShare`, destination `sign` | Override the encrypted share id captured on the dWallet handle (zero-trust / imported-key). |
| `dWalletCap`              | `requestSign`, destination `sign`                                                  | Override the cap object id (multisig-held cap, transferred cap).                            |
| `buildApproval`           | `requestSign`, destination `sign`                                                  | Hook returning a `TransactionObjectArgument` — for sponsored / multisig approval flows.     |
| `buildVerifiedPresignCap` | `requestSign`, destination `sign`                                                  | Hook returning a `TransactionObjectArgument` — for pre-verified caps from upstream flows.   |
| `signal`                  | every async method                                                                 | `AbortSignal` for cooperative cancellation across polling loops.                            |

### 5.2 Destination-side

Destinations expose a thin layer on top of `ctx.source.signMessage`:

- Pick chain-specific (curve, sigAlgo, hash) tuple — user never sees these.
- Determine the byte source per chain + mode (e.g. tx mode on Sui: `tx.build()`; tx mode on Solana:
  `versionedTx.message.serialize()`).
- Apply chain-specific intent prefix + prehash WHERE APPLICABLE (Sui: yes, blake2b over
  intentMessage; Solana: no, raw bytes).
- Forward all source-side overrides verbatim (5.1).
- Discriminate `{ kind: 'transaction' }` vs `{ kind: 'message' }` modes. The mode determines the
  **byte source** (and on Sui, the **intent scope**); the rest of the pipeline within a chain is
  identical regardless of mode.
  - **Sui (both modes):** `messageWithIntent(scope, bytes)` → blake2b-32 digest → source signs the
    digest. Scope is `TransactionData` for tx mode (bytes = `tx.build()`) and `PersonalMessage` for
    message mode (bytes = caller-supplied). The resulting signature is wire-encoded with the scheme
    flag (Ed25519/Secp256k1/Secp256r1) for the Sui serialized-signature format.
  - **Solana (both modes):** raw bytes Ed25519-signed (no intent prefix, no prehash). Tx mode:
    `versionedTx.message.serialize()`; message mode: caller-supplied bytes.
- Publishers are typed to accept only the tx-mode variant of their chain's payload — message-mode
  payloads are a compile-time error to broadcast.

### 5.3 Multi-op transactions

`ika.<source-chain>.transaction(build, opts?)` lets a user compose N coordinator ops into one tx:

```
await ika.sui.transaction(async ({ tx, ikaTx, pay }) => {
  // first DKG
  // second DKG
  // a sign that consumes the cap from the first DKG
});
```

Contract:

- `tx`: fresh `@mysten/sui` Transaction with sender set.
- `ikaTx`: `IkaTransaction` pre-wired with source defaults (signer, USEK).
- `pay()`: allocates one `(ika, sui)` coin pair per call. Multiple calls are supported.
- `opts`: `{ userShareEncryptionKeys?: UserShareEncryptionKeys }`. Overrides the source's default
  USEK for THIS transaction only. Extend cautiously — additional fields would need parity with
  `SuiSourceDefaults`.
- After the user's `build` callback completes, the plugin (NOT the Move contract) calls
  `tx.transferObjects(leftovers, signerAddress)` for every `(ika, sui)` pair issued by `pay()`. Move
  calls take `&mut Coin<T>`, so the handles remain valid even after being consumed by coordinator
  ops.
- If `build` throws, the plugin propagates the throw without executing the tx (no leftover transfer,
  no on-chain state change).
- If `exec(tx)` rejects (RPC drop, coin selection failure, etc.), the tx did not land on chain;
  signer state is consistent. The plugin propagates the underlying error.
- On success, returns `{ result: Awaited<T>, exec: SuiExecResult }` where `result` is the builder's
  return value and `exec` is the raw `signAndExecuteTransaction` payload.

### 5.4 Direct core access

`ika.<source-chain>.client` is the raw `@ika.xyz/sdk` `IkaClient`. The plugin layer is additive;
users may always drop down to the core.

Contract:

- Live getter. Permanent-failure behavior in §7.5.
- dWallets obtained via `ika.sui.client.getDWallet(...)` are NOT auto-decorated. Users must call
  `await ika.decorate(d)` explicitly.

### 5.5 Compose hooks

`ika.<source-chain>.compose.<op>(args)` adds a Move call to an EXISTING `IkaTransaction` without
executing. Used by multi-op flows that want plugin-level dWallet-kind handling + encrypted-share
fetching while supplying their own approval / presign cap.

---

## 6. Type-Level Guarantees

### 6.1 Curve narrowing — three defense layers

Curve filtering is enforced at three layers, from strongest to weakest:

1. **Compile-time, extend-surface call (preferred).** A well-typed destination parameterizes its
   sign helper to accept only its supported curves: `ika.sui.sign` types `dWallet` as
   `DWallet<SuiSupportedCurve>`; `ika.solana.sign` types it as `DWallet<'ED25519'>`. Passing a
   dWallet of a non-supported curve is a compile-time error.
2. **Runtime, in the destination's signCore.** Even if a destination is poorly parameterized (or the
   user circumvents types via `as`), `signCore` rechecks `dWallet.curve` against the destination's
   accepted curves and throws a clear error before the source is called.
3. **Decorate-time filter.** `decorate(d)` iterates registered destinations and SKIPS those whose
   `supportedCurves` doesn't include `d.curve`. The namespace just isn't installed; no throw. This
   is why `dWallet.solana` may be absent on a SECP256K1 handle even though the type allows it (see
   §6.6 caveat).

A destination author writing a NEW plugin must implement layer 1 (the type) AND layer 2 (the runtime
check in signCore). Layer 3 is framework-provided.

### 6.2 Publisher routing

`ika.publish(signed, opts?)` is typed so that:

- `signed.chain` is narrowed to one of the registered publishers' chains;
- `signed.payload` must structurally match THAT publisher's payload type;
- the return type is the publisher's result type.

### 6.3 Auto-decoration depth

The type transformer that adds destination namespaces to source-returned dWallets walks EXACTLY two
levels deep:

1. Top-level chain namespaces (`sui`, `solana`, ...).
2. Methods/values directly on each chain namespace.

It MUST NOT recurse into nested objects (e.g. into the raw core client, into compose namespaces).
Deeper nesting is intentionally NOT auto-decorated — the user reaches for those via the raw client
and decorates manually.

### 6.4 dWallet shapes covered by auto-decoration

At the leaf (a level-2 method's return type), the transformer recognizes and decorates:

1. `Promise<D>` where `D extends DWallet` → `Promise<D & DWalletNs>`.
2. `Promise<{ dWallet: D, ... }>` where `D extends DWallet` →
   `Promise<{ dWallet: D & DWalletNs, ...preserved }>`. Implemented via a homomorphic mapped type so
   `readonly` and optional modifiers on every sibling field are preserved exactly.
3. `Promise<readonly D[]>` or `Promise<D[]>` where `D extends DWallet` → element-wise wrap,
   preserving array's readonly-ness.

Anything else (e.g. `Promise<Map<X, D>>`, `Promise<{ items: D[] }>`) passes through unchanged.
Callers receiving those shapes call `await ika.decorate(d)` manually.

Synchronous (non-Promise) returns of these shapes are NOT supported by the transformer — no plugin
method returns a dWallet synchronously today, and the cost of adding sync support outweighs the
YAGNI benefit.

### 6.5 Reserved keys

`use`, `ready`, `decorate`, `publish`, `source` are owned by the client surface. A plugin attempting
to claim any reserved key MUST throw at registration time.

### 6.6 Metadata propagation

`.use()` returns a typed view with:

- `Ext`: intersection of all merged client-extension namespaces.
- `Pub`: discriminated record of all registered publisher (chain, payload, result) triples.
- `DWalletNs`: intersection of every registered destination's dWallet-level namespace.

These propagate through chained `.use()` calls. Worked example using a SECP256K1 dWallet
(deliberately chosen to expose the type-vs-runtime caveat below — see also the ED25519 case where
they agree):

```
const ika = new IkaClient()
  .use(suiSource(...))         // Ext gains { sui: { createDWallet, ... } }
  .use(suiDestination())       // Ext gains { sui: { sign } } merged into existing sui ns
                               // DWalletNs gains { sui: { sign, getAddress } }
  .use(solanaDestination())    // Ext gains { solana: { sign } }
                               // DWalletNs gains { solana: { sign, getAddress } }
  .use(suiPublisher(...))      // Pub gains { chain: 'sui', payload, result }
  .use(solanaPublisher(...));  // Pub gains { chain: 'solana', payload, result }

// Type system view (same for any curve):
//   ika.sui.createDWallet({ kind: 'shared', curve: 'SECP256K1' })
//     → Promise<SuiDWallet & { sui: ..., solana: ... }>
//
// Runtime view:
//   const d = await ika.sui.createDWallet({ kind: 'shared', curve: 'SECP256K1' })
//   d.sui      // ✓ present — sui dest accepts SECP256K1
//   d.solana   // ✗ ABSENT at runtime — solana dest's supportedCurves = [ED25519]
//
// With curve: 'ED25519' both destinations install — type and runtime agree.
// With curve: 'SECP256K1' only sui installs — type promises more than runtime delivers.
```

**Caveat — DWalletNs is the WIDE union; runtime filters by `supportedCurves`.** The type transformer
adds `& DWalletNs` regardless of the returned dWallet's curve, because the transformer has no curve
information at the call site. At runtime, `decorate()` only installs namespaces from destinations
whose `supportedCurves` includes the dWallet's curve. The SECP256K1 example above shows the
divergence. Two safer patterns:

1. Prefer the **extend-surface** sign call (`ika.solana.sign({ dWallet })`) — destination-side
   typing on that helper rejects unsupported curves at compile time (see §6.1 layer 1).
2. If you need to call `dWallet.<chain>.sign(...)`, guard with `'<chain>' in dWallet` first, or
   stick to dWallets whose curve you control (e.g. always-Ed25519 for a Solana-only flow).

Closing this gap entirely would require curve-aware destination wrapping at the type level — a
future refinement; not blocking.

---

## 7. Runtime Guarantees

### 7.1 Multi-tenant isolation

- **Address caches** (publicKey + chain-address derivation) MUST be per-destination-instance, not
  module-level singletons. Two clients in the same process must not share derived-address state.
- **Decoration stamp** MUST be per-client. Implemented via
  `Symbol.for('@ika.xyz/sdk/plugin@v1:decorated-by')` with a **version-tagged key**: two SDK
  versions in the same bundle get distinct keys (a v1 client and a v2 client can both decorate the
  same handle without conflict), but two copies of the SAME version share the registry (cross-bundle
  dedupe works as intended). Bump the suffix when changing the decoration contract.
- **USEK registration cache** MUST be per-source-instance. It stores Sui addresses of USEKs already
  registered on chain (a `Set<string>` keyed by the USEK's derived Sui address), preventing
  redundant on-chain registration calls within the same source's lifetime. Cross-instance leakage is
  prevented by closure capture inside the source factory.

### 7.2 Concurrency

- `decorate(d)` MUST coalesce concurrent calls on the same dWallet via a per-instance `WeakMap` of
  in-flight promises.
- Address caches MUST coalesce concurrent first-time misses on the same key via a per-cache
  `Map<string, Promise<V>>`. The first caller runs the derivation; subsequent callers await the
  in-flight promise. Settlement rules:
  - **On fulfillment:** insert the resolved value into the value cache, then delete the in-flight
    entry. Subsequent calls hit the value cache.
  - **On rejection:** delete the in-flight entry WITHOUT writing to the value cache, and re-throw to
    all awaiters. Subsequent calls re-run the derivation (the original failure may have been
    transient — RPC blip, missing peer dep load).
  - The order of "delete in-flight after settling" matters: do not let a successor see a
    settled-but-still-in-flight promise.

### 7.3 Source surface auto-awaits init

The source surface (`SourceSurface`) is a **closed interface** in this design: it exposes `chain`
(string property), `signMessage(input)`, and `getDWallet(id)`. The two callable methods are wrapped
to `await ready()` before reaching the raw source; the `chain` property is returned synchronously.
This wrapper prevents the install race where a destination calls `ctx.source.signMessage(...)`
before the source's install promise has settled.

Adding a new method to `SourceSurface` is a deliberate API change — it requires hand-editing
`#wrapSourceSurface` to wrap the new method (the wrapper does not auto-extend). A future ergonomic
improvement could make this auto-wrapping; today it's a known maintenance cost.

### 7.4 Property semantics on decorated dWallets

Decoration installs each namespace as:

- non-enumerable (won't show up in `JSON.stringify`, `Object.keys`)
- non-configurable (can't be re-decorated)
- non-writable (can't be replaced by user code)

### 7.5 Direct-client access locks on permanent failure

`ika.<source-chain>.client` is a getter that throws when init has permanently failed (retry budget
exhausted). Surfacing a half-initialized core client would leak cryptic errors deep in unrelated
code.

---

## 8. Failure Modes & Recovery

### 8.1 Init retry policy

Source plugins MAY use a lazy-init pattern: first call triggers `ikaClient.initialize()`, cached on
success, retried on failure up to a small cap. After the cap, every subsequent operation-method call
rejects immediately with a wrapped error (`permanentFailure`); the `client` getter throws the same
error (§7.5).

The cap is a **plugin-implementation detail**, not a framework requirement. The Sui source today
uses `MAX_INIT_RETRIES = 3`, hardcoded and not user-configurable. A future plugin MAY expose this
via constructor options.

**Relationship to `ready()` (§4.2).** `ready()` observes only the install promise queued during
`.use()`. For a source, that's the FIRST `ensureInit()` attempt. If that first attempt fails,
`ready()` surfaces it once; the queue is then empty. Subsequent retries are NOT queued back onto
`ready()` — they are triggered lazily by user-facing operation methods (e.g. `createDWallet`,
`sign`), each of which awaits `ensureInit()` independently. Consequence: after a `ready()`
rejection, a subsequent `ready()` resolves successfully (queue is empty) — even if the underlying
init has not yet succeeded. Users that need a durable "is the source actually initialized?" check
should call a real operation, not rely on `ready()`.

### 8.2 DKG partial-success recovery

If a network DKG completes but the user-side accept step fails (network blip, process crash), the
dWallet is stuck in `AwaitingKeyHolderSignature`. The plugin MUST expose an
`acceptEncryptedShare(input)` recovery primitive that:

- Pre-checks the current state. If already `Active`, short-circuits and returns the wrapped dWallet.
- If state is `AwaitingKeyHolderSignature`, re-submits the accept tx and waits for `Active`.
- If state is anything else (initial DKG in flight, network rejected, unknown), throws with a
  state-name in the error — the caller must manually diagnose. The recovery primitive does NOT
  attempt to advance the dWallet through earlier states.
- Requires the caller to persist `encryptedShareId` from the original DKG event (it lives in an
  off-state ObjectTable; not derivable from the dWallet's state).

### 8.3 Irreversible operations

`revealUserSecretShare` (imported-key → imported-key-shared) is irreversible. Both the building
block AND the high-level `createDWallet({ kind: 'imported-key-shared' })` MUST require an input
field named **`acknowledge`** with the exact string value **`'i-understand-this-is-irreversible'`**
(literal, case-sensitive). The validation MUST happen synchronously, before any chain work or fee
allocation. A missing or wrong-valued `acknowledge` throws with an instructive error.

### 8.4 Imported-key-shared partial-result recovery

The bundled `createDWallet({ kind: 'imported-key-shared' })` is a two-step on-chain operation: (1)
verify the imported key (produces a verified `imported-key` dWallet) and (2) reveal the user secret
share (promotes it to `imported-key-shared`). If step 1 succeeds and step 2 fails, the plugin MUST
throw a structured error so the caller doesn't lose the verified handle:

```ts
class ImportedKeySharedPartialError extends Error {
	readonly verifiedDWallet: SuiDWallet; // imported-key kind, ready for retry
	readonly cause: unknown; // the underlying reveal failure
	retryReveal(opts?: { signal?: AbortSignal }): Promise<SuiDWallet>;
}
```

`retryReveal()` re-runs only step 2 against the verified dWallet. The error MUST be thrown
EXCLUSIVELY for step-1-success / step-2-failure transitions — any failure during step 1 itself
surfaces as the underlying error directly (no handle to preserve).

**Implementation location:** the class is exported from `@ika.xyz/plugins/sui/source`. The bundled
`createDWallet` wraps the two-step call; on step-2 failure it constructs the error with
`verifiedDWallet` set to the step-1 output and `retryReveal` bound to a continuation that calls
`revealUserSecretShare(verifiedDWallet, { acknowledge: 'i-understand-this-is-irreversible', ...opts })`.

### 8.5 Install error surfacing

`await ika.ready()` is the deterministic point for surfacing async install errors. Surface methods
on the client also self-gate on `ready()`, so a user who never calls `ready()` directly still
observes errors on first use. The policy is "surface once, then forget" — see §4.2.

---

## 9. Decisions (formerly open questions)

All resolved. The originating question is preserved alongside each answer for context.

### Q1 — `ready()` failure surfacing policy

**Decision:** Surface once, then forget. §4.2 documents the contract.

### Q2 — Solana publisher confirmation timeout

**Decision:** Add a **hard ceiling, default 180s, user-configurable** via
`SolanaPublisherOptions.confirmTimeoutMs`.

- The `isBlockhashValid` check is the primary expiry signal; the ceiling is defense-in-depth against
  pathological RPC behavior.
- On timeout, throw with a message that includes the signature so the user can manually check the
  chain.
- Rationale: a `publish()` call that hangs forever is the worst possible DX. Security/availability
  ranks above tighter retry timing.

### Q3 — `imported-key-shared` bundled vs split

**Decision:** **Keep bundled `createDWallet({ kind: 'imported-key-shared' })` for ergonomics, ADD
partial-result recovery.**

- If step 1 (verify) succeeds and step 2 (reveal) fails, throw a typed error
  (`ImportedKeySharedPartialError`) carrying the verified `SuiDWallet` handle and a `retryReveal()`
  continuation.
- The building blocks `ika.sui.requestImportedKeyVerification(...)` and
  `ika.sui.revealUserSecretShare(...)` remain individually addressable for users who want explicit
  two-phase control.
- Rationale: happy-path ergonomics + recoverable failure path = both security (no lost handle) and
  usability (one call for the common case).

### Q4 — `Promise<DWallet[]>` auto-decoration

**Decision:** **Extend the transformer to walk into `Array<DWallet>` returns.** Same depth limit
(top-level method's return type).

- No current method returns `DWallet[]`, but adding the transformer support prospectively avoids a
  breaking type change later.
- Specifically: extend `WrapReturnValue<R>` to recognize `R extends readonly DWallet[]` and map
  element types.

### Q5 — Destination→source override channel

**Decision:** **Keep structural cast.** Formalize §3.1's whitelist convention as the contract.

- Flat input API (`{ presign, dWallet, ... }`) is more ergonomic than `{ overrides: {...} }`.
- All sources are first-party — we control the boundary.
- The cast at the destination → source call site is the only protocol-level mechanism; sources do
  not need to expose helpers for it.

### Q6 — Address cache thundering-herd coalescing

**Decision:** **Add coalescing via `Map<string, Promise<V>>` in-flight tracking.**

- Tiny addition (a few lines per cache); standard pattern.
- Prevents redundant WASM derivation when many concurrent calls hit a cold key.
- No API change.

### Q7 — `compose.*` return decoration

**Decision:** Not applicable. Compose methods return `Promise<void>` by design. Section 5.5
documents this.

### Q8 — Source-surface vs extend-surface `getDWallet`

**Decision:** Deliberate split, documented in §3.1.

- `ctx.source.getDWallet(id)` returns naked (consumer is other plugins).
- `ika.<chain>.getDWallet(id)` auto-decorates (consumer is end users).

### Q9 — `publish(signed)` cancellation

**Decision:** **Add optional second parameter: `publish(signed, opts?: { signal?: AbortSignal })`.**

- Publishers receive the signal through their `broadcast(signed, { signal })` extension.
- Backward-compatible (`opts` is optional).
- Solana publisher's confirmation poll respects the signal and rejects with an `AbortError` on
  cancel.
- Sui publisher's `executeTransaction` already accepts a signal; thread it through.

### Q10 — Multi-source future

**Decision:** **Single-source-per-client is permanent for this iteration.**

- Today's `ctx.source` API would have to become `ctx.sources.<chain>` to support multi-source. Major
  refactor with no current use case.
- When a second source plugin ships, introduce a parallel client class (name TBD when we have the
  use case) — don't burden today's users with multi-source machinery.

### Q11 — Shared-namespace rollback semantics

**Decision:** **Wholesale-nuke wins.** Source rollback deletes the entire namespace including any
destination contributions added afterwards.

- Rationale:
  - Destinations universally depend on `ctx.source`. A namespace with destination methods but no
    source is a hidden runtime footgun (sign calls would throw `no source` deep in user code).
  - Simpler rollback is auditable. Fine-grained ownership adds per-key tracking overhead with no
    real-world payoff today.
  - Registration error visibility > silent half-broken state.
- The round-8 code change in `#mergeExtend` (recording inner keys when creating a top-level
  namespace) is **confirmed dead code** and MUST be reverted. The existing test at
  `plugin-client.test.ts:474` correctly documents this contract.
- If destinations need to outlive a failed source's rollback in the future, the answer is a
  different architecture (e.g. namespace ownership tokens) — not a quiet behavior change.

---

## 10. Test / Invariant Coverage

Each invariant in §4 and §7 must have at least one test. ✓ = test exists in
`test/unit/plugin-client.test.ts` or `test/testnet/plugin-e2e.test.ts`. _gap_ = needs a
fresh-context agent to write.

**Lifecycle (§4):**

- Async install reject → rolled back state. ✓
- Sync install throw (`install()` throws before returning) → rolled back state. _gap_
- `ready()` failure-surfacing policy: first call rejects, second call (no new installs) resolves.
  _gap_
- Rollback granularity — wholesale-nuke: source created `ika.sui`, destination merged inner keys,
  source install rejects → entire `ika.sui` deleted including destination contributions. ✓
  (`plugin-client.test.ts:474`)
- Rollback granularity — subsequent-use isolation: rollback from use #1 doesn't touch keys added by
  use #2. ✓
- `decorate` is atomic across destinations (no half-mutated dWallet on namespace collision). ✓
- Concurrent `decorate(d)` coalesces via WeakMap. ✓
- Cross-client decoration rejected. ✓
- Decorate with zero registered destinations → dWallet untouched, no stamp; later `decorate()` after
  registering a destination still works. ✓
- Reserved-key collision throws at `use()` time. ✓

**Type guarantees (§6):**

- Curve mismatch on destination extend-surface `sign({ dWallet, ... })` is a compile-time error
  (`@ts-expect-error` test). _gap_
- `ika.<chain>.client.getDWallet(...)` does NOT type as auto-decorated. ✓
- `ika.<chain>.createDWallet(...)` IS typed as auto-decorated. ✓
- `{ dWallet }` field in returned objects IS typed as auto-decorated (value-level). ✓
- `{ dWallet }` field decoration preserves `readonly` and optional modifiers on sibling fields
  (homomorphic mapped type — verify by attempting to write into a `readonly` sibling and expecting
  `@ts-expect-error`). _gap_
- Publisher routing: `ika.publish({ chain: 'sui', payload: solanaPayload })` is a compile-time
  error. _gap_

**Source-surface contract (§3.1, §7.3):**

- Source surface `signMessage` auto-awaits `ready()`. ✓
- Source surface `getDWallet` auto-awaits `ready()`. _gap_
- Source `signMessage` silently ignores unknown fields (does not throw). _gap_

**Plugin-implementation behaviors (§8, testnet unless noted):**

- USEK registration cache survives across calls in the same source instance. _gap (testnet)_
- Multi-op transaction: two DKGs + one sign in one PTB succeeds; leftover coins are transferred.
  _gap (testnet)_
- `acceptEncryptedShare` recovery: Active state → short-circuits; AwaitingKeyHolderSignature →
  re-submits; other → throws with state name in error. _gap (testnet)_
- `revealUserSecretShare` requires correct `acknowledge` string; missing/wrong throws before any fee
  allocation. _gap (unit, mock)_
- Init retry policy: 3 failures lock into `permanentFailure`; subsequent calls reject immediately.
  _gap (unit, mock)_
- `ImportedKeySharedPartialError` thrown when step-1 succeeds and step-2 fails; `retryReveal()`
  continuation completes the promotion. _gap (testnet)_

**Decision-driven new tests (§9):**

- Q2: Solana publisher `confirmTimeoutMs` enforces timeout; on timeout, the error message includes
  the signature. _gap (unit, mocked Connection)_
- Q4: `Promise<readonly DWallet[]>` return types are auto-decorated element-wise; readonly-ness
  preserved. _gap (type-only test with @ts-expect-error)_
- Q6: Address cache concurrent first-time miss on the same key triggers exactly ONE WASM derivation.
  _gap (unit, mocked derivation)_
- Q9: `publish(signed, { signal })` aborts the publisher's confirmation poll on abort. _gap (unit,
  mocked publisher with delayed confirm)_
- Q11: Dead-code revert in `#mergeExtend` (no test, code-only change). Existing test at
  `plugin-client.test.ts:474` stays as the contract test for wholesale-nuke.

The three code fixes applied earlier in this audit cycle (homomorphic `WrapReturnValue`,
sync-install-throw rollback, inner-key recording on namespace creation) are covered by typecheck +
the existing test suite passing, but lack dedicated tests for the new behaviors they unlock. The
gaps marked above for those three are first-priority handoffs.

**Dead-code cleanup from Q11 decision.** The round-8 code change in `#mergeExtend` (recording inner
keys when creating a top-level namespace) is dead code under wholesale-nuke. The handoff agent MUST
revert it:

- File: `sdk/typescript/src/plugin/client.ts`, inside `#mergeExtend`, inside the
  `else if (existing === undefined)` branch.
- Remove the
  `if (incoming !== null && typeof incoming === 'object' && !Array.isArray(incoming)) { for (...) recorder?.recordInnerKey(...) }`
  block; keep only the `Object.defineProperty(self, topKey, topDescriptor)` and
  `recorder?.recordTopKey(topKey)` lines that preceded it.
- The existing test at `sdk/typescript/test/unit/plugin-client.test.ts:474` stays as-is (it
  documents the correct contract).
- No new test required for this gap.

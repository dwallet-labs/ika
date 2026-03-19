## Ika SDK Packages

TypeScript SDK for the Ika dWallet network. Split into a chain-agnostic core and chain-specific adapters.

```
sdk/
├── core/        @ika.xyz/core    Chain-agnostic 2PC-MPC protocol and cryptography
├── sui/         @ika.xyz/sui     Sui blockchain adapter (re-exports core)
├── ika-wasm/    @ika.xyz/ika-wasm   Rust-to-WASM crypto bindings
└── typescript/  @ika.xyz/sdk     DEPRECATED — shim re-exporting @ika.xyz/sui
```

### Which package to use

| You are...                               | Install            |
| ---------------------------------------- | ------------------ |
| Building an app on Sui                   | `@ika.xyz/sui`     |
| Building a chain adapter (e.g., Solana)  | `@ika.xyz/core`    |
| Using only crypto primitives (no chain)  | `@ika.xyz/core`    |

`@ika.xyz/sui` re-exports everything from `@ika.xyz/core`, so you only need one dependency.

### Dependency graph

```
@ika.xyz/sui
  ├── @ika.xyz/core
  │     ├── @ika.xyz/ika-wasm
  │     ├── @mysten/bcs
  │     ├── @noble/curves
  │     ├── @noble/hashes
  │     └── @scure/base
  └── @mysten/sui
```

### Building

From the repo root:

```bash
pnpm install
pnpm --filter @ika.xyz/core build
pnpm --filter @ika.xyz/sui build
```

### Testing

```bash
# Core unit tests (chain-agnostic crypto)
pnpm --filter @ika.xyz/core test:unit

# Sui unit tests
pnpm --filter @ika.xyz/sui test:unit

# Sui integration tests (requires localnet)
pnpm --filter @ika.xyz/sui test:integration
```

### License

BSD-3-Clause-Clear (c) dWallet Labs, Ltd.

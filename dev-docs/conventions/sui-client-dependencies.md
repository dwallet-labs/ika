# Sui client dependency boundary

Use the standalone [`MystenLabs/sui-rust-sdk`](https://github.com/MystenLabs/sui-rust-sdk)
for Sui network RPC, transaction finalization, simple-key signing, and faucet
requests. Keep Sui main dependencies only where Ika needs consensus, deployed
wire types, Move tooling, package metadata, execution internals, or test swarms.

## Network RPC

`ika-sui-client/src/grpc.rs:SuiGrpcClient` is the direct fullnode transport. It
must wrap `sui_rpc::Client`, not Sui main's unpublished
`sui_rpc_api::Client`. The transport owns compatibility conversion from SDK
protobuf/BCS responses into the `sui_types` values consumed by the rest of Ika.

Read-only callers should reuse `ika_sui_client::grpc::SuiGrpcClient` instead of
opening a second client implementation. Add narrow inherent methods to that
adapter when a read is generally useful; keep trust-sensitive reads on the
`SuiTransport` abstraction so peer-only and verified-read modes continue to
work.

Interactive transaction execution uses
`sui_rpc::Client::execute_transaction_and_wait_for_checkpoint`. A successful
return normally provides read-your-writes consistency and handles
duplicate-submission races. When checkpoint observation fails after execution,
the adapter preserves and returns the successful effects instead of reporting
the committed transaction as failed.

The notifier's serialized writer uses the raw execution RPC with a submission
deadline and returns as soon as effects are available. It must not hold the
global writer lock while waiting for checkpoint inclusion: checkpoint lag is a
read-side observability concern, and a lagging checkpoint stream cannot make a
committed notifier transaction safe to retry.

Faucet service-root and `/v2/gas` calls use
`sui_rpc::faucet::FaucetClient` through Ika's shared adapter. Exact legacy
`/gas` and `/v1/gas` URLs use a narrow compatibility HTTP request because the
standalone client otherwise appends `/v2/gas`. The legacy local faucet can
return an error-shaped body after a successful drip, so its HTTP status is the
delivery result.

## Wallet and transaction construction

Wallet-backed transaction paths accept
`ika-sui-client/src/transaction_context.rs:TransactionContext`. The Ika CLI
loads ordinary file-based `client.yaml`/`sui.keystore` configurations with
standalone `sui-crypto`. Sui-main `WalletContext` is only an adapter for
upstream in-memory test wallets, external signers, and package bootstrap code.
Do not add `WalletContext` parameters to Ika transaction modules.

Completed core PTBs are replayed by
`ika-sui-client/src/transaction_builder.rs` into standalone
`sui-transaction-builder`. Its RPC-aware `build()` owns object resolution, gas
selection, simulation, and execution-failure checking. New self-contained
transaction constructors should use the standalone builder directly. Existing
protocol constructors can be converted incrementally; the replay boundary
keeps their command and argument semantics unchanged in the meantime.

The RPC endpoint finalizes object references, gas payment, gas price, and the
simulation-estimated gas budget. Before signing, the adapter compares the
returned transaction kind, inputs, and commands with the locally canonicalized
PTB. Gas metadata may differ, and simulation may downgrade a conservatively
mutable shared input to immutable after inspecting the Move signature; object
identity, versions, pure values, and commands may not differ. This check is a
security boundary: never sign an endpoint-returned transaction without it.

The root workspace pins `sui-crypto`, `sui-rpc`, `sui-sdk-types`, and
`sui-transaction-builder` to the exact `sui-rust-sdk` revision used by the
pinned Sui main tag. A Sui version bump must copy the new revision from Sui's
workspace and update all pins together. Check that Cargo resolves one revision
of each standalone SDK crate:

```bash
cargo tree -d | rg 'sui-(crypto|rpc|sdk-types|transaction-builder)'
```

The output includes Sui main's distinct unpublished
`sui-transaction-builder v0.0.0` alongside the standalone SDK's builder. That
name collision is expected while Move publication remains on Sui main; two
different standalone SDK revisions are not.

## Retained Sui main boundaries

Ika has no direct `sui-rpc-api` dependency. The remaining Sui-main
client-command boundary is Move package publication in `ika-swarm-config`,
which calls `SuiClientCommands::TestPublish`. That command owns package
compilation, dependency verification, signing, publication, and the
`Pub.<env>.toml` state used by local bootstrap. A replacement must preserve
ephemeral publication metadata across all four Ika packages; merely calling
standalone `TransactionBuilder::publish` would break cross-package address
resolution.

Do not introduce `sui-rpc-api::Client` for endpoint probes, object or checkpoint
reads, transaction lookups, input resolution, gas selection, simulation,
subscriptions, or submission. Those operations belong on the standalone SDK
adapter.

`sui-types` and other Sui-main crates remain necessary for Ika's deployed wire
types, existing protocol PTB constructors, Move compilation/package metadata,
test swarms, execution internals, and Mysticeti consensus. `sui-sdk` remains in
`ika-sui-client` only for the upstream test-wallet adapter and in bootstrap
crates for package publication. The standalone SDK does not provide a Move
compiler, Sui CLI environment manager, external-signer abstraction, or
test-cluster replacement.

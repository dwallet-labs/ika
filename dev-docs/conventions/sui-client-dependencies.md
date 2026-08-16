# Sui client dependency boundary

Use the standalone [`MystenLabs/sui-rust-sdk`](https://github.com/MystenLabs/sui-rust-sdk)
for Sui network RPC. Keep Sui main dependencies only where Ika needs node,
consensus, Move, wallet, or execution internals that the standalone SDK does not
provide.

## Network RPC

`ika-sui-client/src/grpc.rs:SuiGrpcClient` is the direct fullnode transport. It
must wrap `sui_rpc::Client`, not Sui main's unpublished
`sui_rpc_api::Client`. The transport owns the compatibility conversion from SDK
protobuf/BCS responses into the `sui_types` values consumed by the rest of Ika.

Read-only callers should reuse `ika_sui_client::grpc::SuiGrpcClient` instead of
opening a second client implementation. Add narrow inherent methods to that
adapter when a read is generally useful; keep trust-sensitive reads on the
`SuiTransport` abstraction so peer-only and verified-read modes continue to
work.

Wallet-backed transaction paths also use this adapter for object-reference and
gas selection, simulation, and execution. `WalletContext` remains the source of
the active environment and keystore, but its Sui-main gRPC client must not be
used for network operations.

Use standalone `sui-transaction-builder` for self-contained transaction shapes
that do not depend on Sui-main Move/execution types. Ika's protocol transaction
modules still use Sui's core `ProgrammableTransactionBuilder` because their
public and internal APIs are built around `sui_types::TransactionData`; their
network resolution and submission nevertheless go through the standalone SDK.

The root workspace pins `sui-rpc`, `sui-sdk-types`, and
`sui-transaction-builder` to the exact `sui-rust-sdk` revision used by the
pinned Sui main tag. A Sui version bump must copy the new revision from Sui's
workspace and update all pins together. Check that Cargo resolves one copy of
each SDK crate:

```bash
cargo tree -d | rg 'sui-(rpc|sdk-types|transaction-builder)'
```

## Retained Sui main boundaries

Ika has no direct `sui-rpc-api` dependency. The remaining Sui-main client
boundary is Move package publication in `ika-swarm-config`, which calls
`SuiClientCommands::TestPublish`. That command owns package compilation,
dependency verification, wallet signing, publication, and the `Pub.<env>.toml`
state used by the local bootstrap. Replacing it is a package-publication
rewrite, not an RPC-client substitution.

Do not introduce `sui-rpc-api::Client` for endpoint probes, object or checkpoint
reads, transaction lookups, input resolution, gas selection, simulation,
subscriptions, or submission. Those operations belong on the standalone SDK
adapter.

`sui-sdk`, `sui-types`, and other Sui main crates remain necessary for wallet
configuration/signing, programmable transaction construction, Move packages,
execution types, test swarms, and Mysticeti consensus. Replacing those is not a
client migration and must not be mixed into an RPC dependency cleanup.

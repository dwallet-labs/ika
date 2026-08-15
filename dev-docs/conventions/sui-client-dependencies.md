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

The root workspace pins `sui-rpc` and `sui-sdk-types` to the exact
`sui-rust-sdk` revision used by the pinned Sui main tag. A Sui version bump must
copy the new revision from Sui's workspace and update both pins together. Check
that Cargo resolves one copy of each SDK crate:

```bash
cargo tree -d | rg 'sui-(rpc|sdk-types)'
```

## Retained Sui main client dependencies

Direct `sui-rpc-api` use is limited to compatibility boundaries that do not yet
have a standalone replacement in this repository:

- `ika-sui-client/src/transport.rs:ExecutedTransaction::from_sui` converts the
  result returned by Sui's `WalletContext` into Ika's client result type.
- `ika-swarm-config` uses Sui's wallet-aware transaction builder while creating
  and publishing the local network contracts.
- `ika-upgrade-test/src/workload.rs` uses the same transaction builder to fund
  the upgrade workload account.

Do not use `sui-rpc-api::Client` for endpoint probes, object reads, checkpoint
reads, transaction lookups, subscriptions, or submissions through Ika's node
transport. Those operations belong on the standalone SDK adapter.

`sui-sdk`, `sui-types`, and other Sui main crates remain necessary for wallet
configuration/signing, programmable transaction construction, Move packages,
execution types, test swarms, and Mysticeti consensus. Replacing those is not a
client migration and must not be mixed into an RPC dependency cleanup.

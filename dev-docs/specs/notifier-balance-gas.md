# Notifier address-balance gas

The network's single writer always pays for Sui transactions from its SIP-58
address balance. Gas-coin selection, object-reference caching, and stale gas
object recovery are not supported modes.

## Transaction construction

An empty gas payment on a programmable transaction pays gas from the sender's
SUI address balance. `balance_gas_transaction_data` constructs every notifier
transaction with:

- an empty `gas_data.payment`;
- the fixed notifier gas budget;
- `ValidDuring { min_epoch: current Sui epoch, max_epoch: current + 1,
  chain: full genesis-rooted ChainIdentifier, nonce: random u32 }`.

The one-epoch extension keeps a transaction built immediately before a Sui
epoch boundary valid through submission. It is the maximum window accepted by
`is_replay_protected`. The current Sui epoch is fetched for each submission.
The chain identifier is resolved once at boot and failure to resolve it is a
fatal configuration/startup error.

Checkpoint fee reimbursement cannot merge into `Argument::GasCoin`, because
address-balance transactions have no gas coin. Reimbursement is transferred to
the writer as an owned coin and swept into its address balance on a later boot.

## Boot-time preparation

`prepare_for_sui` runs these steps in order:

1. Resolve the full Sui chain identifier; fail startup if it is unavailable.
2. Read SUI funds split between address balance and owned coin objects; fail
   startup when the balance accumulator is unavailable.
3. If at least 1 SUI remains in coin objects, perform a best-effort migration
   sweep. The sweep uses those coins as ordinary gas payment, splits
   `total - sweep budget`, and calls `coin::send_funds<SUI>` to deposit the
   split amount into the writer's address balance. The small gas remainder is
   below the re-sweep threshold.
4. Refuse to start when the address balance is below one notifier gas budget.
5. Seed and refresh `ika_sui_connector_gas_coin_balance` every 60 seconds from
   the address balance. The historical metric name is retained for dashboard
   compatibility.

## Preconditions

- Sui must enable `enable_accumulators` and
  `enable_address_balance_gas_payments`.
- The notifier address must hold enough SUI in its address balance. Plain coin
  transfers create coin objects; the boot sweep or an explicit balance deposit
  moves those funds into the address balance.
- The writer submits serially. One gas budget is the minimum startup threshold;
  operators should maintain additional float.

## Invariants

1. Ordinary notifier transactions never reference a gas object, so a lagging
   fullnode cannot invalidate them through a stale gas-object version.
2. Every notifier transaction is replay-protected, pinned to the exact chain,
   and unique for its inputs, epoch window, and nonce.
3. Reimbursement funds are transferred to the writer and remain recoverable by
   the boot sweep.
4. The only gas-coin transaction is the migration sweep itself, which is needed
   to move pre-existing coin objects into the mandatory address balance.

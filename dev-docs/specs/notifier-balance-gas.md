# Notifier gas modes (gas coins vs. SIP-58 address-balance gas)

How the network's single writer pays for its Sui transactions, why the
gas-coin path carries a whole caching/recovery apparatus, and the opt-in
SIP-58 mode that deletes that failure class. Actors: the notifier's
`sui_executor`/`build_sui_transaction`, the Sui chain's protocol flags.

## Gas-coin mode (default)

Each submission carries an owned gas-coin `ObjectRef` whose version must be
exactly current. Because the notifier's fullnode view lags the validators,
the executor maintains `NotifierSubmitState`: the post-transaction gas ref is
cached from each transaction's effects, stale-gas rejections clear the cache
and record a re-fetch version floor, and the gas coin must never be shared
with any other spender (equivocation locks it for the epoch). This machinery
exists solely to fight gas-object versioning; it has wedged epoch advance
before and is the reason two writers can never share an address.

## Address-balance mode (`notifier_gas_from_address_balance: true`)

SIP-58: an **empty gas payment** on a programmable transaction pays gas from
the sender's SUI address balance, and a `ValidDuring` expiration replaces the
replay protection that gas-coin version bumps provided. Decision rules:

1. **Construction** (`balance_gas_transaction_data`): empty `gas_data.payment`,
   same fixed budget, expiration `ValidDuring { min_epoch == max_epoch ==
   current SUI epoch, chain: full genesis-rooted ChainIdentifier, nonce:
   random u32 }`. Single-epoch validity is accepted under every protocol
   regime; a submission racing a Sui epoch boundary expires harmlessly and
   the caller's retry rebuilds it against the new epoch.
2. **Chain identifier** is resolved ONCE at boot (compiled-in for
   mainnet/testnet via the short id; genesis checkpoint digest otherwise) and
   a failure to resolve it fails the boot loudly — a writer silently unable
   to build transactions is the issue-#1892 failure shape.
3. **Current SUI epoch** is fetched per submission with the same
   retry-forever contract as the reference gas price.
4. **The whole gas-object apparatus is bypassed**: `next_gas_coins` returns
   no refs, effects-based gas caching is skipped (the effects' gas object is
   a placeholder), and stale-gas rejection handling is inert. The
   stale-gas-version failure class does not exist without gas objects.
5. **Checkpoint fee reimbursement** cannot `MergeCoins` into
   `Argument::GasCoin` (none exists); it is transferred to the writer's
   address as an owned coin instead, for the operator to sweep.

## Preconditions and rollout

- Sui protocol flags `enable_accumulators` + `enable_address_balance_gas_payments`:
  testnet since protocol 108, mainnet since 124, localnets at max version.
- The notifier address must hold SUI in its ADDRESS BALANCE (an explicit
  balance deposit — plain coin transfers do not fund it). Each submission
  reserves the full gas budget from the balance for its validity window; the
  writer submits serially, so one budget of headroom suffices, plus float.
- Default OFF. The intended rollout is a testnet canary of the flag before
  any mainnet use; the gas-coin path stays the default until then.

## Key invariants

1. With the flag off, byte-identical behavior to the pre-SIP-58 writer.
2. With the flag on, no transaction ever references a gas object — node-view
   staleness cannot invalidate a submission.
3. Every balance-gas transaction is replay-protected
   (`TransactionExpiration::is_replay_protected`), pinned to the exact chain,
   and unique per (inputs, epoch window, nonce).
4. Reimbursement funds are never burned or stranded in either mode: merged
   into the gas coin (coin mode) or transferred to the writer address
   (balance mode).

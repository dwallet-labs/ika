# OdWS Policy Engine

**Mainnet Package ID:** `0x9fd74e7ad831f13730ddb59072978eeb51b1eb840f97238d836b27953be52180`

Composable, on-chain policy enforcement for Ika dWallets. The `DWalletCap` is custodied inside a shared `PolicyEngine` object — the agent cannot call `approve_message` directly. It must go through the engine, which requires a `PolicyReceipt<T>` from every registered rule before it releases a `MessageApproval`.

Uses a Sui TransferPolicy-style composable rule system with OTW witnesses.

## How It Works

```
┌──────────────────────────────────┐
│     PolicyEngine (shared)        │
│                                  │
│  DWalletCap (custodied)          │
│  rules: [RateLimit,             │
│          SenderAllowlist,        │
│          SpendingBudget]         │
│  rule_configs: Bag               │
└───────────────┬──────────────────┘
                │
1. create_request(engine, access_cap, ...)
                │
2. rate_limit::enforce(engine, request, clock)     → PolicyReceipt<RateLimit>
3. sender_allowlist::enforce(engine, request, ctx)  → PolicyReceipt<SenderAllowlist>
4. spending_budget::enforce(engine, request, v, c)  → PolicyReceipt<SpendingBudget>
                │
5. request.add_receipt(receipt₁)
   request.add_receipt(receipt₂)
   request.add_receipt(receipt₃)
                │
6. engine.confirm_dkg(coordinator, request) → MessageApproval
   (only if ALL receipts present)
```

### Why It's Unskippable

- The `DWalletCap` lives inside the engine — the agent never holds it
- `confirm_dkg` / `confirm_imported_key` checks that `request.receipts` matches `engine.rules` exactly
- Only the module defining rule type `T` can construct `PolicyReceipt<T>` (witness pattern)
- `ApprovalRequest` has no `drop` ability — must be consumed via `confirm_*` or `cancel`

## Using from the TypeScript SDK

The `@ika.xyz/odws` SDK handles all on-chain interactions. No need to construct PTBs manually.

### One-Call Setup

```typescript
const config = await provider.setupPolicyEngine('0xPKG', 'my-wallet', [
  { type: 'rate_limit', maxPerWindow: 100, windowMs: 3_600_000 },
  { type: 'sender_allowlist', allowed: [agentAddress] },
  { type: 'spending_budget', maxPerWindow: 10000, maxPerTx: 500, windowMs: 86_400_000 },
]);
// Engine created, rules registered, access cap granted, signing wired up.
// All subsequent signTransaction calls go through the engine automatically.
```

### Step-by-Step

```typescript
// Create engine (custodies the DWalletCap)
const { engineId, adminCapId } = await provider.createPolicyEngine('0xPKG', 'my-wallet', [
  { type: 'rate_limit', maxPerWindow: 100, windowMs: 3_600_000 },
]);

// Add more rules
await provider.addPolicyRule('0xPKG', engineId, adminCapId, {
  type: 'expiry', expiryMs: Date.now() + 7 * 86_400_000,
});

// Grant access to an agent
const { accessCapId } = await provider.grantPolicyAccess('0xPKG', engineId, adminCapId, agentAddr);

// Remove a rule
await provider.removePolicyRule('0xPKG', engineId, adminCapId, 'rate_limit');

// Emergency pause / unpause
await provider.pausePolicyEngine('0xPKG', engineId, adminCapId);
await provider.unpausePolicyEngine('0xPKG', engineId, adminCapId);
```

## Capabilities

| Capability | Held By | Can Do |
|------------|---------|--------|
| `PolicyAdminCap` | Wallet owner | Add/remove rules, pause/unpause, grant/revoke access, destroy engine |
| `PolicyAccessCap` | Agent | Create approval requests |

Multiple access caps can exist (one per agent), revocable independently.

## Events

| Event | Emitted When | Fields |
|-------|-------------|--------|
| `PolicyEngineCreatedEvent` | Engine created | `engine_id`, `admin_cap_id` |
| `PolicyAccessGrantedEvent` | Access cap granted | `engine_id`, `access_cap_id`, `recipient` |
| `SpendingDeclaration` | spending_budget enforced | `engine_id`, `declared_value`, `cumulative_spent`, `timestamp_ms` |
| `TargetDeclaration` | target_filter enforced | `engine_id`, `declared_target` |
| `CommitmentCreated` | time_delay commit | `engine_id`, `message_hash`, `commit_ms`, `release_ms` |
| `CommitmentConsumed` | time_delay enforce | `engine_id`, `message_hash`, `consumed_ms` |
| `CommitmentRevoked` | time_delay revoked by admin | `engine_id`, `message_hash`, `revoked_ms` |

## Built-in Rules

### rate_limit

Max N signatures per time window (milliseconds).

```move
rate_limit::add(&mut engine, &admin_cap, 100, 3_600_000, &clock);
let receipt = rate_limit::enforce(&mut engine, &request, &clock);
request.add_receipt(receipt);
```

### expiry

Signing blocked after a timestamp.

```move
expiry::add(&mut engine, &admin_cap, 1748736000000);
let receipt = expiry::enforce(&engine, &request, &clock);
```

### sender_allowlist

Only whitelisted `ctx.sender()` addresses can sign.

```move
sender_allowlist::add(&mut engine, &admin_cap, vector[agent_1, agent_2]);
sender_allowlist::add_address(&mut engine, &admin_cap, new_agent);
sender_allowlist::remove_address(&mut engine, &admin_cap, old_agent);
let receipt = sender_allowlist::enforce(&engine, &request, ctx);
```

### allowed_algorithms

Restrict `(signature_algorithm, hash_scheme)` pairs — controls which chains the agent can sign for.

```move
let pairs = vector[allowed_algorithms::new_pair(0, 1)]; // ECDSA + Keccak256
allowed_algorithms::add(&mut engine, &admin_cap, pairs);
let receipt = allowed_algorithms::enforce(&engine, &request);
```

### spending_budget

Per-tx cap + cumulative budget per window. Agent declares value, emits `SpendingDeclaration` event.

```move
spending_budget::add(&mut engine, &admin_cap, 1000, 100, 3_600_000, &clock);
let receipt = spending_budget::enforce(&mut engine, &request, 50, &clock);
```

### target_filter

Allowlist/blocklist of target addresses. Agent declares target, emits `TargetDeclaration` event.

```move
target_filter::add(&mut engine, &admin_cap, vector[contract_a], vector[]);
target_filter::block_target(&mut engine, &admin_cap, mixer_address);
let receipt = target_filter::enforce(&engine, &request, target_bytes);
```

### time_delay

Commit-reveal with ms-precision delay. Owner can revoke during the window.

```move
time_delay::add(&mut engine, &admin_cap, 3_600_000, ctx);

// Agent: commit
time_delay::commit(&mut engine, &access_cap, message_hash, &clock);
// ... wait ...
let receipt = time_delay::enforce(&mut engine, &request, &clock);

// Owner: revoke during delay
time_delay::revoke_commitment(&mut engine, &admin_cap, message_hash, &clock);
```

## Writing Custom Rules

```move
module my_policy::daily_limit;

use sui::clock::Clock;
use ika_ows_policy::policy_engine::{PolicyEngine, PolicyAdminCap, ApprovalRequest, PolicyReceipt};

public struct DailyLimit has drop {}

public struct DailyLimitConfig has store, drop {
    max_per_day: u64,
    day_count: u64,
    day_start_ms: u64,
}

const MS_PER_DAY: u64 = 86_400_000;

public fun add(engine: &mut PolicyEngine, admin_cap: &PolicyAdminCap, max: u64, clock: &Clock) {
    engine.add_rule(admin_cap, DailyLimit {}, DailyLimitConfig {
        max_per_day: max, day_count: 0, day_start_ms: clock.timestamp_ms(),
    });
}

public fun enforce(
    engine: &mut PolicyEngine, request: &ApprovalRequest, clock: &Clock,
): PolicyReceipt<DailyLimit> {
    let config = engine.rule_config_mut<DailyLimit, DailyLimitConfig>(DailyLimit {});
    let now = clock.timestamp_ms();
    if (now >= config.day_start_ms + MS_PER_DAY) {
        config.day_count = 0;
        config.day_start_ms = now;
    };
    assert!(config.day_count < config.max_per_day, 0);
    config.day_count = config.day_count + 1;
    ika_ows_policy::policy_engine::new_receipt(DailyLimit {}, request)
}
```

Deploy, then register: `daily_limit::add(&mut engine, &admin_cap, 50, &clock);`

## Emergency Pause

Built-in kill switch (not a composable rule — absolute override):

```move
engine.pause(&admin_cap);   // all approvals abort
engine.unpause(&admin_cap); // resume
```

## Engine Lifecycle (Move)

```move
// Create
let admin_cap = create_with_dkg_cap(dwallet_cap, ctx);

// Register rules
rate_limit::add(&mut engine, &admin_cap, 100, 3_600_000, &clock);

// Grant access
let access_cap = engine.grant_access(&admin_cap, ctx);
transfer::transfer(access_cap, agent_address);

// Update rules
rate_limit::set_max_per_window(&mut engine, &admin_cap, 200);

// Destroy (all rules must be removed first)
rate_limit::remove(&mut engine, &admin_cap);
let dwallet_cap = engine.destroy_and_reclaim_dkg_cap(admin_cap);
```

## Building

```bash
sui move build
```

## File Structure

```
sources/
├── policy_engine.move           # Core engine, request/receipt, admin/access caps, events
└── rules/
    ├── rate_limit.move           # Time-window signature rate limiting
    ├── expiry.move               # Auto-expire at timestamp
    ├── sender_allowlist.move     # Sender address access control
    ├── allowed_algorithms.move   # Signature algorithm restriction
    ├── spending_budget.move      # Per-tx + cumulative spending cap
    ├── target_filter.move        # Target address allowlist/blocklist
    └── time_delay.move           # Commit-reveal with owner veto window
```

## License

BSD-3-Clause-Clear

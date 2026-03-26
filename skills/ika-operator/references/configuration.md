# Complete Configuration Reference

All NodeConfig fields with types, defaults, and descriptions. Config is YAML with `kebab-case` keys.

## NodeConfig (Top-Level)

```yaml
# === KEYPAIRS ===

protocol-key-pair:                    # AuthorityKeyPair (required)
  path: /path/to/key                  # OR inline: value: <base64>

consensus-key-pair:                   # Ed25519 only (required)
  path: /path/to/key

network-key-pair:                     # Ed25519 only (required)
  path: /path/to/key

account-key-pair:                     # Any SuiKeyPair (required)
  path: /path/to/key

root-seed-key-pair:                   # RootSeed (validators only, optional in config)
  path: /path/to/seed

# === PATHS ===

db-path: '/opt/ika/db'                # Base database directory (required)
# Derived paths:
#   <db-path>/live/          → active epoch store
#   <db-path>/db_checkpoints → DB snapshots
#   <db-path>/snapshot       → state snapshots
#   <db-path>/archive        → archived state

# === NETWORK ===

network-address: '/ip4/0.0.0.0/tcp/8080'  # gRPC listen address (Multiaddr)
                                            # Default: /ip4/0.0.0.0/tcp/8080

metrics-address: '0.0.0.0:9184'       # Prometheus metrics endpoint
                                       # Default: 0.0.0.0:9184

admin-interface-port: 1337             # Admin HTTP (localhost only)
                                       # Default: 1337

# === SUB-CONFIGS ===

sui-connector-config: { ... }          # Required (see below)
consensus-config: { ... }             # Validators only (see below)
p2p-config: { ... }                   # P2P networking (see below)
authority-overload-config: { ... }     # Overload protection (see below)

# === OPTIONAL ===

metrics:                               # Metrics push config
  push-interval-seconds: 60
  push-url: 'http://metrics.example.com/api/v1/push'

state-archive-write-config: { ... }    # Archive writer (see below)
state-archive-read-config: [{ ... }]   # Archive readers (list, see below)

end-of-epoch-broadcast-channel-capacity: 128  # Default: 128
remove-deprecated-tables: false               # Default: false

# Disaster recovery only:
run-with-range:
  Epoch: 42                            # OR Checkpoint: 12345
```

---

## SuiConnectorConfig

```yaml
sui-connector-config:
  # Sui fullnode RPC endpoint
  sui-rpc-url: 'http://127.0.0.1:9000'    # Default: http://127.0.0.1:9000

  # Chain validation
  sui-chain-identifier: testnet            # Values: mainnet | testnet | custom (kebab-case)

  # Move package IDs (must match deployed contracts)
  ika-package-id: '0x...'
  ika-common-package-id: '0x...'
  ika-dwallet-2pc-mpc-package-id: '0x...'
  ika-dwallet-2pc-mpc-package-id-v2: '0x...'  # Optional v2 package
  ika-system-package-id: '0x...'

  # System object IDs
  ika-system-object-id: '0x...'
  ika-dwallet-coordinator-object-id: '0x...'

  # Notifier mode only: Sui keypair for submitting checkpoints
  notifier-client-key-pair:                # Optional (triggers Notifier mode)
    path: /path/to/sui-key

  # Override event cursor (advanced, rarely used)
  sui-ika-system-module-last-processed-event-id-override:  # Optional
    tx_digest: '<digest>'
    event_seq: 0
```

---

## ConsensusConfig (Validators Only)

Presence of this section triggers Validator mode.

```yaml
consensus-config:
  db-path: '/opt/ika/consensus_db'       # Consensus state directory (required)

  # Retention policy
  db-retention-epochs: 0                  # Epochs to keep (default: 0 = drop immediately)
  db-pruner-period-secs: 3600            # Pruner check interval (default: 3600 = 1 hour)

  # Transaction limits
  max-pending-transactions: 20000         # Default: 20,000
  max-submit-position: null               # Optional cap on submission position
  submit-delay-step-override-millis: null  # Override backoff logic (ms)

  # Advanced consensus parameters (rarely needed)
  parameters: null                        # ConsensusParameters struct
```

---

## P2pConfig

```yaml
p2p-config:
  # Binding
  listen-address: '0.0.0.0:8080'          # Default: 0.0.0.0:8080
  external-address: '/dns/my-node.net/tcp/8080'  # Advertised to peers (optional)

  # Peer connections
  seed-peers:                              # Always maintain connection to these
    - address: /dns/validator-1.net/tcp/8080
      peer-id: '<optional_anemo_peer_id>'
    - address: /ip4/1.2.3.4/tcp/8080

  fixed-peers: null                        # If set, ONLY connect to these (no discovery)

  # Message limits
  excessive-message-size: 33554432         # Default: 32 MiB (logged, not rejected)

  # Sub-configs
  state-sync: { ... }                     # See StateSyncConfig below
  discovery: { ... }                      # See DiscoveryConfig below
```

---

## StateSyncConfig

```yaml
p2p-config:
  state-sync:
    # Polling
    interval-period-ms: 5000               # Query peers interval (default: 5000)
    mailbox-capacity: 1024                 # Actor mailbox size (default: 1024)

    # dWallet checkpoint sync
    dwallet-checkpoint-header-download-concurrency: 400    # Default: 400
    dwallet-checkpoint-content-download-concurrency: 400   # Default: 400
    dwallet-checkpoint-content-download-tx-concurrency: 50000  # Default: 50,000

    # System checkpoint sync
    system-checkpoint-header-download-concurrency: 400     # Default: 400
    system-checkpoint-content-download-concurrency: 400    # Default: 400
    system-checkpoint-content-download-tx-concurrency: 50000  # Default: 50,000

    # Timeouts
    timeout-ms: 10000                      # General RPC timeout (default: 10s)
    dwallet-checkpoint-content-timeout-ms: 60000  # Content timeout (default: 60s)
    system-checkpoint-content-timeout-ms: 10000   # Default: 10s

    # Rate limiting (all default: unlimited)
    push-dwallet-checkpoint-message-rate-limit: null
    get-dwallet-checkpoint-message-rate-limit: null
    get-dwallet-checkpoint-message-inflight-limit: null
    get-dwallet-checkpoint-message-per-checkpoint-limit: null
    push-system-checkpoint-message-rate-limit: null
    get-system-checkpoint-message-rate-limit: null
    get-system-checkpoint-message-inflight-limit: null
    get-system-checkpoint-message-per-checkpoint-limit: null

    # Broadcast channels
    synced-dwallet-checkpoint-broadcast-channel-capacity: 1024   # Default: 1024
    synced-system-checkpoint-broadcast-channel-capacity: 1024    # Default: 1024

    # No-peer wait interval
    wait-interval-when-no-peer-to-sync-content-ms: 10000  # Default: 10s

    # Checkpoint pinning (fork recovery / network stall)
    pinned-dwallet-checkpoints:            # List of [seq_num, digest]
      - [123, '0xabcdef...']
    pinned-system-checkpoints:
      - [456, '0x123456...']
```

---

## DiscoveryConfig

```yaml
p2p-config:
  discovery:
    interval-period-ms: 5000               # Peer query interval (default: 5000)
    target-concurrent-connections: 4       # Target connections (default: 4)
    peers-to-query: 1                      # Peers queried per interval (default: 1)
    get-known-peers-rate-limit: null       # Per-peer rate limit (default: unlimited)

    # Access control
    access-type: Public                    # Public | Private
    # Public: advertised to all peers
    # Private: only visible to allowlisted/seed peers

    allowlisted-peers:                     # Always allowed regardless of concurrency limit
      - peer-id: '4e2f113e...'
        address: /dns/trusted.net/tcp/8080  # Optional
```

---

## AuthorityOverloadConfig

```yaml
authority-overload-config:
  max-txn-age-in-queue: 500ms                    # Default: 500ms
  overload-monitor-interval: 10s                  # Default: 10s
  execution-queue-latency-soft-limit: 1s          # Enter load shedding (default: 1s)
  execution-queue-latency-hard-limit: 10s         # Aggressive shedding (default: 10s)
  max-load-shedding-percentage: 95                # Max % to shed (default: 95)
  min-load-shedding-percentage-above-hard-limit: 50  # Min % above hard (default: 50)
  safe-transaction-ready-rate: 100                # Below = no shedding (default: 100)
  check-system-overload-at-signing: true          # Default: true
  check-system-overload-at-execution: false        # Default: false
  max-transaction-manager-queue-length: 100000     # Default: 100,000
  max-transaction-manager-per-object-queue-length: 20  # Default: 20
```

---

## StateArchiveConfig

### Write (archiving node state)

```yaml
state-archive-write-config:
  object-store-config:
    object-store: 'S3'                    # S3 | GCS | File
    bucket: 'my-ika-archives'
    aws-region: 'us-west-2'
    aws-access-key-id: '...'             # Or use no-sign-request: true
    aws-secret-access-key: '...'
    no-sign-request: false
    object-store-connection-limit: 20
  concurrency: 5
  use-for-pruning-watermark: false
```

### Read (syncing from archive)

```yaml
state-archive-read-config:
  - object-store-config:
      object-store: 'S3'
      bucket: 'mysten-testnet-archives'    # Or mainnet
      no-sign-request: true
      aws-region: 'us-west-2'
      object-store-connection-limit: 20
    concurrency: 5
    use-for-pruning-watermark: false
```

---

## Genesis Config (Initiation Parameters)

Used during network genesis setup:

| Parameter | Default | Notes |
|---|---|---|
| `protocol-version` | MAX | Current max supported |
| `epoch-duration-ms` | 86,400,000 (24h) | Epoch length |
| `min-validator-count` | 4 | Range: 4-102 |
| `max-validator-count` | 102 | Range: 4-102 |
| `min-validator-joining-stake` | 40M IKA | Minimum stake (mainnet) |
| `stake-subsidy-start-epoch` | 1 | When subsidies begin |
| `stake-subsidy-rate` | 1000 bps (10%) | Subsidy rate |
| `stake-subsidy-period-length` | 365 | Epochs per period |
| `max-validator-change-count` | 10 | Per epoch |
| `reward-slashing-rate` | 10000 bps (100%) | Slashing severity |

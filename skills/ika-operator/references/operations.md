# Operations Reference

Deployment, monitoring, admin API, recovery, and metrics proxy.

## Deployment

### Prerequisites

- Rust 1.94+ toolchain (see `rust-toolchain.toml`)
- Access to a Sui fullnode RPC endpoint
- Ika contract package/object IDs for the target network
- Generated keypairs for the node type

### Build

```bash
# Always release mode (crypto is extremely slow in debug)
cargo build --release

# Binaries produced:
# target/release/ika-validator
# target/release/ika-fullnode
# target/release/ika-notifier
# target/release/ika-node        (auto-detect mode)
```

### Keypair Generation

Keys are Base64-encoded. Store in files referenced by config:

```
protocol-key-pair:    AuthorityKeyPair (BLS12-381)
consensus-key-pair:   Ed25519
network-key-pair:     Ed25519
account-key-pair:     Any SuiKeyPair (Ed25519, Secp256k1, or Secp256r1)
root-seed-key-pair:   RootSeed (loaded from file, validators only)
notifier-client-key-pair: Any SuiKeyPair (notifiers only)
```

### Directory Setup

```bash
mkdir -p /opt/ika/{db,consensus_db,keys,config}

# Place keypair files
# Place config YAML in /opt/ika/config/

# Validator
./target/release/ika-validator --config-path /opt/ika/config/validator.yaml

# Fullnode
./target/release/ika-fullnode --config-path /opt/ika/config/fullnode.yaml

# Notifier
./target/release/ika-notifier --config-path /opt/ika/config/notifier.yaml
```

### Systemd Service (Example)

```ini
[Unit]
Description=Ika Validator
After=network.target

[Service]
Type=simple
User=ika
ExecStart=/opt/ika/bin/ika-validator --config-path /opt/ika/config/validator.yaml
Restart=on-failure
RestartSec=10
LimitNOFILE=65536

# 16 MB stack for RocksDB and crypto operations
Environment="RUST_MIN_STACK=16777216"

[Install]
WantedBy=multi-user.target
```

---

## Startup Sequence

1. Load config YAML and validate against node mode
2. Initialize Prometheus metrics registry
3. Start metrics HTTP server (separate Tokio runtime)
4. Initialize RocksDB databases
5. Create P2P network (Anemo/QUIC)
6. Create AuthorityState
7. Start SuiConnectorService (event sync from Sui)
8. Start validator-specific components (if validator):
   - ConsensusManager (Mysticeti consensus)
   - ConsensusAdapter
   - DWalletMPCService (2PC-MPC protocol)
9. Start admin HTTP interface
10. Wait for shutdown signal (SIGTERM/SIGINT)

**Runtime configuration**: Multiple Tokio runtimes with 16 MB thread stacks.

---

## Monitoring

### Prometheus Metrics

Default endpoint: `http://0.0.0.0:9184/metrics`

Scrape with Prometheus/Grafana. Key metric categories:
- **Consensus**: Round progress, latency, pending transactions
- **MPC**: DKG sessions, presign sessions, sign sessions
- **P2P**: Connection count, message rates, peer states
- **Sui Connector**: Event processing lag, checkpoint progress
- **State Sync**: Checkpoint download rates, sync lag
- **Authority**: Transaction queue lengths, execution latency, load shedding

### Metrics Push

```yaml
metrics:
  push-interval-seconds: 60
  push-url: 'http://mimir.example.com/api/v1/push'
```

---

## Admin API

Bound to `127.0.0.1:<admin-interface-port>` (default: 1337). Localhost only.

### Endpoints

```bash
# View current log filter
curl http://127.0.0.1:1337/logging

# Enable debug tracing temporarily (auto-resets after duration)
curl -X POST 'http://127.0.0.1:1337/enable-tracing?filter=debug&duration=10s'

# More specific filter
curl -X POST 'http://127.0.0.1:1337/enable-tracing?filter=ika_core=debug,ika_network=trace&duration=30s'

# Reset tracing to TRACE_FILTER env var
curl -X POST http://127.0.0.1:1337/reset-tracing

# View node config (keypairs masked)
curl http://127.0.0.1:1337/node-config

# View all received capabilities
curl http://127.0.0.1:1337/capabilities

# Buffer stake override (advanced, for validators)
curl -X POST 'http://127.0.0.1:1337/set-override-buffer-stake?buffer_bps=1500&epoch=2'
curl -X POST 'http://127.0.0.1:1337/clear-override-buffer-stake?epoch=2'
```

---

## Recovery Procedures

### Replay to Specific Point

For disaster recovery debugging only:

```bash
# Stop at specific epoch
./target/release/ika-validator --config-path config.yaml --run-with-range-epoch 42

# Stop at specific checkpoint
./target/release/ika-validator --config-path config.yaml --run-with-range-checkpoint 12345
```

### Checkpoint Pinning (Fork Recovery)

If the network forks or stalls, pin known-good checkpoints:

```yaml
p2p-config:
  state-sync:
    pinned-dwallet-checkpoints:
      - [123, '0xabcdef...']    # [sequence_number, digest]
    pinned-system-checkpoints:
      - [456, '0x123456...']
```

Pinned checkpoints skip verification and reject mismatched digests.

### Database Recovery

If database is corrupted:

```bash
# Stop the node
# Remove the database directory
rm -rf /opt/ika/db/live

# Restart - node will resync from peers via state sync
./target/release/ika-fullnode --config-path config.yaml
```

For validators, also clear consensus DB:

```bash
rm -rf /opt/ika/consensus_db/*
```

### Event Cursor Override

If Sui event processing is stuck:

```yaml
sui-connector-config:
  sui-ika-system-module-last-processed-event-id-override:
    tx_digest: '<valid_tx_digest>'
    event_seq: 0
```

**Warning**: The EventID must exist and match the filter. An invalid cursor will cause missed events.

---

## Metrics Proxy (ika-proxy)

Separate binary for collecting metrics from validators and routing to monitoring backends.

### Config

```yaml
network: joenet
listen-address: '127.0.0.1:8080'
metrics-address: 'localhost:9184'
histogram-address: 'localhost:9185'

remote-write:
  url: 'http://mimir.example.com/api/v1/push'
  username: user
  password: pass
  pool-max-idle-per-host: 8

# Dynamic peer discovery from Sui chain
dynamic-peers:
  url: 'http://127.0.0.1:9000'         # Sui RPC
  interval: 30s
  hostname: 'localhost'                  # optional; default 'localhost'
  certificate-file: /path/to/cert.pem   # optional
  private-key: /path/to/key.pem         # optional
  # Contract addresses — copy from deployed_contracts/{mainnet,testnet}/address.yaml
  ika-package-id: '0x...'
  ika-common-package-id: '0x...'
  ika-dwallet-2pc-mpc-package-id: '0x...'
  ika-dwallet-2pc-mpc-package-id-v2: '0x...'   # optional; omit if not yet deployed
  ika-system-package-id: '0x...'
  ika-system-object-id: '0x...'
  ika-dwallet-coordinator-object-id: '0x...'

# OR static peer list
static-peers:
  pub-keys:
    - name: validator-1
      peer-id: '4e2f113e...'
```

### Proxy Environment Variables

| Variable | Purpose | Default |
|---|---|---|
| `IKA_PROXY_VERBOSE_HTTP` | Verbose HTTP logging | false |
| `NODE_CLIENT_TIMEOUT` | Node client timeout | 20s |
| `MIMIR_CLIENT_TIMEOUT` | Mimir client timeout | 30s |
| `MAX_BODY_SIZE` | Max request body size | 5 MB |
| `INVENTORY_HOSTNAME` | Hostname label for metrics | "unknown" |

---

## Common Issues & Solutions

| Issue | Cause | Fix |
|---|---|---|
| Extremely slow startup | Debug build | Build with `--release` |
| Port conflict on 8080 | P2P port taken | Change `p2p-config.listen-address` |
| Sui chain mismatch error | Wrong chain identifier | Verify `sui-rpc-url` matches `sui-chain-identifier` |
| Missing package ID error | Wrong contract IDs | Update package/object IDs to match deployed contracts |
| Consensus DB disk full | No pruning | Set `db-retention-epochs: 0`, lower `db-pruner-period-secs` |
| State sync stalled | No peers | Add seed peers, check network connectivity |
| Event processing stuck | Bad cursor | Use event cursor override (carefully) |
| Node won't start | Missing keypairs | Ensure all required keypair files exist and are valid Base64 |
| Validator mode rejected | Missing consensus-config | Add `consensus-config` section for validators |
| Notifier mode rejected | Missing notifier key | Add `notifier-client-key-pair` to `sui-connector-config` |

---

## Health Check Script

```bash
#!/bin/bash
# Basic health check for Ika node

METRICS_URL="http://localhost:9184/metrics"
ADMIN_URL="http://localhost:1337"

# Check metrics endpoint
if curl -sf "$METRICS_URL" > /dev/null 2>&1; then
    echo "Metrics: OK"
else
    echo "Metrics: FAIL"
fi

# Check admin endpoint
if curl -sf "$ADMIN_URL/logging" > /dev/null 2>&1; then
    echo "Admin: OK"
else
    echo "Admin: FAIL"
fi

# Check specific metrics
UPTIME=$(curl -sf "$METRICS_URL" | grep 'uptime' | head -1)
echo "Uptime: $UPTIME"
```

---

## Local Test Network (ika-swarm)

For development/testing. Uses `ika-swarm` crate:

```rust
// Programmatic setup
SwarmBuilder::new()
    .committee_size(NonZeroUsize::new(4).unwrap())
    .with_fullnode_count(2)
    .with_epoch_duration_ms(5000)
    .build()
    .await;
```

The swarm builder:
1. Generates all validator/fullnode configs with keypairs
2. Publishes Move contracts to local Sui
3. Initializes system state (genesis)
4. Starts all nodes in-process

For CLI-based setup, use `ika-swarm-config` crate which generates network configs.

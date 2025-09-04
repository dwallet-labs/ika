# Sui Proxy

A secure metrics proxy server for the Sui blockchain network that collects Prometheus metrics from Sui validators and
bridge nodes, then forwards them to remote monitoring systems like Mimir.

## Overview

Sui Proxy acts as an intermediary between Sui network nodes (validators and bridge nodes) and external monitoring
infrastructure. It provides secure TLS-based communication with peer validation, metrics processing, and reliable
forwarding to time-series databases.

## Key Features

### 🔐 **Secure Peer Validation**

- **Dynamic Peer Discovery**: Automatically discovers and validates Sui validators through JSON-RPC calls to the
  blockchain
- **Bridge Node Support**: Validates bridge committee members for cross-chain operations
- **Static Peer Configuration**: Support for manually configured trusted peers
- **TLS Certificate Management**: Automatic self-signed certificate generation or custom certificate support

### 📊 **Metrics Processing**

- **Prometheus Protocol**: Native support for Prometheus protobuf format
- **Label Injection**: Automatically adds network, hostname, and peer identification labels
- **Histogram Relay**: Dedicated histogram metrics processing and forwarding
- **Remote Write**: Forwards processed metrics to external TSDB systems (Mimir, Prometheus, etc.)

### 🚀 **High Performance**

- **Connection Pooling**: Configurable HTTP connection pooling for remote write operations
- **Concurrent Processing**: Async processing with configurable timeouts
- **Graceful Shutdown**: Proper cleanup and graceful shutdown handling
- **Metrics Monitoring**: Built-in metrics for proxy performance monitoring

### 🛡️ **Security & Reliability**

- **Mutual TLS**: Client certificate validation for secure communication
- **Request Validation**: Content-length and header validation middleware
- **Timeout Protection**: Configurable timeouts to prevent hanging connections
- **Error Handling**: Comprehensive error handling and logging

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Sui Nodes     │───▶│   Sui Proxy     │───▶│  Remote TSDB    │
│  (Validators &  │    │                 │    │   (Mimir)       │
│  Bridge Nodes)  │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌─────────────────┐
                       │  Sui Blockchain │
                       │   (JSON-RPC)    │
                       └─────────────────┘
```

## Configuration

### Configuration File Structure

The proxy uses a YAML configuration file (default: `./sui-proxy.yaml`):

```yaml
# Network identifier for labeling metrics
network: mainnet

# Address where the proxy listens for incoming metrics
listen-address: 0.0.0.0:8080

# Remote write configuration for forwarding metrics
remote-write:
  url: https://mimir.example.com/api/v1/push
  username: your-username
  password: your-password
  pool-max-idle-per-host: 8  # Connection pool size (default: 8)

# Dynamic peer validation (discovers validators from blockchain)
dynamic-peers:
  url: https://fullnode.mainnet.sui.io:443  # Sui JSON-RPC endpoint
  interval: 30  # Polling interval in seconds
  hostname: proxy.example.com  # Hostname for self-signed cert (optional)
  certificate-file: /path/to/cert.pem  # Custom TLS certificate (optional)
  private-key: /path/to/key.pem        # Custom private key (optional)

# Static peer validation (manually configured peers)
static-peers:
  pub-keys:
    - name: validator-1
      peer-id: 4e2f113e61784fdcd611650f36595db8f79e9420319f42a5b571dc2f2b295af2

# Metrics server addresses
metrics-address: localhost:9184      # Proxy metrics endpoint
histogram-address: localhost:9185    # Histogram relay endpoint
```

### Configuration Options

#### Network Settings

- **`network`**: String identifier for the Sui network (mainnet, testnet, devnet, etc.)
- **`listen-address`**: Socket address where the proxy accepts incoming connections

#### Remote Write Configuration

- **`url`**: Target URL for forwarding processed metrics
- **`username`/`password`**: Authentication credentials for the remote endpoint
- **`pool-max-idle-per-host`**: Maximum idle connections per host (default: 8)

#### Dynamic Peer Validation

- **`url`**: Sui JSON-RPC endpoint for validator discovery
- **`interval`**: How often to refresh the validator list (seconds)
- **`hostname`**: Hostname for self-signed certificate generation
- **`certificate-file`**: Path to custom TLS certificate (PEM format)
- **`private-key`**: Path to custom private key (PEM format)

#### Static Peer Configuration

- **`pub-keys`**: Array of manually configured trusted peers
    - **`name`**: Human-readable identifier for the peer
    - **`peer-id`**: Ed25519 public key of the peer (hex encoded)

## Usage

### Starting the Proxy

```bash
# Using default config file
sui-proxy

# Using custom config file
sui-proxy --config /path/to/custom-config.yaml

# Short form
sui-proxy -c /path/to/custom-config.yaml
```

### Environment Variables

The proxy supports several environment variables for runtime configuration:

- **`NODE_CLIENT_TIMEOUT`**: Timeout for client connections (seconds, default: 20)
- **`MIMIR_CLIENT_TIMEOUT`**: Timeout for remote write requests (seconds, default: 30)
- **`MAX_BODY_SIZE`**: Maximum request body size (bytes, default: 5MB)
- **`INVENTORY_HOSTNAME`**: Ansible inventory hostname for labeling

### API Endpoints

#### Metrics Ingestion

- **`POST /publish/metrics`**: Accepts Prometheus protobuf metrics from Sui nodes
    - Requires valid TLS client certificate
    - Content-Type: `application/x-protobuf`
    - Validates peer against allowlist

#### Monitoring Endpoints

- **`GET :9184/metrics`**: Proxy performance metrics (Prometheus format)
- **`GET :9185/metrics`**: Histogram relay metrics (Prometheus format)

## Security Model

### TLS Configuration

The proxy supports two TLS modes:

1. **Self-Signed Mode**: Automatically generates certificates (allows all connections)
2. **Peer Validation Mode**: Uses custom certificates with strict peer validation

### Peer Validation

Peers are validated through multiple mechanisms:

1. **Dynamic Validation**: Queries Sui blockchain for current validator set
2. **Bridge Validation**: Validates bridge committee members
3. **Static Validation**: Uses manually configured peer list

### Request Validation

All incoming requests are validated through middleware:

- TLS client certificate verification
- Content-length header validation
- Custom proxy headers validation
- Peer public key verification

## Monitoring

### Built-in Metrics

The proxy exposes comprehensive metrics about its operation:

- **`http_handler_hits`**: Request count by handler and peer
- **`http_handler_duration_seconds`**: Request latency by handler and peer
- **`json_rpc_state`**: JSON-RPC call success/failure counts
- **`json_rpc_duration_seconds`**: JSON-RPC call latencies
- **`ika_proxy_uptime`**: Proxy uptime information

### Log Output

The proxy provides structured logging with:

- Request tracing with latency information
- Peer validation events
- Configuration loading status
- Error conditions and debugging information

## Deployment

### Docker Deployment

```dockerfile
FROM rust:1.70 as builder
WORKDIR /app
COPY . .
RUN cargo build --release --bin sui-proxy

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/sui-proxy /usr/local/bin/
COPY config.yaml /etc/sui-proxy/
EXPOSE 8080 9184 9185
CMD ["sui-proxy", "--config", "/etc/sui-proxy/config.yaml"]
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sui-proxy
spec:
  replicas: 2
  selector:
    matchLabels:
      app: sui-proxy
  template:
    metadata:
      labels:
        app: sui-proxy
    spec:
      containers:
        - name: sui-proxy
          image: sui-proxy:latest
          ports:
            - containerPort: 8080
            - containerPort: 9184
            - containerPort: 9185
          env:
            - name: INVENTORY_HOSTNAME
              valueFrom:
                fieldRef:
                  fieldPath: spec.nodeName
          volumeMounts:
            - name: config
              mountPath: /etc/sui-proxy
            - name: tls-certs
              mountPath: /etc/ssl/sui-proxy
      volumes:
        - name: config
          configMap:
            name: sui-proxy-config
        - name: tls-certs
          secret:
            secretName: sui-proxy-tls
```

## Troubleshooting

### Common Issues

1. **Certificate Validation Failures**
    - Ensure client certificates are properly configured
    - Check that peer public keys are in the validator set
    - Verify TLS certificate paths and permissions

2. **Connection Timeouts**
    - Adjust `NODE_CLIENT_TIMEOUT` and `MIMIR_CLIENT_TIMEOUT`
    - Check network connectivity to remote write endpoint
    - Monitor connection pool settings

3. **Peer Discovery Issues**
    - Verify JSON-RPC endpoint accessibility
    - Check polling interval configuration
    - Monitor JSON-RPC metrics for errors

### Debug Mode

Enable debug logging by setting the `RUST_LOG` environment variable:

```bash
RUST_LOG=debug sui-proxy --config config.yaml
```

## Development

### Building from Source

```bash
# Clone the repository
git clone https://github.com/MystenLabs/sui.git
cd sui/crates/sui-proxy

# Build the project
cargo build --release

# Run tests
cargo test
```

### Testing

The project includes comprehensive tests:

```bash
# Run all tests
cargo test

# Run specific test modules
cargo test test_axum_acceptor
cargo test peers::tests
```

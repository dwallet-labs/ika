# Direct Signature Query Implementation Plan

## Executive Summary

This document outlines the implementation strategy for querying signatures directly from Ika network full nodes, bypassing the need to write signatures to Sui blockchain. This optimization will significantly reduce latency and costs associated with signature operations.

## Current Architecture Analysis

### Signature Flow (Current)
1. **MPC Computation** → Signature generated via 2PC-MPC protocol
2. **Checkpoint Creation** → Signature wrapped in `SignOutput` → `DWalletCheckpointMessageKind::RespondDWalletSign`
3. **Storage** → Checkpoint stored in RocksDB via `DWalletCheckpointStore`
4. **Sui Write** → `SuiExecutor` writes checkpoint to Sui blockchain (15KB chunks)
5. **Query** → Users query signatures from Sui blockchain

### Pain Points
- **Latency**: Writing to Sui adds 2-3 seconds per signature
- **Cost**: Each Sui transaction incurs gas fees
- **Complexity**: Chunking large checkpoints adds overhead
- **Availability**: Signatures unavailable until Sui transaction confirms

## Proposed Solution

### Architecture Overview

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   MPC Engine    │────▶│ Signature Index  │────▶│   Query API     │
└─────────────────┘     └──────────────────┘     └─────────────────┘
         │                       │                         │
         ▼                       ▼                         ▼
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│ Checkpoint Store│     │  RocksDB Tables  │     │  REST/JSON-RPC  │
└─────────────────┘     └──────────────────┘     └─────────────────┘
         │
         ▼
┌─────────────────┐
│  Sui (Optional) │
└─────────────────┘
```

### New Components

#### 1. Signature Index Store
Create dedicated RocksDB tables for efficient signature queries:

```rust
// crates/ika-core/src/signature_store.rs
pub struct SignatureStore {
    // Primary index: sign_id -> signature data
    signatures_by_id: DBMap<Vec<u8>, StoredSignature>,

    // Secondary indexes
    signatures_by_dwallet: DBMap<Vec<u8>, Vec<Vec<u8>>>, // dwallet_id -> [sign_ids]
    signatures_by_checkpoint: DBMap<u64, Vec<Vec<u8>>>,  // checkpoint_seq -> [sign_ids]
    signatures_by_timestamp: DBMap<u64, Vec<Vec<u8>>>,   // timestamp -> [sign_ids]

    // Metadata
    signature_metadata: DBMap<Vec<u8>, SignatureMetadata>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct StoredSignature {
    pub sign_output: SignOutput,
    pub checkpoint_sequence: u64,
    pub epoch: EpochId,
    pub timestamp_ms: u64,
    pub algorithm: SignatureAlgorithm,
    pub verified: bool,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SignatureMetadata {
    pub dwallet_id: Vec<u8>,
    pub sign_id: Vec<u8>,
    pub message_hash: Vec<u8>,
    pub public_key: Vec<u8>,
    pub curve: String,
    pub created_at: u64,
    pub sui_tx_digest: Option<TransactionDigest>, // Optional Sui reference
}
```

#### 2. Query API Service

Extend the node's admin interface with signature query endpoints:

```rust
// crates/ika-node/src/signature_api.rs
pub fn signature_query_routes() -> Router {
    Router::new()
        // Get signature by ID
        .route("/api/v1/signature/:sign_id", get(get_signature_by_id))

        // Get signatures by dWallet
        .route("/api/v1/dwallet/:dwallet_id/signatures", get(get_signatures_by_dwallet))

        // Get signatures by checkpoint
        .route("/api/v1/checkpoint/:seq/signatures", get(get_signatures_by_checkpoint))

        // Batch query
        .route("/api/v1/signatures/batch", post(get_signatures_batch))

        // Search with filters
        .route("/api/v1/signatures/search", post(search_signatures))

        // Verify signature
        .route("/api/v1/signature/:sign_id/verify", get(verify_signature))

        // WebSocket for real-time updates
        .route("/api/v1/signatures/stream", get(signature_stream))
}
```

#### 3. Response Formats

```typescript
// TypeScript SDK types
interface SignatureResponse {
  signId: string;
  dwalletId: string;
  signature: string; // Base64 encoded
  algorithm: 'ECDSA_SECP256K1' | 'ECDSA_SECP256R1' | 'EDDSA' | 'SCHNORRKEL' | 'TAPROOT';
  checkpoint: {
    sequence: number;
    epoch: number;
    timestamp: number;
  };
  metadata: {
    messageHash?: string;
    publicKey?: string;
    curve?: string;
  };
  suiReference?: {
    transactionDigest: string;
    eventSeq: number;
  };
}

interface SignatureQueryOptions {
  limit?: number;
  offset?: number;
  fromTimestamp?: number;
  toTimestamp?: number;
  includeMetadata?: boolean;
  verifySignature?: boolean;
}
```

### Implementation Phases

#### Phase 1: Core Storage Layer (Week 1-2)
- [ ] Implement `SignatureStore` with RocksDB tables
- [ ] Add signature indexing to checkpoint processing
- [ ] Create migration for existing signatures
- [ ] Add metrics and monitoring

#### Phase 2: Query API (Week 2-3)
- [ ] Implement REST endpoints in ika-node
- [ ] Add authentication/authorization
- [ ] Implement rate limiting
- [ ] Add caching layer (LRU cache)

#### Phase 3: SDK Integration (Week 3-4)
- [ ] Update TypeScript SDK with direct query support
- [ ] Add fallback to Sui queries
- [ ] Implement connection pooling
- [ ] Add retry logic

#### Phase 4: Optimization (Week 4-5)
- [ ] Implement WebSocket streaming
- [ ] Add signature verification endpoint
- [ ] Optimize indexes for common queries
- [ ] Add compression for large responses

#### Phase 5: Migration & Testing (Week 5-6)
- [ ] Historical data migration tool
- [ ] Load testing
- [ ] Integration tests
- [ ] Documentation

## Configuration

Add to node configuration:

```toml
[signature_query]
enabled = true
port = 8080
max_connections = 1000
cache_size_mb = 512
index_historical = true
retention_days = 90

[signature_query.rate_limit]
requests_per_second = 100
burst_size = 200

[signature_query.auth]
enabled = false  # Enable in production
api_key_header = "X-API-Key"
```

## Performance Considerations

### Storage Overhead
- Estimated 500 bytes per signature with indexes
- At 1000 signatures/day: ~15 MB/month additional storage
- Compression can reduce by 40-60%

### Query Performance Targets
- Single signature query: < 10ms
- Batch query (100 signatures): < 50ms
- Search with filters: < 100ms
- WebSocket latency: < 5ms

### Caching Strategy
- LRU cache for recent signatures (512MB default)
- Cache hit ratio target: > 80%
- TTL: 5 minutes for active signatures

## Security Considerations

1. **Authentication**: Optional API key authentication
2. **Rate Limiting**: Per-IP and per-key limits
3. **DoS Protection**: Query complexity limits
4. **Data Privacy**: No private key material exposed
5. **Audit Logging**: All queries logged with client info

## Backwards Compatibility

- Sui writing remains optional (configurable)
- SDK falls back to Sui queries if direct query fails
- No breaking changes to existing APIs
- Gradual migration path for clients

## Monitoring & Metrics

New metrics to track:
- `signature_queries_total` - Total queries by endpoint
- `signature_query_latency_seconds` - Query latency histogram
- `signature_index_size_bytes` - Index size on disk
- `signature_cache_hit_ratio` - Cache effectiveness
- `signature_store_errors_total` - Storage errors

## Testing Strategy

1. **Unit Tests**: Storage layer, API handlers
2. **Integration Tests**: End-to-end query scenarios
3. **Load Tests**: 10,000 queries/second target
4. **Chaos Tests**: Node failures, network partitions
5. **Migration Tests**: Historical data import

## Rollout Plan

1. **Stage 1**: Deploy to testnet with feature flag disabled
2. **Stage 2**: Enable for internal testing (10% traffic)
3. **Stage 3**: Gradual rollout (25%, 50%, 75%)
4. **Stage 4**: Full production deployment
5. **Stage 5**: Deprecate Sui queries (optional, 6 months later)

## Alternative Approaches Considered

1. **GraphQL API**: More flexible but higher complexity
2. **gRPC Streaming**: Better performance but less accessible
3. **Separate Query Service**: Additional infrastructure overhead
4. **IPFS Storage**: Decentralized but slower queries
5. **PostgreSQL Index**: Better queries but operational complexity

## Conclusion

This implementation provides a direct, efficient path for querying signatures from Ika network nodes, eliminating the dependency on Sui blockchain for signature retrieval. The solution maintains backwards compatibility while providing significant performance improvements and cost savings.

## Next Steps

1. Review and approve design
2. Create detailed technical specifications
3. Set up development environment
4. Begin Phase 1 implementation
5. Establish testing infrastructure
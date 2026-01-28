// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import {
  createSignatureQueryClient,
  SignatureAlgorithm,
  SignatureQueryClient,
} from '../src/signature-query-client';

/**
 * Example: Basic signature query
 */
async function basicQuery() {
  // Create client
  const client = createSignatureQueryClient({
    nodeUrl: 'http://localhost:8080',
    apiKey: process.env.IKA_API_KEY, // Optional
    timeout: 10000,
    maxRetries: 3,
    fallbackToSui: false, // Disable Sui fallback for this example
  });

  // Get a single signature
  const signId = '0x1234567890abcdef';
  const signature = await client.getSignature(signId);

  if (signature) {
    console.log('Signature found:', {
      signId: signature.signId,
      dwalletId: signature.dwalletId,
      algorithm: signature.algorithm,
      checkpoint: signature.checkpoint.sequence,
      verified: signature.verified,
    });

    // Decode signature bytes
    const signatureBytes = Buffer.from(signature.signature, 'base64');
    console.log('Signature bytes:', signatureBytes.toString('hex'));
  } else {
    console.log('Signature not found');
  }
}

/**
 * Example: Query signatures by dWallet
 */
async function queryByDwallet() {
  const client = createSignatureQueryClient({
    nodeUrl: 'http://localhost:8080',
  });

  const dwalletId = '0xabcdef1234567890';
  const response = await client.getSignaturesByDwallet(dwalletId, {
    limit: 10,
    offset: 0,
    includeMetadata: true,
    algorithm: SignatureAlgorithm.ECDSASecp256k1,
  });

  console.log(`Found ${response.totalCount} signatures for dWallet ${dwalletId}`);

  response.signatures.forEach((sig, index) => {
    console.log(`Signature ${index + 1}:`, {
      signId: sig.signId,
      timestamp: new Date(sig.checkpoint.timestamp).toISOString(),
      rejected: sig.rejected,
    });
  });

  if (response.metadata) {
    console.log('Metadata available for', response.metadata.length, 'signatures');
  }

  if (response.hasMore) {
    console.log('More signatures available, use offset to paginate');
  }
}

/**
 * Example: Batch query multiple signatures
 */
async function batchQuery() {
  const client = createSignatureQueryClient({
    nodeUrl: 'http://localhost:8080',
  });

  const signIds = [
    '0x1111111111111111',
    '0x2222222222222222',
    '0x3333333333333333',
  ];

  const response = await client.getSignaturesBatch(signIds);

  response.signatures.forEach((sig, index) => {
    if (sig) {
      console.log(`Signature ${signIds[index]} found`);
    } else {
      console.log(`Signature ${signIds[index]} not found`);
    }
  });
}

/**
 * Example: Search signatures with filters
 */
async function searchSignatures() {
  const client = createSignatureQueryClient({
    nodeUrl: 'http://localhost:8080',
  });

  // Search for signatures in the last hour
  const oneHourAgo = Date.now() - 3600000;

  const response = await client.searchSignatures({
    fromTimestamp: oneHourAgo,
    toTimestamp: Date.now(),
    limit: 50,
    includeMetadata: true,
  });

  console.log(`Found ${response.signatures.length} signatures in the last hour`);

  // Group by algorithm
  const byAlgorithm = response.signatures.reduce((acc, sig) => {
    acc[sig.algorithm] = (acc[sig.algorithm] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  console.log('Signatures by algorithm:', byAlgorithm);
}

/**
 * Example: Real-time signature streaming
 */
async function streamSignatures() {
  const client = createSignatureQueryClient({
    nodeUrl: 'http://localhost:8080',
  });

  console.log('Starting real-time signature stream...');

  const stream = client.streamSignatures({
    algorithm: SignatureAlgorithm.ECDSASecp256k1,
  });

  stream.on('connected', () => {
    console.log('Connected to signature stream');
  });

  stream.on('signature', (signature) => {
    console.log('New signature:', {
      signId: signature.signId,
      dwalletId: signature.dwalletId,
      timestamp: new Date(signature.checkpoint.timestamp).toISOString(),
    });
  });

  stream.on('error', (error) => {
    console.error('Stream error:', error);
  });

  stream.on('disconnected', () => {
    console.log('Disconnected from stream');
  });

  // Stop streaming after 60 seconds
  setTimeout(() => {
    (stream as any).close();
    console.log('Stream closed');
  }, 60000);
}

/**
 * Example: Using cache and events
 */
async function cacheExample() {
  const client = createSignatureQueryClient({
    nodeUrl: 'http://localhost:8080',
  });

  // Listen for cache events
  client.on('cache-hit', (signId) => {
    console.log(`Cache hit for signature ${signId}`);
  });

  client.on('error', ({ method, error }) => {
    console.error(`Error in ${method}:`, error);
  });

  client.on('sui-fallback', ({ method }) => {
    console.log(`Falling back to Sui for ${method}`);
  });

  // Query same signature twice
  const signId = '0x1234567890abcdef';

  console.log('First query (will fetch from API)...');
  await client.getSignature(signId);

  console.log('Second query (should hit cache)...');
  await client.getSignature(signId);

  // Clear cache
  client.clearCache();
  console.log('Cache cleared');
}

/**
 * Example: Query signatures from a specific checkpoint
 */
async function queryByCheckpoint() {
  const client = createSignatureQueryClient({
    nodeUrl: 'http://localhost:8080',
  });

  const checkpointSeq = 12345;
  const response = await client.getSignaturesByCheckpoint(checkpointSeq, {
    limit: 20,
    includeMetadata: false,
  });

  console.log(`Checkpoint ${checkpointSeq} contains ${response.signatures.length} signatures`);

  // Verify all signatures are from the same checkpoint
  const allSameCheckpoint = response.signatures.every(
    sig => sig.checkpoint.sequence === checkpointSeq
  );
  console.log('All signatures from same checkpoint:', allSameCheckpoint);
}

/**
 * Main function to run examples
 */
async function main() {
  console.log('=== Ika Signature Query Examples ===\n');

  try {
    console.log('1. Basic Query Example');
    await basicQuery();
    console.log('\n---\n');

    console.log('2. Query by dWallet Example');
    await queryByDwallet();
    console.log('\n---\n');

    console.log('3. Batch Query Example');
    await batchQuery();
    console.log('\n---\n');

    console.log('4. Search Signatures Example');
    await searchSignatures();
    console.log('\n---\n');

    console.log('5. Cache Example');
    await cacheExample();
    console.log('\n---\n');

    console.log('6. Query by Checkpoint Example');
    await queryByCheckpoint();
    console.log('\n---\n');

    // Uncomment to test streaming (runs for 60 seconds)
    // console.log('7. Streaming Example');
    // await streamSignatures();
  } catch (error) {
    console.error('Example failed:', error);
  }
}

// Run if executed directly
if (require.main === module) {
  main().catch(console.error);
}

export {
  basicQuery,
  queryByDwallet,
  batchQuery,
  searchSignatures,
  streamSignatures,
  cacheExample,
  queryByCheckpoint,
};
// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { EventEmitter } from 'events';

/**
 * Signature algorithms supported by the network
 */
export enum SignatureAlgorithm {
  ECDSASecp256k1 = 'ECDSA_SECP256K1',
  ECDSASecp256r1 = 'ECDSA_SECP256R1',
  EdDSA = 'EDDSA',
  SchnorrkelSubstrate = 'SCHNORRKEL',
  Taproot = 'TAPROOT',
}

/**
 * Signature response from the API
 */
export interface SignatureResponse {
  signId: string;
  dwalletId: string;
  signature: string; // Base64 encoded
  algorithm: SignatureAlgorithm;
  isFutureSign: boolean;
  rejected: boolean;
  sessionSequenceNumber: number;
  checkpoint: {
    sequence: number;
    epoch: number;
    timestamp: number;
  };
  verified: boolean;
}

/**
 * Signature metadata
 */
export interface SignatureMetadata {
  dwalletId: string;
  signId: string;
  messageHash?: string;
  publicKey?: string;
  curve?: string;
  createdAt: number;
  suiTxDigest?: string;
}

/**
 * Query options for signature searches
 */
export interface SignatureQueryOptions {
  limit?: number;
  offset?: number;
  fromTimestamp?: number;
  toTimestamp?: number;
  includeMetadata?: boolean;
  verifySignature?: boolean;
  algorithm?: SignatureAlgorithm;
}

/**
 * Query response with pagination info
 */
export interface SignatureQueryResponse {
  signatures: SignatureResponse[];
  metadata?: SignatureMetadata[];
  totalCount: number;
  hasMore: boolean;
}

/**
 * Batch query request
 */
export interface BatchSignatureRequest {
  signIds: string[];
}

/**
 * Batch query response
 */
export interface BatchSignatureResponse {
  signatures: (SignatureResponse | null)[];
}

/**
 * Search request parameters
 */
export interface SearchSignatureRequest {
  dwalletId?: string;
  fromTimestamp?: number;
  toTimestamp?: number;
  limit?: number;
  offset?: number;
  includeMetadata?: boolean;
}

/**
 * Configuration for the signature query client
 */
export interface SignatureQueryClientConfig {
  nodeUrl: string;
  apiKey?: string;
  timeout?: number;
  maxRetries?: number;
  fallbackToSui?: boolean;
  suiClient?: any; // SuiClient instance for fallback
}

/**
 * Client for querying signatures directly from Ika nodes
 */
export class SignatureQueryClient extends EventEmitter {
  private nodeUrl: string;
  private apiKey?: string;
  private timeout: number;
  private maxRetries: number;
  private fallbackToSui: boolean;
  private suiClient?: any;
  private cache: Map<string, { data: SignatureResponse; timestamp: number }> = new Map();
  private cacheTimeout = 300000; // 5 minutes

  constructor(config: SignatureQueryClientConfig) {
    super();
    this.nodeUrl = config.nodeUrl.replace(/\/$/, ''); // Remove trailing slash
    this.apiKey = config.apiKey;
    this.timeout = config.timeout || 10000;
    this.maxRetries = config.maxRetries || 3;
    this.fallbackToSui = config.fallbackToSui ?? true;
    this.suiClient = config.suiClient;
  }

  /**
   * Get a signature by its ID
   */
  async getSignature(signId: string): Promise<SignatureResponse | null> {
    // Check cache first
    const cached = this.getCached(signId);
    if (cached) {
      this.emit('cache-hit', signId);
      return cached;
    }

    try {
      const response = await this.request<SignatureResponse>(
        `GET`,
        `/api/v1/signature/${signId}`
      );

      if (response) {
        this.setCached(signId, response);
      }

      return response;
    } catch (error) {
      this.emit('error', { method: 'getSignature', signId, error });

      if (this.fallbackToSui && this.suiClient) {
        return this.getSignatureFromSui(signId);
      }

      throw error;
    }
  }

  /**
   * Get signatures by dWallet ID
   */
  async getSignaturesByDwallet(
    dwalletId: string,
    options?: SignatureQueryOptions
  ): Promise<SignatureQueryResponse> {
    try {
      return await this.request<SignatureQueryResponse>(
        'GET',
        `/api/v1/dwallet/${dwalletId}/signatures`,
        options
      );
    } catch (error) {
      this.emit('error', { method: 'getSignaturesByDwallet', dwalletId, error });

      if (this.fallbackToSui && this.suiClient) {
        return this.getSignaturesByDwalletFromSui(dwalletId, options);
      }

      throw error;
    }
  }

  /**
   * Get signatures by checkpoint sequence
   */
  async getSignaturesByCheckpoint(
    sequence: number,
    options?: SignatureQueryOptions
  ): Promise<SignatureQueryResponse> {
    return await this.request<SignatureQueryResponse>(
      'GET',
      `/api/v1/checkpoint/${sequence}/signatures`,
      options
    );
  }

  /**
   * Batch query multiple signatures
   */
  async getSignaturesBatch(signIds: string[]): Promise<BatchSignatureResponse> {
    const request: BatchSignatureRequest = { signIds };
    return await this.request<BatchSignatureResponse>(
      'POST',
      `/api/v1/signatures/batch`,
      undefined,
      request
    );
  }

  /**
   * Search signatures with filters
   */
  async searchSignatures(
    request: SearchSignatureRequest
  ): Promise<SignatureQueryResponse> {
    return await this.request<SignatureQueryResponse>(
      'POST',
      `/api/v1/signatures/search`,
      undefined,
      request
    );
  }

  /**
   * Stream signatures in real-time (WebSocket)
   */
  streamSignatures(
    filter?: { dwalletId?: string; algorithm?: SignatureAlgorithm }
  ): EventEmitter {
    const stream = new EventEmitter();

    const ws = new WebSocket(`${this.nodeUrl.replace('http', 'ws')}/api/v1/signatures/stream`);

    ws.onopen = () => {
      if (filter) {
        ws.send(JSON.stringify(filter));
      }
      stream.emit('connected');
    };

    ws.onmessage = (event) => {
      try {
        const signature = JSON.parse(event.data) as SignatureResponse;
        stream.emit('signature', signature);

        // Update cache
        this.setCached(signature.signId, signature);
      } catch (error) {
        stream.emit('error', error);
      }
    };

    ws.onerror = (error) => {
      stream.emit('error', error);
    };

    ws.onclose = () => {
      stream.emit('disconnected');
    };

    // Add close method to stream
    (stream as any).close = () => ws.close();

    return stream;
  }

  /**
   * Clear the local cache
   */
  clearCache(): void {
    this.cache.clear();
    this.emit('cache-cleared');
  }

  // Private helper methods

  private async request<T>(
    method: string,
    path: string,
    query?: any,
    body?: any
  ): Promise<T> {
    const url = new URL(`${this.nodeUrl}${path}`);

    if (query) {
      Object.keys(query).forEach(key => {
        if (query[key] !== undefined) {
          url.searchParams.append(key, query[key].toString());
        }
      });
    }

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };

    if (this.apiKey) {
      headers['X-API-Key'] = this.apiKey;
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await fetch(url.toString(), {
        method,
        headers,
        body: body ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        const errorBody = await response.json().catch(() => ({}));
        throw new Error(
          errorBody.error || `HTTP ${response.status}: ${response.statusText}`
        );
      }

      return await response.json();
    } catch (error: any) {
      if (error.name === 'AbortError') {
        throw new Error(`Request timeout after ${this.timeout}ms`);
      }
      throw error;
    }
  }

  private getCached(signId: string): SignatureResponse | null {
    const cached = this.cache.get(signId);
    if (cached && Date.now() - cached.timestamp < this.cacheTimeout) {
      return cached.data;
    }
    this.cache.delete(signId);
    return null;
  }

  private setCached(signId: string, data: SignatureResponse): void {
    this.cache.set(signId, { data, timestamp: Date.now() });

    // Limit cache size
    if (this.cache.size > 1000) {
      const firstKey = this.cache.keys().next().value;
      this.cache.delete(firstKey);
    }
  }

  // Sui fallback methods (stubs - would need actual implementation)

  private async getSignatureFromSui(signId: string): Promise<SignatureResponse | null> {
    // This would query Sui blockchain for the signature
    // Implementation would depend on how signatures are stored on Sui
    this.emit('sui-fallback', { method: 'getSignature', signId });

    // Placeholder - actual implementation would query Sui
    throw new Error('Sui fallback not implemented');
  }

  private async getSignaturesByDwalletFromSui(
    dwalletId: string,
    options?: SignatureQueryOptions
  ): Promise<SignatureQueryResponse> {
    this.emit('sui-fallback', { method: 'getSignaturesByDwallet', dwalletId });

    // Placeholder - actual implementation would query Sui
    throw new Error('Sui fallback not implemented');
  }
}

/**
 * Factory function to create a signature query client
 */
export function createSignatureQueryClient(
  config: SignatureQueryClientConfig
): SignatureQueryClient {
  return new SignatureQueryClient(config);
}

// Export types
export type {
  SignatureQueryClientConfig,
  SignatureResponse,
  SignatureMetadata,
  SignatureQueryOptions,
  SignatureQueryResponse,
  BatchSignatureRequest,
  BatchSignatureResponse,
  SearchSignatureRequest,
};
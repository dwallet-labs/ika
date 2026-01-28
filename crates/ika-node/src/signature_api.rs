// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use ika_core::signature_store::{
    SignatureQueryOptions, SignatureQueryResponse, SignatureStore, StoredSignature,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{error, info};

/// State for the signature API handlers
#[derive(Clone)]
pub struct SignatureApiState {
    pub signature_store: Arc<SignatureStore>,
}

/// Request body for batch signature queries
#[derive(Debug, Deserialize)]
pub struct BatchSignatureRequest {
    pub sign_ids: Vec<String>,
}

/// Response for batch signature queries
#[derive(Debug, Serialize)]
pub struct BatchSignatureResponse {
    pub signatures: Vec<Option<StoredSignature>>,
}

/// Request body for signature search
#[derive(Debug, Deserialize)]
pub struct SearchSignatureRequest {
    pub dwallet_id: Option<String>,
    pub from_timestamp: Option<u64>,
    pub to_timestamp: Option<u64>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    pub include_metadata: Option<bool>,
}

/// Error response
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub code: u16,
}

/// Create the signature query API router
pub fn signature_query_routes(state: SignatureApiState) -> Router {
    Router::new()
        // Get signature by ID
        .route("/api/v1/signature/:sign_id", get(get_signature_by_id))
        // Get signatures by dWallet
        .route(
            "/api/v1/dwallet/:dwallet_id/signatures",
            get(get_signatures_by_dwallet),
        )
        // Get signatures by checkpoint
        .route(
            "/api/v1/checkpoint/:seq/signatures",
            get(get_signatures_by_checkpoint),
        )
        // Batch query
        .route("/api/v1/signatures/batch", post(get_signatures_batch))
        // Search with filters
        .route("/api/v1/signatures/search", post(search_signatures))
        // Health check
        .route("/api/v1/health", get(health_check))
        .with_state(state)
}

/// Get a signature by its ID
async fn get_signature_by_id(
    Path(sign_id): Path<String>,
    State(state): State<SignatureApiState>,
) -> impl IntoResponse {
    let sign_id_bytes = match hex::decode(&sign_id) {
        Ok(bytes) => bytes,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("Invalid sign_id hex: {}", e),
                    code: 400,
                }),
            )
                .into_response()
        }
    };

    match state.signature_store.get_signature_by_id(&sign_id_bytes) {
        Ok(Some(signature)) => Json(signature).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("Signature not found: {}", sign_id),
                code: 404,
            }),
        )
            .into_response(),
        Err(e) => {
            error!("Failed to get signature {}: {:?}", sign_id, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Internal server error".to_string(),
                    code: 500,
                }),
            )
                .into_response()
        }
    }
}

/// Get signatures by dWallet ID
async fn get_signatures_by_dwallet(
    Path(dwallet_id): Path<String>,
    Query(options): Query<SignatureQueryOptions>,
    State(state): State<SignatureApiState>,
) -> impl IntoResponse {
    let dwallet_id_bytes = match hex::decode(&dwallet_id) {
        Ok(bytes) => bytes,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("Invalid dwallet_id hex: {}", e),
                    code: 400,
                }),
            )
                .into_response()
        }
    };

    match state
        .signature_store
        .get_signatures_by_dwallet(&dwallet_id_bytes, &options)
    {
        Ok(response) => Json(response).into_response(),
        Err(e) => {
            error!("Failed to get signatures for dwallet {}: {:?}", dwallet_id, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Internal server error".to_string(),
                    code: 500,
                }),
            )
                .into_response()
        }
    }
}

/// Get signatures by checkpoint sequence number
async fn get_signatures_by_checkpoint(
    Path(seq): Path<u64>,
    Query(options): Query<SignatureQueryOptions>,
    State(state): State<SignatureApiState>,
) -> impl IntoResponse {
    match state
        .signature_store
        .get_signatures_by_checkpoint(seq, &options)
    {
        Ok(response) => Json(response).into_response(),
        Err(e) => {
            error!("Failed to get signatures for checkpoint {}: {:?}", seq, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Internal server error".to_string(),
                    code: 500,
                }),
            )
                .into_response()
        }
    }
}

/// Batch query for multiple signatures
async fn get_signatures_batch(
    State(state): State<SignatureApiState>,
    Json(request): Json<BatchSignatureRequest>,
) -> impl IntoResponse {
    let mut signatures = Vec::new();

    for sign_id in request.sign_ids {
        let sign_id_bytes = match hex::decode(&sign_id) {
            Ok(bytes) => bytes,
            Err(_) => {
                signatures.push(None);
                continue;
            }
        };

        match state.signature_store.get_signature_by_id(&sign_id_bytes) {
            Ok(sig) => signatures.push(sig),
            Err(e) => {
                error!("Failed to get signature {}: {:?}", sign_id, e);
                signatures.push(None);
            }
        }
    }

    Json(BatchSignatureResponse { signatures })
}

/// Search signatures with filters
async fn search_signatures(
    State(state): State<SignatureApiState>,
    Json(request): Json<SearchSignatureRequest>,
) -> impl IntoResponse {
    let options = SignatureQueryOptions {
        from_timestamp: request.from_timestamp,
        to_timestamp: request.to_timestamp,
        limit: request.limit,
        offset: request.offset,
        include_metadata: request.include_metadata.unwrap_or(false),
        ..Default::default()
    };

    // If dwallet_id is specified, use that index
    if let Some(dwallet_id) = request.dwallet_id {
        let dwallet_id_bytes = match hex::decode(&dwallet_id) {
            Ok(bytes) => bytes,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: format!("Invalid dwallet_id hex: {}", e),
                        code: 400,
                    }),
                )
                    .into_response()
            }
        };

        match state
            .signature_store
            .get_signatures_by_dwallet(&dwallet_id_bytes, &options)
        {
            Ok(response) => Json(response).into_response(),
            Err(e) => {
                error!("Failed to search signatures: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Internal server error".to_string(),
                        code: 500,
                    }),
                )
                    .into_response()
            }
        }
    } else {
        // General search with filters
        match state.signature_store.search_signatures(&options) {
            Ok(response) => Json(response).into_response(),
            Err(e) => {
                error!("Failed to search signatures: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Internal server error".to_string(),
                        code: 500,
                    }),
                )
                    .into_response()
            }
        }
    }
}

/// Health check endpoint
async fn health_check() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "healthy",
        "service": "signature-query-api"
    }))
}

/// Configuration for the signature API service
#[derive(Debug, Clone, Deserialize)]
pub struct SignatureApiConfig {
    pub enabled: bool,
    pub port: u16,
    pub max_connections: usize,
    pub cache_size_mb: usize,
    pub index_historical: bool,
    pub retention_days: u32,
}

impl Default for SignatureApiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            port: 8080,
            max_connections: 1000,
            cache_size_mb: 512,
            index_historical: true,
            retention_days: 90,
        }
    }
}

/// Start the signature API server
pub async fn start_signature_api_server(
    config: SignatureApiConfig,
    signature_store: Arc<SignatureStore>,
) {
    if !config.enabled {
        info!("Signature API server is disabled");
        return;
    }

    let state = SignatureApiState { signature_store };
    let app = signature_query_routes(state);

    let addr = format!("0.0.0.0:{}", config.port);
    info!("Starting signature API server on {}", addr);

    axum::Server::bind(&addr.parse().unwrap())
        .serve(app.into_make_service())
        .await
        .expect("Failed to start signature API server");
}
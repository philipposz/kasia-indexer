use crate::api::to_rpc_address;
use crate::context::IndexerContext;
use anyhow::Context;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use indexer_db::AddressPayload;
use indexer_db::messages::self_stash::{
    SelfStashByOwnerPartition, SelfStashByScopePartition, TxIdToSelfStashPartition,
};
use indexer_db::processing::tx_id_to_acceptance::TxIDToAcceptancePartition;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use tokio::task::spawn_blocking;
use utoipa::{IntoParams, ToSchema};

#[derive(Clone)]
pub struct SelfStashApi {
    tx_keyspace: fjall::TxKeyspace,
    self_stash_by_owner_partition: SelfStashByOwnerPartition,
    self_stash_by_scope_partition: SelfStashByScopePartition,
    tx_id_to_acceptance_partition: TxIDToAcceptancePartition,
    tx_id_to_self_stash_partition: TxIdToSelfStashPartition,
    context: IndexerContext,
}

impl SelfStashApi {
    pub fn new(
        tx_keyspace: fjall::TxKeyspace,
        self_stash_by_owner_partition: SelfStashByOwnerPartition,
        self_stash_by_scope_partition: SelfStashByScopePartition,
        tx_id_to_acceptance_partition: TxIDToAcceptancePartition,
        tx_id_to_self_stash_partition: TxIdToSelfStashPartition,
        context: IndexerContext,
    ) -> Self {
        Self {
            tx_keyspace,
            self_stash_by_owner_partition,
            self_stash_by_scope_partition,
            tx_id_to_acceptance_partition,
            tx_id_to_self_stash_partition,
            context,
        }
    }

    pub fn router() -> Router<Self> {
        Router::new()
            .route("/by-owner", get(get_self_stash_by_owner))
            .route("/by-scope", get(get_self_stash_by_scope))
    }
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct SelfStashPaginationParams {
    pub limit: Option<usize>,
    pub block_time: Option<u64>,
    pub scope: String,
    pub owner: String,
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct SelfStashByScopePaginationParams {
    pub limit: Option<usize>,
    pub block_time: Option<u64>,
    pub scope: String,
    pub q: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SelfStashResponse {
    pub tx_id: String,
    pub owner: Option<String>,
    pub scope: String,
    pub block_time: u64,
    pub accepting_block: Option<String>,
    pub accepting_daa_score: Option<u64>,
    pub stashed_data: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ErrorResponse {
    pub error: String,
}

fn decode_scope_hex(scope_hex: &str) -> Result<[u8; 255], (StatusCode, Json<ErrorResponse>)> {
    if scope_hex.len() > 510 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Scope hex length cannot exceed 510 characters".to_string(),
            }),
        ));
    }

    let mut scope_bytes = [0u8; 255];
    match faster_hex::hex_decode(
        scope_hex.as_bytes(),
        &mut scope_bytes[..scope_hex.len() / 2],
    ) {
        Ok(_) => Ok(scope_bytes),
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("Invalid scope hex: {e}"),
            }),
        )),
    }
}

#[utoipa::path(
    get,
    path = "/self-stash/by-owner",
    params(SelfStashPaginationParams),
    responses(
        (status = 200, description = "Get self-stash entries by owner", body = [SelfStashResponse]),
        (status = 400, description = "Bad request", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
async fn get_self_stash_by_owner(
    State(state): State<SelfStashApi>,
    Query(params): Query<SelfStashPaginationParams>,
) -> impl IntoResponse {
    let limit = params.limit.unwrap_or(10).min(50);
    let cursor = params.block_time.unwrap_or(0);

    let owner_rpc = match kaspa_rpc_core::RpcAddress::try_from(params.owner) {
        Ok(addr) => addr,
        Err(e) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("Invalid address: {e}"),
                }),
            ));
        }
    };
    let owner = match AddressPayload::try_from(&owner_rpc) {
        Ok(payload) => payload,
        Err(e) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("Invalid address payload: {e}"),
                }),
            ));
        }
    };

    let scope_bytes = decode_scope_hex(&params.scope)?;

    let result = spawn_blocking(move || {
        let rtx = state.tx_keyspace.read_tx();
        let mut seen_tx_ids = HashSet::with_capacity(limit);

        state
            .self_stash_by_owner_partition
            .iter_by_owner_and_scope_from_block_time_rtx(&rtx, &scope_bytes, owner, cursor)
            .process_results(|iter| {
                iter.filter(|self_stash_key| seen_tx_ids.insert(self_stash_key.tx_id))
                    .take(limit)
                    .map(|self_stash_key| {
                        let block_time = self_stash_key.block_time.get();
                        let owner =
                            to_rpc_address(&self_stash_key.owner, state.context.network_type)
                                .context("Address conversion error")?
                                .map(|addr| addr.to_string());
                        let acceptance = state
                            .tx_id_to_acceptance_partition
                            .acceptance_by_tx_id_rtx(&rtx, &self_stash_key.tx_id)?;

                        let (accepting_block, accepting_daa_score) = if let Some(key) = acceptance {
                            (
                                Some(faster_hex::hex_string(&key.accepting_block_hash)),
                                Some(key.accepting_daa.get()),
                            )
                        } else {
                            (None, None)
                        };

                        let stash = state
                            .tx_id_to_self_stash_partition
                            .get_rtx(&rtx, &self_stash_key.tx_id)?
                            .ok_or_else(|| anyhow::anyhow!("Self stash not found"))?;
                        let stashed_data_str = faster_hex::hex_string(stash.as_ref());

                        Ok(SelfStashResponse {
                            tx_id: faster_hex::hex_string(&self_stash_key.tx_id),
                            owner,
                            scope: params.scope.clone(),
                            stashed_data: stashed_data_str,
                            block_time,
                            accepting_block,
                            accepting_daa_score,
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .flatten()
    })
    .await;

    match result {
        Ok(Ok(messages)) => Ok(Json(messages)),
        Ok(Err(e)) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )),
        Err(join_err) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Task error: {join_err}"),
            }),
        )),
    }
}

#[utoipa::path(
    get,
    path = "/self-stash/by-scope",
    params(SelfStashByScopePaginationParams),
    responses(
        (status = 200, description = "Get self-stash entries by scope", body = [SelfStashResponse]),
        (status = 400, description = "Bad request", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
async fn get_self_stash_by_scope(
    State(state): State<SelfStashApi>,
    Query(params): Query<SelfStashByScopePaginationParams>,
) -> impl IntoResponse {
    let limit = params.limit.unwrap_or(20).min(50);
    let cursor = params.block_time.unwrap_or(0);
    let scope_bytes = decode_scope_hex(&params.scope)?;
    let query = params
        .q
        .map(|value| value.trim().to_lowercase())
        .filter(|value| !value.is_empty());

    let result = spawn_blocking(move || {
        let rtx = state.tx_keyspace.read_tx();
        let mut seen_tx_ids = HashSet::with_capacity(limit);
        let mut messages = Vec::with_capacity(limit);

        for self_stash_key in state
            .self_stash_by_scope_partition
            .iter_by_scope_from_block_time_rtx(&rtx, &scope_bytes, cursor)
        {
            let self_stash_key = self_stash_key?;
            if !seen_tx_ids.insert(self_stash_key.tx_id) {
                continue;
            }

            let owner = to_rpc_address(&self_stash_key.owner, state.context.network_type)
                .context("Address conversion error")?
                .map(|addr| addr.to_string());

            let stash = state
                .tx_id_to_self_stash_partition
                .get_rtx(&rtx, &self_stash_key.tx_id)?
                .ok_or_else(|| anyhow::anyhow!("Self stash not found"))?;

            if let Some(query) = query.as_ref() {
                let owner_matches = owner
                    .as_ref()
                    .map(|value| value.to_lowercase().contains(query))
                    .unwrap_or(false);
                let payload_matches = std::str::from_utf8(stash.as_ref())
                    .map(|value| value.to_lowercase().contains(query))
                    .unwrap_or(false);
                if !owner_matches && !payload_matches {
                    continue;
                }
            }

            let acceptance = state
                .tx_id_to_acceptance_partition
                .acceptance_by_tx_id_rtx(&rtx, &self_stash_key.tx_id)?;
            let (accepting_block, accepting_daa_score) = if let Some(key) = acceptance {
                (
                    Some(faster_hex::hex_string(&key.accepting_block_hash)),
                    Some(key.accepting_daa.get()),
                )
            } else {
                (None, None)
            };

            messages.push(SelfStashResponse {
                tx_id: faster_hex::hex_string(&self_stash_key.tx_id),
                owner,
                scope: params.scope.clone(),
                block_time: self_stash_key.block_time.get(),
                accepting_block,
                accepting_daa_score,
                stashed_data: faster_hex::hex_string(stash.as_ref()),
            });

            if messages.len() >= limit {
                break;
            }
        }

        Ok::<_, anyhow::Error>(messages)
    })
    .await;

    match result {
        Ok(Ok(messages)) => Ok(Json(messages)),
        Ok(Err(e)) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )),
        Err(join_err) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Task error: {join_err}"),
            }),
        )),
    }
}

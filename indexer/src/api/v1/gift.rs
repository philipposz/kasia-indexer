use crate::gift::{GiftApiError, GiftService};
use axum::extract::{ConnectInfo, State};
use axum::routing::{get, post};
use axum::http::HeaderMap;
use axum::{Json, Router};
use std::net::SocketAddr;

pub use crate::gift::{
    GiftChallengeResponse, GiftClaimRequest, GiftClaimResponse, GiftDeviceCheckDebugQueryRequest,
    GiftDeviceCheckDebugQueryResponse, GiftDeviceCheckDebugUpdateRequest,
    GiftDeviceCheckDebugUpdateResponse, GiftErrorResponse,
};

#[derive(Clone)]
pub struct GiftApi {
    service: GiftService,
}

impl GiftApi {
    pub fn new(service: GiftService) -> Self {
        Self { service }
    }

    pub fn router() -> Router<Self> {
        Router::new()
            .route("/challenge", get(create_challenge))
            .route("/claim", post(claim_gift))
            .route("/debug/query-bit0", post(debug_query_devicecheck_bit0))
            .route("/debug/update-bit0", post(debug_update_devicecheck_bit0))
    }
}

#[utoipa::path(
    get,
    path = "/v1/gift/challenge",
    responses(
        (status = 200, description = "Create one-time gift challenge", body = GiftChallengeResponse),
        (status = 500, description = "Internal error", body = GiftErrorResponse),
        (status = 503, description = "Gift service unavailable", body = GiftErrorResponse)
    )
)]
pub async fn create_challenge(
    State(state): State<GiftApi>,
) -> Result<Json<GiftChallengeResponse>, (axum::http::StatusCode, Json<GiftErrorResponse>)> {
    let response = state
        .service
        .create_challenge()
        .await
        .map_err(GiftApiError::into_response)?;

    Ok(Json(response))
}

#[utoipa::path(
    post,
    path = "/v1/gift/claim",
    request_body = GiftClaimRequest,
    responses(
        (status = 200, description = "Gift claim succeeded", body = GiftClaimResponse),
        (status = 400, description = "Bad request", body = GiftErrorResponse),
        (status = 409, description = "Already claimed", body = GiftErrorResponse),
        (status = 429, description = "Rate limited", body = GiftErrorResponse),
        (status = 500, description = "Internal error", body = GiftErrorResponse),
        (status = 503, description = "Gift service unavailable", body = GiftErrorResponse)
    )
)]
pub async fn claim_gift(
    State(state): State<GiftApi>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(request): Json<GiftClaimRequest>,
) -> Result<Json<GiftClaimResponse>, (axum::http::StatusCode, Json<GiftErrorResponse>)> {
    let source_ip = Some(addr.ip().to_string());

    let response = state
        .service
        .claim(request, source_ip)
        .await
        .map_err(GiftApiError::into_response)?;

    Ok(Json(response))
}

#[utoipa::path(
    post,
    path = "/v1/gift/debug/query-bit0",
    request_body = GiftDeviceCheckDebugQueryRequest,
    responses(
        (status = 200, description = "DeviceCheck query_two_bits debug call succeeded", body = GiftDeviceCheckDebugQueryResponse),
        (status = 400, description = "Bad request", body = GiftErrorResponse),
        (status = 401, description = "Unauthorized", body = GiftErrorResponse),
        (status = 500, description = "Internal error", body = GiftErrorResponse),
        (status = 503, description = "Gift service unavailable", body = GiftErrorResponse)
    )
)]
pub async fn debug_query_devicecheck_bit0(
    State(state): State<GiftApi>,
    headers: HeaderMap,
    Json(request): Json<GiftDeviceCheckDebugQueryRequest>,
) -> Result<Json<GiftDeviceCheckDebugQueryResponse>, (axum::http::StatusCode, Json<GiftErrorResponse>)> {
    let debug_secret = headers
        .get("x-gift-debug-secret")
        .and_then(|value| value.to_str().ok());

    let response = state
        .service
        .debug_query_devicecheck_bit0(request, debug_secret)
        .await
        .map_err(GiftApiError::into_response)?;

    Ok(Json(response))
}

#[utoipa::path(
    post,
    path = "/v1/gift/debug/update-bit0",
    request_body = GiftDeviceCheckDebugUpdateRequest,
    responses(
        (status = 200, description = "DeviceCheck update_two_bits debug call succeeded", body = GiftDeviceCheckDebugUpdateResponse),
        (status = 400, description = "Bad request", body = GiftErrorResponse),
        (status = 401, description = "Unauthorized", body = GiftErrorResponse),
        (status = 500, description = "Internal error", body = GiftErrorResponse),
        (status = 503, description = "Gift service unavailable", body = GiftErrorResponse)
    )
)]
pub async fn debug_update_devicecheck_bit0(
    State(state): State<GiftApi>,
    headers: HeaderMap,
    Json(request): Json<GiftDeviceCheckDebugUpdateRequest>,
) -> Result<Json<GiftDeviceCheckDebugUpdateResponse>, (axum::http::StatusCode, Json<GiftErrorResponse>)> {
    let debug_secret = headers
        .get("x-gift-debug-secret")
        .and_then(|value| value.to_str().ok());

    let response = state
        .service
        .debug_update_devicecheck_bit0(request, debug_secret)
        .await
        .map_err(GiftApiError::into_response)?;

    Ok(Json(response))
}

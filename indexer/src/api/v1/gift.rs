use crate::gift::{GiftApiError, GiftService};
use axum::extract::{ConnectInfo, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use std::net::SocketAddr;

pub use crate::gift::{
    GiftChallengeResponse, GiftClaimRequest, GiftClaimResponse, GiftErrorResponse,
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

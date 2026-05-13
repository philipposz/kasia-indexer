use crate::push::{PushApiError, PushService};
use axum::extract::{Query, State};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};

pub use crate::push::{
    PushChallengeResponse, PushErrorResponse, PushOkResponse, PushRegistrationRequest,
    PushPeerStatusQuery, PushPeerStatusResponse, PushPresenceRequest, PushUnregisterRequest,
    PushUpdateRequest,
};

#[derive(Clone)]
pub struct PushApi {
    service: PushService,
}

impl PushApi {
    pub fn new(service: PushService) -> Self {
        Self { service }
    }

    pub fn router() -> Router<Self> {
        Router::new()
            .route("/challenge", post(create_challenge))
            .route("/register", post(register_device))
            .route("/presence", post(send_presence))
            .route("/update", put(update_device))
            .route("/unregister", delete(unregister_device))
            .route("/status/by-wallet-address", get(peer_status_by_wallet_address))
    }
}

#[utoipa::path(
    post,
    path = "/v1/push/challenge",
    responses(
        (status = 200, description = "Create a challenge nonce for push auth", body = PushChallengeResponse),
        (status = 500, description = "Internal server error", body = PushErrorResponse)
    )
)]
pub async fn create_challenge(
    State(state): State<PushApi>,
) -> Result<Json<PushChallengeResponse>, (axum::http::StatusCode, Json<PushErrorResponse>)> {
    Ok(Json(state.service.create_challenge().await))
}

#[utoipa::path(
    post,
    path = "/v1/push/register",
    request_body = PushRegistrationRequest,
    responses(
        (status = 200, description = "Register a push device", body = PushOkResponse),
        (status = 400, description = "Bad request", body = PushErrorResponse),
        (status = 401, description = "Unauthorized", body = PushErrorResponse),
        (status = 500, description = "Internal server error", body = PushErrorResponse)
    )
)]
pub async fn register_device(
    State(state): State<PushApi>,
    Json(request): Json<PushRegistrationRequest>,
) -> Result<Json<PushOkResponse>, (axum::http::StatusCode, Json<PushErrorResponse>)> {
    state
        .service
        .register(request)
        .await
        .map_err(PushApiError::into_response)?;

    Ok(Json(PushOkResponse { ok: true }))
}

#[utoipa::path(
    post,
    path = "/v1/push/presence",
    request_body = PushPresenceRequest,
    responses(
        (status = 200, description = "Send an ephemeral presence event", body = PushOkResponse),
        (status = 400, description = "Bad request", body = PushErrorResponse),
        (status = 401, description = "Unauthorized", body = PushErrorResponse),
        (status = 500, description = "Internal server error", body = PushErrorResponse)
    )
)]
pub async fn send_presence(
    State(state): State<PushApi>,
    Json(request): Json<PushPresenceRequest>,
) -> Result<Json<PushOkResponse>, (axum::http::StatusCode, Json<PushErrorResponse>)> {
    state
        .service
        .dispatch_presence(request)
        .await
        .map_err(PushApiError::into_response)?;

    Ok(Json(PushOkResponse { ok: true }))
}

#[utoipa::path(
    put,
    path = "/v1/push/update",
    request_body = PushUpdateRequest,
    responses(
        (status = 200, description = "Update watched addresses", body = PushOkResponse),
        (status = 400, description = "Bad request", body = PushErrorResponse),
        (status = 401, description = "Unauthorized", body = PushErrorResponse),
        (status = 404, description = "Registration not found", body = PushErrorResponse),
        (status = 500, description = "Internal server error", body = PushErrorResponse)
    )
)]
pub async fn update_device(
    State(state): State<PushApi>,
    Json(request): Json<PushUpdateRequest>,
) -> Result<Json<PushOkResponse>, (axum::http::StatusCode, Json<PushErrorResponse>)> {
    state
        .service
        .update(request)
        .await
        .map_err(PushApiError::into_response)?;

    Ok(Json(PushOkResponse { ok: true }))
}

#[utoipa::path(
    delete,
    path = "/v1/push/unregister",
    request_body = PushUnregisterRequest,
    responses(
        (status = 200, description = "Unregister device", body = PushOkResponse),
        (status = 400, description = "Bad request", body = PushErrorResponse),
        (status = 401, description = "Unauthorized", body = PushErrorResponse),
        (status = 500, description = "Internal server error", body = PushErrorResponse)
    )
)]
pub async fn unregister_device(
    State(state): State<PushApi>,
    Json(request): Json<PushUnregisterRequest>,
) -> Result<Json<PushOkResponse>, (axum::http::StatusCode, Json<PushErrorResponse>)> {
    state
        .service
        .unregister(request)
        .await
        .map_err(PushApiError::into_response)?;

    Ok(Json(PushOkResponse { ok: true }))
}

#[utoipa::path(
    get,
    path = "/v1/push/status/by-wallet-address",
    params(
        ("wallet_address" = String, Query, description = "Kaspa wallet address of the contact")
    ),
    responses(
        (status = 200, description = "Peer push registration status", body = PushPeerStatusResponse),
        (status = 400, description = "Bad request", body = PushErrorResponse),
        (status = 500, description = "Internal server error", body = PushErrorResponse)
    )
)]
pub async fn peer_status_by_wallet_address(
    State(state): State<PushApi>,
    Query(query): Query<PushPeerStatusQuery>,
) -> Result<Json<PushPeerStatusResponse>, (axum::http::StatusCode, Json<PushErrorResponse>)> {
    state
        .service
        .peer_status_for_wallet_address(query.wallet_address.as_str())
        .await
        .map(Json)
        .map_err(PushApiError::into_response)
}

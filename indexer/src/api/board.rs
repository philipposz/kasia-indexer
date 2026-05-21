use crate::context::IndexerContext;
use crate::push::{PulseReplyPushEvent, PushService};
use anyhow::{Context, bail};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use indexer_db::messages::board::{
    BoardClientGeneratedIdToPostIdPartition, BoardPostByCreatedAtKey, BoardPostByCreatedAtPartition,
    BoardFollowByFollowerTargetPartition, BoardFollowByTargetFollowerPartition,
    BoardPostByIdPartition, BoardReactionByPostActorEmojiPartition,
    BoardReportByPostActorPartition,
    BoardReplyByParentCreatedAtKey, BoardReplyByParentCreatedAtPartition,
};
use indexer_db::AddressPayload;
use kaspa_addresses::Version;
use kaspa_rpc_core::RpcAddress;
use secp256k1::ffi;
use secp256k1::ffi::CPtr;
use secp256k1::{Secp256k1, XOnlyPublicKey, schnorr};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::collections::HashMap;
use time::Duration;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::task::spawn_blocking;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use zerocopy::big_endian::U64;

#[derive(Clone)]
pub struct BoardApi {
    tx_keyspace: fjall::TxKeyspace,
    board_post_by_id_partition: BoardPostByIdPartition,
    board_post_by_created_at_partition: BoardPostByCreatedAtPartition,
    board_client_generated_id_to_post_id_partition: BoardClientGeneratedIdToPostIdPartition,
    board_reply_by_parent_created_at_partition: BoardReplyByParentCreatedAtPartition,
    board_reaction_by_post_actor_emoji_partition: BoardReactionByPostActorEmojiPartition,
    board_follow_by_follower_target_partition: BoardFollowByFollowerTargetPartition,
    board_follow_by_target_follower_partition: BoardFollowByTargetFollowerPartition,
    board_report_by_post_actor_partition: BoardReportByPostActorPartition,
    context: IndexerContext,
    push_service: Option<PushService>,
}

impl BoardApi {
    pub fn new(
        tx_keyspace: fjall::TxKeyspace,
        board_post_by_id_partition: BoardPostByIdPartition,
        board_post_by_created_at_partition: BoardPostByCreatedAtPartition,
        board_client_generated_id_to_post_id_partition: BoardClientGeneratedIdToPostIdPartition,
        board_reply_by_parent_created_at_partition: BoardReplyByParentCreatedAtPartition,
        board_reaction_by_post_actor_emoji_partition: BoardReactionByPostActorEmojiPartition,
        board_follow_by_follower_target_partition: BoardFollowByFollowerTargetPartition,
        board_follow_by_target_follower_partition: BoardFollowByTargetFollowerPartition,
        board_report_by_post_actor_partition: BoardReportByPostActorPartition,
        context: IndexerContext,
        push_service: Option<PushService>,
    ) -> Self {
        Self {
            tx_keyspace,
            board_post_by_id_partition,
            board_post_by_created_at_partition,
            board_client_generated_id_to_post_id_partition,
            board_reply_by_parent_created_at_partition,
            board_reaction_by_post_actor_emoji_partition,
            board_follow_by_follower_target_partition,
            board_follow_by_target_follower_partition,
            board_report_by_post_actor_partition,
            context,
            push_service,
        }
    }

    pub fn router() -> Router<Self> {
        Router::new()
            .route("/feed", get(get_board_feed))
            .route("/feed/changes", get(get_board_feed_changes))
            .route("/posts", post(create_board_post))
            .route("/profile/{address}", get(get_board_profile_feed))
            .route("/profile/{address}/connections", get(get_board_profile_connections))
            .route("/profile/{address}/follow", post(set_board_follow_state))
            .route("/posts/{post_id}", get(get_board_post_detail))
            .route("/posts/{post_id}/replies", post(create_board_reply))
            .route("/posts/{post_id}/reactions", post(toggle_board_reaction))
            .route("/posts/{post_id}/report", post(report_board_post))
    }
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct BoardFeedQuery {
    pub mode: Option<String>,
    pub limit: Option<usize>,
    pub cursor: Option<String>,
}

#[derive(Debug, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct BoardFeedChangesQuery {
    pub mode: Option<String>,
    pub limit: Option<usize>,
    pub since_revision: String,
}

#[derive(Debug, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct BoardPostDetailQuery {
    pub viewer_address: Option<String>,
}

#[derive(Debug, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct BoardProfileQuery {
    pub limit: Option<usize>,
    pub viewer_address: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BoardCreatePostRequest {
    pub author_address: String,
    #[serde(default)]
    pub author_display_name: String,
    #[serde(default)]
    pub content_text: String,
    #[serde(default)]
    pub attachments: Vec<BoardAttachmentPayload>,
    #[serde(default)]
    pub reply_to_post_id: Option<String>,
    #[serde(alias = "primaryLinkURL")]
    #[serde(default)]
    pub primary_link_url: Option<String>,
    #[serde(default)]
    pub created_at: String,
    pub client_generated_id: String,
    pub signature: String,
    pub network: String,
}

#[derive(Debug, Deserialize, Serialize, ToSchema, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BoardCreateReactionRequest {
    pub actor_address: String,
    pub emoji: String,
    #[serde(default)]
    pub created_at: String,
    pub client_generated_id: String,
    pub signature: String,
    pub network: String,
}

#[derive(Debug, Deserialize, Serialize, ToSchema, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BoardCreateFollowRequest {
    pub actor_address: String,
    #[serde(default)]
    pub actor_display_name: String,
    #[serde(default)]
    pub actor_avatar_url: Option<String>,
    #[serde(default)]
    pub actor_avatar_file_id: Option<String>,
    #[serde(default)]
    pub actor_avatar_file_extension: Option<String>,
    pub target_address: String,
    #[serde(default)]
    pub target_display_name: String,
    #[serde(default)]
    pub target_avatar_url: Option<String>,
    #[serde(default)]
    pub target_avatar_file_id: Option<String>,
    #[serde(default)]
    pub target_avatar_file_extension: Option<String>,
    pub follow: bool,
    #[serde(default)]
    pub created_at: String,
    pub client_generated_id: String,
    pub signature: String,
    pub network: String,
}

#[derive(Debug, Deserialize, Serialize, ToSchema, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BoardCreateReportRequest {
    pub actor_address: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub created_at: String,
    pub client_generated_id: String,
    pub signature: String,
    pub network: String,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct BoardCreatePostSignablePayload {
    author_address: String,
    author_display_name: String,
    content_text: String,
    attachments: Vec<BoardAttachmentPayload>,
    reply_to_post_id: Option<String>,
    primary_link_url: Option<String>,
    created_at: String,
    client_generated_id: String,
    network: String,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct BoardCreateReactionSignablePayload {
    actor_address: String,
    emoji: String,
    created_at: String,
    client_generated_id: String,
    network: String,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct BoardCreateFollowSignablePayload {
    actor_address: String,
    actor_display_name: String,
    actor_avatar_url: Option<String>,
    actor_avatar_file_id: Option<String>,
    actor_avatar_file_extension: Option<String>,
    target_address: String,
    target_display_name: String,
    target_avatar_url: Option<String>,
    target_avatar_file_id: Option<String>,
    target_avatar_file_extension: Option<String>,
    follow: bool,
    created_at: String,
    client_generated_id: String,
    network: String,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct BoardCreateReportSignablePayload {
    actor_address: String,
    reason: String,
    created_at: String,
    client_generated_id: String,
    network: String,
}

#[derive(Debug, Deserialize, Serialize, ToSchema, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BoardAttachmentPayload {
    pub id: String,
    pub sort_index: i32,
    #[serde(rename = "type")]
    pub kind: String,
    pub relay_file_id: String,
    #[serde(alias = "relayDownloadURL")]
    pub relay_download_url: String,
    #[serde(alias = "downloadURL")]
    pub download_url: String,
    pub mime_type: String,
    pub file_name: String,
    pub file_extension: String,
    pub size_bytes: Option<i64>,
    #[serde(alias = "thumbnailURL")]
    pub thumbnail_url: Option<String>,
    pub width: Option<i32>,
    pub height: Option<i32>,
    pub duration_ms: Option<i32>,
    pub relay_profile_id: Option<String>,
    pub relay_access_owner: Option<String>,
    pub key: String,
    pub sha256: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BoardAuthorResponse {
    pub address: String,
    pub display_name: String,
    pub avatar_url: Option<String>,
    pub avatar_file_id: Option<String>,
    pub avatar_file_extension: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BoardLinkPreviewResponse {
    pub url: String,
    pub title: Option<String>,
    pub subtitle: Option<String>,
    pub image_url: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BoardReactionSummaryResponse {
    pub emoji: String,
    pub count: i32,
    pub includes_current_user: bool,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BoardPostResponse {
    pub id: String,
    pub author: BoardAuthorResponse,
    pub content_text: String,
    pub attachments: Vec<BoardAttachmentPayload>,
    pub reply_to_post_id: Option<String>,
    pub primary_link_url: Option<String>,
    pub link_preview: Option<BoardLinkPreviewResponse>,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub reply_count: i32,
    pub reaction_count: i32,
    pub visibility_state: String,
    pub moderation_state: String,
    pub revision_token: Option<String>,
    pub updated_at: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BoardPostDetailResponse {
    pub post: BoardPostResponse,
    pub replies: Vec<BoardPostResponse>,
    pub reactions: Vec<BoardReactionSummaryResponse>,
    pub server_time: String,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct BoardFeedResponse {
    pub items: Vec<BoardPostResponse>,
    pub next_cursor: Option<String>,
    pub server_time: String,
    pub feed_revision: Option<String>,
    pub page_digest: Option<String>,
    pub supports_changes_since_revision: bool,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BoardFeedChangeResponse {
    pub operation: String,
    pub post_id: String,
    pub post: Option<BoardPostResponse>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BoardFeedChangesResponse {
    pub base_revision: String,
    pub target_revision: String,
    pub next_cursor: Option<String>,
    pub server_time: String,
    pub requires_full_reload: bool,
    pub changes: Vec<BoardFeedChangeResponse>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BoardProfileConnectionsResponse {
    pub address: String,
    pub following: Vec<BoardAuthorResponse>,
    pub followers: Vec<BoardAuthorResponse>,
    pub following_count: i32,
    pub follower_count: i32,
    pub viewer_follows_author: bool,
    pub server_time: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BoardFollowMutationResponse {
    pub target_address: String,
    pub actor_address: String,
    pub is_following: bool,
    pub following_count: i32,
    pub follower_count: i32,
    pub server_time: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BoardReportMutationResponse {
    pub post_id: String,
    pub actor_address: String,
    pub report_count: i32,
    pub moderation_state: String,
    pub server_time: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct BoardErrorResponse {
    pub error: String,
}

enum BoardFeedLoadResult {
    NotModified { revision: String },
    Feed(BoardFeedResponse),
}

enum BoardFeedChangesLoadResult {
    NotModified { revision: String },
    Changes(BoardFeedChangesResponse),
}

#[utoipa::path(
    get,
    path = "/board/feed",
    params(BoardFeedQuery),
    responses(
        (status = 200, description = "Get board feed", body = BoardFeedResponse),
        (status = 304, description = "Feed unchanged"),
        (status = 400, description = "Bad request", body = BoardErrorResponse),
        (status = 500, description = "Internal server error", body = BoardErrorResponse)
    )
)]
pub async fn get_board_feed(
    State(state): State<BoardApi>,
    headers: HeaderMap,
    Query(query): Query<BoardFeedQuery>,
) -> Result<Response, (StatusCode, Json<BoardErrorResponse>)> {
    let mode = query
        .mode
        .as_deref()
        .unwrap_or("latest")
        .trim()
        .to_lowercase();
    if mode != "latest" {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(BoardErrorResponse {
                error: format!("unsupported board feed mode: {mode}"),
            }),
        ));
    }

    let limit = query.limit.unwrap_or(25).clamp(1, 100);
    let cursor_ms = query.cursor.as_deref().and_then(|value| value.parse::<u64>().ok());
    let if_none_match_revision = normalized_revision_value_from_headers(&headers);

    let result = spawn_blocking(move || build_feed_response(&state, limit, cursor_ms, if_none_match_revision))
    .await;

    match result {
        Ok(Ok(BoardFeedLoadResult::NotModified { revision })) => {
            let mut headers = feed_transport_headers(revision.as_str(), true)
                .map_err(|error| error_response(StatusCode::INTERNAL_SERVER_ERROR, error))?;
            headers.insert("content-length", HeaderValue::from_static("0"));
            Ok((StatusCode::NOT_MODIFIED, headers).into_response())
        }
        Ok(Ok(BoardFeedLoadResult::Feed(feed))) => {
            let revision = feed_revision_value(&feed)
                .map_err(|error| error_response(StatusCode::INTERNAL_SERVER_ERROR, error))?;
            let headers = feed_transport_headers(revision.as_str(), feed.supports_changes_since_revision)
                .map_err(|error| error_response(StatusCode::INTERNAL_SERVER_ERROR, error))?;
            Ok((headers, Json(feed)).into_response())
        }
        Ok(Err(error)) => Err(error_response(StatusCode::INTERNAL_SERVER_ERROR, error)),
        Err(join_error) => Err(task_error_response(join_error)),
    }
}

#[utoipa::path(
    get,
    path = "/board/feed/changes",
    params(BoardFeedChangesQuery),
    responses(
        (status = 200, description = "Get incremental Pulse feed changes", body = BoardFeedChangesResponse),
        (status = 304, description = "Feed unchanged"),
        (status = 400, description = "Bad request", body = BoardErrorResponse),
        (status = 500, description = "Internal server error", body = BoardErrorResponse)
    )
)]
pub async fn get_board_feed_changes(
    State(state): State<BoardApi>,
    Query(query): Query<BoardFeedChangesQuery>,
) -> Result<Response, (StatusCode, Json<BoardErrorResponse>)> {
    let mode = query
        .mode
        .as_deref()
        .unwrap_or("latest")
        .trim()
        .to_lowercase();
    if mode != "latest" {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(BoardErrorResponse {
                error: format!("unsupported board feed mode: {mode}"),
            }),
        ));
    }

    let limit = query.limit.unwrap_or(25).clamp(1, 100);
    let since_revision = normalize_revision_value(query.since_revision.as_str())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(BoardErrorResponse {
                    error: "sinceRevision is required".to_string(),
                }),
            )
        })?;

    let result = spawn_blocking(move || build_feed_changes_response(&state, limit, since_revision.as_str())).await;
    match result {
        Ok(Ok(BoardFeedChangesLoadResult::NotModified { revision })) => {
            let mut headers = feed_transport_headers(revision.as_str(), true)
                .map_err(|error| error_response(StatusCode::INTERNAL_SERVER_ERROR, error))?;
            headers.insert("content-length", HeaderValue::from_static("0"));
            Ok((StatusCode::NOT_MODIFIED, headers).into_response())
        }
        Ok(Ok(BoardFeedChangesLoadResult::Changes(response))) => {
            let headers = feed_transport_headers(response.target_revision.as_str(), true)
                .map_err(|error| error_response(StatusCode::INTERNAL_SERVER_ERROR, error))?;
            Ok((headers, Json(response)).into_response())
        }
        Ok(Err(error)) => Err(error_response(StatusCode::INTERNAL_SERVER_ERROR, error)),
        Err(join_error) => Err(task_error_response(join_error)),
    }
}

#[utoipa::path(
    get,
    path = "/board/profile/{address}",
    params(
        ("address" = String, Path, description = "Kaspa address"),
        BoardProfileQuery
    ),
    responses(
        (status = 200, description = "Get posts by author", body = BoardFeedResponse),
        (status = 400, description = "Bad request", body = BoardErrorResponse),
        (status = 500, description = "Internal server error", body = BoardErrorResponse)
    )
)]
pub async fn get_board_profile_feed(
    State(state): State<BoardApi>,
    Path(address): Path<String>,
    Query(query): Query<BoardProfileQuery>,
) -> impl IntoResponse {
    let normalized_address = address.trim().to_lowercase();
    let limit = query.limit.unwrap_or(50).clamp(1, 100);
    let result = spawn_blocking(move || -> anyhow::Result<BoardFeedResponse> {
        validate_board_actor_address("address", normalized_address.as_str())?;
        let rtx = state.tx_keyspace.read_tx();
        let mut items = Vec::with_capacity(limit);

        for entry in state.board_post_by_created_at_partition.iter_all(&rtx).rev() {
            let (_key, value) = entry?;
            let post: BoardPostResponse =
                serde_json::from_slice(value.as_ref()).context("decode board post from author feed")?;
            if post.author.address.trim().eq_ignore_ascii_case(normalized_address.as_str()) {
                items.push(post);
            }
            if items.len() >= limit {
                break;
            }
        }

        let mut response = BoardFeedResponse {
            items,
            next_cursor: None,
            server_time: timestamp_string(OffsetDateTime::now_utc())?,
            feed_revision: None,
            page_digest: None,
            supports_changes_since_revision: false,
        };
        apply_feed_metadata(&mut response)?;
        Ok(response)
    })
    .await;

    match result {
        Ok(Ok(feed)) => Ok(Json(feed)),
        Ok(Err(error)) => Err(status_for_board_error(&error, false)),
        Err(join_error) => Err(task_error_response(join_error)),
    }
}

#[utoipa::path(
    get,
    path = "/board/profile/{address}/connections",
    params(
        ("address" = String, Path, description = "Kaspa address"),
        BoardProfileQuery
    ),
    responses(
        (status = 200, description = "Get Pulse followers/following for an address", body = BoardProfileConnectionsResponse),
        (status = 400, description = "Bad request", body = BoardErrorResponse),
        (status = 500, description = "Internal server error", body = BoardErrorResponse)
    )
)]
pub async fn get_board_profile_connections(
    State(state): State<BoardApi>,
    Path(address): Path<String>,
    Query(query): Query<BoardProfileQuery>,
) -> impl IntoResponse {
    let normalized_address = address.trim().to_lowercase();
    let viewer_address = query.viewer_address;
    let result = spawn_blocking(move || {
        build_profile_connections_response(&state, normalized_address.as_str(), viewer_address.as_deref())
    })
    .await;

    match result {
        Ok(Ok(response)) => Ok(Json(response)),
        Ok(Err(error)) => Err(status_for_board_error(&error, false)),
        Err(join_error) => Err(task_error_response(join_error)),
    }
}

#[utoipa::path(
    get,
    path = "/board/posts/{post_id}",
    params(
        ("post_id" = String, Path, description = "Board post id"),
        BoardPostDetailQuery
    ),
    responses(
        (status = 200, description = "Get board post detail", body = BoardPostDetailResponse),
        (status = 404, description = "Post not found", body = BoardErrorResponse),
        (status = 500, description = "Internal server error", body = BoardErrorResponse)
    )
)]
pub async fn get_board_post_detail(
    State(state): State<BoardApi>,
    Path(post_id): Path<String>,
    Query(query): Query<BoardPostDetailQuery>,
) -> impl IntoResponse {
    let viewer_address = query.viewer_address;
    let result = spawn_blocking(move || {
        build_post_detail_response(&state, post_id.trim(), viewer_address.as_deref())
    })
    .await;

    match result {
        Ok(Ok(detail)) => Ok(Json(detail)),
        Ok(Err(error)) => Err(status_for_board_error(&error, false)),
        Err(join_error) => Err(task_error_response(join_error)),
    }
}

#[utoipa::path(
    post,
    path = "/board/posts",
    request_body = BoardCreatePostRequest,
    responses(
        (status = 200, description = "Create board post", body = BoardPostResponse),
        (status = 400, description = "Bad request", body = BoardErrorResponse),
        (status = 409, description = "Duplicate client generated id", body = BoardErrorResponse),
        (status = 500, description = "Internal server error", body = BoardErrorResponse)
    )
)]
pub async fn create_board_post(
    State(state): State<BoardApi>,
    Json(request): Json<BoardCreatePostRequest>,
) -> impl IntoResponse {
    let result = spawn_blocking(move || create_post_record(&state, &request, None)).await;

    match result {
        Ok(Ok(response)) => Ok(Json(response)),
        Ok(Err(error)) => Err(status_for_board_error(&error, true)),
        Err(join_error) => Err(task_error_response(join_error)),
    }
}

#[utoipa::path(
    post,
    path = "/board/posts/{post_id}/replies",
    params(("post_id" = String, Path, description = "Parent board post id")),
    request_body = BoardCreatePostRequest,
    responses(
        (status = 200, description = "Create board reply", body = BoardPostDetailResponse),
        (status = 400, description = "Bad request", body = BoardErrorResponse),
        (status = 404, description = "Post not found", body = BoardErrorResponse),
        (status = 409, description = "Duplicate client generated id", body = BoardErrorResponse),
        (status = 500, description = "Internal server error", body = BoardErrorResponse)
    )
)]
pub async fn create_board_reply(
    State(state): State<BoardApi>,
    Path(post_id): Path<String>,
    Json(request): Json<BoardCreatePostRequest>,
) -> impl IntoResponse {
    let parent_post_id = post_id.trim().to_string();
    let viewer_address = request.author_address.clone();
    let push_service = state.push_service.clone();
    let result = spawn_blocking(move || -> anyhow::Result<(BoardPostDetailResponse, Option<PulseReplyPushEvent>)> {
        let parent_post = load_post_response(&state, parent_post_id.as_str())?;
        let reply_post = create_post_record(&state, &request, Some(parent_post_id.as_str()))?;
        let detail = build_post_detail_response(&state, parent_post_id.as_str(), Some(viewer_address.as_str()))?;
        let push_event = build_pulse_reply_push_event(&parent_post, &reply_post);
        Ok((detail, push_event))
    })
    .await;

    match result {
        Ok(Ok((detail, push_event))) => {
            if let (Some(push_service), Some(push_event)) = (push_service, push_event) {
                if let Err(error) = push_service.dispatch_pulse_reply(push_event).await {
                    tracing::warn!(%error, "failed to dispatch pulse reply push");
                }
            }
            Ok(Json(detail))
        }
        Ok(Err(error)) => Err(status_for_board_error(&error, true)),
        Err(join_error) => Err(task_error_response(join_error)),
    }
}

#[utoipa::path(
    post,
    path = "/board/posts/{post_id}/reactions",
    params(("post_id" = String, Path, description = "Board post id")),
    request_body = BoardCreateReactionRequest,
    responses(
        (status = 200, description = "Toggle board reaction", body = BoardPostDetailResponse),
        (status = 400, description = "Bad request", body = BoardErrorResponse),
        (status = 404, description = "Post not found", body = BoardErrorResponse),
        (status = 500, description = "Internal server error", body = BoardErrorResponse)
    )
)]
pub async fn toggle_board_reaction(
    State(state): State<BoardApi>,
    Path(post_id): Path<String>,
    Json(request): Json<BoardCreateReactionRequest>,
) -> impl IntoResponse {
    let normalized_post_id = post_id.trim().to_string();
    let viewer_address = request.actor_address.clone();
    let result = spawn_blocking(move || -> anyhow::Result<BoardPostDetailResponse> {
        toggle_reaction_record(&state, normalized_post_id.as_str(), &request)?;
        build_post_detail_response(&state, normalized_post_id.as_str(), Some(viewer_address.as_str()))
    })
    .await;

    match result {
        Ok(Ok(detail)) => Ok(Json(detail)),
        Ok(Err(error)) => Err(status_for_board_error(&error, false)),
        Err(join_error) => Err(task_error_response(join_error)),
    }
}

#[utoipa::path(
    post,
    path = "/board/profile/{address}/follow",
    params(("address" = String, Path, description = "Target author address")),
    request_body = BoardCreateFollowRequest,
    responses(
        (status = 200, description = "Follow or unfollow a Pulse author", body = BoardFollowMutationResponse),
        (status = 400, description = "Bad request", body = BoardErrorResponse),
        (status = 500, description = "Internal server error", body = BoardErrorResponse)
    )
)]
pub async fn set_board_follow_state(
    State(state): State<BoardApi>,
    Path(address): Path<String>,
    Json(request): Json<BoardCreateFollowRequest>,
) -> impl IntoResponse {
    let normalized_target_address = address.trim().to_string();
    let result = spawn_blocking(move || apply_follow_state(&state, normalized_target_address.as_str(), &request)).await;

    match result {
        Ok(Ok(response)) => Ok(Json(response)),
        Ok(Err(error)) => Err(status_for_board_error(&error, false)),
        Err(join_error) => Err(task_error_response(join_error)),
    }
}

#[utoipa::path(
    post,
    path = "/board/posts/{post_id}/report",
    params(("post_id" = String, Path, description = "Board post id")),
    request_body = BoardCreateReportRequest,
    responses(
        (status = 200, description = "Report a board post", body = BoardReportMutationResponse),
        (status = 400, description = "Bad request", body = BoardErrorResponse),
        (status = 404, description = "Post not found", body = BoardErrorResponse),
        (status = 500, description = "Internal server error", body = BoardErrorResponse)
    )
)]
pub async fn report_board_post(
    State(state): State<BoardApi>,
    Path(post_id): Path<String>,
    Json(request): Json<BoardCreateReportRequest>,
) -> impl IntoResponse {
    let normalized_post_id = post_id.trim().to_string();
    let result = spawn_blocking(move || submit_report_record(&state, normalized_post_id.as_str(), &request)).await;

    match result {
        Ok(Ok(response)) => Ok(Json(response)),
        Ok(Err(error)) => Err(status_for_board_error(&error, false)),
        Err(join_error) => Err(task_error_response(join_error)),
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct StoredBoardFollowRecord {
    actor: BoardAuthorResponse,
    target: BoardAuthorResponse,
    created_at: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct StoredBoardReportRecord {
    actor_address: String,
    reason: String,
    created_at: String,
    client_generated_id: String,
}

fn create_post_record(
    state: &BoardApi,
    request: &BoardCreatePostRequest,
    forced_reply_to_post_id: Option<&str>,
) -> anyhow::Result<BoardPostResponse> {
    validate_create_post_request(request, &state.context, forced_reply_to_post_id)?;

    let normalized_reply_to_post_id = forced_reply_to_post_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);

    let rtx = state.tx_keyspace.read_tx();
    if let Some(existing_post_id) = state
        .board_client_generated_id_to_post_id_partition
        .get_rtx(&rtx, request.client_generated_id.trim())?
    {
        let existing_post_id =
            std::str::from_utf8(existing_post_id.as_ref()).context("decode existing board post id")?;
        if let Some(existing_post) = state.board_post_by_id_partition.get_rtx(&rtx, existing_post_id)? {
            let response: BoardPostResponse =
                serde_json::from_slice(existing_post.as_ref()).context("decode existing board post")?;
            return Ok(response);
        }
    }

    if let Some(parent_post_id) = normalized_reply_to_post_id.as_deref() {
        ensure_post_exists(&rtx, state, parent_post_id)?;
    }
    drop(rtx);

    let created_at = parse_requested_created_at(&request.created_at)?;
    let expires_at = created_at + Duration::days(30);
    let post_id = Uuid::new_v4();
    let post_id_string = post_id.to_string();
    let created_at_string = timestamp_string(created_at)?;

    let response = BoardPostResponse {
        id: post_id_string.clone(),
        author: BoardAuthorResponse {
            address: request.author_address.trim().to_string(),
            display_name: normalized_or_fallback(&request.author_display_name, &request.author_address),
            avatar_url: None,
            avatar_file_id: None,
            avatar_file_extension: None,
        },
        content_text: request.content_text.trim().to_string(),
        attachments: request.attachments.clone(),
        reply_to_post_id: normalized_reply_to_post_id.clone(),
        primary_link_url: normalized_optional(&request.primary_link_url),
        link_preview: build_link_preview(request.primary_link_url.as_deref()),
        created_at: created_at_string.clone(),
        expires_at: Some(timestamp_string(expires_at)?),
        reply_count: 0,
        reaction_count: 0,
        visibility_state: "visible".to_string(),
        moderation_state: "none".to_string(),
        revision_token: None,
        updated_at: None,
    };

    let mut wtx = state.tx_keyspace.write_tx()?;
    let _ = write_post_response_with_touch(state, &mut wtx, &response, false)?;
    state.board_client_generated_id_to_post_id_partition.insert_wtx(
        &mut wtx,
        request.client_generated_id.trim(),
        &post_id_string,
    );

    if let Some(parent_post_id) = normalized_reply_to_post_id.as_deref() {
        let parent_post_uuid =
            Uuid::parse_str(parent_post_id).context("replyToPostId must be a valid board post id")?;
        state.board_reply_by_parent_created_at_partition.insert_wtx(
            &mut wtx,
            &BoardReplyByParentCreatedAtKey {
                parent_post_uuid: *parent_post_uuid.as_bytes(),
                created_at_ms: U64::new(parse_timestamp_ms(&created_at_string)?),
                reply_uuid: *post_id.as_bytes(),
            },
        );
        update_post_reply_count(state, &mut wtx, parent_post_id, 1)?;
    }

    wtx.commit()?
        .map_err(|_| anyhow::anyhow!("board post write conflict"))?;

    load_post_response(state, post_id_string.as_str())
}

fn toggle_reaction_record(
    state: &BoardApi,
    post_id: &str,
    request: &BoardCreateReactionRequest,
) -> anyhow::Result<()> {
    validate_create_reaction_request(request, &state.context)?;

    let normalized_post_id = post_id.trim();
    let normalized_actor_address = request.actor_address.trim();
    let normalized_emoji = request.emoji.trim();

    let rtx = state.tx_keyspace.read_tx();
    ensure_post_exists(&rtx, state, normalized_post_id)?;

    let had_existing_reaction = state.board_reaction_by_post_actor_emoji_partition.contains_rtx(
        &rtx,
        normalized_post_id,
        normalized_actor_address,
        normalized_emoji,
    )?;
    let current_reaction_count = count_reactions_for_post(
        &state.board_reaction_by_post_actor_emoji_partition,
        &rtx,
        normalized_post_id,
    )?;
    drop(rtx);

    let new_reaction_count = if had_existing_reaction {
        current_reaction_count.saturating_sub(1)
    } else {
        current_reaction_count.saturating_add(1)
    };

    let mut wtx = state.tx_keyspace.write_tx()?;
    if had_existing_reaction {
        state.board_reaction_by_post_actor_emoji_partition.remove_wtx(
            &mut wtx,
            normalized_post_id,
            normalized_actor_address,
            normalized_emoji,
        );
    } else {
        state.board_reaction_by_post_actor_emoji_partition.insert_wtx(
            &mut wtx,
            normalized_post_id,
            normalized_actor_address,
            normalized_emoji,
        );
    }
    update_post_reaction_count(state, &mut wtx, normalized_post_id, new_reaction_count)?;
    wtx.commit()?
        .map_err(|_| anyhow::anyhow!("board reaction write conflict"))?;
    Ok(())
}

fn submit_report_record(
    state: &BoardApi,
    post_id: &str,
    request: &BoardCreateReportRequest,
) -> anyhow::Result<BoardReportMutationResponse> {
    validate_create_report_request(request, &state.context)?;

    let normalized_post_id = post_id.trim();
    let normalized_actor_address = request.actor_address.trim();

    let rtx = state.tx_keyspace.read_tx();
    let mut post = load_post_response_from_rtx(&rtx, state, normalized_post_id)?;
    let had_existing_report = state
        .board_report_by_post_actor_partition
        .get_rtx(&rtx, normalized_post_id, normalized_actor_address)?
        .is_some();
    let current_report_count = count_reports_for_post(
        &state.board_report_by_post_actor_partition,
        &rtx,
        normalized_post_id,
    )?;
    drop(rtx);

    let reason = normalized_optional(&Some(request.reason.clone())).unwrap_or_else(|| "user_report".to_string());
    let created_at = parse_requested_created_at(&request.created_at)?;
    let stored_record = StoredBoardReportRecord {
        actor_address: normalized_actor_address.to_string(),
        reason,
        created_at: timestamp_string(created_at)?,
        client_generated_id: request.client_generated_id.trim().to_string(),
    };
    let json_bytes = serde_json::to_vec(&stored_record).context("serialize board report")?;

    let mut wtx = state.tx_keyspace.write_tx()?;
    state.board_report_by_post_actor_partition.insert_wtx(
        &mut wtx,
        normalized_post_id,
        normalized_actor_address,
        &json_bytes,
    );

    let report_count = if had_existing_report {
        current_report_count
    } else {
        current_report_count.saturating_add(1)
    };
    post.moderation_state = if report_count > 0 {
        "reported".to_string()
    } else {
        "none".to_string()
    };
    let _ = write_post_response_with_touch(state, &mut wtx, &post, true)?;
    wtx.commit()?
        .map_err(|_| anyhow::anyhow!("board report write conflict"))?;

    Ok(BoardReportMutationResponse {
        post_id: normalized_post_id.to_string(),
        actor_address: normalized_actor_address.to_string(),
        report_count,
        moderation_state: post.moderation_state,
        server_time: timestamp_string(OffsetDateTime::now_utc())?,
    })
}

fn apply_follow_state(
    state: &BoardApi,
    path_target_address: &str,
    request: &BoardCreateFollowRequest,
) -> anyhow::Result<BoardFollowMutationResponse> {
    validate_create_follow_request(request, &state.context, path_target_address)?;

    let normalized_actor_address = request.actor_address.trim().to_lowercase();
    let normalized_target_address = path_target_address.trim().to_lowercase();

    let actor = BoardAuthorResponse {
        address: normalized_actor_address.clone(),
        display_name: normalized_or_fallback(&request.actor_display_name, normalized_actor_address.as_str()),
        avatar_url: normalized_optional(&request.actor_avatar_url),
        avatar_file_id: normalized_optional(&request.actor_avatar_file_id),
        avatar_file_extension: normalized_optional(&request.actor_avatar_file_extension),
    };
    let target = BoardAuthorResponse {
        address: normalized_target_address.clone(),
        display_name: normalized_or_fallback(&request.target_display_name, normalized_target_address.as_str()),
        avatar_url: normalized_optional(&request.target_avatar_url),
        avatar_file_id: normalized_optional(&request.target_avatar_file_id),
        avatar_file_extension: normalized_optional(&request.target_avatar_file_extension),
    };
    let created_at = parse_requested_created_at(&request.created_at)?;
    let created_at_string = timestamp_string(created_at)?;
    let record = StoredBoardFollowRecord {
        actor,
        target,
        created_at: created_at_string,
    };
    let record_bytes = serde_json::to_vec(&record).context("serialize board follow record")?;

    let mut wtx = state.tx_keyspace.write_tx()?;
    if request.follow {
        state.board_follow_by_follower_target_partition.insert_wtx(
            &mut wtx,
            normalized_actor_address.as_str(),
            normalized_target_address.as_str(),
            &record_bytes,
        );
        state.board_follow_by_target_follower_partition.insert_wtx(
            &mut wtx,
            normalized_target_address.as_str(),
            normalized_actor_address.as_str(),
            &record_bytes,
        );
    } else {
        state.board_follow_by_follower_target_partition.remove_wtx(
            &mut wtx,
            normalized_actor_address.as_str(),
            normalized_target_address.as_str(),
        );
        state.board_follow_by_target_follower_partition.remove_wtx(
            &mut wtx,
            normalized_target_address.as_str(),
            normalized_actor_address.as_str(),
        );
    }
    wtx.commit()?
        .map_err(|_| anyhow::anyhow!("board follow write conflict"))?;

    let connections =
        build_profile_connections_response(state, normalized_target_address.as_str(), Some(normalized_actor_address.as_str()))?;

    Ok(BoardFollowMutationResponse {
        target_address: normalized_target_address,
        actor_address: normalized_actor_address,
        is_following: connections.viewer_follows_author,
        following_count: connections.following_count,
        follower_count: connections.follower_count,
        server_time: connections.server_time,
    })
}

fn build_profile_connections_response(
    state: &BoardApi,
    address: &str,
    viewer_address: Option<&str>,
) -> anyhow::Result<BoardProfileConnectionsResponse> {
    validate_board_actor_address("address", address)?;
    let normalized_address = address.trim().to_lowercase();
    let normalized_viewer_address = viewer_address
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_lowercase());

    let rtx = state.tx_keyspace.read_tx();

    let following = state
        .board_follow_by_follower_target_partition
        .get_by_follower(&rtx, normalized_address.as_str())?
        .into_iter()
        .filter_map(|(_key, value)| {
            serde_json::from_slice::<StoredBoardFollowRecord>(value.as_ref())
                .ok()
                .map(|record| record.target)
        })
        .collect::<Vec<_>>();

    let followers = state
        .board_follow_by_target_follower_partition
        .get_by_target(&rtx, normalized_address.as_str())?
        .into_iter()
        .filter_map(|(_key, value)| {
            serde_json::from_slice::<StoredBoardFollowRecord>(value.as_ref())
                .ok()
                .map(|record| record.actor)
        })
        .collect::<Vec<_>>();

    let viewer_follows_author = normalized_viewer_address
        .as_deref()
        .filter(|viewer| *viewer != normalized_address)
        .map(|viewer| {
            state
                .board_follow_by_follower_target_partition
                .contains_rtx(&rtx, viewer, normalized_address.as_str())
        })
        .transpose()?
        .unwrap_or(false);

    Ok(BoardProfileConnectionsResponse {
        address: normalized_address,
        following_count: i32::try_from(following.len()).unwrap_or(i32::MAX),
        follower_count: i32::try_from(followers.len()).unwrap_or(i32::MAX),
        following,
        followers,
        viewer_follows_author,
        server_time: timestamp_string(OffsetDateTime::now_utc())?,
    })
}

fn build_post_detail_response(
    state: &BoardApi,
    post_id: &str,
    viewer_address: Option<&str>,
) -> anyhow::Result<BoardPostDetailResponse> {
    let rtx = state.tx_keyspace.read_tx();
    let post = load_post_response_from_rtx(&rtx, state, post_id)?;
    let post_uuid = Uuid::parse_str(post.id.trim()).context("board post id is not a valid UUID")?;
    let normalized_viewer_address = viewer_address
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_lowercase());

    let mut replies = Vec::new();
    for reply_key in state
        .board_reply_by_parent_created_at_partition
        .get_by_parent_post_id(&rtx, post_uuid.as_bytes())
    {
        let reply_key = reply_key?;
        let reply_id = Uuid::from_bytes(reply_key.reply_uuid).to_string();
        if let Some(reply_json) = state.board_post_by_id_partition.get_rtx(&rtx, &reply_id)? {
            let reply: BoardPostResponse = serde_json::from_slice(reply_json.as_ref())
                .context("decode board reply from board_post_by_id")?;
            replies.push(reply);
        }
    }

    let reactions = build_reaction_summary(
        &state.board_reaction_by_post_actor_emoji_partition,
        &rtx,
        post.id.as_str(),
        normalized_viewer_address.as_deref(),
    )?;

    Ok(BoardPostDetailResponse {
        post,
        replies,
        reactions,
        server_time: timestamp_string(OffsetDateTime::now_utc())?,
    })
}

fn build_reaction_summary(
    partition: &BoardReactionByPostActorEmojiPartition,
    rtx: &fjall::ReadTransaction,
    post_id: &str,
    viewer_address: Option<&str>,
) -> anyhow::Result<Vec<BoardReactionSummaryResponse>> {
    let mut counters: HashMap<String, (i32, bool)> = HashMap::new();
    for key_bytes in partition.get_by_post_id(rtx, post_id)? {
        let key = std::str::from_utf8(key_bytes.as_ref()).context("decode board reaction key")?;
        let mut segments = key.splitn(3, '|');
        let _ = segments.next();
        let actor_address = segments.next().unwrap_or_default().trim().to_lowercase();
        let emoji = segments.next().unwrap_or_default().trim().to_string();
        if emoji.is_empty() {
            continue;
        }
        let bucket = counters.entry(emoji).or_insert((0, false));
        bucket.0 = bucket.0.saturating_add(1);
        if viewer_address.is_some_and(|viewer| viewer == actor_address) {
            bucket.1 = true;
        }
    }

    let mut summary = counters
        .into_iter()
        .map(|(emoji, (count, includes_current_user))| BoardReactionSummaryResponse {
            emoji,
            count,
            includes_current_user,
        })
        .collect::<Vec<_>>();

    summary.sort_by(|lhs, rhs| {
        rhs.count
            .cmp(&lhs.count)
            .then_with(|| lhs.emoji.cmp(&rhs.emoji))
    });
    Ok(summary)
}

fn build_feed_response(
    state: &BoardApi,
    limit: usize,
    cursor_ms: Option<u64>,
    if_none_match_revision: Option<String>,
) -> anyhow::Result<BoardFeedLoadResult> {
    let rtx = state.tx_keyspace.read_tx();
    let mut items = Vec::with_capacity(limit);

    for entry in state.board_post_by_created_at_partition.iter_all(&rtx).rev() {
        let (key, value) = entry?;
        let created_at_ms = key.created_at_ms.get();
        if let Some(cursor_ms) = cursor_ms
            && created_at_ms >= cursor_ms
        {
            continue;
        }

        let post: BoardPostResponse =
            serde_json::from_slice(value.as_ref()).context("decode board post from feed")?;
        items.push(post);

        if items.len() >= limit {
            break;
        }
    }

    let next_cursor = items.last().and_then(|post| {
        parse_timestamp_ms(&post.created_at)
            .ok()
            .map(|value| value.to_string())
    });

    let mut response = BoardFeedResponse {
        items,
        next_cursor,
        server_time: timestamp_string(OffsetDateTime::now_utc())?,
        feed_revision: None,
        page_digest: None,
        supports_changes_since_revision: true,
    };
    apply_feed_metadata(&mut response)?;

    let revision = feed_revision_value(&response)?;
    if if_none_match_revision
        .as_deref()
        .is_some_and(|candidate| candidate == revision)
    {
        return Ok(BoardFeedLoadResult::NotModified { revision });
    }

    Ok(BoardFeedLoadResult::Feed(response))
}

fn build_feed_changes_response(
    state: &BoardApi,
    limit: usize,
    since_revision: &str,
) -> anyhow::Result<BoardFeedChangesLoadResult> {
    let current_feed = match build_feed_response(state, limit, None, None)? {
        BoardFeedLoadResult::NotModified { revision: _ } => unreachable!("not modified without conditional request"),
        BoardFeedLoadResult::Feed(feed) => feed,
    };

    let target_revision = feed_revision_value(&current_feed)?;
    if normalize_revision_value(since_revision).as_deref() == Some(target_revision.as_str()) {
        return Ok(BoardFeedChangesLoadResult::NotModified {
            revision: target_revision,
        });
    }

    let base_cutoff_ms = match parse_feed_revision_cutoff_ms(since_revision) {
        Some(value) => value,
        None => {
            return Ok(BoardFeedChangesLoadResult::Changes(BoardFeedChangesResponse {
                base_revision: since_revision.to_string(),
                target_revision,
                next_cursor: current_feed.next_cursor.clone(),
                server_time: current_feed.server_time.clone(),
                requires_full_reload: true,
                changes: Vec::new(),
            }));
        }
    };

    let mut changes = Vec::new();
    for post in &current_feed.items {
        let updated_at_ms = board_post_updated_at_ms(post).unwrap_or_default();
        if updated_at_ms > base_cutoff_ms {
            changes.push(BoardFeedChangeResponse {
                operation: "upsert".to_string(),
                post_id: post.id.clone(),
                post: Some(post.clone()),
            });
        }
    }

    if changes.is_empty() {
        return Ok(BoardFeedChangesLoadResult::Changes(BoardFeedChangesResponse {
            base_revision: since_revision.to_string(),
            target_revision,
            next_cursor: current_feed.next_cursor.clone(),
            server_time: current_feed.server_time.clone(),
            requires_full_reload: true,
            changes,
        }));
    }

    Ok(BoardFeedChangesLoadResult::Changes(BoardFeedChangesResponse {
        base_revision: since_revision.to_string(),
        target_revision,
        next_cursor: current_feed.next_cursor.clone(),
        server_time: current_feed.server_time.clone(),
        requires_full_reload: false,
        changes,
    }))
}

fn apply_feed_metadata(feed: &mut BoardFeedResponse) -> anyhow::Result<()> {
    let page_digest = board_feed_page_digest(feed.items.as_slice(), feed.next_cursor.as_deref())?;
    let max_updated_at_ms = feed
        .items
        .iter()
        .map(board_post_updated_at_ms)
        .collect::<anyhow::Result<Vec<_>>>()?
        .into_iter()
        .max()
        .unwrap_or_default();

    feed.page_digest = Some(page_digest.clone());
    feed.feed_revision = Some(format!("pulse-feed-v1-latest-{max_updated_at_ms}-{page_digest}"));
    Ok(())
}

fn feed_revision_value(feed: &BoardFeedResponse) -> anyhow::Result<String> {
    feed.feed_revision
        .clone()
        .with_context(|| "feed revision missing".to_string())
}

fn board_feed_page_digest(items: &[BoardPostResponse], next_cursor: Option<&str>) -> anyhow::Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(b"pulse-feed-page-v1");
    if let Some(next_cursor) = next_cursor {
        hasher.update(next_cursor.as_bytes());
    }

    for post in items {
        hasher.update(post.id.as_bytes());
        hasher.update(b"|");
        hasher.update(board_post_revision_value(post)?.as_bytes());
        hasher.update(b"|");
    }

    Ok(hex_string(&hasher.finalize()))
}

fn board_post_revision_value(post: &BoardPostResponse) -> anyhow::Result<String> {
    if let Some(revision) = post
        .revision_token
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return Ok(revision.to_string());
    }

    let updated_at = post
        .updated_at
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(post.created_at.as_str());
    let updated_at_ms = parse_timestamp_ms(updated_at)?;

    let mut clone = post.clone();
    clone.revision_token = None;
    let digest = Sha256::digest(serde_json::to_vec(&clone).context("encode board post fallback revision")?);
    Ok(format!(
        "post-v1-{updated_at_ms}-{}",
        hex_string(digest.as_slice())
    ))
}

fn materialize_post_response_for_storage(
    response: &BoardPostResponse,
    touch_updated_at: bool,
) -> anyhow::Result<BoardPostResponse> {
    let mut stored = response.clone();
    let updated_at = if touch_updated_at {
        timestamp_string(OffsetDateTime::now_utc())?
    } else {
        stored
            .updated_at
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| stored.created_at.clone())
    };

    stored.updated_at = Some(updated_at.clone());
    stored.revision_token = None;

    let updated_at_ms = parse_timestamp_ms(updated_at.as_str())?;
    let payload_bytes = serde_json::to_vec(&stored).context("encode board post revision payload")?;
    let digest = Sha256::digest(payload_bytes);
    stored.revision_token = Some(format!(
        "post-v1-{updated_at_ms}-{}",
        hex_string(digest.as_slice())
    ));
    Ok(stored)
}

fn board_post_updated_at_ms(post: &BoardPostResponse) -> anyhow::Result<u64> {
    let updated_at = post
        .updated_at
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(post.created_at.as_str());
    parse_timestamp_ms(updated_at)
}

fn normalize_revision_value(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    let trimmed = trimmed
        .strip_prefix("W/")
        .or_else(|| trimmed.strip_prefix("w/"))
        .unwrap_or(trimmed)
        .trim();
    let trimmed = trimmed.trim_matches('"').trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn normalized_revision_value_from_headers(headers: &HeaderMap) -> Option<String> {
    headers
        .get("if-none-match")
        .and_then(|value| value.to_str().ok())
        .and_then(normalize_revision_value)
}

fn parse_feed_revision_cutoff_ms(revision: &str) -> Option<u64> {
    let normalized = normalize_revision_value(revision)?;
    let mut segments = normalized.rsplitn(2, '-');
    let _digest = segments.next()?;
    let prefix = segments.next()?;
    let cutoff_ms = prefix.rsplit('-').next()?;
    cutoff_ms.parse::<u64>().ok()
}

fn feed_transport_headers(revision: &str, supports_changes_since_revision: bool) -> anyhow::Result<HeaderMap> {
    let mut headers = HeaderMap::new();
    headers.insert(
        "etag",
        HeaderValue::from_str(revision).context("encode Pulse feed revision header")?,
    );
    headers.insert(
        "x-kbeam-feed-changes",
        HeaderValue::from_static(if supports_changes_since_revision { "true" } else { "false" }),
    );
    Ok(headers)
}

fn count_reports_for_post(
    partition: &BoardReportByPostActorPartition,
    rtx: &fjall::ReadTransaction,
    post_id: &str,
) -> anyhow::Result<i32> {
    let reports = partition.get_by_post_id(rtx, post_id)?;
    Ok(i32::try_from(reports.len()).unwrap_or(i32::MAX))
}

fn count_reactions_for_post(
    partition: &BoardReactionByPostActorEmojiPartition,
    rtx: &fjall::ReadTransaction,
    post_id: &str,
) -> anyhow::Result<i32> {
    let mut total = 0i32;
    for _ in partition.get_by_post_id(rtx, post_id)? {
        total = total.saturating_add(1);
    }
    Ok(total)
}

fn load_post_response_from_rtx(
    rtx: &fjall::ReadTransaction,
    state: &BoardApi,
    post_id: &str,
) -> anyhow::Result<BoardPostResponse> {
    let normalized_post_id = post_id.trim();
    let post_json = state
        .board_post_by_id_partition
        .get_rtx(rtx, normalized_post_id)?
        .with_context(|| format!("board post {normalized_post_id} not found"))?;
    serde_json::from_slice(post_json.as_ref()).context("decode board post response")
}

fn load_post_response(state: &BoardApi, post_id: &str) -> anyhow::Result<BoardPostResponse> {
    let rtx = state.tx_keyspace.read_tx();
    load_post_response_from_rtx(&rtx, state, post_id)
}

fn build_pulse_reply_push_event(
    parent_post: &BoardPostResponse,
    reply_post: &BoardPostResponse,
) -> Option<PulseReplyPushEvent> {
    let parent_author_address = parent_post.author.address.trim();
    let reply_author_address = reply_post.author.address.trim();
    if parent_author_address.is_empty()
        || reply_author_address.is_empty()
        || parent_author_address.eq_ignore_ascii_case(reply_author_address)
    {
        return None;
    }

    Some(PulseReplyPushEvent {
        reply_id: reply_post.id.clone(),
        post_id: parent_post.id.clone(),
        parent_author_address: parent_author_address.to_string(),
        actor_address: reply_author_address.to_string(),
        actor_display_name: reply_post.author.display_name.clone(),
        actor_avatar_url: reply_post.author.avatar_url.clone(),
        timestamp: parse_timestamp_ms(&reply_post.created_at).unwrap_or_default(),
    })
}

fn ensure_post_exists(
    rtx: &fjall::ReadTransaction,
    state: &BoardApi,
    post_id: &str,
) -> anyhow::Result<()> {
    let normalized_post_id = post_id.trim();
    if state
        .board_post_by_id_partition
        .get_rtx(rtx, normalized_post_id)?
        .is_some()
    {
        Ok(())
    } else {
        bail!("board post {normalized_post_id} not found")
    }
}

fn write_post_response_with_touch(
    state: &BoardApi,
    wtx: &mut fjall::WriteTransaction,
    response: &BoardPostResponse,
    touch_updated_at: bool,
) -> anyhow::Result<BoardPostResponse> {
    let stored_response = materialize_post_response_for_storage(response, touch_updated_at)?;
    let json_bytes = serde_json::to_vec(&stored_response).context("serialize board post response")?;
    state
        .board_post_by_id_partition
        .insert_wtx(wtx, stored_response.id.as_str(), &json_bytes);

    if stored_response.reply_to_post_id.is_none() {
        let post_uuid = Uuid::parse_str(stored_response.id.trim()).context("board post id must be a UUID")?;
        state.board_post_by_created_at_partition.insert_wtx(
            wtx,
            &BoardPostByCreatedAtKey {
                created_at_ms: U64::new(parse_timestamp_ms(&stored_response.created_at)?),
                post_uuid: *post_uuid.as_bytes(),
            },
            &json_bytes,
        );
    }

    Ok(stored_response)
}

fn update_post_reply_count(
    state: &BoardApi,
    wtx: &mut fjall::WriteTransaction,
    post_id: &str,
    delta: i32,
) -> anyhow::Result<()> {
    let rtx = state.tx_keyspace.read_tx();
    let mut post = load_post_response_from_rtx(&rtx, state, post_id)?;
    drop(rtx);

    post.reply_count = post.reply_count.saturating_add(delta);
    let _ = write_post_response_with_touch(state, wtx, &post, true)?;
    Ok(())
}

fn update_post_reaction_count(
    state: &BoardApi,
    wtx: &mut fjall::WriteTransaction,
    post_id: &str,
    new_count: i32,
) -> anyhow::Result<()> {
    let rtx = state.tx_keyspace.read_tx();
    let mut post = load_post_response_from_rtx(&rtx, state, post_id)?;
    drop(rtx);

    post.reaction_count = new_count.max(0);
    let _ = write_post_response_with_touch(state, wtx, &post, true)?;
    Ok(())
}

fn validate_create_post_request(
    request: &BoardCreatePostRequest,
    context: &IndexerContext,
    forced_reply_to_post_id: Option<&str>,
) -> anyhow::Result<()> {
    validate_board_actor_address("authorAddress", request.author_address.as_str())?;

    if request.signature.trim().is_empty() {
        bail!("signature is required");
    }

    validate_network(context, request.network.as_str())?;

    let has_text = !request.content_text.trim().is_empty();
    let has_link = normalized_optional(&request.primary_link_url).is_some();
    let has_attachments = !request.attachments.is_empty();
    if !has_text && !has_link && !has_attachments {
        bail!("post must include text, a link, or an attachment");
    }

    if request.client_generated_id.trim().is_empty() {
        bail!("clientGeneratedId is required");
    }

    if request.content_text.chars().count() > 10_000 {
        bail!("contentText is too long");
    }

    if request.attachments.len() > 8 {
        bail!("too many attachments");
    }

    let request_reply_to_post_id = normalized_optional(&request.reply_to_post_id);
    match (
        forced_reply_to_post_id.map(str::trim).filter(|value| !value.is_empty()),
        request_reply_to_post_id.as_deref(),
    ) {
        (Some(forced_parent_id), Some(request_parent_id)) if forced_parent_id != request_parent_id => {
            bail!("replyToPostId does not match the target board post")
        }
        (None, Some(_)) => bail!("use /board/posts/:post_id/replies for replies"),
        _ => {}
    }

    let signable_payload = BoardCreatePostSignablePayload {
        author_address: request.author_address.clone(),
        author_display_name: request.author_display_name.clone(),
        content_text: request.content_text.clone(),
        attachments: request.attachments.clone(),
        reply_to_post_id: request.reply_to_post_id.clone(),
        primary_link_url: request.primary_link_url.clone(),
        created_at: request.created_at.clone(),
        client_generated_id: request.client_generated_id.clone(),
        network: request.network.clone(),
    };
    verify_board_signature(
        request.author_address.as_str(),
        canonical_json_bytes(&signable_payload)?.as_slice(),
        request.signature.as_str(),
    )?;
    Ok(())
}

fn validate_create_reaction_request(
    request: &BoardCreateReactionRequest,
    context: &IndexerContext,
) -> anyhow::Result<()> {
    validate_board_actor_address("actorAddress", request.actor_address.as_str())?;

    if request.signature.trim().is_empty() {
        bail!("signature is required");
    }

    if request.client_generated_id.trim().is_empty() {
        bail!("clientGeneratedId is required");
    }

    let emoji = request.emoji.trim();
    if emoji.is_empty() {
        bail!("emoji is required");
    }
    if emoji.chars().count() > 16 {
        bail!("emoji is too long");
    }

    validate_network(context, request.network.as_str())?;
    let signable_payload = BoardCreateReactionSignablePayload {
        actor_address: request.actor_address.clone(),
        emoji: request.emoji.clone(),
        created_at: request.created_at.clone(),
        client_generated_id: request.client_generated_id.clone(),
        network: request.network.clone(),
    };
    verify_board_signature(
        request.actor_address.as_str(),
        canonical_json_bytes(&signable_payload)?.as_slice(),
        request.signature.as_str(),
    )?;
    Ok(())
}

fn validate_create_follow_request(
    request: &BoardCreateFollowRequest,
    context: &IndexerContext,
    path_target_address: &str,
) -> anyhow::Result<()> {
    validate_board_actor_address("actorAddress", request.actor_address.as_str())?;
    validate_board_actor_address("targetAddress", request.target_address.as_str())?;
    validate_board_actor_address("pathTargetAddress", path_target_address)?;

    let normalized_target = request.target_address.trim().to_lowercase();
    let normalized_path_target = path_target_address.trim().to_lowercase();
    if normalized_target != normalized_path_target {
        bail!("targetAddress does not match the target board profile");
    }

    let normalized_actor = request.actor_address.trim().to_lowercase();
    if normalized_actor == normalized_target {
        bail!("you cannot follow yourself");
    }

    if request.signature.trim().is_empty() {
        bail!("signature is required");
    }
    if request.client_generated_id.trim().is_empty() {
        bail!("clientGeneratedId is required");
    }

    validate_network(context, request.network.as_str())?;
    let signable_payload = BoardCreateFollowSignablePayload {
        actor_address: request.actor_address.clone(),
        actor_display_name: request.actor_display_name.clone(),
        actor_avatar_url: request.actor_avatar_url.clone(),
        actor_avatar_file_id: request.actor_avatar_file_id.clone(),
        actor_avatar_file_extension: request.actor_avatar_file_extension.clone(),
        target_address: request.target_address.clone(),
        target_display_name: request.target_display_name.clone(),
        target_avatar_url: request.target_avatar_url.clone(),
        target_avatar_file_id: request.target_avatar_file_id.clone(),
        target_avatar_file_extension: request.target_avatar_file_extension.clone(),
        follow: request.follow,
        created_at: request.created_at.clone(),
        client_generated_id: request.client_generated_id.clone(),
        network: request.network.clone(),
    };
    verify_board_signature(
        request.actor_address.as_str(),
        canonical_json_bytes(&signable_payload)?.as_slice(),
        request.signature.as_str(),
    )?;
    Ok(())
}

fn validate_create_report_request(
    request: &BoardCreateReportRequest,
    context: &IndexerContext,
) -> anyhow::Result<()> {
    validate_board_actor_address("actorAddress", request.actor_address.as_str())?;

    if request.signature.trim().is_empty() {
        bail!("signature is required");
    }

    if request.client_generated_id.trim().is_empty() {
        bail!("clientGeneratedId is required");
    }

    let reason = request.reason.trim();
    if reason.chars().count() > 120 {
        bail!("reason is too long");
    }

    validate_network(context, request.network.as_str())?;
    let signable_payload = BoardCreateReportSignablePayload {
        actor_address: request.actor_address.clone(),
        reason: request.reason.clone(),
        created_at: request.created_at.clone(),
        client_generated_id: request.client_generated_id.clone(),
        network: request.network.clone(),
    };
    verify_board_signature(
        request.actor_address.as_str(),
        canonical_json_bytes(&signable_payload)?.as_slice(),
        request.signature.as_str(),
    )?;
    Ok(())
}

fn validate_board_actor_address(field_name: &str, address: &str) -> anyhow::Result<()> {
    let address_text = address.trim();
    if address_text.is_empty() {
        bail!("{field_name} is required");
    }
    let rpc_address =
        RpcAddress::try_from(address_text).with_context(|| format!("{field_name} is not a valid Kaspa address"))?;
    let _address_payload =
        AddressPayload::try_from(&rpc_address).with_context(|| format!("{field_name} payload is invalid"))?;
    Ok(())
}

fn verify_board_signature(address: &str, message_bytes: &[u8], signature_hex: &str) -> anyhow::Result<()> {
    let address_text = address.trim();
    let rpc_address =
        RpcAddress::try_from(address_text).with_context(|| format!("{address_text} is not a valid Kaspa address"))?;
    let address_payload =
        AddressPayload::try_from(&rpc_address).with_context(|| format!("{address_text} payload is invalid"))?;

    let version = Version::try_from(u8::MAX - address_payload.inverse_version)
        .context("unsupported Kaspa address version for Pulse signature verification")?;
    if version != Version::PubKey {
        bail!("Pulse signature verification currently requires a Schnorr public-key address");
    }

    let pubkey = XOnlyPublicKey::from_slice(&address_payload.payload[..32])
        .context("failed to parse x-only public key from Kaspa address")?;

    let signature_bytes = decode_fixed_hex::<64>(signature_hex.trim(), "signature")?;
    let signature = schnorr::Signature::from_slice(&signature_bytes)
        .context("failed to parse Schnorr signature")?;
    let serialized_signature = signature.serialize();

    let secp = Secp256k1::verification_only();
    let verified = unsafe {
        ffi::secp256k1_schnorrsig_verify(
            secp.ctx().as_ptr(),
            serialized_signature.as_ptr(),
            message_bytes.as_ptr(),
            message_bytes.len(),
            pubkey.as_c_ptr(),
        )
    };

    if verified == 1 {
        Ok(())
    } else {
        bail!("signature verification failed")
    }
}

fn canonical_json_bytes<T: Serialize>(value: &T) -> anyhow::Result<Vec<u8>> {
    let value = serde_json::to_value(value).context("encode Pulse signing payload")?;
    let value = recursively_sorted_json(value);
    serde_json::to_vec(&value).context("encode canonical Pulse signing payload")
}

fn decode_fixed_hex<const N: usize>(value: &str, label: &str) -> anyhow::Result<[u8; N]> {
    let hex = value.trim();
    if hex.len() != N * 2 {
        bail!("{label} must be {} hex characters", N * 2);
    }
    let mut bytes = [0u8; N];
    faster_hex::hex_decode(hex.as_bytes(), &mut bytes).with_context(|| format!("decode {label} hex"))?;
    Ok(bytes)
}

fn recursively_sorted_json(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut sorted = serde_json::Map::with_capacity(map.len());
            let mut entries = map.into_iter().collect::<Vec<_>>();
            entries.sort_by(|lhs, rhs| lhs.0.cmp(&rhs.0));
            for (key, value) in entries {
                sorted.insert(key, recursively_sorted_json(value));
            }
            serde_json::Value::Object(sorted)
        }
        serde_json::Value::Array(items) => serde_json::Value::Array(
            items
                .into_iter()
                .map(recursively_sorted_json)
                .collect::<Vec<_>>(),
        ),
        other => other,
    }
}

fn validate_network(context: &IndexerContext, network_text: &str) -> anyhow::Result<()> {
    let network = network_text.trim().to_lowercase();
    let expected_network = match context.network_type {
        kaspa_wrpc_client::prelude::NetworkType::Mainnet => "mainnet",
        _ => "testnet",
    };
    if network != expected_network {
        bail!("network mismatch: expected {expected_network}, got {}", network_text.trim());
    }
    Ok(())
}

fn status_for_board_error(error: &anyhow::Error, allow_conflict: bool) -> (StatusCode, Json<BoardErrorResponse>) {
    let text = error.to_string();
    let lowered = text.to_lowercase();
    let status = if allow_conflict && lowered.contains("write conflict") {
        StatusCode::CONFLICT
    } else if lowered.contains("not found") {
        StatusCode::NOT_FOUND
    } else {
        StatusCode::BAD_REQUEST
    };
    error_response_message(status, error.to_string())
}

fn error_response(status: StatusCode, error: anyhow::Error) -> (StatusCode, Json<BoardErrorResponse>) {
    error_response_message(status, error.to_string())
}

fn error_response_message(
    status: StatusCode,
    error_message: String,
) -> (StatusCode, Json<BoardErrorResponse>) {
    (
        status,
        Json(BoardErrorResponse {
            error: error_message,
        }),
    )
}

fn task_error_response(join_error: tokio::task::JoinError) -> (StatusCode, Json<BoardErrorResponse>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(BoardErrorResponse {
            error: format!("Task error: {join_error}"),
        }),
    )
}

fn normalized_optional(value: &Option<String>) -> Option<String> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn normalized_or_fallback(value: &str, fallback: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        fallback.trim().to_string()
    } else {
        trimmed.to_string()
    }
}

fn parse_requested_created_at(value: &str) -> anyhow::Result<OffsetDateTime> {
    if let Ok(parsed) = OffsetDateTime::parse(value.trim(), &Rfc3339) {
        return Ok(parsed);
    }
    Ok(OffsetDateTime::now_utc())
}

fn parse_timestamp_ms(value: &str) -> anyhow::Result<u64> {
    let timestamp = OffsetDateTime::parse(value.trim(), &Rfc3339)
        .context("invalid RFC3339 timestamp")?;
    let millis = timestamp.unix_timestamp_nanos() / 1_000_000;
    Ok(u64::try_from(millis).context("timestamp must be >= unix epoch")?)
}

fn timestamp_string(value: OffsetDateTime) -> anyhow::Result<String> {
    value
        .format(&Rfc3339)
        .context("format RFC3339 timestamp")
}

fn build_link_preview(primary_link_url: Option<&str>) -> Option<BoardLinkPreviewResponse> {
    let url = primary_link_url?.trim();
    if url.is_empty() {
        return None;
    }

    let parsed = url::Url::parse(url).ok();
    let host = parsed
        .as_ref()
        .and_then(|url| url.host_str())
        .map(str::to_string);
    let subtitle = parsed
        .as_ref()
        .map(|url| display_url(url.as_str()))
        .unwrap_or_else(|| Cow::Borrowed(url));

    Some(BoardLinkPreviewResponse {
        url: url.to_string(),
        title: host.clone(),
        subtitle: Some(subtitle.into_owned()),
        image_url: None,
    })
}

fn display_url(url: &str) -> Cow<'_, str> {
    if let Some(stripped) = url.strip_prefix("https://") {
        return Cow::Owned(stripped.to_string());
    }
    if let Some(stripped) = url.strip_prefix("http://") {
        return Cow::Owned(stripped.to_string());
    }
    Cow::Borrowed(url)
}

fn hex_string(bytes: &[u8]) -> String {
    let mut output = vec![0u8; bytes.len() * 2];
    faster_hex::hex_encode(bytes, &mut output).expect("hex encode board digest");
    String::from_utf8(output).expect("hex output is valid utf8")
}

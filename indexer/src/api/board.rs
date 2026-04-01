use crate::context::IndexerContext;
use crate::push::{PulseReplyPushEvent, PushService};
use anyhow::{Context, bail};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use indexer_db::messages::board::{
    BoardClientGeneratedIdToPostIdPartition, BoardPostByCreatedAtKey, BoardPostByCreatedAtPartition,
    BoardPostByIdPartition, BoardReactionByPostActorEmojiPartition,
    BoardReplyByParentCreatedAtKey, BoardReplyByParentCreatedAtPartition,
};
use indexer_db::AddressPayload;
use kaspa_rpc_core::RpcAddress;
use serde::{Deserialize, Serialize};
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
            context,
            push_service,
        }
    }

    pub fn router() -> Router<Self> {
        Router::new()
            .route("/feed", get(get_board_feed))
            .route("/posts", post(create_board_post))
            .route("/posts/{post_id}", get(get_board_post_detail))
            .route("/posts/{post_id}/replies", post(create_board_reply))
            .route("/posts/{post_id}/reactions", post(toggle_board_reaction))
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
pub struct BoardPostDetailQuery {
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
}

#[derive(Debug, Serialize, ToSchema)]
pub struct BoardErrorResponse {
    pub error: String,
}

#[utoipa::path(
    get,
    path = "/board/feed",
    params(BoardFeedQuery),
    responses(
        (status = 200, description = "Get board feed", body = BoardFeedResponse),
        (status = 400, description = "Bad request", body = BoardErrorResponse),
        (status = 500, description = "Internal server error", body = BoardErrorResponse)
    )
)]
pub async fn get_board_feed(
    State(state): State<BoardApi>,
    Query(query): Query<BoardFeedQuery>,
) -> impl IntoResponse {
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

    let result = spawn_blocking(move || -> anyhow::Result<BoardFeedResponse> {
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

        Ok(BoardFeedResponse {
            items,
            next_cursor,
            server_time: timestamp_string(OffsetDateTime::now_utc())?,
        })
    })
    .await;

    match result {
        Ok(Ok(feed)) => Ok(Json(feed)),
        Ok(Err(error)) => Err(error_response(StatusCode::INTERNAL_SERVER_ERROR, error)),
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
    };

    let mut wtx = state.tx_keyspace.write_tx()?;
    write_post_response(state, &mut wtx, &response)?;
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

    Ok(response)
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
        preview_text: pulse_reply_preview_text(reply_post),
        timestamp: parse_timestamp_ms(&reply_post.created_at).unwrap_or_default(),
    })
}

fn pulse_reply_preview_text(reply_post: &BoardPostResponse) -> Option<String> {
    let content_text = reply_post.content_text.trim();
    if !content_text.is_empty() {
        return Some(content_text.to_string());
    }
    if !reply_post.attachments.is_empty() {
        return Some("Attachment".to_string());
    }
    if reply_post.primary_link_url.is_some() {
        return Some("Link".to_string());
    }
    None
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

fn write_post_response(
    state: &BoardApi,
    wtx: &mut fjall::WriteTransaction,
    response: &BoardPostResponse,
) -> anyhow::Result<()> {
    let json_bytes = serde_json::to_vec(response).context("serialize board post response")?;
    state
        .board_post_by_id_partition
        .insert_wtx(wtx, response.id.as_str(), &json_bytes);

    if response.reply_to_post_id.is_none() {
        let post_uuid = Uuid::parse_str(response.id.trim()).context("board post id must be a UUID")?;
        state.board_post_by_created_at_partition.insert_wtx(
            wtx,
            &BoardPostByCreatedAtKey {
                created_at_ms: U64::new(parse_timestamp_ms(&response.created_at)?),
                post_uuid: *post_uuid.as_bytes(),
            },
            &json_bytes,
        );
    }

    Ok(())
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
    write_post_response(state, wtx, &post)
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
    write_post_response(state, wtx, &post)
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

    // TODO: verify the Schnorr signature against a server-compatible public identity derivation.
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

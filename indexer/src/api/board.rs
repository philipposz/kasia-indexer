use crate::context::IndexerContext;
use anyhow::{Context, bail};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use indexer_db::messages::board::{
    BoardClientGeneratedIdToPostIdPartition, BoardPostByCreatedAtKey, BoardPostByCreatedAtPartition,
    BoardPostByIdPartition,
};
use indexer_db::AddressPayload;
use kaspa_rpc_core::RpcAddress;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
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
    context: IndexerContext,
}

impl BoardApi {
    pub fn new(
        tx_keyspace: fjall::TxKeyspace,
        board_post_by_id_partition: BoardPostByIdPartition,
        board_post_by_created_at_partition: BoardPostByCreatedAtPartition,
        board_client_generated_id_to_post_id_partition: BoardClientGeneratedIdToPostIdPartition,
        context: IndexerContext,
    ) -> Self {
        Self {
            tx_keyspace,
            board_post_by_id_partition,
            board_post_by_created_at_partition,
            board_client_generated_id_to_post_id_partition,
            context,
        }
    }

    pub fn router() -> Router<Self> {
        Router::new()
            .route("/feed", get(get_board_feed))
            .route("/posts", post(create_board_post))
    }
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct BoardFeedQuery {
    pub mode: Option<String>,
    pub limit: Option<usize>,
    pub cursor: Option<String>,
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
pub struct BoardPostResponse {
    pub id: String,
    pub author: BoardAuthorResponse,
    pub content_text: String,
    pub attachments: Vec<BoardAttachmentPayload>,
    pub primary_link_url: Option<String>,
    pub link_preview: Option<BoardLinkPreviewResponse>,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub reply_count: i32,
    pub reaction_count: i32,
    pub visibility_state: String,
    pub moderation_state: String,
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
        Ok(Err(error)) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(BoardErrorResponse {
                error: error.to_string(),
            }),
        )),
        Err(join_error) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(BoardErrorResponse {
                error: format!("Task error: {join_error}"),
            }),
        )),
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
    let result = spawn_blocking(move || -> anyhow::Result<BoardPostResponse> {
        validate_create_post_request(&request, &state.context)?;

        let rtx = state.tx_keyspace.read_tx();
        if let Some(existing_post_id) = state
            .board_client_generated_id_to_post_id_partition
            .get_rtx(&rtx, request.client_generated_id.trim())?
        {
            let existing_post_id = std::str::from_utf8(existing_post_id.as_ref())
                .context("decode existing board post id")?;
            if let Some(existing_post) = state.board_post_by_id_partition.get_rtx(&rtx, existing_post_id)? {
                let response: BoardPostResponse =
                    serde_json::from_slice(existing_post.as_ref()).context("decode existing board post")?;
                return Ok(response);
            }
        }
        drop(rtx);

        let created_at = parse_requested_created_at(&request.created_at)?;
        let expires_at = created_at + Duration::days(30);
        let post_id = Uuid::new_v4();
        let post_id_string = post_id.to_string();

        let response = BoardPostResponse {
            id: post_id_string.clone(),
            author: BoardAuthorResponse {
                address: request.author_address.trim().to_string(),
                display_name: normalized_or_fallback(
                    &request.author_display_name,
                    &request.author_address,
                ),
                avatar_url: None,
                avatar_file_id: None,
                avatar_file_extension: None,
            },
            content_text: request.content_text.trim().to_string(),
            attachments: request.attachments.clone(),
            primary_link_url: normalized_optional(&request.primary_link_url),
            link_preview: build_link_preview(request.primary_link_url.as_deref()),
            created_at: timestamp_string(created_at)?,
            expires_at: Some(timestamp_string(expires_at)?),
            reply_count: 0,
            reaction_count: 0,
            visibility_state: "visible".to_string(),
            moderation_state: "none".to_string(),
        };

        let json_bytes = serde_json::to_vec(&response).context("serialize board post response")?;

        let mut wtx = state.tx_keyspace.write_tx()?;
        state
            .board_post_by_id_partition
            .insert_wtx(&mut wtx, &post_id_string, &json_bytes);
        state.board_post_by_created_at_partition.insert_wtx(
            &mut wtx,
            &BoardPostByCreatedAtKey {
                created_at_ms: U64::new(parse_timestamp_ms(&response.created_at)?),
                post_uuid: *post_id.as_bytes(),
            },
            &json_bytes,
        );
        state.board_client_generated_id_to_post_id_partition.insert_wtx(
            &mut wtx,
            request.client_generated_id.trim(),
            &post_id_string,
        );
        wtx.commit()?
            .map_err(|_| anyhow::anyhow!("board post write conflict"))?;

        Ok(response)
    })
    .await;

    match result {
        Ok(Ok(response)) => Ok(Json(response)),
        Ok(Err(error)) => {
            let status = if error.to_string().contains("duplicate") {
                StatusCode::CONFLICT
            } else {
                StatusCode::BAD_REQUEST
            };
            Err((
                status,
                Json(BoardErrorResponse {
                    error: error.to_string(),
                }),
            ))
        }
        Err(join_error) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(BoardErrorResponse {
                error: format!("Task error: {join_error}"),
            }),
        )),
    }
}

fn validate_create_post_request(
    request: &BoardCreatePostRequest,
    context: &IndexerContext,
) -> anyhow::Result<()> {
    let address_text = request.author_address.trim();
    if address_text.is_empty() {
        bail!("authorAddress is required");
    }
    let rpc_address =
        RpcAddress::try_from(address_text).context("authorAddress is not a valid Kaspa address")?;
    let _address_payload =
        AddressPayload::try_from(&rpc_address).context("authorAddress payload is invalid")?;

    if request.signature.trim().is_empty() {
        bail!("signature is required");
    }

    let network = request.network.trim().to_lowercase();
    let expected_network = match context.network_type {
        kaspa_wrpc_client::prelude::NetworkType::Mainnet => "mainnet",
        _ => "testnet",
    };
    if network != expected_network {
        bail!("network mismatch: expected {expected_network}, got {}", request.network.trim());
    }

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

    // TODO: verify the Schnorr signature against a server-compatible public identity derivation.
    Ok(())
}

fn normalized_optional(value: &Option<String>) -> Option<String> {
    value.as_deref().map(str::trim).filter(|value| !value.is_empty()).map(str::to_string)
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

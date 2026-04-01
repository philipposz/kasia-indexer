use crate::api::board::BoardApi;
use crate::api::v1::contextual_messages::ContextualMessageApi;
use crate::api::v1::gift::GiftApi;
use crate::api::v1::handshakes::HandshakeApi;
use crate::api::v1::payments::PaymentApi;
use crate::api::v1::push::PushApi;
use crate::api::v1::self_stash::SelfStashApi;
use crate::context::IndexerContext;
use crate::push::PushService;
use axum::extract::State;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use indexer_actors::metrics::{IndexerMetricsSnapshot, SharedMetrics};
use indexer_db::messages::board::{
    BoardClientGeneratedIdToPostIdPartition, BoardPostByCreatedAtPartition, BoardPostByIdPartition,
    BoardReactionByPostActorEmojiPartition, BoardReplyByParentCreatedAtPartition,
};
use indexer_db::messages::contextual_message::{
    ContextualMessageBySenderPartition, TxIdToContextualMessagePartition,
};
use indexer_db::messages::handshake::{
    HandshakeByReceiverPartition, HandshakeBySenderPartition, TxIdToHandshakePartition,
};
use indexer_db::messages::payment::{
    PaymentByReceiverPartition, PaymentBySenderPartition, TxIdToPaymentPartition,
};
use indexer_db::messages::self_stash::{
    SelfStashByOwnerPartition, SelfStashByScopePartition, TxIdToSelfStashPartition,
};
use indexer_db::processing::tx_id_to_acceptance::TxIDToAcceptancePartition;
use std::net::SocketAddr;
use tower_http::cors::CorsLayer;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

pub mod contextual_messages;
pub mod gift;
pub mod handshakes;
pub mod payments;
pub mod push;
pub mod self_stash;

#[derive(OpenApi)]
#[openapi(
    paths(
        handshakes::get_handshakes_by_sender,
        handshakes::get_handshakes_by_receiver,
        contextual_messages::get_contextual_messages_by_sender,
        payments::get_payments_by_sender,
        payments::get_payments_by_receiver,
        gift::create_challenge,
        gift::claim_gift,
        gift::debug_query_devicecheck_bit0,
        gift::debug_update_devicecheck_bit0,
        push::create_challenge,
        push::register_device,
        push::update_device,
        push::unregister_device,
        crate::api::board::get_board_feed,
        crate::api::board::get_board_post_detail,
        crate::api::board::create_board_post,
        crate::api::board::create_board_reply,
        crate::api::board::toggle_board_reaction,
        self_stash::get_self_stash_by_owner,
        self_stash::get_self_stash_by_scope,
        get_metrics,
    ),
    components(
        schemas(handshakes::HandshakeResponse, contextual_messages::ContextualMessageResponse, payments::PaymentResponse, gift::GiftChallengeResponse, gift::GiftClaimRequest, gift::GiftClaimResponse, gift::GiftDeviceCheckDebugQueryRequest, gift::GiftDeviceCheckDebugQueryResponse, gift::GiftDeviceCheckDebugUpdateRequest, gift::GiftDeviceCheckDebugUpdateResponse, gift::GiftErrorResponse, push::PushChallengeResponse, push::PushErrorResponse, push::PushOkResponse, self_stash::SelfStashResponse, crate::api::board::BoardFeedResponse, crate::api::board::BoardPostResponse, crate::api::board::BoardPostDetailResponse, crate::api::board::BoardCreatePostRequest, crate::api::board::BoardCreateReactionRequest, crate::api::board::BoardAuthorResponse, crate::api::board::BoardAttachmentPayload, crate::api::board::BoardLinkPreviewResponse, crate::api::board::BoardReactionSummaryResponse, crate::api::board::BoardErrorResponse, IndexerMetricsSnapshot)
    ),
    tags(
        (name = "Kasia Indexer API", description = "Kasia Indexer API")
    )
)]
pub struct ApiDoc;

#[derive(Clone)]
pub struct Api {
    handshake_api: HandshakeApi,
    contextual_message_api: ContextualMessageApi,
    payment_api: PaymentApi,
    gift_api: GiftApi,
    push_api: PushApi,
    board_api: BoardApi,
    self_stash_api: SelfStashApi,
    metrics: SharedMetrics,
}

impl Api {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tx_keyspace: fjall::TxKeyspace,
        handshake_by_sender_partition: HandshakeBySenderPartition,
        handshake_by_receiver_partition: HandshakeByReceiverPartition,
        contextual_message_by_sender_partition: ContextualMessageBySenderPartition,
        tx_id_to_contextual_message_partition: TxIdToContextualMessagePartition,
        payment_by_sender_partition: PaymentBySenderPartition,
        payment_by_receiver_partition: PaymentByReceiverPartition,
        tx_id_to_acceptance_partition: TxIDToAcceptancePartition,
        tx_id_to_handshake_partition: TxIdToHandshakePartition,
        tx_id_to_payment_partition: TxIdToPaymentPartition,
        self_stash_by_owner_partition: SelfStashByOwnerPartition,
        self_stash_by_scope_partition: SelfStashByScopePartition,
        tx_id_to_self_stash_partition: TxIdToSelfStashPartition,
        board_post_by_id_partition: BoardPostByIdPartition,
        board_post_by_created_at_partition: BoardPostByCreatedAtPartition,
        board_client_generated_id_to_post_id_partition: BoardClientGeneratedIdToPostIdPartition,
        board_reply_by_parent_created_at_partition: BoardReplyByParentCreatedAtPartition,
        board_reaction_by_post_actor_emoji_partition: BoardReactionByPostActorEmojiPartition,
        gift_api: GiftApi,
        push_api: PushApi,
        push_service: PushService,
        metrics: SharedMetrics,
        context: IndexerContext,
    ) -> Self {
        let handshake_api = HandshakeApi::new(
            tx_keyspace.clone(),
            handshake_by_sender_partition,
            handshake_by_receiver_partition,
            tx_id_to_acceptance_partition.clone(),
            tx_id_to_handshake_partition,
            context.clone(),
        );

        let contextual_message_api = ContextualMessageApi::new(
            tx_keyspace.clone(),
            contextual_message_by_sender_partition,
            tx_id_to_acceptance_partition.clone(),
            tx_id_to_contextual_message_partition,
            context.clone(),
        );

        let payment_api = PaymentApi::new(
            tx_keyspace.clone(),
            payment_by_sender_partition,
            payment_by_receiver_partition,
            tx_id_to_payment_partition,
            tx_id_to_acceptance_partition.clone(),
            context.clone(),
        );

        let self_stash_api = SelfStashApi::new(
            tx_keyspace.clone(),
            self_stash_by_owner_partition,
            self_stash_by_scope_partition,
            tx_id_to_acceptance_partition,
            tx_id_to_self_stash_partition,
            context.clone(),
        );

        let board_api = BoardApi::new(
            tx_keyspace,
            board_post_by_id_partition,
            board_post_by_created_at_partition,
            board_client_generated_id_to_post_id_partition,
            board_reply_by_parent_created_at_partition,
            board_reaction_by_post_actor_emoji_partition,
            context,
            Some(push_service),
        );

        Self {
            handshake_api,
            contextual_message_api,
            payment_api,
            gift_api,
            push_api,
            board_api,
            self_stash_api,
            metrics,
        }
    }

    pub async fn serve(
        self,
        bind_address: &str,
        mut shutdown: tokio::sync::mpsc::Receiver<()>,
    ) -> anyhow::Result<()> {
        let addr: SocketAddr = bind_address.parse()?;
        let app = self.router();
        let listener = tokio::net::TcpListener::bind(addr).await?;
        tracing::info!("Starting API server on {}", addr);
        axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
            .with_graceful_shutdown(async move {
                shutdown.recv().await;
            })
            .await?;
        Ok(())
    }

    fn router(&self) -> Router {
        Router::new()
            .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
            .nest(
                "/handshakes",
                HandshakeApi::router().with_state(self.handshake_api.clone()),
            )
            .nest(
                "/contextual-messages",
                ContextualMessageApi::router().with_state(self.contextual_message_api.clone()),
            )
            .nest(
                "/payments",
                PaymentApi::router().with_state(self.payment_api.clone()),
            )
            .nest(
                "/self-stash",
                SelfStashApi::router().with_state(self.self_stash_api.clone()),
            )
            .nest(
                "/v1/gift",
                GiftApi::router().with_state(self.gift_api.clone()),
            )
            .nest(
                "/v1/push",
                PushApi::router().with_state(self.push_api.clone()),
            )
            .nest("/board", BoardApi::router().with_state(self.board_api.clone()))
            .route(
                "/metrics",
                get(get_metrics).with_state(self.metrics.clone()),
            )
            .layer(CorsLayer::permissive())
    }
}

#[utoipa::path(
    get,
    path = "/metrics",
    responses(
        (status = 200, description = "Get system metrics", body = IndexerMetricsSnapshot)
    )
)]
async fn get_metrics(State(metrics): State<SharedMetrics>) -> impl IntoResponse {
    Json(metrics.snapshot())
}

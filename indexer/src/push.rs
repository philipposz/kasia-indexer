use crate::api::to_rpc_address;
use crate::context::IndexerContext;
use anyhow::Context;
use axum::http::StatusCode;
use indexer_actors::block_processor::{PushDispatchEvent, PushMessageType};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use kaspa_rpc_core::RpcNetworkType;
use reqwest::StatusCode as HttpStatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, info, warn};
use utoipa::ToSchema;
use uuid::Uuid;

const PUSH_SUPPRESSED_ALIAS_SUFFIX: &str = "__kbs1";
const PUSH_VISIBLE_ALIAS_SUFFIX: &str = "__kbp1";
const LEGACY_PUSH_SUPPRESSED_ALIAS_SUFFIX: &str = "__silent";
const LEGACY_PUSH_VISIBLE_ALIAS_SUFFIX: &str = "__push";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ContextualAliasPolicy {
    Visible,
    Silent,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ContextualUnknownPolicy {
    Drop,
    Visible,
}

#[derive(Clone)]
pub struct PushService {
    config: PushConfig,
    network: RpcNetworkType,
    registrations_path: PathBuf,
    registrations: Arc<RwLock<HashMap<String, DeviceRegistration>>>,
    challenges: Arc<RwLock<HashMap<String, ChallengeEntry>>>,
    apns_client: Option<Arc<ApnsClient>>,
    fcm_client: Option<Arc<FcmClient>>,
    recent_dispatches: Arc<Mutex<HashMap<String, u64>>>,
    dispatch_dedupe_ttl_ms: u64,
    dispatch_counters: Arc<PushDispatchCounters>,
}

#[derive(Clone, Debug)]
pub struct PushConfig {
    pub push_provider: String,
    pub push_ios_enabled: bool,
    pub push_fcm_enabled: bool,
    pub challenge_ttl_ms: u64,
    pub challenge_skew_ms: u64,
    pub apns_environment: String,
    pub apns_team_id: Option<String>,
    pub apns_key_id: Option<String>,
    pub apns_bundle_id: Option<String>,
    pub apns_key_path: Option<PathBuf>,
    pub apns_inline_payload_limit: usize,
    pub apns_timeout_ms: u64,
    pub fcm_project_id: Option<String>,
    pub fcm_service_account_path: Option<PathBuf>,
    pub fcm_timeout_ms: u64,
}

impl PushConfig {
    pub fn from_env() -> Self {
        Self {
            push_provider: read_env_string("PUSH_PROVIDER").unwrap_or_else(|| "apns".to_string()),
            push_ios_enabled: read_env_bool("PUSH_IOS_ENABLED", true),
            push_fcm_enabled: read_env_bool("PUSH_FCM_ENABLED", false),
            challenge_ttl_ms: read_env_u64("PUSH_CHALLENGE_TTL_MS", 120_000),
            challenge_skew_ms: read_env_u64("PUSH_CHALLENGE_SKEW_MS", 15_000),
            apns_environment: read_env_string("PUSH_APNS_ENVIRONMENT")
                .unwrap_or_else(|| "auto".to_string())
                .trim()
                .to_lowercase(),
            apns_team_id: read_env_string("PUSH_APNS_TEAM_ID"),
            apns_key_id: read_env_string("PUSH_APNS_KEY_ID"),
            apns_bundle_id: read_env_string("PUSH_APNS_BUNDLE_ID"),
            apns_key_path: read_env_string("PUSH_APNS_KEY_PATH").map(PathBuf::from),
            apns_inline_payload_limit: read_env_usize("PUSH_INLINE_PAYLOAD_LIMIT", 3500),
            apns_timeout_ms: read_env_u64("PUSH_APNS_TIMEOUT_MS", 15_000),
            fcm_project_id: read_env_string("PUSH_FCM_PROJECT_ID"),
            fcm_service_account_path: read_env_string("PUSH_FCM_SERVICE_ACCOUNT_PATH")
                .map(PathBuf::from),
            fcm_timeout_ms: read_env_u64("PUSH_FCM_TIMEOUT_MS", 15_000),
        }
    }
}

#[derive(Debug, Default)]
struct PushDispatchCounters {
    events: AtomicU64,
    targets: AtomicU64,
    attempts: AtomicU64,
    sent: AtomicU64,
    invalid: AtomicU64,
    failed: AtomicU64,
    deduped: AtomicU64,
}

#[derive(Clone, Copy, Debug, Default)]
struct PushDispatchSnapshot {
    events: u64,
    targets: u64,
    attempts: u64,
    sent: u64,
    invalid: u64,
    failed: u64,
    deduped: u64,
}

impl PushDispatchCounters {
    fn snapshot(&self) -> PushDispatchSnapshot {
        PushDispatchSnapshot {
            events: self.events.load(Ordering::Relaxed),
            targets: self.targets.load(Ordering::Relaxed),
            attempts: self.attempts.load(Ordering::Relaxed),
            sent: self.sent.load(Ordering::Relaxed),
            invalid: self.invalid.load(Ordering::Relaxed),
            failed: self.failed.load(Ordering::Relaxed),
            deduped: self.deduped.load(Ordering::Relaxed),
        }
    }
}

impl PushDispatchSnapshot {
    fn delta_since(self, previous: Self) -> Self {
        Self {
            events: self.events.saturating_sub(previous.events),
            targets: self.targets.saturating_sub(previous.targets),
            attempts: self.attempts.saturating_sub(previous.attempts),
            sent: self.sent.saturating_sub(previous.sent),
            invalid: self.invalid.saturating_sub(previous.invalid),
            failed: self.failed.saturating_sub(previous.failed),
            deduped: self.deduped.saturating_sub(previous.deduped),
        }
    }

    fn has_activity(self) -> bool {
        self.events > 0
            || self.targets > 0
            || self.attempts > 0
            || self.sent > 0
            || self.invalid > 0
            || self.failed > 0
            || self.deduped > 0
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct DeviceRegistration {
    device_token: String,
    token_type: String,
    platform: String,
    app_bundle_id: Option<String>,
    watched_addresses: HashSet<String>,
    #[serde(default)]
    watch_pulse_reply_addresses: HashSet<String>,
    primary_address: Option<String>,
    aliases: Vec<String>,
    wallet_pubkey: String,
    wallet_address: String,
    created_at_ms: u64,
    updated_at_ms: u64,
}

#[derive(Clone)]
struct ChallengeEntry {
    issued_at_ms: u64,
    expires_at_ms: u64,
}

#[derive(Serialize, Deserialize)]
struct RegistrySnapshot {
    registrations: Vec<DeviceRegistration>,
}

#[derive(Debug)]
pub struct PushApiError {
    status: StatusCode,
    message: String,
}

impl PushApiError {
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: message.into(),
        }
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
        }
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: message.into(),
        }
    }

    pub fn into_response(self) -> (StatusCode, axum::Json<PushErrorResponse>) {
        (
            self.status,
            axum::Json(PushErrorResponse {
                error: self.message,
            }),
        )
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PushErrorResponse {
    pub error: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PushOkResponse {
    pub ok: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PushChallengeResponse {
    pub nonce: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct PushPeerStatusQuery {
    pub wallet_address: String,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct PushPeerStatusResponse {
    pub wallet_address: String,
    pub registered: bool,
    pub last_seen_ms: Option<u64>,
    pub device_count: usize,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct PushRegistrationRequest {
    pub device_token: String,
    pub token_type: String,
    pub platform: String,
    pub app_bundle_id: Option<String>,
    pub watched_addresses: Vec<String>,
    #[serde(default)]
    pub watch_pulse_reply_addresses: Vec<String>,
    pub primary_address: Option<String>,
    pub aliases: Option<Vec<String>>,
    #[serde(default)]
    pub replace_wallet_devices: bool,
    pub auth: Option<PushAuthRequest>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct PushUpdateRequest {
    pub device_token: String,
    pub token_type: String,
    pub app_bundle_id: Option<String>,
    pub watched_addresses: Vec<String>,
    #[serde(default)]
    pub watch_pulse_reply_addresses: Vec<String>,
    pub primary_address: Option<String>,
    pub aliases: Option<Vec<String>>,
    pub auth: Option<PushAuthRequest>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct PushUnregisterRequest {
    pub device_token: String,
    pub token_type: String,
    pub auth: Option<PushAuthRequest>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct PushPresenceRequest {
    pub sender_address: String,
    pub recipient_address: String,
    pub event_type: String,
    pub timestamp_ms: u64,
    pub auth: Option<PushAuthRequest>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct PushAuthRequest {
    pub wallet_pubkey: String,
    pub wallet_address: String,
    pub nonce: String,
    pub timestamp_ms: u64,
    pub expires_at_ms: u64,
    pub signature: String,
}

#[derive(Debug)]
struct ValidatedAuth {
    wallet_pubkey: String,
    wallet_address: String,
}

#[derive(Debug, Clone)]
pub struct PulseReplyPushEvent {
    pub reply_id: String,
    pub post_id: String,
    pub parent_author_address: String,
    pub actor_address: String,
    pub actor_display_name: String,
    pub actor_avatar_url: Option<String>,
    pub preview_text: Option<String>,
    pub timestamp: u64,
}

impl PushService {
    pub async fn from_context(context: &IndexerContext) -> anyhow::Result<Self> {
        let config = PushConfig::from_env();
        let registrations_path = read_env_string("PUSH_REGISTRATIONS_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|| context.db_path.join("push-registrations.json"));
        let registrations = load_registrations(&registrations_path).await?;
        let network = context.network_type.into();
        let apns_client = ApnsClient::from_config(&config, network)
            .inspect_err(
                |error| warn!(%error, "Failed to initialize APNs client, push dispatch disabled"),
            )
            .ok()
            .map(Arc::new);
        let fcm_client = if config.push_fcm_enabled {
            FcmClient::from_config(&config)
                .inspect_err(|error| {
                    warn!(%error, "Failed to initialize FCM client, Android push dispatch disabled")
                })
                .ok()
                .map(Arc::new)
        } else {
            None
        };

        info!(
            "Push service initialized provider={} ios_enabled={} fcm_enabled={} apns_ready={} fcm_ready={} registrations={}",
            config.push_provider,
            config.push_ios_enabled,
            config.push_fcm_enabled,
            apns_client.is_some(),
            fcm_client.is_some(),
            registrations.len()
        );

        Ok(Self {
            config,
            network,
            registrations_path,
            registrations: Arc::new(RwLock::new(registrations)),
            challenges: Arc::new(RwLock::new(HashMap::new())),
            apns_client,
            fcm_client,
            recent_dispatches: Arc::new(Mutex::new(HashMap::new())),
            dispatch_dedupe_ttl_ms: 15 * 60 * 1000,
            dispatch_counters: Arc::new(PushDispatchCounters::default()),
        })
    }

    pub async fn run_dispatch_worker(self, event_rx: flume::Receiver<PushDispatchEvent>) {
        info!("Push dispatch worker started");

        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(10));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut previous_snapshot = self.dispatch_counters.snapshot();

        loop {
            tokio::select! {
                event = event_rx.recv_async() => {
                    let Ok(event) = event else {
                        break;
                    };
                    if let Err(error) = self.dispatch_event(event).await {
                        warn!(%error, "Push dispatch failed");
                    }
                }
                _ = ticker.tick() => {
                    self.log_dispatch_monitor(&mut previous_snapshot);
                }
            }
        }

        self.log_dispatch_monitor(&mut previous_snapshot);

        info!("Push dispatch worker stopped");
    }

    fn log_dispatch_monitor(&self, previous_snapshot: &mut PushDispatchSnapshot) {
        let current = self.dispatch_counters.snapshot();
        let delta = current.delta_since(*previous_snapshot);
        if !delta.has_activity() {
            return;
        }

        info!(
            events_delta = delta.events,
            targets_delta = delta.targets,
            attempts_delta = delta.attempts,
            sent_delta = delta.sent,
            invalid_delta = delta.invalid,
            failed_delta = delta.failed,
            deduped_delta = delta.deduped,
            events_total = current.events,
            targets_total = current.targets,
            attempts_total = current.attempts,
            sent_total = current.sent,
            invalid_total = current.invalid,
            failed_total = current.failed,
            deduped_total = current.deduped,
            "APNs monitor"
        );

        *previous_snapshot = current;
    }

    async fn dispatch_event(&self, event: PushDispatchEvent) -> anyhow::Result<()> {
        self.dispatch_counters
            .events
            .fetch_add(1, Ordering::Relaxed);

        if self.apns_client.is_none() && self.fcm_client.is_none() {
            return Ok(());
        }

        let Some(sender) = event.sender else {
            return Ok(());
        };

        let Some(sender_address) = self.address_payload_to_string(&sender)? else {
            return Ok(());
        };
        let receiver_address = self.address_payload_to_string(&event.receiver)?;
        let contextual_alias = if matches!(event.message_type, PushMessageType::Contextual) {
            event.payload.as_deref().and_then(extract_contextual_alias)
        } else {
            None
        };

        if matches!(event.message_type, PushMessageType::Contextual)
            && contextual_alias.as_deref().is_none()
        {
            debug!(
                tx_id = %faster_hex::hex_string(&event.tx_id),
                sender = %sender_address,
                "Skipping contextual push dispatch due to missing alias"
            );
            return Ok(());
        }

        if matches!(event.message_type, PushMessageType::Contextual) {
            let alias_mode = parse_contextual_alias_mode();
            let allow_legacy_suffix = read_env_bool("PUSH_CONTEXTUAL_ALLOW_LEGACY_SUFFIX", false);
            let unknown_policy = parse_contextual_unknown_policy();
            let alias_policy = contextual_alias
                .as_deref()
                .map(|alias| parse_contextual_alias_policy(alias, allow_legacy_suffix))
                .unwrap_or(ContextualAliasPolicy::Unknown);

            debug!(
                tx_id = %faster_hex::hex_string(&event.tx_id),
                sender = %sender_address,
                alias = %contextual_alias.as_deref().unwrap_or_default(),
                alias_mode,
                alias_policy = %contextual_alias_policy_tag(alias_policy),
                unknown_policy = %contextual_unknown_policy_tag(unknown_policy),
                allow_legacy_suffix,
                "Decoded contextual alias policy"
            );

            match alias_policy {
                ContextualAliasPolicy::Silent => {
                    debug!(
                        tx_id = %faster_hex::hex_string(&event.tx_id),
                        sender = %sender_address,
                        alias = %contextual_alias.as_deref().unwrap_or_default(),
                        "Skipping push dispatch for push-suppressed contextual alias"
                    );
                    return Ok(());
                }
                ContextualAliasPolicy::Visible => {}
                ContextualAliasPolicy::Unknown => {
                    if matches!(unknown_policy, ContextualUnknownPolicy::Drop) {
                        debug!(
                            tx_id = %faster_hex::hex_string(&event.tx_id),
                            sender = %sender_address,
                            alias = %contextual_alias.as_deref().unwrap_or_default(),
                            "Skipping contextual push dispatch due to unknown alias policy"
                        );
                        return Ok(());
                    }
                    debug!(
                        tx_id = %faster_hex::hex_string(&event.tx_id),
                        sender = %sender_address,
                        alias = %contextual_alias.as_deref().unwrap_or_default(),
                        "Allowing contextual push dispatch due to unknown-policy override"
                    );
                }
            }
        }

        let tx_id = faster_hex::hex_string(&event.tx_id);
        let payload_hex = event
            .payload
            .as_ref()
            .map(|payload| faster_hex::hex_string(payload))
            .filter(|payload| payload.len() <= self.config.apns_inline_payload_limit);
        let message_type_tag = push_message_type_tag(event.message_type);

        let mut body = serde_json::Map::new();
        body.insert(
            "aps".to_string(),
            json!({
                "alert": {
                    "title": "KBeam",
                    "body": match event.message_type {
                        PushMessageType::Payment => "Received payment",
                        PushMessageType::Handshake => "Started a conversation",
                        // Contextual payload text is rendered by the iOS notification service extension.
                        // Keep backend fallback neutral to avoid leaking control-payload noise if extension processing fails.
                        PushMessageType::Contextual => " ",
                        PushMessageType::PulseReply => "New Pulse reply",
                    }
                },
                "mutable-content": 1,
                "content-available": 1
            }),
        );
        body.insert("tx_id".to_string(), json!(tx_id));
        body.insert("sender".to_string(), json!(sender_address));
        body.insert("type".to_string(), json!(message_type_tag));
        body.insert("timestamp".to_string(), json!(event.timestamp));
        if let Some(amount) = event.amount {
            body.insert("amount".to_string(), json!(amount));
        }
        if let Some(payload) = payload_hex.as_deref() {
            body.insert("payload".to_string(), json!(payload));
        }
        let payload = Value::Object(body);

        let mut data = HashMap::new();
        data.insert("tx_id".to_string(), tx_id.clone());
        data.insert("sender".to_string(), sender_address.clone());
        data.insert("type".to_string(), message_type_tag.to_string());
        data.insert("timestamp".to_string(), event.timestamp.to_string());
        if let Some(amount) = event.amount {
            data.insert("amount".to_string(), amount.to_string());
        }
        if let Some(payload) = payload_hex {
            data.insert("payload".to_string(), payload);
        }

        let mut stale_tokens = Vec::new();
        if let Some(apns_client) = &self.apns_client {
            let apns_targets = self
                .matching_registrations(
                    event.message_type,
                    &sender_address,
                    receiver_address.as_deref(),
                    contextual_alias.as_deref(),
                    "apns",
                )
                .await;
            self.dispatch_counters
                .targets
                .fetch_add(apns_targets.len() as u64, Ordering::Relaxed);

            for registration in apns_targets {
                if self
                    .was_recently_dispatched(&registration.device_token, &tx_id, event.message_type)
                    .await
                {
                    self.dispatch_counters
                        .deduped
                        .fetch_add(1, Ordering::Relaxed);
                    debug!(
                        token = %registration.device_token,
                        tx_id = %tx_id,
                        "Skipping duplicate push dispatch"
                    );
                    continue;
                }

                self.dispatch_counters
                    .attempts
                    .fetch_add(1, Ordering::Relaxed);

                match apns_client
                    .send_notification(&registration.device_token, &payload, event.message_type)
                    .await
                {
                    Ok(ApnsSendOutcome::Sent) => {
                        self.dispatch_counters.sent.fetch_add(1, Ordering::Relaxed);
                        self.mark_recent_dispatch(
                            &registration.device_token,
                            &tx_id,
                            event.message_type,
                        )
                        .await;
                        debug!(
                            token = %registration.device_token,
                            tx_id = %tx_id,
                            "APNs notification sent"
                        );
                    }
                    Ok(ApnsSendOutcome::InvalidToken) => {
                        self.dispatch_counters
                            .invalid
                            .fetch_add(1, Ordering::Relaxed);
                        warn!(token = %registration.device_token, "APNs token is invalid, pruning registration");
                        stale_tokens.push(registration.device_token);
                    }
                    Err(error) => {
                        self.dispatch_counters
                            .failed
                            .fetch_add(1, Ordering::Relaxed);
                        warn!(
                            %error,
                            token = %registration.device_token,
                            tx_id = %tx_id,
                            "APNs delivery failed"
                        );
                    }
                }
            }
        }

        if let Some(fcm_client) = &self.fcm_client {
            let fcm_targets = self
                .matching_registrations(
                    event.message_type,
                    &sender_address,
                    receiver_address.as_deref(),
                    contextual_alias.as_deref(),
                    "fcm",
                )
                .await;
            self.dispatch_counters
                .targets
                .fetch_add(fcm_targets.len() as u64, Ordering::Relaxed);

            for registration in fcm_targets {
                if self
                    .was_recently_dispatched(&registration.device_token, &tx_id, event.message_type)
                    .await
                {
                    self.dispatch_counters
                        .deduped
                        .fetch_add(1, Ordering::Relaxed);
                    debug!(
                        token = %registration.device_token,
                        tx_id = %tx_id,
                        "Skipping duplicate push dispatch"
                    );
                    continue;
                }

                self.dispatch_counters
                    .attempts
                    .fetch_add(1, Ordering::Relaxed);

                match fcm_client
                    .send_data_message(&registration.device_token, &data)
                    .await
                {
                    Ok(FcmSendOutcome::Sent) => {
                        self.dispatch_counters.sent.fetch_add(1, Ordering::Relaxed);
                        self.mark_recent_dispatch(
                            &registration.device_token,
                            &tx_id,
                            event.message_type,
                        )
                        .await;
                        debug!(
                            token = %registration.device_token,
                            tx_id = %tx_id,
                            "FCM notification sent"
                        );
                    }
                    Ok(FcmSendOutcome::InvalidToken) => {
                        self.dispatch_counters
                            .invalid
                            .fetch_add(1, Ordering::Relaxed);
                        warn!(token = %registration.device_token, "FCM token is invalid, pruning registration");
                        stale_tokens.push(registration.device_token);
                    }
                    Err(error) => {
                        self.dispatch_counters
                            .failed
                            .fetch_add(1, Ordering::Relaxed);
                        warn!(
                            %error,
                            token = %registration.device_token,
                            tx_id = %tx_id,
                            "FCM delivery failed"
                        );
                    }
                }
            }
        }

        if !stale_tokens.is_empty() {
            self.remove_stale_registrations(stale_tokens).await?;
        }

        Ok(())
    }

    async fn was_recently_dispatched(
        &self,
        device_token: &str,
        tx_id: &str,
        message_type: PushMessageType,
    ) -> bool {
        let now = now_ms();
        let cutoff = now.saturating_sub(self.dispatch_dedupe_ttl_ms);
        let mut recent = self.recent_dispatches.lock().await;
        recent.retain(|_, ts| *ts >= cutoff);
        let key = Self::dispatch_dedupe_key(device_token, tx_id, message_type);
        recent.contains_key(&key)
    }

    async fn mark_recent_dispatch(
        &self,
        device_token: &str,
        tx_id: &str,
        message_type: PushMessageType,
    ) {
        let now = now_ms();
        let cutoff = now.saturating_sub(self.dispatch_dedupe_ttl_ms);
        let mut recent = self.recent_dispatches.lock().await;
        recent.retain(|_, ts| *ts >= cutoff);
        let key = Self::dispatch_dedupe_key(device_token, tx_id, message_type);
        recent.insert(key, now);
    }

    fn dispatch_dedupe_key(
        device_token: &str,
        tx_id: &str,
        _message_type: PushMessageType,
    ) -> String {
        format!("{device_token}:{tx_id}")
    }

    async fn matching_registrations(
        &self,
        message_type: PushMessageType,
        _sender_address: &str,
        receiver_address: Option<&str>,
        contextual_alias: Option<&str>,
        token_type: &str,
    ) -> Vec<DeviceRegistration> {
        let registrations = self.registrations.read().await;
        let configured_bundle_id = self
            .config
            .apns_bundle_id
            .as_deref()
            .and_then(normalize_bundle_id);

        registrations
            .values()
            .filter(|registration| registration.token_type == token_type)
            .filter(|registration| {
                if token_type != "apns" {
                    return true;
                }
                if let Some(required_bundle_id) = configured_bundle_id.as_deref() {
                    registration.app_bundle_id.as_deref() == Some(required_bundle_id)
                } else {
                    true
                }
            })
            .filter(|registration| match message_type {
                PushMessageType::Contextual => {
                    let Some(alias) = contextual_alias else {
                        return false;
                    };
                    registration.aliases.iter().any(|value| value == alias)
                }
                PushMessageType::Handshake | PushMessageType::Payment => {
                    let Some(receiver) = receiver_address else {
                        return false;
                    };
                    registration
                        .primary_address
                        .as_deref()
                        .is_some_and(|value| value == receiver)
                        || registration.wallet_address == receiver
                }
                PushMessageType::PulseReply => {
                    let Some(receiver) = receiver_address else {
                        return false;
                    };
                    registration.watch_pulse_reply_addresses.contains(receiver)
                }
            })
            .cloned()
            .collect()
    }

    async fn registrations_for_wallet(
        &self,
        wallet_address: &str,
        token_type: &str,
    ) -> Vec<DeviceRegistration> {
        let registrations = self.registrations.read().await;
        let configured_bundle_id = self
            .config
            .apns_bundle_id
            .as_deref()
            .and_then(normalize_bundle_id);

        registrations
            .values()
            .filter(|registration| registration.token_type == token_type)
            .filter(|registration| {
                if token_type != "apns" {
                    return true;
                }
                if let Some(required_bundle_id) = configured_bundle_id.as_deref() {
                    registration.app_bundle_id.as_deref() == Some(required_bundle_id)
                } else {
                    true
                }
            })
            .filter(|registration| {
                registration.wallet_address == wallet_address
                    || registration.primary_address.as_deref() == Some(wallet_address)
            })
            .cloned()
            .collect()
    }

    fn address_payload_to_string(
        &self,
        payload: &indexer_db::AddressPayload,
    ) -> anyhow::Result<Option<String>> {
        Ok(
            to_rpc_address(payload, self.network)?
                .map(|address| address.to_string().to_lowercase()),
        )
    }

    async fn remove_stale_registrations(&self, stale_tokens: Vec<String>) -> anyhow::Result<()> {
        let stale_tokens: HashSet<String> = stale_tokens.into_iter().collect();
        let mut registrations = self.registrations.write().await;
        registrations.retain(|token, _| !stale_tokens.contains(token));
        let snapshot = registrations.values().cloned().collect::<Vec<_>>();
        drop(registrations);
        persist_registrations(&self.registrations_path, snapshot).await
    }

    pub async fn create_challenge(&self) -> PushChallengeResponse {
        let now = now_ms();
        let challenge = PushChallengeResponse {
            nonce: Uuid::new_v4().as_simple().to_string(),
            issued_at_ms: now,
            expires_at_ms: now.saturating_add(self.config.challenge_ttl_ms),
        };

        let mut challenges = self.challenges.write().await;
        challenges.retain(|_, entry| {
            entry.expires_at_ms >= now.saturating_sub(self.config.challenge_skew_ms)
        });
        challenges.insert(
            challenge.nonce.clone(),
            ChallengeEntry {
                issued_at_ms: challenge.issued_at_ms,
                expires_at_ms: challenge.expires_at_ms,
            },
        );

        challenge
    }

    pub async fn dispatch_presence(
        &self,
        request: PushPresenceRequest,
    ) -> Result<(), PushApiError> {
        self.dispatch_counters
            .events
            .fetch_add(1, Ordering::Relaxed);

        let sender_address = normalize_address(request.sender_address.as_str())
            .ok_or_else(|| PushApiError::bad_request("invalid sender address"))?;
        let recipient_address = normalize_address(request.recipient_address.as_str())
            .ok_or_else(|| PushApiError::bad_request("invalid recipient address"))?;
        if sender_address == recipient_address {
            return Err(PushApiError::bad_request(
                "sender and recipient must be different",
            ));
        }

        let event_type = request.event_type.trim().to_lowercase();
        if !matches!(
            event_type.as_str(),
            "presence_typing_start" | "presence_typing_stop" | "presence_activity"
        ) {
            return Err(PushApiError::bad_request("unsupported presence event type"));
        }

        let auth = self.validate_auth(request.auth.as_ref()).await?;
        if auth.wallet_address != sender_address {
            return Err(PushApiError::unauthorized(
                "presence sender does not match authenticated wallet",
            ));
        }

        if self.apns_client.is_none() && self.fcm_client.is_none() {
            return Ok(());
        }

        let payload = json!({
            "aps": {
                "content-available": 1
            },
            "type": event_type,
            "sender": sender_address,
            "timestamp": request.timestamp_ms,
        });

        let mut data = HashMap::new();
        data.insert("type".to_string(), event_type.clone());
        data.insert("sender".to_string(), sender_address.clone());
        data.insert("timestamp".to_string(), request.timestamp_ms.to_string());

        let mut stale_tokens = Vec::new();
        if let Some(apns_client) = &self.apns_client {
            let apns_targets = self
                .registrations_for_wallet(recipient_address.as_str(), "apns")
                .await;
            self.dispatch_counters
                .targets
                .fetch_add(apns_targets.len() as u64, Ordering::Relaxed);

            for registration in apns_targets {
                self.dispatch_counters
                    .attempts
                    .fetch_add(1, Ordering::Relaxed);
                match apns_client
                    .send_notification(
                        &registration.device_token,
                        &payload,
                        PushMessageType::Contextual,
                    )
                    .await
                {
                    Ok(ApnsSendOutcome::Sent) => {
                        self.dispatch_counters.sent.fetch_add(1, Ordering::Relaxed);
                    }
                    Ok(ApnsSendOutcome::InvalidToken) => {
                        self.dispatch_counters
                            .invalid
                            .fetch_add(1, Ordering::Relaxed);
                        stale_tokens.push(registration.device_token);
                    }
                    Err(error) => {
                        self.dispatch_counters
                            .failed
                            .fetch_add(1, Ordering::Relaxed);
                        warn!(
                            %error,
                            token = %registration.device_token,
                            recipient = %recipient_address,
                            presence_type = %event_type,
                            "APNs presence delivery failed"
                        );
                    }
                }
            }
        }

        if let Some(fcm_client) = &self.fcm_client {
            let fcm_targets = self
                .registrations_for_wallet(recipient_address.as_str(), "fcm")
                .await;
            self.dispatch_counters
                .targets
                .fetch_add(fcm_targets.len() as u64, Ordering::Relaxed);

            for registration in fcm_targets {
                self.dispatch_counters
                    .attempts
                    .fetch_add(1, Ordering::Relaxed);
                match fcm_client
                    .send_data_message(&registration.device_token, &data)
                    .await
                {
                    Ok(FcmSendOutcome::Sent) => {
                        self.dispatch_counters.sent.fetch_add(1, Ordering::Relaxed);
                    }
                    Ok(FcmSendOutcome::InvalidToken) => {
                        self.dispatch_counters
                            .invalid
                            .fetch_add(1, Ordering::Relaxed);
                        stale_tokens.push(registration.device_token);
                    }
                    Err(error) => {
                        self.dispatch_counters
                            .failed
                            .fetch_add(1, Ordering::Relaxed);
                        warn!(
                            %error,
                            token = %registration.device_token,
                            recipient = %recipient_address,
                            presence_type = %event_type,
                            "FCM presence delivery failed"
                        );
                    }
                }
            }
        }

        if !stale_tokens.is_empty() {
            self.remove_stale_registrations(stale_tokens)
                .await
                .map_err(|error| {
                    PushApiError::internal(format!(
                        "failed to prune stale push registrations: {error}"
                    ))
                })?;
        }

        Ok(())
    }

    pub async fn register(&self, request: PushRegistrationRequest) -> Result<(), PushApiError> {
        let now = now_ms();
        let token_type = normalize_token_type(&request.token_type);
        let token = normalize_device_token(&request.device_token, &token_type)?;
        self.validate_token_and_type(&token, &token_type)?;

        let auth = self.validate_auth(request.auth.as_ref()).await?;
        let app_bundle_id = normalize_optional_bundle_id(request.app_bundle_id.as_deref());
        let watched_addresses = normalize_addresses(request.watched_addresses);
        let watch_pulse_reply_addresses = normalize_addresses(request.watch_pulse_reply_addresses);
        let primary_address = normalize_optional_address(request.primary_address.as_deref());
        let aliases = normalize_aliases(request.aliases.unwrap_or_default());

        let mut registrations = self.registrations.write().await;
        let existing_registration = registrations.get(&token).cloned();
        let created_at_ms = existing_registration
            .as_ref()
            .filter(|value| value.wallet_pubkey == auth.wallet_pubkey)
            .map(|value| value.created_at_ms)
            .unwrap_or(now);

        if let Some(existing) = existing_registration.as_ref()
            && existing.wallet_pubkey != auth.wallet_pubkey
        {
            warn!(
                token = %token,
                previous_wallet = %existing.wallet_address,
                new_wallet = %auth.wallet_address,
                "Rebinding push device token to newly authenticated wallet"
            );
        }

        if request.replace_wallet_devices {
            let wallet_pubkey = auth.wallet_pubkey.as_str();
            let wallet_address = auth.wallet_address.as_str();
            let before = registrations.len();
            registrations.retain(|registration_token, registration| {
                registration_token == &token
                    || (registration.wallet_pubkey != wallet_pubkey
                        && registration.wallet_address != wallet_address
                        && registration.primary_address.as_deref() != Some(wallet_address))
            });
            let removed = before.saturating_sub(registrations.len());
            if removed > 0 {
                info!(
                    wallet = %auth.wallet_address,
                    removed,
                    "Removed stale push registrations for wallet during replace-device registration"
                );
            }
        }

        registrations.insert(
            token.clone(),
            DeviceRegistration {
                device_token: token,
                token_type,
                platform: request.platform.trim().to_lowercase(),
                app_bundle_id,
                watched_addresses,
                watch_pulse_reply_addresses,
                primary_address,
                aliases,
                wallet_pubkey: auth.wallet_pubkey,
                wallet_address: auth.wallet_address,
                created_at_ms,
                updated_at_ms: now,
            },
        );

        let snapshot = registrations.values().cloned().collect::<Vec<_>>();
        drop(registrations);
        persist_registrations(&self.registrations_path, snapshot)
            .await
            .map_err(|error| {
                PushApiError::internal(format!("failed to persist registrations: {error}"))
            })
    }

    pub async fn update(&self, request: PushUpdateRequest) -> Result<(), PushApiError> {
        let now = now_ms();
        let token_type = normalize_token_type(&request.token_type);
        let token = normalize_device_token(&request.device_token, &token_type)?;
        self.validate_token_and_type(&token, &token_type)?;

        let auth = self.validate_auth(request.auth.as_ref()).await?;
        let app_bundle_id = normalize_optional_bundle_id(request.app_bundle_id.as_deref());
        let watched_addresses = normalize_addresses(request.watched_addresses);
        let watch_pulse_reply_addresses = normalize_addresses(request.watch_pulse_reply_addresses);
        let primary_address = normalize_optional_address(request.primary_address.as_deref());
        let aliases = normalize_aliases(request.aliases.unwrap_or_default());

        let mut registrations = self.registrations.write().await;
        let registration = registrations
            .get_mut(&token)
            .ok_or_else(|| PushApiError::not_found("registration not found"))?;

        if registration.wallet_pubkey != auth.wallet_pubkey {
            return Err(PushApiError::unauthorized(
                "device token is bound to another wallet",
            ));
        }

        registration.token_type = token_type;
        registration.app_bundle_id = app_bundle_id;
        registration.watched_addresses = watched_addresses;
        registration.watch_pulse_reply_addresses = watch_pulse_reply_addresses;
        registration.primary_address = primary_address;
        registration.aliases = aliases;
        registration.wallet_address = auth.wallet_address;
        registration.updated_at_ms = now;

        let snapshot = registrations.values().cloned().collect::<Vec<_>>();
        drop(registrations);
        persist_registrations(&self.registrations_path, snapshot)
            .await
            .map_err(|error| {
                PushApiError::internal(format!("failed to persist registrations: {error}"))
            })
    }

    pub async fn unregister(&self, request: PushUnregisterRequest) -> Result<(), PushApiError> {
        let token_type = normalize_token_type(&request.token_type);
        let token = normalize_device_token(&request.device_token, &token_type)?;
        self.validate_token_and_type(&token, &token_type)?;

        let auth = self.validate_auth(request.auth.as_ref()).await?;

        let mut registrations = self.registrations.write().await;
        if let Some(existing) = registrations.get(&token)
            && existing.wallet_pubkey != auth.wallet_pubkey
        {
            return Err(PushApiError::unauthorized(
                "device token is bound to another wallet",
            ));
        }

        registrations.remove(&token);

        let snapshot = registrations.values().cloned().collect::<Vec<_>>();
        drop(registrations);
        persist_registrations(&self.registrations_path, snapshot)
            .await
            .map_err(|error| {
                PushApiError::internal(format!("failed to persist registrations: {error}"))
            })
    }

    pub async fn peer_status_for_wallet_address(
        &self,
        wallet_address: &str,
    ) -> Result<PushPeerStatusResponse, PushApiError> {
        let normalized_wallet_address = normalize_address(wallet_address)
            .ok_or_else(|| PushApiError::bad_request("invalid wallet address"))?;
        let now = now_ms();
        let active_window_ms =
            read_env_u64("PUSH_STATUS_ACTIVE_WINDOW_MS", 45 * 24 * 60 * 60 * 1000);
        let configured_bundle_id = self
            .config
            .apns_bundle_id
            .as_deref()
            .and_then(normalize_bundle_id)
            .or_else(|| normalize_bundle_id("com.kbeam.app"));

        let registrations = self.registrations.read().await;
        let matching_registrations = registrations
            .values()
            .filter(|registration| {
                if registration.token_type != "apns" {
                    return true;
                }
                if let Some(required_bundle_id) = configured_bundle_id.as_deref() {
                    registration.app_bundle_id.as_deref() == Some(required_bundle_id)
                } else {
                    true
                }
            })
            .filter(|registration| {
                registration.wallet_address == normalized_wallet_address
                    || registration.primary_address.as_deref()
                        == Some(normalized_wallet_address.as_str())
            })
            .collect::<Vec<_>>();

        let last_seen_ms = matching_registrations
            .iter()
            .map(|registration| registration.updated_at_ms)
            .max();
        let device_count = matching_registrations
            .iter()
            .filter(|registration| {
                now.saturating_sub(registration.updated_at_ms) <= active_window_ms
            })
            .count();

        Ok(PushPeerStatusResponse {
            wallet_address: normalized_wallet_address,
            registered: device_count > 0,
            last_seen_ms,
            device_count,
        })
    }

    pub async fn dispatch_pulse_reply(&self, event: PulseReplyPushEvent) -> anyhow::Result<()> {
        self.dispatch_counters
            .events
            .fetch_add(1, Ordering::Relaxed);

        if self.apns_client.is_none() && self.fcm_client.is_none() {
            return Ok(());
        }

        let parent_author_address = normalize_address(&event.parent_author_address)
            .ok_or_else(|| anyhow::anyhow!("invalid pulse reply target address"))?;
        let actor_address = normalize_address(&event.actor_address)
            .ok_or_else(|| anyhow::anyhow!("invalid pulse reply actor address"))?;

        let actor_display_name = event.actor_display_name.trim();
        let actor_display_name = if actor_display_name.is_empty() {
            actor_address.clone()
        } else {
            actor_display_name.to_string()
        };
        let fallback_body = format!("{actor_display_name} replied to your Pulse");
        let preview_text = event
            .preview_text
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| truncate_for_push(value, 180));
        let actor_avatar_url = event
            .actor_avatar_url
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let payload = json!({
            "aps": {
                "alert": {
                    "title": actor_display_name,
                    "body": fallback_body
                },
                "mutable-content": 1,
                "content-available": 1
            },
            "tx_id": event.reply_id,
            "type": "pulse_reply",
            "sender": actor_address,
            "post_id": event.post_id,
            "actor_avatar_url": actor_avatar_url,
            "preview_text": preview_text,
            "timestamp": event.timestamp,
        });

        let mut data = HashMap::new();
        data.insert("tx_id".to_string(), event.reply_id.clone());
        data.insert("type".to_string(), "pulse_reply".to_string());
        data.insert("sender".to_string(), actor_address.clone());
        data.insert("post_id".to_string(), event.post_id.clone());
        data.insert("actor_display_name".to_string(), actor_display_name.clone());
        data.insert("body".to_string(), fallback_body);
        data.insert("timestamp".to_string(), event.timestamp.to_string());
        if let Some(actor_avatar_url) = actor_avatar_url {
            data.insert("actor_avatar_url".to_string(), actor_avatar_url.to_string());
        }
        if let Some(preview_text) = preview_text {
            data.insert("preview_text".to_string(), preview_text);
        }

        let mut stale_tokens = Vec::new();
        if let Some(apns_client) = &self.apns_client {
            let apns_targets = self
                .matching_registrations(
                    PushMessageType::PulseReply,
                    &actor_address,
                    Some(parent_author_address.as_str()),
                    None,
                    "apns",
                )
                .await;
            self.dispatch_counters
                .targets
                .fetch_add(apns_targets.len() as u64, Ordering::Relaxed);

            for registration in apns_targets {
                if self
                    .was_recently_dispatched(
                        &registration.device_token,
                        event.reply_id.as_str(),
                        PushMessageType::PulseReply,
                    )
                    .await
                {
                    self.dispatch_counters
                        .deduped
                        .fetch_add(1, Ordering::Relaxed);
                    continue;
                }

                self.dispatch_counters
                    .attempts
                    .fetch_add(1, Ordering::Relaxed);
                match apns_client
                    .send_notification(
                        &registration.device_token,
                        &payload,
                        PushMessageType::PulseReply,
                    )
                    .await
                {
                    Ok(ApnsSendOutcome::Sent) => {
                        self.dispatch_counters.sent.fetch_add(1, Ordering::Relaxed);
                        self.mark_recent_dispatch(
                            &registration.device_token,
                            event.reply_id.as_str(),
                            PushMessageType::PulseReply,
                        )
                        .await;
                    }
                    Ok(ApnsSendOutcome::InvalidToken) => {
                        self.dispatch_counters
                            .invalid
                            .fetch_add(1, Ordering::Relaxed);
                        stale_tokens.push(registration.device_token);
                    }
                    Err(error) => {
                        self.dispatch_counters
                            .failed
                            .fetch_add(1, Ordering::Relaxed);
                        warn!(
                            %error,
                            token = %registration.device_token,
                            post_id = %event.post_id,
                            reply_id = %event.reply_id,
                            "APNs delivery failed for pulse reply"
                        );
                    }
                }
            }
        }

        if let Some(fcm_client) = &self.fcm_client {
            let fcm_targets = self
                .matching_registrations(
                    PushMessageType::PulseReply,
                    &actor_address,
                    Some(parent_author_address.as_str()),
                    None,
                    "fcm",
                )
                .await;
            self.dispatch_counters
                .targets
                .fetch_add(fcm_targets.len() as u64, Ordering::Relaxed);

            for registration in fcm_targets {
                if self
                    .was_recently_dispatched(
                        &registration.device_token,
                        event.reply_id.as_str(),
                        PushMessageType::PulseReply,
                    )
                    .await
                {
                    self.dispatch_counters
                        .deduped
                        .fetch_add(1, Ordering::Relaxed);
                    continue;
                }

                self.dispatch_counters
                    .attempts
                    .fetch_add(1, Ordering::Relaxed);
                match fcm_client
                    .send_data_message(&registration.device_token, &data)
                    .await
                {
                    Ok(FcmSendOutcome::Sent) => {
                        self.dispatch_counters.sent.fetch_add(1, Ordering::Relaxed);
                        self.mark_recent_dispatch(
                            &registration.device_token,
                            event.reply_id.as_str(),
                            PushMessageType::PulseReply,
                        )
                        .await;
                    }
                    Ok(FcmSendOutcome::InvalidToken) => {
                        self.dispatch_counters
                            .invalid
                            .fetch_add(1, Ordering::Relaxed);
                        stale_tokens.push(registration.device_token);
                    }
                    Err(error) => {
                        self.dispatch_counters
                            .failed
                            .fetch_add(1, Ordering::Relaxed);
                        warn!(
                            %error,
                            token = %registration.device_token,
                            post_id = %event.post_id,
                            reply_id = %event.reply_id,
                            "FCM delivery failed for pulse reply"
                        );
                    }
                }
            }
        }

        if !stale_tokens.is_empty() {
            self.remove_stale_registrations(stale_tokens).await?;
        }

        Ok(())
    }

    fn validate_token_and_type(&self, token: &str, token_type: &str) -> Result<(), PushApiError> {
        if token_type == "apns" {
            if token.len() != 64 || !is_hex_string(token) {
                return Err(PushApiError::bad_request("invalid device token length"));
            }
            return Ok(());
        }

        if token_type == "fcm" {
            if !self.config.push_fcm_enabled {
                return Err(PushApiError::bad_request("FCM push is disabled"));
            }
            return Ok(());
        }

        Err(PushApiError::bad_request("unsupported token type"))
    }

    async fn validate_auth(
        &self,
        auth: Option<&PushAuthRequest>,
    ) -> Result<ValidatedAuth, PushApiError> {
        let auth = auth.ok_or_else(|| PushApiError::unauthorized("missing auth"))?;

        let wallet_pubkey = auth.wallet_pubkey.trim().to_lowercase();
        if wallet_pubkey.len() != 64 || !is_hex_string(&wallet_pubkey) {
            return Err(PushApiError::unauthorized("invalid wallet pubkey"));
        }

        let wallet_address = normalize_address(auth.wallet_address.as_str())
            .ok_or_else(|| PushApiError::unauthorized("invalid wallet address"))?;

        if auth.signature.trim().is_empty() {
            return Err(PushApiError::unauthorized("invalid schnorr signature"));
        }

        let now = now_ms();
        let skew = self.config.challenge_skew_ms;

        if now.saturating_add(skew) < auth.timestamp_ms {
            return Err(PushApiError::unauthorized(
                "auth timestamp is in the future",
            ));
        }
        if now > auth.expires_at_ms.saturating_add(skew) {
            return Err(PushApiError::unauthorized("auth expired"));
        }

        let nonce = auth.nonce.trim();
        if nonce.is_empty() {
            return Err(PushApiError::unauthorized("invalid nonce"));
        }

        let mut challenges = self.challenges.write().await;
        challenges.retain(|_, entry| entry.expires_at_ms.saturating_add(skew) >= now);

        let challenge = challenges
            .remove(nonce)
            .ok_or_else(|| PushApiError::unauthorized("invalid challenge nonce"))?;

        if auth.expires_at_ms != challenge.expires_at_ms {
            return Err(PushApiError::unauthorized("invalid challenge expiry"));
        }

        if auth.timestamp_ms < challenge.issued_at_ms.saturating_sub(skew)
            || auth.timestamp_ms > challenge.expires_at_ms.saturating_add(skew)
        {
            return Err(PushApiError::unauthorized(
                "auth timestamp outside challenge window",
            ));
        }

        Ok(ValidatedAuth {
            wallet_pubkey,
            wallet_address,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApnsSendOutcome {
    Sent,
    InvalidToken,
}

#[derive(Clone)]
struct ApnsClient {
    client: reqwest::Client,
    host: String,
    topic: String,
    team_id: String,
    key_id: String,
    encoding_key: EncodingKey,
    token_cache: Arc<Mutex<Option<ApnsBearerToken>>>,
}

#[derive(Clone)]
struct ApnsBearerToken {
    token: String,
    issued_at_secs: u64,
}

#[derive(Serialize)]
struct ApnsClaims<'a> {
    iss: &'a str,
    iat: usize,
}

#[derive(Deserialize)]
struct ApnsErrorBody {
    reason: Option<String>,
}

impl ApnsClient {
    fn from_config(config: &PushConfig, network: RpcNetworkType) -> anyhow::Result<Self> {
        if config.push_provider != "apns" || !config.push_ios_enabled {
            anyhow::bail!("APNs push provider is disabled")
        }

        let team_id = config
            .apns_team_id
            .clone()
            .ok_or_else(|| anyhow::anyhow!("PUSH_APNS_TEAM_ID is not set"))?;
        let key_id = config
            .apns_key_id
            .clone()
            .ok_or_else(|| anyhow::anyhow!("PUSH_APNS_KEY_ID is not set"))?;
        let topic = config
            .apns_bundle_id
            .clone()
            .ok_or_else(|| anyhow::anyhow!("PUSH_APNS_BUNDLE_ID is not set"))?;
        let key_path = config
            .apns_key_path
            .clone()
            .ok_or_else(|| anyhow::anyhow!("PUSH_APNS_KEY_PATH is not set"))?;

        let key_bytes = std::fs::read(&key_path)
            .with_context(|| format!("failed to read APNs key file {}", key_path.display()))?;
        let encoding_key = EncodingKey::from_ec_pem(&key_bytes)
            .context("failed to parse APNs private key (expected .p8 PEM)")?;

        let host = match config.apns_environment.as_str() {
            "sandbox" | "development" => "https://api.sandbox.push.apple.com".to_string(),
            "production" | "prod" => "https://api.push.apple.com".to_string(),
            "auto" => {
                if matches!(network, RpcNetworkType::Mainnet) {
                    "https://api.push.apple.com".to_string()
                } else {
                    "https://api.sandbox.push.apple.com".to_string()
                }
            }
            value => anyhow::bail!("unsupported PUSH_APNS_ENVIRONMENT value: {value}"),
        };

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(config.apns_timeout_ms))
            .build()
            .context("failed to build APNs HTTP client")?;

        Ok(Self {
            client,
            host,
            topic,
            team_id,
            key_id,
            encoding_key,
            token_cache: Arc::new(Mutex::new(None)),
        })
    }

    async fn send_notification(
        &self,
        device_token: &str,
        payload: &Value,
        message_type: PushMessageType,
    ) -> anyhow::Result<ApnsSendOutcome> {
        let auth_token = self.auth_token().await?;
        let url = format!("{}/3/device/{}", self.host, device_token);
        let has_alert = payload
            .get("aps")
            .and_then(|aps| aps.get("alert"))
            .is_some();
        let (apns_push_type, apns_priority) = match (message_type, has_alert) {
            (PushMessageType::Contextual, false) => ("background", "5"),
            _ => ("alert", "10"),
        };

        let response = self
            .client
            .post(url)
            .header("authorization", format!("bearer {auth_token}"))
            .header("apns-topic", &self.topic)
            .header("apns-push-type", apns_push_type)
            .header("apns-priority", apns_priority)
            .json(payload)
            .send()
            .await
            .context("failed to send APNs notification")?;

        let status = response.status();
        if status.is_success() {
            return Ok(ApnsSendOutcome::Sent);
        }

        let body = response.text().await.unwrap_or_default();
        let reason = extract_apns_reason(&body).unwrap_or_else(|| "unknown".to_string());

        if status == HttpStatusCode::UNAUTHORIZED {
            self.invalidate_auth_token().await;
        }

        if is_invalid_token_response(status, &reason) {
            return Ok(ApnsSendOutcome::InvalidToken);
        }

        anyhow::bail!(
            "APNs rejected notification: status={} reason={reason}",
            status
        )
    }

    async fn auth_token(&self) -> anyhow::Result<String> {
        let now_secs = now_ms() / 1000;
        {
            let cached = self.token_cache.lock().await;
            if let Some(cached) = cached.as_ref()
                && now_secs.saturating_sub(cached.issued_at_secs) < 50 * 60
            {
                return Ok(cached.token.clone());
            }
        }

        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.key_id.clone());
        let claims = ApnsClaims {
            iss: &self.team_id,
            iat: now_secs as usize,
        };
        let token = jsonwebtoken::encode(&header, &claims, &self.encoding_key)
            .context("failed to sign APNs JWT")?;

        let mut cache = self.token_cache.lock().await;
        *cache = Some(ApnsBearerToken {
            token: token.clone(),
            issued_at_secs: now_secs,
        });
        Ok(token)
    }

    async fn invalidate_auth_token(&self) {
        let mut cache = self.token_cache.lock().await;
        *cache = None;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FcmSendOutcome {
    Sent,
    InvalidToken,
}

#[derive(Clone)]
struct FcmClient {
    client: reqwest::Client,
    project_id: String,
    service_account: Arc<FcmServiceAccount>,
    encoding_key: EncodingKey,
    token_cache: Arc<Mutex<Option<FcmBearerToken>>>,
}

#[derive(Debug, Clone, Deserialize)]
struct FcmServiceAccount {
    project_id: Option<String>,
    private_key_id: Option<String>,
    private_key: String,
    client_email: String,
    token_uri: Option<String>,
}

#[derive(Clone)]
struct FcmBearerToken {
    token: String,
    expires_at_secs: u64,
}

#[derive(Serialize)]
struct FcmClaims<'a> {
    iss: &'a str,
    scope: &'a str,
    aud: &'a str,
    iat: usize,
    exp: usize,
}

#[derive(Deserialize)]
struct FcmTokenResponse {
    access_token: String,
    expires_in: Option<u64>,
}

impl FcmClient {
    fn from_config(config: &PushConfig) -> anyhow::Result<Self> {
        if !config.push_fcm_enabled {
            anyhow::bail!("FCM push provider is disabled")
        }

        let service_account_path = config
            .fcm_service_account_path
            .clone()
            .ok_or_else(|| anyhow::anyhow!("PUSH_FCM_SERVICE_ACCOUNT_PATH is not set"))?;
        let service_account_bytes = std::fs::read(&service_account_path).with_context(|| {
            format!(
                "failed to read FCM service account file {}",
                service_account_path.display()
            )
        })?;
        let service_account: FcmServiceAccount = serde_json::from_slice(&service_account_bytes)
            .context("failed to parse FCM service account JSON")?;
        let project_id = config
            .fcm_project_id
            .clone()
            .or_else(|| service_account.project_id.clone())
            .ok_or_else(|| anyhow::anyhow!("PUSH_FCM_PROJECT_ID is not set"))?;
        let encoding_key = EncodingKey::from_rsa_pem(service_account.private_key.as_bytes())
            .context("failed to parse FCM service account private key")?;
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(config.fcm_timeout_ms))
            .build()
            .context("failed to build FCM HTTP client")?;

        Ok(Self {
            client,
            project_id,
            service_account: Arc::new(service_account),
            encoding_key,
            token_cache: Arc::new(Mutex::new(None)),
        })
    }

    async fn send_data_message(
        &self,
        device_token: &str,
        data: &HashMap<String, String>,
    ) -> anyhow::Result<FcmSendOutcome> {
        let auth_token = self.auth_token().await?;
        let url = format!(
            "https://fcm.googleapis.com/v1/projects/{}/messages:send",
            self.project_id
        );
        let payload = json!({
            "message": {
                "token": device_token,
                "data": data,
                "android": {
                    "priority": "HIGH"
                }
            }
        });

        let response = self
            .client
            .post(url)
            .bearer_auth(auth_token)
            .json(&payload)
            .send()
            .await
            .context("failed to send FCM notification")?;

        let status = response.status();
        if status.is_success() {
            return Ok(FcmSendOutcome::Sent);
        }

        let body = response.text().await.unwrap_or_default();
        if status == HttpStatusCode::UNAUTHORIZED {
            self.invalidate_auth_token().await;
        }
        if is_invalid_fcm_token_response(&body) {
            return Ok(FcmSendOutcome::InvalidToken);
        }

        anyhow::bail!("FCM rejected notification: status={} body={body}", status)
    }

    async fn auth_token(&self) -> anyhow::Result<String> {
        let now_secs = now_ms() / 1000;
        {
            let cached = self.token_cache.lock().await;
            if let Some(cached) = cached.as_ref()
                && cached.expires_at_secs > now_secs.saturating_add(60)
            {
                return Ok(cached.token.clone());
            }
        }

        let token_uri = self
            .service_account
            .token_uri
            .as_deref()
            .unwrap_or("https://oauth2.googleapis.com/token");
        let mut header = Header::new(Algorithm::RS256);
        header.kid = self.service_account.private_key_id.clone();
        let claims = FcmClaims {
            iss: &self.service_account.client_email,
            scope: "https://www.googleapis.com/auth/firebase.messaging",
            aud: token_uri,
            iat: now_secs as usize,
            exp: now_secs.saturating_add(3600) as usize,
        };
        let assertion = jsonwebtoken::encode(&header, &claims, &self.encoding_key)
            .context("failed to sign FCM OAuth JWT")?;
        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
            .append_pair("assertion", &assertion)
            .finish();

        let response = self
            .client
            .post(token_uri)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await
            .context("failed to request FCM OAuth token")?;
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        if !status.is_success() {
            anyhow::bail!(
                "FCM OAuth token request failed: status={} body={body}",
                status
            );
        }

        let token_response: FcmTokenResponse =
            serde_json::from_str(&body).context("failed to parse FCM OAuth token response")?;
        let expires_in = token_response.expires_in.unwrap_or(3600);
        let mut cache = self.token_cache.lock().await;
        *cache = Some(FcmBearerToken {
            token: token_response.access_token.clone(),
            expires_at_secs: now_secs.saturating_add(expires_in),
        });
        Ok(token_response.access_token)
    }

    async fn invalidate_auth_token(&self) {
        let mut cache = self.token_cache.lock().await;
        *cache = None;
    }
}

fn extract_apns_reason(body: &str) -> Option<String> {
    serde_json::from_str::<ApnsErrorBody>(body)
        .ok()
        .and_then(|payload| payload.reason)
}

fn is_invalid_token_response(status: HttpStatusCode, reason: &str) -> bool {
    matches!(
        (status, reason),
        (HttpStatusCode::BAD_REQUEST, "BadDeviceToken")
            | (HttpStatusCode::BAD_REQUEST, "DeviceTokenNotForTopic")
            | (HttpStatusCode::GONE, "Unregistered")
    )
}

fn is_invalid_fcm_token_response(body: &str) -> bool {
    let Ok(value) = serde_json::from_str::<Value>(body) else {
        return false;
    };
    let error = value.get("error").unwrap_or(&value);
    let status = error
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or_default();

    if status == "NOT_FOUND" || status == "UNREGISTERED" {
        return true;
    }

    if status != "INVALID_ARGUMENT" {
        return false;
    }

    error
        .get("details")
        .and_then(Value::as_array)
        .is_some_and(|details| {
            details.iter().any(|detail| {
                detail
                    .get("@type")
                    .and_then(Value::as_str)
                    .is_some_and(|value| {
                        value == "type.googleapis.com/google.firebase.fcm.v1.FcmError"
                    })
            })
        })
}

fn push_message_type_tag(message_type: PushMessageType) -> &'static str {
    match message_type {
        PushMessageType::Handshake => "handshake",
        PushMessageType::Payment => "payment",
        PushMessageType::Contextual => "contextual",
        PushMessageType::PulseReply => "pulse_reply",
    }
}

fn truncate_for_push(value: &str, max_chars: usize) -> String {
    let trimmed = value.trim();
    let mut iter = trimmed.chars();
    let truncated: String = iter.by_ref().take(max_chars).collect();
    if iter.next().is_some() {
        format!("{truncated}...")
    } else {
        truncated
    }
}

fn normalize_addresses(values: Vec<String>) -> HashSet<String> {
    values
        .into_iter()
        .filter_map(|value| normalize_address(&value))
        .collect()
}

fn normalize_aliases(values: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut aliases = Vec::new();

    for value in values {
        let normalized = value.trim();
        if normalized.is_empty() {
            continue;
        }
        let normalized = normalized.to_string();
        if seen.insert(normalized.clone()) {
            aliases.push(normalized);
        }
    }

    aliases
}

fn extract_contextual_alias(payload: &[u8]) -> Option<String> {
    let payload = std::str::from_utf8(payload).ok()?;
    let mut parts = payload.splitn(5, ':');

    if parts.next()? != "ciph_msg" {
        return None;
    }
    if parts.next()? != "1" {
        return None;
    }
    if parts.next()? != "comm" {
        return None;
    }

    let alias = parts.next()?.trim();
    if alias.is_empty() {
        return None;
    }

    Some(alias.to_string())
}

fn parse_contextual_alias_policy(alias: &str, allow_legacy_suffix: bool) -> ContextualAliasPolicy {
    let normalized = alias.trim();

    if normalized.ends_with(PUSH_SUPPRESSED_ALIAS_SUFFIX) {
        return ContextualAliasPolicy::Silent;
    }
    if normalized.ends_with(PUSH_VISIBLE_ALIAS_SUFFIX) {
        return ContextualAliasPolicy::Visible;
    }

    if allow_legacy_suffix {
        if normalized.ends_with(LEGACY_PUSH_SUPPRESSED_ALIAS_SUFFIX) {
            return ContextualAliasPolicy::Silent;
        }
        if normalized.ends_with(LEGACY_PUSH_VISIBLE_ALIAS_SUFFIX) {
            return ContextualAliasPolicy::Visible;
        }
    }

    ContextualAliasPolicy::Unknown
}

fn parse_contextual_unknown_policy() -> ContextualUnknownPolicy {
    let value =
        read_env_string("PUSH_CONTEXTUAL_UNKNOWN_POLICY").unwrap_or_else(|| "drop".to_string());
    match value.trim().to_lowercase().as_str() {
        "visible" => ContextualUnknownPolicy::Visible,
        _ => ContextualUnknownPolicy::Drop,
    }
}

fn parse_contextual_alias_mode() -> &'static str {
    let value =
        read_env_string("PUSH_CONTEXTUAL_ALIAS_MODE").unwrap_or_else(|| "strict".to_string());
    match value.trim().to_lowercase().as_str() {
        "strict" => "strict",
        _ => "strict",
    }
}

fn contextual_unknown_policy_tag(policy: ContextualUnknownPolicy) -> &'static str {
    match policy {
        ContextualUnknownPolicy::Drop => "drop",
        ContextualUnknownPolicy::Visible => "visible",
    }
}

fn contextual_alias_policy_tag(policy: ContextualAliasPolicy) -> &'static str {
    match policy {
        ContextualAliasPolicy::Visible => "visible",
        ContextualAliasPolicy::Silent => "silent",
        ContextualAliasPolicy::Unknown => "unknown",
    }
}

fn normalize_optional_address(value: Option<&str>) -> Option<String> {
    value.and_then(normalize_address)
}

fn normalize_optional_bundle_id(value: Option<&str>) -> Option<String> {
    value.and_then(normalize_bundle_id)
}

fn normalize_bundle_id(value: &str) -> Option<String> {
    let normalized = value.trim().to_lowercase();
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

fn normalize_address(value: &str) -> Option<String> {
    let normalized = value.trim().to_lowercase();
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

fn normalize_device_token(value: &str, token_type: &str) -> Result<String, PushApiError> {
    let token = value.trim();
    if token.is_empty() {
        return Err(PushApiError::bad_request("missing device token"));
    }
    if token_type == "apns" {
        Ok(token.to_lowercase())
    } else {
        Ok(token.to_string())
    }
}

fn normalize_token_type(value: &str) -> String {
    let normalized = value.trim().to_lowercase();
    if normalized.is_empty() {
        "apns".to_string()
    } else {
        normalized
    }
}

fn read_env_bool(name: &str, default: bool) -> bool {
    std::env::var(name)
        .ok()
        .map(|value| match value.trim().to_lowercase().as_str() {
            "1" | "true" | "yes" | "y" | "on" => true,
            "0" | "false" | "no" | "n" | "off" => false,
            _ => default,
        })
        .unwrap_or(default)
}

fn read_env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(default)
}

fn read_env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(default)
}

fn read_env_string(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn is_hex_string(value: &str) -> bool {
    !value.is_empty() && value.chars().all(|ch| ch.is_ascii_hexdigit())
}

async fn load_registrations(path: &Path) -> anyhow::Result<HashMap<String, DeviceRegistration>> {
    let data = match std::fs::read(path) {
        Ok(data) => data,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(error) => {
            return Err(anyhow::anyhow!(
                "failed to read push registrations: {error}"
            ));
        }
    };

    let snapshot: RegistrySnapshot =
        serde_json::from_slice(&data).context("failed to parse push registrations file")?;

    Ok(snapshot
        .registrations
        .into_iter()
        .map(|registration| (registration.device_token.clone(), registration))
        .collect())
}

async fn persist_registrations(path: &Path, values: Vec<DeviceRegistration>) -> anyhow::Result<()> {
    let snapshot = RegistrySnapshot {
        registrations: values,
    };

    let encoded =
        serde_json::to_vec_pretty(&snapshot).context("failed to serialize push registrations")?;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create push registration directory {}",
                parent.display()
            )
        })?;
    }

    std::fs::write(path, encoded)
        .with_context(|| format!("failed to write push registrations to {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_apns_tokens_to_lowercase() {
        let token = normalize_device_token(
            " ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789 ",
            "apns",
        )
        .unwrap();

        assert_eq!(
            token,
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        );
    }

    #[test]
    fn preserves_fcm_token_case() {
        let token = normalize_device_token(" fcm:AbC_123-XyZ ", "fcm").unwrap();

        assert_eq!(token, "fcm:AbC_123-XyZ");
    }

    #[test]
    fn detects_invalid_fcm_registration_token_errors() {
        let body = r#"{
            "error": {
                "code": 400,
                "status": "INVALID_ARGUMENT",
                "details": [
                    {
                        "@type": "type.googleapis.com/google.firebase.fcm.v1.FcmError",
                        "errorCode": "INVALID_ARGUMENT"
                    }
                ]
            }
        }"#;

        assert!(is_invalid_fcm_token_response(body));
    }

    #[test]
    fn keeps_fcm_payload_errors_from_pruning_tokens() {
        let body = r#"{
            "error": {
                "code": 400,
                "status": "INVALID_ARGUMENT",
                "details": [
                    {
                        "@type": "type.googleapis.com/google.rpc.BadRequest",
                        "fieldViolations": []
                    }
                ]
            }
        }"#;

        assert!(!is_invalid_fcm_token_response(body));
    }

    #[test]
    fn matching_registrations_separates_apns_bundle_and_fcm_tokens() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        runtime.block_on(async {
            let mut registrations = HashMap::new();
            registrations.insert(
                "apns-allowed".to_string(),
                test_registration(
                    "apns-allowed",
                    "apns",
                    Some("com.kbeam.app"),
                    "kaspa:qreceiver",
                ),
            );
            registrations.insert(
                "apns-other-bundle".to_string(),
                test_registration(
                    "apns-other-bundle",
                    "apns",
                    Some("com.other.app"),
                    "kaspa:qreceiver",
                ),
            );
            registrations.insert(
                "fcm-token".to_string(),
                test_registration("fcm-token", "fcm", None, "kaspa:qreceiver"),
            );

            let service = test_service(registrations);
            let apns_targets = service
                .matching_registrations(
                    PushMessageType::Payment,
                    "kaspa:qsender",
                    Some("kaspa:qreceiver"),
                    None,
                    "apns",
                )
                .await;
            let fcm_targets = service
                .matching_registrations(
                    PushMessageType::Payment,
                    "kaspa:qsender",
                    Some("kaspa:qreceiver"),
                    None,
                    "fcm",
                )
                .await;

            assert_eq!(apns_targets.len(), 1);
            assert_eq!(apns_targets[0].device_token, "apns-allowed");
            assert_eq!(fcm_targets.len(), 1);
            assert_eq!(fcm_targets[0].device_token, "fcm-token");
        });
    }

    #[test]
    fn peer_status_counts_fcm_without_relaxing_apns_bundle_filter() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        runtime.block_on(async {
            let mut registrations = HashMap::new();
            registrations.insert(
                "apns-allowed".to_string(),
                test_registration(
                    "apns-allowed",
                    "apns",
                    Some("com.kbeam.app"),
                    "kaspa:qreceiver",
                ),
            );
            registrations.insert(
                "apns-other-bundle".to_string(),
                test_registration(
                    "apns-other-bundle",
                    "apns",
                    Some("com.other.app"),
                    "kaspa:qreceiver",
                ),
            );
            registrations.insert(
                "fcm-token".to_string(),
                test_registration(
                    "fcm-token",
                    "fcm",
                    Some("com.kbeam.android"),
                    "kaspa:qreceiver",
                ),
            );

            let service = test_service(registrations);
            let status = service
                .peer_status_for_wallet_address("kaspa:qreceiver")
                .await
                .unwrap();

            assert!(status.registered);
            assert_eq!(status.device_count, 2);
        });
    }

    #[test]
    fn register_rebinds_existing_device_token_to_new_wallet() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        runtime.block_on(async {
            let token = "aa".repeat(32);
            let mut registrations = HashMap::new();
            registrations.insert(
                token.clone(),
                test_registration(
                    token.as_str(),
                    "apns",
                    Some("com.kbeam.app"),
                    "kaspa:qoldwallet",
                ),
            );

            let service = test_service(registrations);
            let challenge = service.create_challenge().await;
            service
                .register(PushRegistrationRequest {
                    device_token: token.to_uppercase(),
                    token_type: "apns".to_string(),
                    platform: "ios".to_string(),
                    app_bundle_id: Some("com.kbeam.app".to_string()),
                    watched_addresses: vec!["kaspa:qnewwallet".to_string()],
                    watch_pulse_reply_addresses: vec!["kaspa:qnewwallet".to_string()],
                    primary_address: Some("kaspa:qnewwallet".to_string()),
                    aliases: Some(vec!["new-alias__kbp1".to_string()]),
                    replace_wallet_devices: false,
                    auth: Some(PushAuthRequest {
                        wallet_pubkey: "11".repeat(32),
                        wallet_address: "kaspa:qnewwallet".to_string(),
                        nonce: challenge.nonce,
                        timestamp_ms: challenge.issued_at_ms,
                        expires_at_ms: challenge.expires_at_ms,
                        signature: "signature".to_string(),
                    }),
                })
                .await
                .unwrap();

            let registrations = service.registrations.read().await;
            let rebound = registrations.get(token.as_str()).unwrap();
            assert_eq!(registrations.len(), 1);
            assert_eq!(rebound.wallet_pubkey, "11".repeat(32));
            assert_eq!(rebound.wallet_address, "kaspa:qnewwallet");
            assert_eq!(rebound.primary_address.as_deref(), Some("kaspa:qnewwallet"));
            assert!(rebound.watched_addresses.contains("kaspa:qnewwallet"));
            assert_eq!(rebound.aliases, vec!["new-alias__kbp1".to_string()]);
            assert_ne!(rebound.created_at_ms, 1);
        });
    }

    #[test]
    fn register_can_replace_other_devices_for_same_wallet() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        runtime.block_on(async {
            let mut registrations = HashMap::new();
            registrations.insert(
                "apns-old".to_string(),
                test_registration("apns-old", "apns", Some("com.kbeam.app"), "kaspa:qwallet"),
            );
            registrations.insert(
                "fcm-old".to_string(),
                test_registration("fcm-old", "fcm", None, "kaspa:qwallet"),
            );
            let mut other_registration =
                test_registration("apns-other", "apns", Some("com.kbeam.app"), "kaspa:qother");
            other_registration.wallet_pubkey = "11".repeat(32);
            registrations.insert("apns-other".to_string(), other_registration);

            let service = test_service(registrations);
            let challenge = service.create_challenge().await;
            let new_token = "aa".repeat(32);
            service
                .register(PushRegistrationRequest {
                    device_token: new_token.clone(),
                    token_type: "apns".to_string(),
                    platform: "ios".to_string(),
                    app_bundle_id: Some("com.kbeam.app".to_string()),
                    watched_addresses: vec!["kaspa:qwallet".to_string()],
                    watch_pulse_reply_addresses: vec!["kaspa:qwallet".to_string()],
                    primary_address: Some("kaspa:qwallet".to_string()),
                    aliases: Some(vec![]),
                    replace_wallet_devices: true,
                    auth: Some(PushAuthRequest {
                        wallet_pubkey: "00".repeat(32),
                        wallet_address: "kaspa:qwallet".to_string(),
                        nonce: challenge.nonce,
                        timestamp_ms: challenge.issued_at_ms,
                        expires_at_ms: challenge.expires_at_ms,
                        signature: "signature".to_string(),
                    }),
                })
                .await
                .unwrap();

            let registrations = service.registrations.read().await;
            assert!(registrations.contains_key(&new_token));
            assert!(!registrations.contains_key("apns-old"));
            assert!(!registrations.contains_key("fcm-old"));
            assert!(registrations.contains_key("apns-other"));
        });
    }

    fn test_service(registrations: HashMap<String, DeviceRegistration>) -> PushService {
        PushService {
            config: PushConfig {
                push_provider: "apns".to_string(),
                push_ios_enabled: true,
                push_fcm_enabled: true,
                challenge_ttl_ms: 120_000,
                challenge_skew_ms: 15_000,
                apns_environment: "auto".to_string(),
                apns_team_id: None,
                apns_key_id: None,
                apns_bundle_id: Some("com.kbeam.app".to_string()),
                apns_key_path: None,
                apns_inline_payload_limit: 3500,
                apns_timeout_ms: 15_000,
                fcm_project_id: Some("kbeam-test".to_string()),
                fcm_service_account_path: None,
                fcm_timeout_ms: 15_000,
            },
            network: RpcNetworkType::Mainnet,
            registrations_path: PathBuf::from("/tmp/kbeam-test-push-registrations.json"),
            registrations: Arc::new(RwLock::new(registrations)),
            challenges: Arc::new(RwLock::new(HashMap::new())),
            apns_client: None,
            fcm_client: None,
            recent_dispatches: Arc::new(Mutex::new(HashMap::new())),
            dispatch_dedupe_ttl_ms: 15 * 60 * 1000,
            dispatch_counters: Arc::new(PushDispatchCounters::default()),
        }
    }

    fn test_registration(
        token: &str,
        token_type: &str,
        app_bundle_id: Option<&str>,
        wallet_address: &str,
    ) -> DeviceRegistration {
        DeviceRegistration {
            device_token: token.to_string(),
            token_type: token_type.to_string(),
            platform: token_type.to_string(),
            app_bundle_id: app_bundle_id.map(str::to_string),
            watched_addresses: HashSet::new(),
            watch_pulse_reply_addresses: HashSet::new(),
            primary_address: Some(wallet_address.to_string()),
            aliases: Vec::new(),
            wallet_pubkey: "00".repeat(32),
            wallet_address: wallet_address.to_string(),
            created_at_ms: 1,
            updated_at_ms: now_ms(),
        }
    }
}

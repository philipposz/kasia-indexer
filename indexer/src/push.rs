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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, info, warn};
use utoipa::ToSchema;
use uuid::Uuid;

const PUSH_SUPPRESSED_ALIAS_SUFFIX: &str = "__silent";

#[derive(Clone)]
pub struct PushService {
    config: PushConfig,
    network: RpcNetworkType,
    registrations_path: PathBuf,
    registrations: Arc<RwLock<HashMap<String, DeviceRegistration>>>,
    challenges: Arc<RwLock<HashMap<String, ChallengeEntry>>>,
    apns_client: Option<Arc<ApnsClient>>,
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
pub struct PushRegistrationRequest {
    pub device_token: String,
    pub token_type: String,
    pub platform: String,
    pub app_bundle_id: Option<String>,
    pub watched_addresses: Vec<String>,
    pub primary_address: Option<String>,
    pub aliases: Option<Vec<String>>,
    pub auth: Option<PushAuthRequest>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct PushUpdateRequest {
    pub device_token: String,
    pub token_type: String,
    pub app_bundle_id: Option<String>,
    pub watched_addresses: Vec<String>,
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

        info!(
            "Push service initialized provider={} ios_enabled={} fcm_enabled={} registrations={}",
            config.push_provider,
            config.push_ios_enabled,
            config.push_fcm_enabled,
            registrations.len()
        );

        Ok(Self {
            config,
            network,
            registrations_path,
            registrations: Arc::new(RwLock::new(registrations)),
            challenges: Arc::new(RwLock::new(HashMap::new())),
            apns_client,
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
        self.dispatch_counters.events.fetch_add(1, Ordering::Relaxed);

        let Some(apns_client) = &self.apns_client else {
            return Ok(());
        };

        let Some(sender) = event.sender else {
            return Ok(());
        };

        let Some(sender_address) = self.address_payload_to_string(&sender)? else {
            return Ok(());
        };
        let receiver_address = self.address_payload_to_string(&event.receiver)?;
        let contextual_alias = if matches!(event.message_type, PushMessageType::Contextual) {
            event
                .payload
                .as_deref()
                .and_then(extract_contextual_alias)
        } else {
            None
        };

        if contextual_alias
            .as_deref()
            .is_some_and(is_push_suppressed_alias)
        {
            debug!(
                tx_id = %faster_hex::hex_string(&event.tx_id),
                sender = %sender_address,
                alias = %contextual_alias.unwrap_or_default(),
                "Skipping push dispatch for push-suppressed contextual alias"
            );
            return Ok(());
        }

        let targets = self
            .matching_registrations(
                event.message_type,
                &sender_address,
                receiver_address.as_deref(),
            )
            .await;
        self.dispatch_counters
            .targets
            .fetch_add(targets.len() as u64, Ordering::Relaxed);

        if targets.is_empty() {
            return Ok(());
        }

        let tx_id = faster_hex::hex_string(&event.tx_id);
        let payload_hex = event
            .payload
            .as_ref()
            .map(|payload| faster_hex::hex_string(payload))
            .filter(|payload| payload.len() <= self.config.apns_inline_payload_limit);

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
                    }
                },
                "mutable-content": 1,
                "content-available": 1
            }),
        );
        body.insert("tx_id".to_string(), json!(tx_id));
        body.insert("sender".to_string(), json!(sender_address));
        body.insert(
            "type".to_string(),
            json!(match event.message_type {
                PushMessageType::Handshake => "handshake",
                PushMessageType::Payment => "payment",
                PushMessageType::Contextual => "contextual",
            }),
        );
        body.insert("timestamp".to_string(), json!(event.timestamp));
        if let Some(amount) = event.amount {
            body.insert("amount".to_string(), json!(amount));
        }
        if let Some(payload) = payload_hex {
            body.insert("payload".to_string(), json!(payload));
        }
        let payload = Value::Object(body);

        let mut stale_tokens = Vec::new();
        for registration in targets {
            if self
                .was_recently_dispatched(&registration.device_token, &tx_id, event.message_type)
                .await
            {
                self.dispatch_counters.deduped.fetch_add(1, Ordering::Relaxed);
                debug!(
                    token = %registration.device_token,
                    tx_id = %tx_id,
                    "Skipping duplicate push dispatch"
                );
                continue;
            }

            self.dispatch_counters.attempts.fetch_add(1, Ordering::Relaxed);

            match apns_client
                .send_notification(&registration.device_token, &payload)
                .await
            {
                Ok(ApnsSendOutcome::Sent) => {
                    self.dispatch_counters.sent.fetch_add(1, Ordering::Relaxed);
                    self
                        .mark_recent_dispatch(&registration.device_token, &tx_id, event.message_type)
                        .await;
                    debug!(
                        token = %registration.device_token,
                        tx_id = %tx_id,
                        "Push notification sent"
                    );
                }
                Ok(ApnsSendOutcome::InvalidToken) => {
                    self.dispatch_counters.invalid.fetch_add(1, Ordering::Relaxed);
                    warn!(token = %registration.device_token, "APNs token is invalid, pruning registration");
                    stale_tokens.push(registration.device_token);
                }
                Err(error) => {
                    self.dispatch_counters.failed.fetch_add(1, Ordering::Relaxed);
                    warn!(
                        %error,
                        token = %registration.device_token,
                        tx_id = %tx_id,
                        "APNs delivery failed"
                    );
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

    fn dispatch_dedupe_key(device_token: &str, tx_id: &str, _message_type: PushMessageType) -> String {
        format!("{device_token}:{tx_id}")
    }

    async fn matching_registrations(
        &self,
        message_type: PushMessageType,
        sender_address: &str,
        receiver_address: Option<&str>,
    ) -> Vec<DeviceRegistration> {
        let registrations = self.registrations.read().await;
        let configured_bundle_id = self
            .config
            .apns_bundle_id
            .as_deref()
            .and_then(normalize_bundle_id);

        registrations
            .values()
            .filter(|registration| registration.token_type == "apns")
            .filter(|registration| {
                if let Some(required_bundle_id) = configured_bundle_id.as_deref() {
                    registration.app_bundle_id.as_deref() == Some(required_bundle_id)
                } else {
                    true
                }
            })
            .filter(|registration| match message_type {
                PushMessageType::Contextual => registration.watched_addresses.contains(sender_address),
                PushMessageType::Handshake | PushMessageType::Payment => {
                    let Some(receiver) = receiver_address else {
                        return false;
                    };
                    registration
                        .primary_address
                        .as_deref()
                        .is_some_and(|value| value == receiver)
                        || registration.wallet_address == receiver
                        || registration.watched_addresses.contains(receiver)
                }
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

    pub async fn register(&self, request: PushRegistrationRequest) -> Result<(), PushApiError> {
        let now = now_ms();
        let token = normalize_device_token(&request.device_token)?;
        let token_type = normalize_token_type(&request.token_type);
        self.validate_token_and_type(&token, &token_type)?;

        let auth = self.validate_auth(request.auth.as_ref()).await?;
        let app_bundle_id = normalize_optional_bundle_id(request.app_bundle_id.as_deref());
        let watched_addresses = normalize_addresses(request.watched_addresses);
        let primary_address = normalize_optional_address(request.primary_address.as_deref());
        let aliases = normalize_aliases(request.aliases.unwrap_or_default());

        let mut registrations = self.registrations.write().await;
        let created_at_ms = registrations
            .get(&token)
            .map(|value| value.created_at_ms)
            .unwrap_or(now);

        if let Some(existing) = registrations.get(&token)
            && existing.wallet_pubkey != auth.wallet_pubkey
        {
            return Err(PushApiError::unauthorized(
                "device token is bound to another wallet",
            ));
        }

        registrations.insert(
            token.clone(),
            DeviceRegistration {
                device_token: token,
                token_type,
                platform: request.platform.trim().to_lowercase(),
                app_bundle_id,
                watched_addresses,
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
        let token = normalize_device_token(&request.device_token)?;
        let token_type = normalize_token_type(&request.token_type);
        self.validate_token_and_type(&token, &token_type)?;

        let auth = self.validate_auth(request.auth.as_ref()).await?;
        let app_bundle_id = normalize_optional_bundle_id(request.app_bundle_id.as_deref());
        let watched_addresses = normalize_addresses(request.watched_addresses);
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
        let token = normalize_device_token(&request.device_token)?;
        let token_type = normalize_token_type(&request.token_type);
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

    fn validate_token_and_type(&self, token: &str, token_type: &str) -> Result<(), PushApiError> {
        if token_type == "apns" {
            if token.len() != 64 || !is_hex_string(token) {
                return Err(PushApiError::bad_request("invalid device token length"));
            }
            return Ok(());
        }

        if token_type == "fcm" {
            if !self.config.push_fcm_enabled {
                return Err(PushApiError::bad_request("invalid device token length"));
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
    ) -> anyhow::Result<ApnsSendOutcome> {
        let auth_token = self.auth_token().await?;
        let url = format!("{}/3/device/{}", self.host, device_token);

        let response = self
            .client
            .post(url)
            .header("authorization", format!("bearer {auth_token}"))
            .header("apns-topic", &self.topic)
            .header("apns-push-type", "alert")
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

fn push_message_type_tag(message_type: PushMessageType) -> &'static str {
    match message_type {
        PushMessageType::Handshake => "handshake",
        PushMessageType::Payment => "payment",
        PushMessageType::Contextual => "contextual",
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

fn is_push_suppressed_alias(alias: &str) -> bool {
    alias
        .trim()
        .ends_with(PUSH_SUPPRESSED_ALIAS_SUFFIX)
}

fn normalize_optional_address(value: Option<&str>) -> Option<String> {
    value
        .and_then(normalize_address)
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

fn normalize_device_token(value: &str) -> Result<String, PushApiError> {
    let token = value.trim().to_lowercase();
    if token.is_empty() {
        return Err(PushApiError::bad_request("missing device token"));
    }
    Ok(token)
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

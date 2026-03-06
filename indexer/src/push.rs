use crate::context::IndexerContext;
use anyhow::Context;
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Clone)]
pub struct PushService {
    config: PushConfig,
    registrations_path: PathBuf,
    registrations: Arc<RwLock<HashMap<String, DeviceRegistration>>>,
    challenges: Arc<RwLock<HashMap<String, ChallengeEntry>>>,
}

#[derive(Clone, Debug)]
pub struct PushConfig {
    pub push_provider: String,
    pub push_ios_enabled: bool,
    pub push_fcm_enabled: bool,
    pub challenge_ttl_ms: u64,
    pub challenge_skew_ms: u64,
}

impl PushConfig {
    pub fn from_env() -> Self {
        Self {
            push_provider: read_env_string("PUSH_PROVIDER").unwrap_or_else(|| "apns".to_string()),
            push_ios_enabled: read_env_bool("PUSH_IOS_ENABLED", true),
            push_fcm_enabled: read_env_bool("PUSH_FCM_ENABLED", false),
            challenge_ttl_ms: read_env_u64("PUSH_CHALLENGE_TTL_MS", 120_000),
            challenge_skew_ms: read_env_u64("PUSH_CHALLENGE_SKEW_MS", 15_000),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct DeviceRegistration {
    device_token: String,
    token_type: String,
    platform: String,
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

        info!(
            "Push service initialized provider={} ios_enabled={} fcm_enabled={} registrations={}",
            config.push_provider,
            config.push_ios_enabled,
            config.push_fcm_enabled,
            registrations.len()
        );

        Ok(Self {
            config,
            registrations_path,
            registrations: Arc::new(RwLock::new(registrations)),
            challenges: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub async fn create_challenge(&self) -> PushChallengeResponse {
        let now = now_ms();
        let challenge = PushChallengeResponse {
            nonce: Uuid::new_v4().as_simple().to_string(),
            issued_at_ms: now,
            expires_at_ms: now.saturating_add(self.config.challenge_ttl_ms),
        };

        let mut challenges = self.challenges.write().await;
        challenges.retain(|_, entry| entry.expires_at_ms >= now.saturating_sub(self.config.challenge_skew_ms));
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
            .map_err(|error| PushApiError::internal(format!("failed to persist registrations: {error}")))
    }

    pub async fn update(&self, request: PushUpdateRequest) -> Result<(), PushApiError> {
        let now = now_ms();
        let token = normalize_device_token(&request.device_token)?;
        let token_type = normalize_token_type(&request.token_type);
        self.validate_token_and_type(&token, &token_type)?;

        let auth = self.validate_auth(request.auth.as_ref()).await?;
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
        registration.watched_addresses = watched_addresses;
        registration.primary_address = primary_address;
        registration.aliases = aliases;
        registration.wallet_address = auth.wallet_address;
        registration.updated_at_ms = now;

        let snapshot = registrations.values().cloned().collect::<Vec<_>>();
        drop(registrations);
        persist_registrations(&self.registrations_path, snapshot)
            .await
            .map_err(|error| PushApiError::internal(format!("failed to persist registrations: {error}")))
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
            .map_err(|error| PushApiError::internal(format!("failed to persist registrations: {error}")))
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

    async fn validate_auth(&self, auth: Option<&PushAuthRequest>) -> Result<ValidatedAuth, PushApiError> {
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
            return Err(PushApiError::unauthorized("auth timestamp is in the future"));
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
            return Err(PushApiError::unauthorized("auth timestamp outside challenge window"));
        }

        Ok(ValidatedAuth {
            wallet_pubkey,
            wallet_address,
        })
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

fn normalize_optional_address(value: Option<&str>) -> Option<String> {
    value.and_then(normalize_address)
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
    let data = match tokio::fs::read(path).await {
        Ok(data) => data,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(error) => {
            return Err(anyhow::anyhow!(
                "failed to read push registrations: {error}"
            ));
        }
    };

    let snapshot: RegistrySnapshot = serde_json::from_slice(&data)
        .context("failed to parse push registrations file")?;

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

    let encoded = serde_json::to_vec_pretty(&snapshot)
        .context("failed to serialize push registrations")?;

    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create push registration directory {}", parent.display()))?;
    }

    tokio::fs::write(path, encoded)
        .await
        .with_context(|| format!("failed to write push registrations to {}", path.display()))
}

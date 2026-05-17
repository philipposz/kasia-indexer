use crate::context::IndexerContext;
use anyhow::Context;
use axum::http::StatusCode;
use base64::{Engine, engine::general_purpose};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use kaspa_rpc_core::RpcNetworkType;
use reqwest::StatusCode as HttpStatusCode;
use serde::{Deserialize, Serialize};
use serde_cbor::Value as CborValue;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, RwLock};
use tracing::{info, warn};
use utoipa::ToSchema;
use uuid::Uuid;
use x509_parser::prelude::parse_x509_certificate;

const APP_ATTEST_NONCE_OID: &str = "1.2.840.113635.100.8.2";
const APP_ATTEST_AAGUID_PRODUCTION: [u8; 16] = *b"appattest\0\0\0\0\0\0\0";
const APP_ATTEST_AAGUID_DEVELOPMENT: [u8; 16] = *b"appattestdevelop";
const ANDROID_LOCAL_PROOF_SCHEMA: &str = "kbeam-android-local-proof-v1";
const ANDROID_DEVICE_SCHEMA: &str = "kbeam-android-gift-device-v1";

#[derive(Clone)]
pub struct GiftService {
    config: GiftConfig,
    claims_path: PathBuf,
    claims: Arc<RwLock<HashMap<String, GiftClaimRecord>>>,
    challenges: Arc<RwLock<HashMap<String, ChallengeEntry>>>,
    ip_attempts: Arc<Mutex<HashMap<String, Vec<u64>>>>,
    devicecheck_client: Option<Arc<DeviceCheckClient>>,
    app_attest_verifier: Option<Arc<AppAttestVerifier>>,
}

#[derive(Clone, Debug)]
pub struct GiftConfig {
    pub enabled: bool,
    pub challenge_ttl_ms: u64,
    pub challenge_skew_ms: u64,
    pub amount_sompi: u64,
    pub ip_limit_count: usize,
    pub ip_limit_window_ms: u64,
    pub require_appattest: bool,
    pub appattest_environment: String,
    pub appattest_team_id: Option<String>,
    pub appattest_bundle_id: Option<String>,
    pub require_devicecheck: bool,
    pub allow_simulator_claims: bool,
    pub devicecheck_environment: String,
    pub devicecheck_team_id: Option<String>,
    pub devicecheck_key_id: Option<String>,
    pub devicecheck_key_path: Option<PathBuf>,
    pub devicecheck_timeout_ms: u64,
    pub devicecheck_debug_secret: Option<String>,
    pub payout_command: Option<String>,
    pub payout_timeout_ms: u64,
}

impl GiftConfig {
    pub fn from_env() -> Self {
        let devicecheck_team_id = read_env_string("GIFT_DEVICECHECK_TEAM_ID");
        let appattest_team_id = read_env_string("GIFT_APPATTEST_TEAM_ID")
            .or_else(|| devicecheck_team_id.clone());

        Self {
            enabled: read_env_bool("GIFT_ENABLED", true),
            challenge_ttl_ms: read_env_u64("GIFT_CHALLENGE_TTL_MS", 120_000),
            challenge_skew_ms: read_env_u64("GIFT_CHALLENGE_SKEW_MS", 15_000),
            amount_sompi: read_env_u64("GIFT_AMOUNT_SOMPI", 10_000_000),
            ip_limit_count: read_env_usize("GIFT_IP_RATE_LIMIT_COUNT", 3),
            ip_limit_window_ms: read_env_u64("GIFT_IP_RATE_LIMIT_WINDOW_MS", 86_400_000),
            require_appattest: read_env_bool("GIFT_REQUIRE_APPATTEST", true),
            appattest_environment: read_env_string("GIFT_APPATTEST_ENVIRONMENT")
                .unwrap_or_else(|| "auto".to_string())
                .trim()
                .to_lowercase(),
            appattest_team_id,
            appattest_bundle_id: read_env_string("GIFT_APPATTEST_BUNDLE_ID")
                .or_else(|| read_env_string("PUSH_APNS_BUNDLE_ID")),
            require_devicecheck: read_env_bool("GIFT_REQUIRE_DEVICECHECK", true),
            allow_simulator_claims: read_env_bool("GIFT_ALLOW_SIMULATOR_CLAIMS", false),
            devicecheck_environment: read_env_string("GIFT_DEVICECHECK_ENVIRONMENT")
                .unwrap_or_else(|| "auto".to_string())
                .trim()
                .to_lowercase(),
            devicecheck_team_id,
            devicecheck_key_id: read_env_string("GIFT_DEVICECHECK_KEY_ID"),
            devicecheck_key_path: read_env_string("GIFT_DEVICECHECK_KEY_PATH").map(PathBuf::from),
            devicecheck_timeout_ms: read_env_u64("GIFT_DEVICECHECK_TIMEOUT_MS", 10_000),
            devicecheck_debug_secret: read_env_string("GIFT_DEVICECHECK_DEBUG_SECRET"),
            payout_command: read_env_string("GIFT_PAYOUT_COMMAND"),
            payout_timeout_ms: read_env_u64("GIFT_PAYOUT_TIMEOUT_MS", 30_000),
        }
    }
}

#[derive(Debug)]
pub struct GiftApiError {
    status: StatusCode,
    message: String,
}

impl GiftApiError {
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            message: message.into(),
        }
    }

    pub fn too_many_requests(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            message: message.into(),
        }
    }

    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: message.into(),
        }
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: message.into(),
        }
    }

    pub fn service_unavailable(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: message.into(),
        }
    }

    pub fn into_response(self) -> (StatusCode, axum::Json<GiftErrorResponse>) {
        (
            self.status,
            axum::Json(GiftErrorResponse {
                error: self.message,
            }),
        )
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct GiftErrorResponse {
    pub error: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct GiftChallengeResponse {
    pub challenge: String,
    pub nonce: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GiftClaimRequest {
    pub platform: Option<String>,
    #[serde(alias = "proof_schema")]
    pub proof_schema: Option<String>,
    #[serde(alias = "proof_format")]
    pub proof_format: Option<String>,
    #[serde(alias = "device_token")]
    pub device_token: String,
    #[serde(alias = "wallet_address")]
    pub wallet_address: String,
    pub attestation: String,
    #[serde(alias = "key_id")]
    pub key_id: String,
    pub challenge: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct GiftClaimResponse {
    pub tx_id: String,
    pub claim_id: String,
    pub amount_sompi: u64,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GiftDeviceCheckDebugQueryRequest {
    #[serde(alias = "device_token")]
    pub device_token: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct GiftDeviceCheckDebugQueryResponse {
    pub bit0: bool,
    pub device_token_sha256: String,
    pub primary_host: String,
    pub secondary_host: Option<String>,
    pub environment: String,
    pub timeout_ms: u64,
    pub require_devicecheck: bool,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GiftDeviceCheckDebugUpdateRequest {
    #[serde(alias = "device_token")]
    pub device_token: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct GiftDeviceCheckDebugUpdateResponse {
    pub bit0_after_update: bool,
    pub updated: bool,
    pub device_token_sha256: String,
    pub primary_host: String,
    pub secondary_host: Option<String>,
    pub environment: String,
    pub timeout_ms: u64,
    pub require_devicecheck: bool,
}

#[derive(Clone)]
struct ChallengeEntry {
    issued_at_ms: u64,
    expires_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum GiftClaimStatus {
    Reserved,
    PayoutSubmitted,
    Completed,
    Failed,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GiftClaimRecord {
    claim_id: String,
    wallet_address: String,
    device_fingerprint: String,
    tx_id: Option<String>,
    status: GiftClaimStatus,
    reason: Option<String>,
    amount_sompi: u64,
    source_ip: Option<String>,
    created_at_ms: u64,
    updated_at_ms: u64,
}

#[derive(Serialize, Deserialize)]
struct GiftClaimsSnapshot {
    claims: Vec<GiftClaimRecord>,
}

#[derive(Clone)]
struct DeviceCheckClient {
    client: reqwest::Client,
    host: String,
    secondary_host: Option<String>,
    team_id: String,
    key_id: String,
    encoding_key: EncodingKey,
}

#[derive(Serialize)]
struct DeviceCheckJwtClaims<'a> {
    iss: &'a str,
    iat: usize,
    exp: usize,
}

#[derive(Serialize)]
struct DeviceCheckQueryRequest<'a> {
    device_token: &'a str,
    transaction_id: &'a str,
    timestamp: u64,
}

#[derive(Serialize)]
struct DeviceCheckUpdateRequest<'a> {
    device_token: &'a str,
    transaction_id: &'a str,
    timestamp: u64,
    bit0: bool,
    bit1: bool,
}

#[derive(Debug, Deserialize)]
struct DeviceCheckErrorResponse {
    reason: Option<String>,
}

#[derive(Clone)]
struct AppAttestVerifier {
    expected_app_id_hash: [u8; 32],
    expected_aaguids: Vec<[u8; 16]>,
}

struct ParsedAppAttestation {
    auth_data: Vec<u8>,
    leaf_certificate_der: Vec<u8>,
}

struct ParsedAuthData {
    rp_id_hash: [u8; 32],
    sign_count: u32,
    aaguid: [u8; 16],
    credential_id: Vec<u8>,
}

impl GiftService {
    pub async fn from_context(context: &IndexerContext) -> anyhow::Result<Self> {
        let config = GiftConfig::from_env();
        let claims_path = read_env_string("GIFT_CLAIMS_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|| context.db_path.join("gift-claims.json"));
        let claims = load_claims(&claims_path).await?;

        let devicecheck_client = DeviceCheckClient::from_config(&config, context.network_type.into())
            .inspect_err(|error| warn!(%error, "Gift DeviceCheck disabled"))
            .ok()
            .map(Arc::new);

        let app_attest_verifier =
            AppAttestVerifier::from_config(&config, context.network_type.into())
                .inspect_err(|error| warn!(%error, "Gift App Attest verification disabled"))
                .ok()
                .map(Arc::new);

        if config.require_devicecheck && devicecheck_client.is_none() {
            warn!("Gift DeviceCheck required but not configured; claims will be rejected");
        }

        if config.require_appattest && app_attest_verifier.is_none() {
            warn!("Gift App Attest required but not configured; claims will be rejected");
        }

        info!(
            "Gift service initialized enabled={} claims={} amount_sompi={} require_appattest={} require_devicecheck={} simulator_claims={} debug_devicecheck={}",
            config.enabled,
            claims.len(),
            config.amount_sompi,
            config.require_appattest,
            config.require_devicecheck,
            config.allow_simulator_claims,
            config
                .devicecheck_debug_secret
                .as_ref()
                .map(|value| !value.trim().is_empty())
                .unwrap_or(false)
        );

        Ok(Self {
            config,
            claims_path,
            claims: Arc::new(RwLock::new(claims)),
            challenges: Arc::new(RwLock::new(HashMap::new())),
            ip_attempts: Arc::new(Mutex::new(HashMap::new())),
            devicecheck_client,
            app_attest_verifier,
        })
    }

    pub async fn create_challenge(&self) -> Result<GiftChallengeResponse, GiftApiError> {
        if !self.config.enabled {
            return Err(GiftApiError::service_unavailable("gift claim service is disabled"));
        }
        let now = now_ms();
        let nonce = Uuid::new_v4().as_simple().to_string();
        let response = GiftChallengeResponse {
            challenge: nonce.clone(),
            nonce: nonce.clone(),
            issued_at_ms: now,
            expires_at_ms: now.saturating_add(self.config.challenge_ttl_ms),
        };

        let mut challenges = self.challenges.write().await;
        challenges.retain(|_, entry| {
            entry.expires_at_ms >= now.saturating_sub(self.config.challenge_skew_ms)
        });
        challenges.insert(
            nonce,
            ChallengeEntry {
                issued_at_ms: response.issued_at_ms,
                expires_at_ms: response.expires_at_ms,
            },
        );

        Ok(response)
    }

    pub async fn debug_query_devicecheck_bit0(
        &self,
        request: GiftDeviceCheckDebugQueryRequest,
        debug_secret_header: Option<&str>,
    ) -> Result<GiftDeviceCheckDebugQueryResponse, GiftApiError> {
        self.require_devicecheck_debug_authorization(debug_secret_header)?;

        let normalized_device_token = request.device_token.trim();
        if normalized_device_token.is_empty() {
            return Err(GiftApiError::bad_request("missing device token"));
        }

        let token_bytes = validate_base64_blob(normalized_device_token, "invalid device token")?;
        let token_fingerprint = sha256_hex(&token_bytes);

        let client = self.require_devicecheck_client()?;
        let bit0 = client
            .query_bit0(normalized_device_token)
            .await
            .map_err(|error| GiftApiError::internal(format!("devicecheck query failed: {error}")))?;

        Ok(GiftDeviceCheckDebugQueryResponse {
            bit0,
            device_token_sha256: token_fingerprint,
            primary_host: client.host.clone(),
            secondary_host: client.secondary_host.clone(),
            environment: self.config.devicecheck_environment.clone(),
            timeout_ms: self.config.devicecheck_timeout_ms,
            require_devicecheck: self.config.require_devicecheck,
        })
    }

    pub async fn debug_update_devicecheck_bit0(
        &self,
        request: GiftDeviceCheckDebugUpdateRequest,
        debug_secret_header: Option<&str>,
    ) -> Result<GiftDeviceCheckDebugUpdateResponse, GiftApiError> {
        self.require_devicecheck_debug_authorization(debug_secret_header)?;

        let normalized_device_token = request.device_token.trim();
        if normalized_device_token.is_empty() {
            return Err(GiftApiError::bad_request("missing device token"));
        }

        let token_bytes = validate_base64_blob(normalized_device_token, "invalid device token")?;
        let token_fingerprint = sha256_hex(&token_bytes);

        let client = self.require_devicecheck_client()?;
        client
            .update_bit0_true(normalized_device_token)
            .await
            .map_err(|error| GiftApiError::internal(format!("devicecheck update failed: {error}")))?;

        let bit0_after_update = client
            .query_bit0(normalized_device_token)
            .await
            .map_err(|error| {
                GiftApiError::internal(format!("devicecheck query after update failed: {error}"))
            })?;

        Ok(GiftDeviceCheckDebugUpdateResponse {
            bit0_after_update,
            updated: true,
            device_token_sha256: token_fingerprint,
            primary_host: client.host.clone(),
            secondary_host: client.secondary_host.clone(),
            environment: self.config.devicecheck_environment.clone(),
            timeout_ms: self.config.devicecheck_timeout_ms,
            require_devicecheck: self.config.require_devicecheck,
        })
    }

    pub async fn claim(
        &self,
        request: GiftClaimRequest,
        source_ip: Option<String>,
    ) -> Result<GiftClaimResponse, GiftApiError> {
        if !self.config.enabled {
            return Err(GiftApiError::service_unavailable("gift claim service is disabled"));
        }

        let now = now_ms();
        let wallet_address = normalize_wallet_address(&request.wallet_address)
            .ok_or_else(|| GiftApiError::bad_request("invalid wallet address"))?;

        let challenge = request.challenge.trim().to_string();
        if challenge.is_empty() {
            return Err(GiftApiError::bad_request("missing challenge"));
        }
        self.consume_challenge(&challenge, now).await?;

        let device_token_bytes = validate_base64_blob(&request.device_token, "invalid device token")?;
        let attestation_bytes = validate_base64_blob(&request.attestation, "invalid attestation")?;

        let key_id = request.key_id.trim();
        if key_id.is_empty() {
            return Err(GiftApiError::bad_request("missing key id"));
        }

        let is_android_claim = request
            .platform
            .as_deref()
            .map(|value| value.eq_ignore_ascii_case("android"))
            .unwrap_or(false)
            || request
                .proof_schema
                .as_deref()
                .map(|value| value == ANDROID_LOCAL_PROOF_SCHEMA)
                .unwrap_or(false)
            || key_id.starts_with("android-local-proof-v1:");

        let skip_device_attestation = self.config.allow_simulator_claims && key_id.starts_with("simulator-");

        let android_device_fingerprint = if is_android_claim {
            if let Some(proof_format) = request.proof_format.as_deref() {
                if proof_format != "json-base64" {
                    return Err(GiftApiError::bad_request("invalid Android proof format"));
                }
            }
            Some(verify_android_local_proof(
                &device_token_bytes,
                &attestation_bytes,
                key_id,
                &challenge,
                &wallet_address,
            )?)
        } else {
            None
        };

        if self.config.require_appattest && !skip_device_attestation && !is_android_claim {
            let verifier = self.require_app_attest_verifier()?;
            verifier
                .verify_attestation(&attestation_bytes, key_id, &challenge)
                .map_err(|error| {
                    GiftApiError::bad_request(format!("invalid app attestation: {error}"))
                })?;
        }

        let device_fingerprint =
            android_device_fingerprint.unwrap_or_else(|| sha256_hex(&device_token_bytes));
        let normalized_ip = normalize_source_ip(source_ip.as_deref());
        self.enforce_ip_rate_limit(normalized_ip.as_deref(), now).await?;

        let skip_devicecheck = skip_device_attestation || is_android_claim;
        if self.config.require_devicecheck && !skip_devicecheck {
            let client = self.require_devicecheck_client()?;
            let already_claimed = client
                .query_bit0(request.device_token.trim())
                .await
                .map_err(|error| {
                    GiftApiError::internal(format!("device verification failed: {error}"))
                })?;

            if already_claimed {
                let rejected = GiftClaimRecord {
                    claim_id: Uuid::new_v4().as_simple().to_string(),
                    wallet_address: wallet_address.clone(),
                    device_fingerprint: device_fingerprint.clone(),
                    tx_id: None,
                    status: GiftClaimStatus::Rejected,
                    reason: Some("already claimed on device".to_string()),
                    amount_sompi: self.config.amount_sompi,
                    source_ip: normalized_ip.clone(),
                    created_at_ms: now,
                    updated_at_ms: now,
                };
                self.persist_claim(rejected).await?;
                return Err(GiftApiError::conflict("gift already claimed on this device"));
            }
        }

        let claim_id = Uuid::new_v4().as_simple().to_string();
        let mut record = self
            .reserve_claim(
                claim_id.clone(),
                wallet_address.clone(),
                device_fingerprint.clone(),
                normalized_ip,
                now,
            )
            .await?;

        let tx_id = match self
            .run_payout_command(&claim_id, &wallet_address, self.config.amount_sompi)
            .await
        {
            Ok(value) => value,
            Err(error) => {
                record.status = GiftClaimStatus::Failed;
                record.reason = Some(format!("payout failed: {error}"));
                record.updated_at_ms = now_ms();
                self.persist_claim(record).await?;
                return Err(GiftApiError::internal("gift payout failed"));
            }
        };

        record.status = GiftClaimStatus::PayoutSubmitted;
        record.tx_id = Some(tx_id.clone());
        record.updated_at_ms = now_ms();
        self.persist_claim(record.clone()).await?;

        if self.config.require_devicecheck && !skip_devicecheck {
            let client = self.require_devicecheck_client()?;
            if let Err(error) = client.update_bit0_true(request.device_token.trim()).await {
                record.status = GiftClaimStatus::Failed;
                record.reason = Some(format!("devicecheck update failed: {error}"));
                record.updated_at_ms = now_ms();
                self.persist_claim(record).await?;
                return Err(GiftApiError::internal(
                    "gift payout sent but device lock update failed",
                ));
            }
        }

        record.status = GiftClaimStatus::Completed;
        record.reason = None;
        record.updated_at_ms = now_ms();
        self.persist_claim(record).await?;

        Ok(GiftClaimResponse {
            tx_id,
            claim_id,
            amount_sompi: self.config.amount_sompi,
        })
    }

    async fn consume_challenge(&self, challenge: &str, now: u64) -> Result<(), GiftApiError> {
        let skew = self.config.challenge_skew_ms;
        let mut challenges = self.challenges.write().await;
        challenges.retain(|_, entry| entry.expires_at_ms.saturating_add(skew) >= now);

        let entry = challenges
            .remove(challenge)
            .ok_or_else(|| GiftApiError::bad_request("invalid challenge"))?;

        if now.saturating_add(skew) < entry.issued_at_ms {
            return Err(GiftApiError::bad_request("challenge not valid yet"));
        }
        if now > entry.expires_at_ms.saturating_add(skew) {
            return Err(GiftApiError::bad_request("challenge expired"));
        }

        Ok(())
    }

    async fn enforce_ip_rate_limit(
        &self,
        source_ip: Option<&str>,
        now: u64,
    ) -> Result<(), GiftApiError> {
        let Some(ip) = source_ip else {
            return Ok(());
        };

        let cutoff = now.saturating_sub(self.config.ip_limit_window_ms);
        let mut attempts = self.ip_attempts.lock().await;
        let records = attempts.entry(ip.to_string()).or_default();
        records.retain(|timestamp| *timestamp >= cutoff);

        if records.len() >= self.config.ip_limit_count {
            return Err(GiftApiError::too_many_requests(
                "too many gift claims from this IP",
            ));
        }

        records.push(now);
        Ok(())
    }

    async fn reserve_claim(
        &self,
        claim_id: String,
        wallet_address: String,
        device_fingerprint: String,
        source_ip: Option<String>,
        created_at_ms: u64,
    ) -> Result<GiftClaimRecord, GiftApiError> {
        let mut claims = self.claims.write().await;

        let wallet_blocked = claims.values().any(|claim| {
            claim.wallet_address == wallet_address
                && claim_consumes_unique_slot(claim)
        });

        if wallet_blocked {
            return Err(GiftApiError::conflict(
                "gift already claimed for this wallet address",
            ));
        }

        let device_blocked = claims.values().any(|claim| {
            claim.device_fingerprint == device_fingerprint
                && claim_consumes_unique_slot(claim)
        });

        if device_blocked {
            return Err(GiftApiError::conflict("gift already claimed on this device"));
        }

        let record = GiftClaimRecord {
            claim_id: claim_id.clone(),
            wallet_address,
            device_fingerprint,
            tx_id: None,
            status: GiftClaimStatus::Reserved,
            reason: None,
            amount_sompi: self.config.amount_sompi,
            source_ip,
            created_at_ms,
            updated_at_ms: created_at_ms,
        };
        claims.insert(claim_id, record.clone());
        let snapshot = claims.values().cloned().collect::<Vec<_>>();
        drop(claims);

        persist_claims(&self.claims_path, snapshot)
            .await
            .map_err(|error| GiftApiError::internal(format!("failed to persist claims: {error}")))?;

        Ok(record)
    }

    async fn persist_claim(&self, record: GiftClaimRecord) -> Result<(), GiftApiError> {
        let mut claims = self.claims.write().await;
        claims.insert(record.claim_id.clone(), record);
        let snapshot = claims.values().cloned().collect::<Vec<_>>();
        drop(claims);

        persist_claims(&self.claims_path, snapshot)
            .await
            .map_err(|error| GiftApiError::internal(format!("failed to persist claims: {error}")))
    }

    fn require_devicecheck_client(&self) -> Result<&DeviceCheckClient, GiftApiError> {
        if !self.config.require_devicecheck {
            return Err(GiftApiError::service_unavailable(
                "device verification is disabled",
            ));
        }

        self.devicecheck_client
            .as_deref()
            .ok_or_else(|| GiftApiError::service_unavailable("device verification is not configured"))
    }

    fn require_devicecheck_debug_authorization(
        &self,
        provided_secret: Option<&str>,
    ) -> Result<(), GiftApiError> {
        let configured_secret = self
            .config
            .devicecheck_debug_secret
            .as_ref()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                GiftApiError::service_unavailable(
                    "devicecheck debug endpoint is disabled (set GIFT_DEVICECHECK_DEBUG_SECRET)",
                )
            })?;

        let provided_secret = provided_secret
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| GiftApiError::unauthorized("missing x-gift-debug-secret header"))?;

        if provided_secret != configured_secret {
            return Err(GiftApiError::unauthorized("invalid x-gift-debug-secret header"));
        }

        Ok(())
    }

    fn require_app_attest_verifier(&self) -> Result<&AppAttestVerifier, GiftApiError> {
        if !self.config.require_appattest {
            return Err(GiftApiError::service_unavailable(
                "app attestation verification is disabled",
            ));
        }

        self.app_attest_verifier.as_deref().ok_or_else(|| {
            GiftApiError::service_unavailable("app attestation verification is not configured")
        })
    }

    async fn run_payout_command(
        &self,
        claim_id: &str,
        wallet_address: &str,
        amount_sompi: u64,
    ) -> anyhow::Result<String> {
        let command_template = self
            .config
            .payout_command
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("GIFT_PAYOUT_COMMAND is not configured"))?;

        let amount_kas = sompi_to_kas_decimal(amount_sompi);
        let command = command_template
            .replace("{wallet}", wallet_address)
            .replace("{sompi}", &amount_sompi.to_string())
            .replace("{amount_kas}", &amount_kas)
            .replace("{claim_id}", claim_id);

        let timeout_ms = self.config.payout_timeout_ms;
        let command_for_log = command.clone();
        let join_handle = tokio::task::spawn_blocking(move || {
            std::process::Command::new("sh")
                .arg("-lc")
                .arg(&command)
                .output()
        });

        let output = tokio::time::timeout(Duration::from_millis(timeout_ms), join_handle)
            .await
            .context("payout command timed out")?
            .context("payout command task failed")?
            .context("failed to execute payout command")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            anyhow::bail!(
                "payout command failed status={} stdout='{}' stderr='{}' cmd='{}'",
                output.status,
                stdout,
                stderr,
                command_for_log
            );
        }

        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let tx_id = stdout
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty())
            .ok_or_else(|| anyhow::anyhow!("payout command produced empty output"))?
            .to_string();

        Ok(tx_id)
    }
}

impl AppAttestVerifier {
    fn from_config(config: &GiftConfig, network: RpcNetworkType) -> anyhow::Result<Self> {
        let team_id = config
            .appattest_team_id
            .clone()
            .ok_or_else(|| anyhow::anyhow!("GIFT_APPATTEST_TEAM_ID is not set"))?;
        let bundle_id = config
            .appattest_bundle_id
            .clone()
            .ok_or_else(|| anyhow::anyhow!("GIFT_APPATTEST_BUNDLE_ID is not set"))?;

        let expected_aaguids = match config.appattest_environment.as_str() {
            "sandbox" | "development" => vec![APP_ATTEST_AAGUID_DEVELOPMENT],
            "production" | "prod" => vec![APP_ATTEST_AAGUID_PRODUCTION],
            "auto" => {
                // In auto mode we accept both environments to avoid hard failures when
                // development-signed devices hit mainnet infra (or vice versa).
                if matches!(network, RpcNetworkType::Mainnet) {
                    vec![APP_ATTEST_AAGUID_PRODUCTION, APP_ATTEST_AAGUID_DEVELOPMENT]
                } else {
                    vec![APP_ATTEST_AAGUID_DEVELOPMENT, APP_ATTEST_AAGUID_PRODUCTION]
                }
            }
            value => anyhow::bail!("unsupported GIFT_APPATTEST_ENVIRONMENT value: {value}"),
        };

        let app_id = format!("{}.{}", team_id.trim(), bundle_id.trim());
        if app_id.trim().is_empty() || app_id.contains("..") {
            anyhow::bail!("invalid App Attest app identifier");
        }

        let mut expected_app_id_hash = [0u8; 32];
        expected_app_id_hash.copy_from_slice(Sha256::digest(app_id.as_bytes()).as_slice());

        Ok(Self {
            expected_app_id_hash,
            expected_aaguids,
        })
    }

    fn verify_attestation(
        &self,
        attestation_bytes: &[u8],
        key_id: &str,
        challenge: &str,
    ) -> anyhow::Result<()> {
        let parsed = parse_app_attestation_object(attestation_bytes)?;
        let auth_data = parse_auth_data(&parsed.auth_data)?;

        if auth_data.rp_id_hash != self.expected_app_id_hash {
            anyhow::bail!("rpId hash mismatch");
        }

        if auth_data.sign_count != 0 {
            anyhow::bail!("invalid attestation sign counter");
        }

        if !self
            .expected_aaguids
            .iter()
            .any(|candidate| *candidate == auth_data.aaguid)
        {
            let aaguid_hex = format_aaguid_hex(&auth_data.aaguid);
            if !is_probable_app_attest_aaguid(&auth_data.aaguid) {
                anyhow::bail!("unexpected app attest environment ({aaguid_hex})");
            }
            warn!(
                aaguid = %aaguid_hex,
                "Gift App Attest received non-canonical AAGUID, accepting as App Attest"
            );
        }

        let key_id_bytes = decode_base64_any(key_id)
            .ok_or_else(|| anyhow::anyhow!("key id is not valid base64/base64url"))?;
        if key_id_bytes != auth_data.credential_id {
            anyhow::bail!("key id does not match attested credential id");
        }

        let (_, certificate) = parse_x509_certificate(&parsed.leaf_certificate_der)
            .map_err(|_| anyhow::anyhow!("failed to parse app attest leaf certificate"))?;
        let nonce_extension = certificate
            .extensions()
            .iter()
            .find(|extension| extension.oid.to_id_string() == APP_ATTEST_NONCE_OID)
            .ok_or_else(|| anyhow::anyhow!("app attest nonce extension is missing"))?;
        let certificate_nonce = extract_nonce_from_der_extension(nonce_extension.value)
            .ok_or_else(|| anyhow::anyhow!("failed to parse app attest nonce extension"))?;

        let challenge_hash = Sha256::digest(challenge.as_bytes());
        let mut nonce_input = Vec::with_capacity(parsed.auth_data.len() + challenge_hash.len());
        nonce_input.extend_from_slice(&parsed.auth_data);
        nonce_input.extend_from_slice(&challenge_hash);
        let expected_nonce = Sha256::digest(&nonce_input);
        let mut expected_nonce_bytes = [0u8; 32];
        expected_nonce_bytes.copy_from_slice(expected_nonce.as_slice());

        if certificate_nonce != expected_nonce_bytes {
            anyhow::bail!("attestation nonce mismatch");
        }

        Ok(())
    }
}

impl DeviceCheckClient {
    fn from_config(config: &GiftConfig, network: RpcNetworkType) -> anyhow::Result<Self> {
        let team_id = config
            .devicecheck_team_id
            .clone()
            .ok_or_else(|| anyhow::anyhow!("GIFT_DEVICECHECK_TEAM_ID is not set"))?;
        let key_id = config
            .devicecheck_key_id
            .clone()
            .ok_or_else(|| anyhow::anyhow!("GIFT_DEVICECHECK_KEY_ID is not set"))?;
        let key_path = config
            .devicecheck_key_path
            .clone()
            .ok_or_else(|| anyhow::anyhow!("GIFT_DEVICECHECK_KEY_PATH is not set"))?;

        let key_bytes = std::fs::read(&key_path)
            .with_context(|| format!("failed to read DeviceCheck key file {}", key_path.display()))?;
        let encoding_key = EncodingKey::from_ec_pem(&key_bytes)
            .context("failed to parse DeviceCheck private key (.p8 PEM expected)")?;

        let (host, secondary_host) = match config.devicecheck_environment.as_str() {
            "sandbox" | "development" => (
                "https://api.development.devicecheck.apple.com".to_string(),
                None,
            ),
            "production" | "prod" => ("https://api.devicecheck.apple.com".to_string(), None),
            "auto" => {
                if matches!(network, RpcNetworkType::Mainnet) {
                    (
                        "https://api.devicecheck.apple.com".to_string(),
                        Some("https://api.development.devicecheck.apple.com".to_string()),
                    )
                } else {
                    (
                        "https://api.development.devicecheck.apple.com".to_string(),
                        Some("https://api.devicecheck.apple.com".to_string()),
                    )
                }
            }
            value => anyhow::bail!("unsupported GIFT_DEVICECHECK_ENVIRONMENT value: {value}"),
        };

        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(config.devicecheck_timeout_ms))
            .build()
            .context("failed to build DeviceCheck HTTP client")?;

        Ok(Self {
            client,
            host,
            secondary_host,
            team_id,
            key_id,
            encoding_key,
        })
    }

    fn host_candidates(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.host.as_str()).chain(self.secondary_host.as_deref())
    }

    async fn query_bit0(&self, device_token: &str) -> anyhow::Result<bool> {
        let transaction_id = Uuid::new_v4().to_string();
        let timestamp = now_ms();
        let request = DeviceCheckQueryRequest {
            device_token,
            transaction_id: &transaction_id,
            timestamp,
        };

        let auth_token = self.auth_token()?;
        let mut attempt_errors: Vec<String> = Vec::new();

        for (attempt_index, host) in self.host_candidates().enumerate() {
            let response = match self
                .client
                .post(format!("{host}/v1/query_two_bits"))
                .bearer_auth(&auth_token)
                .json(&request)
                .send()
                .await
            {
                Ok(response) => response,
                Err(error) => {
                    let detail = format!("host={} transport_error={}", host, error);
                    let should_retry = attempt_index == 0 && self.secondary_host.is_some();
                    if should_retry {
                        warn!("DeviceCheck query retrying alternate host after {}", detail);
                        attempt_errors.push(detail);
                        continue;
                    }
                    anyhow::bail!("failed to call DeviceCheck query_two_bits ({detail})");
                }
            };

            if response.status().is_success() {
                let content_type = response
                    .headers()
                    .get(reqwest::header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or("unknown")
                    .to_string();
                let body = response
                    .text()
                    .await
                    .context("failed to read DeviceCheck query response body")?;
                let bit0 = parse_devicecheck_query_bit0(&body).with_context(|| {
                    format!(
                        "failed to decode DeviceCheck query response content_type={} body={}",
                        content_type,
                        summarize_devicecheck_body_for_log(&body)
                    )
                })?;
                return Ok(bit0);
            }

            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            let reason = parse_devicecheck_reason(&body).unwrap_or_else(|| "unknown".to_string());
            let detail = format!("host={} status={} reason={}", host, status, reason);
            let should_retry = attempt_index == 0
                && self.secondary_host.is_some()
                && matches!(status, HttpStatusCode::BAD_REQUEST | HttpStatusCode::UNAUTHORIZED);

            if should_retry {
                warn!("DeviceCheck query retrying alternate host after {}", detail);
                attempt_errors.push(detail);
                continue;
            }

            if status == HttpStatusCode::UNAUTHORIZED {
                anyhow::bail!(
                    "DeviceCheck query auth rejected {} (check GIFT_DEVICECHECK_TEAM_ID, GIFT_DEVICECHECK_KEY_ID, GIFT_DEVICECHECK_KEY_PATH)",
                    detail
                );
            }

            anyhow::bail!("DeviceCheck query failed {}", detail);
        }

        if attempt_errors.is_empty() {
            anyhow::bail!("DeviceCheck query failed: no host candidates available");
        }
        anyhow::bail!(
            "DeviceCheck query failed after host fallback {}",
            attempt_errors.join(" -> ")
        )
    }

    async fn update_bit0_true(&self, device_token: &str) -> anyhow::Result<()> {
        let transaction_id = Uuid::new_v4().to_string();
        let timestamp = now_ms();
        let request = DeviceCheckUpdateRequest {
            device_token,
            transaction_id: &transaction_id,
            timestamp,
            bit0: true,
            bit1: false,
        };

        let auth_token = self.auth_token()?;
        let mut attempt_errors: Vec<String> = Vec::new();

        for (attempt_index, host) in self.host_candidates().enumerate() {
            let response = match self
                .client
                .post(format!("{host}/v1/update_two_bits"))
                .bearer_auth(&auth_token)
                .json(&request)
                .send()
                .await
            {
                Ok(response) => response,
                Err(error) => {
                    let detail = format!("host={} transport_error={}", host, error);
                    let should_retry = attempt_index == 0 && self.secondary_host.is_some();
                    if should_retry {
                        warn!("DeviceCheck update retrying alternate host after {}", detail);
                        attempt_errors.push(detail);
                        continue;
                    }
                    anyhow::bail!("failed to call DeviceCheck update_two_bits ({detail})");
                }
            };

            if response.status().is_success() {
                return Ok(());
            }

            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            let reason = parse_devicecheck_reason(&body).unwrap_or_else(|| "unknown".to_string());
            let detail = format!("host={} status={} reason={}", host, status, reason);
            let should_retry = attempt_index == 0
                && self.secondary_host.is_some()
                && matches!(status, HttpStatusCode::BAD_REQUEST | HttpStatusCode::UNAUTHORIZED);

            if should_retry {
                warn!("DeviceCheck update retrying alternate host after {}", detail);
                attempt_errors.push(detail);
                continue;
            }

            if status == HttpStatusCode::UNAUTHORIZED {
                anyhow::bail!(
                    "DeviceCheck update auth rejected {} (check GIFT_DEVICECHECK_TEAM_ID, GIFT_DEVICECHECK_KEY_ID, GIFT_DEVICECHECK_KEY_PATH)",
                    detail
                );
            }

            anyhow::bail!("DeviceCheck update failed {}", detail);
        }

        if attempt_errors.is_empty() {
            anyhow::bail!("DeviceCheck update failed: no host candidates available");
        }
        anyhow::bail!(
            "DeviceCheck update failed after host fallback {}",
            attempt_errors.join(" -> ")
        )
    }

    fn auth_token(&self) -> anyhow::Result<String> {
        let now_secs = now_ms() / 1000;
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.key_id.clone());

        let claims = DeviceCheckJwtClaims {
            iss: &self.team_id,
            iat: now_secs as usize,
            exp: now_secs.saturating_add(55 * 60) as usize,
        };

        jsonwebtoken::encode(&header, &claims, &self.encoding_key)
            .context("failed to sign DeviceCheck JWT")
    }
}

fn parse_app_attestation_object(attestation_bytes: &[u8]) -> anyhow::Result<ParsedAppAttestation> {
    let parsed: CborValue = serde_cbor::from_slice(attestation_bytes)
        .context("attestation payload is not valid CBOR")?;
    let parsed_map = expect_cbor_map(&parsed, "attestation")?;

    let fmt = expect_cbor_text(parsed_map.get(&CborValue::Text("fmt".to_string())), "fmt")?;
    if fmt != "apple-appattest" {
        anyhow::bail!("unexpected attestation format");
    }

    let auth_data = expect_cbor_bytes(
        parsed_map.get(&CborValue::Text("authData".to_string())),
        "authData",
    )?
    .to_vec();

    let att_stmt_value = parsed_map
        .get(&CborValue::Text("attStmt".to_string()))
        .ok_or_else(|| anyhow::anyhow!("attestation statement is missing"))?;
    let att_stmt = expect_cbor_map(att_stmt_value, "attStmt")?;
    let x5c = expect_cbor_array(att_stmt.get(&CborValue::Text("x5c".to_string())), "x5c")?;

    let Some(CborValue::Bytes(leaf_certificate_der)) = x5c.first() else {
        anyhow::bail!("attestation certificate chain is missing");
    };

    Ok(ParsedAppAttestation {
        auth_data,
        leaf_certificate_der: leaf_certificate_der.clone(),
    })
}

fn parse_auth_data(auth_data: &[u8]) -> anyhow::Result<ParsedAuthData> {
    const RP_ID_HASH_LEN: usize = 32;
    const FLAGS_OFFSET: usize = RP_ID_HASH_LEN;
    const SIGN_COUNT_OFFSET: usize = FLAGS_OFFSET + 1;
    const HEADER_LEN: usize = SIGN_COUNT_OFFSET + 4;
    const AAGUID_LEN: usize = 16;

    if auth_data.len() < HEADER_LEN + AAGUID_LEN + 2 {
        anyhow::bail!("authData is too short");
    }

    let mut rp_id_hash = [0u8; RP_ID_HASH_LEN];
    rp_id_hash.copy_from_slice(&auth_data[..RP_ID_HASH_LEN]);

    let flags = auth_data[FLAGS_OFFSET];
    if flags & 0x40 == 0 {
        anyhow::bail!("attested credential data is missing");
    }

    let sign_count = u32::from_be_bytes(
        auth_data[SIGN_COUNT_OFFSET..SIGN_COUNT_OFFSET + 4]
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid authData sign counter"))?,
    );

    let mut cursor = HEADER_LEN;
    let mut aaguid = [0u8; AAGUID_LEN];
    aaguid.copy_from_slice(&auth_data[cursor..cursor + AAGUID_LEN]);
    cursor += AAGUID_LEN;

    let credential_id_len = u16::from_be_bytes(
        auth_data[cursor..cursor + 2]
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid credential id length"))?,
    ) as usize;
    cursor += 2;

    if auth_data.len() < cursor + credential_id_len {
        anyhow::bail!("credential id length exceeds authData size");
    }

    let credential_id = auth_data[cursor..cursor + credential_id_len].to_vec();
    if credential_id.is_empty() {
        anyhow::bail!("credential id is empty");
    }

    Ok(ParsedAuthData {
        rp_id_hash,
        sign_count,
        aaguid,
        credential_id,
    })
}

fn is_probable_app_attest_aaguid(aaguid: &[u8; 16]) -> bool {
    aaguid.starts_with(b"appattest")
}

fn format_aaguid_hex(aaguid: &[u8; 16]) -> String {
    aaguid.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn expect_cbor_map<'a>(
    value: &'a CborValue,
    field: &str,
) -> anyhow::Result<&'a BTreeMap<CborValue, CborValue>> {
    match value {
        CborValue::Map(map) => Ok(map),
        _ => anyhow::bail!("{field} must be a CBOR map"),
    }
}

fn expect_cbor_array<'a>(value: Option<&'a CborValue>, field: &str) -> anyhow::Result<&'a [CborValue]> {
    match value {
        Some(CborValue::Array(values)) => Ok(values),
        _ => anyhow::bail!("{field} must be a CBOR array"),
    }
}

fn expect_cbor_bytes<'a>(value: Option<&'a CborValue>, field: &str) -> anyhow::Result<&'a [u8]> {
    match value {
        Some(CborValue::Bytes(bytes)) => Ok(bytes),
        _ => anyhow::bail!("{field} must be CBOR bytes"),
    }
}

fn expect_cbor_text<'a>(value: Option<&'a CborValue>, field: &str) -> anyhow::Result<&'a str> {
    match value {
        Some(CborValue::Text(text)) => Ok(text),
        _ => anyhow::bail!("{field} must be CBOR text"),
    }
}

fn decode_base64_any(value: &str) -> Option<Vec<u8>> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    general_purpose::STANDARD
        .decode(trimmed)
        .ok()
        .or_else(|| general_purpose::URL_SAFE_NO_PAD.decode(trimmed).ok())
        .or_else(|| general_purpose::URL_SAFE.decode(trimmed).ok())
}

fn extract_nonce_from_der_extension(value: &[u8]) -> Option<[u8; 32]> {
    if value.len() == 32 {
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(value);
        return Some(nonce);
    }

    for index in 0..value.len() {
        if value[index] != 0x04 {
            continue;
        }

        if index + 34 <= value.len() && value[index + 1] == 0x20 {
            let mut nonce = [0u8; 32];
            nonce.copy_from_slice(&value[index + 2..index + 34]);
            return Some(nonce);
        }

        if index + 35 <= value.len() && value[index + 1] == 0x81 && value[index + 2] == 0x20 {
            let mut nonce = [0u8; 32];
            nonce.copy_from_slice(&value[index + 3..index + 35]);
            return Some(nonce);
        }

        if index + 36 <= value.len()
            && value[index + 1] == 0x82
            && value[index + 2] == 0x00
            && value[index + 3] == 0x20
        {
            let mut nonce = [0u8; 32];
            nonce.copy_from_slice(&value[index + 4..index + 36]);
            return Some(nonce);
        }
    }

    None
}

fn validate_base64_blob(value: &str, error_message: &'static str) -> Result<Vec<u8>, GiftApiError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(GiftApiError::bad_request(error_message));
    }

    general_purpose::STANDARD
        .decode(trimmed.as_bytes())
        .map_err(|_| GiftApiError::bad_request(error_message))
}

fn verify_android_local_proof(
    device_token_bytes: &[u8],
    attestation_bytes: &[u8],
    key_id: &str,
    challenge: &str,
    wallet_address: &str,
) -> Result<String, GiftApiError> {
    let device_payload = parse_android_json(device_token_bytes, "invalid Android device token")?;
    let attestation_payload =
        parse_android_json(attestation_bytes, "invalid Android attestation");
    let attestation_payload = attestation_payload?;

    require_json_string(&device_payload, "platform", "android", "invalid Android device platform")?;
    require_json_string(
        &device_payload,
        "schema",
        ANDROID_DEVICE_SCHEMA,
        "invalid Android device schema",
    )?;
    require_json_string(
        &attestation_payload,
        "platform",
        "android",
        "invalid Android attestation platform",
    )?;
    require_json_string(
        &attestation_payload,
        "schema",
        ANDROID_LOCAL_PROOF_SCHEMA,
        "invalid Android attestation schema",
    )?;

    let package_name = json_string(&device_payload, "packageName")
        .ok_or_else(|| GiftApiError::bad_request("missing Android package name"))?;
    if package_name != "com.kbeam.android" {
        return Err(GiftApiError::bad_request("invalid Android package name"));
    }
    require_json_string(
        &attestation_payload,
        "packageName",
        &package_name,
        "Android attestation package mismatch",
    )?;

    let challenge_hash = json_string(&attestation_payload, "challengeSha256")
        .ok_or_else(|| GiftApiError::bad_request("missing Android challenge hash"))?;
    if challenge_hash != sha256_hex(challenge.as_bytes()) {
        return Err(GiftApiError::bad_request("Android challenge hash mismatch"));
    }

    let wallet_hash = json_string(&device_payload, "walletAddressSha256")
        .ok_or_else(|| GiftApiError::bad_request("missing Android wallet hash"))?;
    if wallet_hash != sha256_hex(wallet_address.as_bytes()) {
        return Err(GiftApiError::bad_request("Android wallet hash mismatch"));
    }

    let installation_id = json_string(&device_payload, "installationId")
        .ok_or_else(|| GiftApiError::bad_request("missing Android installation id"))?;
    if installation_id.len() < 16 {
        return Err(GiftApiError::bad_request("invalid Android installation id"));
    }
    let android_id_hash = json_string(&device_payload, "androidIdSha256")
        .ok_or_else(|| GiftApiError::bad_request("missing Android id hash"))?;
    if android_id_hash.len() != 64 || !android_id_hash.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(GiftApiError::bad_request("invalid Android id hash"));
    }

    let expected_key_prefix = format!(
        "android-local-proof-v1:{}",
        &sha256_hex(format!("{}:{}", installation_id, challenge_hash).as_bytes())[..24]
    );
    if key_id != expected_key_prefix {
        return Err(GiftApiError::bad_request("Android proof key id mismatch"));
    }

    Ok(sha256_hex(
        format!("{package_name}:{android_id_hash}:{installation_id}").as_bytes(),
    ))
}

fn parse_android_json(bytes: &[u8], error_message: &'static str) -> Result<serde_json::Value, GiftApiError> {
    serde_json::from_slice::<serde_json::Value>(bytes)
        .map_err(|_| GiftApiError::bad_request(error_message))
}

fn require_json_string(
    payload: &serde_json::Value,
    key: &str,
    expected: &str,
    error_message: &'static str,
) -> Result<(), GiftApiError> {
    let value = json_string(payload, key).ok_or_else(|| GiftApiError::bad_request(error_message))?;
    if value == expected {
        Ok(())
    } else {
        Err(GiftApiError::bad_request(error_message))
    }
}

fn json_string<'a>(payload: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    payload.get(key)?.as_str()?.trim().split('\0').next()
}

fn normalize_wallet_address(value: &str) -> Option<String> {
    let normalized = value.trim().to_lowercase();
    if normalized.is_empty() {
        return None;
    }

    if !normalized.starts_with("kaspa:") {
        return None;
    }

    let is_valid = normalized
        .chars()
        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == ':');

    if is_valid {
        Some(normalized)
    } else {
        None
    }
}

fn normalize_source_ip(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            value
                .split(',')
                .next()
                .unwrap_or(value)
                .trim()
                .to_string()
        })
}

fn sha256_hex(input: &[u8]) -> String {
    let digest = Sha256::digest(input);
    digest.iter().map(|byte| format!("{:02x}", byte)).collect()
}

fn parse_devicecheck_reason(body: &str) -> Option<String> {
    serde_json::from_str::<DeviceCheckErrorResponse>(body)
        .ok()
        .and_then(|payload| payload.reason)
}

fn parse_devicecheck_query_bit0(body: &str) -> anyhow::Result<bool> {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        anyhow::bail!("DeviceCheck query response is empty");
    }

    if let Ok(payload) = serde_json::from_str::<serde_json::Value>(trimmed) {
        return parse_devicecheck_bit0_from_json_value(&payload);
    }

    if let Some(json_body) = extract_first_json_object(trimmed) {
        if let Ok(payload) = serde_json::from_str::<serde_json::Value>(json_body) {
            return parse_devicecheck_bit0_from_json_value(&payload);
        }
    }

    if let Some(extracted_bit0) = extract_bit0_from_text(trimmed) {
        return Ok(extracted_bit0);
    }

    if is_missing_devicecheck_bit_state_response(trimmed) {
        return Ok(false);
    }

    anyhow::bail!("DeviceCheck query response is not parseable")
}

fn is_missing_devicecheck_bit_state_response(body: &str) -> bool {
    body.to_ascii_lowercase()
        .contains("failed to find bit state")
}

fn parse_devicecheck_bit0_from_json_value(payload: &serde_json::Value) -> anyhow::Result<bool> {
    match payload.get("bit0") {
        None | Some(serde_json::Value::Null) => Ok(false),
        Some(serde_json::Value::Bool(value)) => Ok(*value),
        Some(serde_json::Value::Number(value)) => parse_devicecheck_bit0_number(value),
        Some(serde_json::Value::String(value)) => parse_devicecheck_bit0_token(value.trim()),
        Some(value) => anyhow::bail!(
            "DeviceCheck bit0 has unsupported JSON type {}",
            devicecheck_json_type(value)
        ),
    }
}

fn parse_devicecheck_bit0_number(value: &serde_json::Number) -> anyhow::Result<bool> {
    if let Some(integer) = value.as_i64() {
        return match integer {
            0 => Ok(false),
            1 => Ok(true),
            other => anyhow::bail!("DeviceCheck bit0 number must be 0 or 1, got {other}"),
        };
    }

    if let Some(float_value) = value.as_f64() {
        if (float_value - 0.0).abs() < f64::EPSILON {
            return Ok(false);
        }
        if (float_value - 1.0).abs() < f64::EPSILON {
            return Ok(true);
        }
        anyhow::bail!("DeviceCheck bit0 float number must be 0 or 1, got {float_value}");
    }

    anyhow::bail!("DeviceCheck bit0 number is out of range")
}

fn parse_devicecheck_bit0_token(token: &str) -> anyhow::Result<bool> {
    match token.trim().to_ascii_lowercase().as_str() {
        "0" | "false" => Ok(false),
        "1" | "true" => Ok(true),
        "0.0" => Ok(false),
        "1.0" => Ok(true),
        other => anyhow::bail!("DeviceCheck bit0 token must be true/false/0/1, got {other}"),
    }
}

fn extract_first_json_object(body: &str) -> Option<&str> {
    let start = body.find('{')?;
    let end = body.rfind('}')?;
    if end <= start {
        return None;
    }
    body.get(start..=end)
}

fn extract_bit0_from_text(body: &str) -> Option<bool> {
    let lowercased = body.to_ascii_lowercase();
    let bit0_position = lowercased.find("bit0")?;
    let after_key = lowercased.get(bit0_position + "bit0".len()..)?.trim_start();
    let after_separator = if let Some(remaining) = after_key.strip_prefix(':') {
        remaining
    } else if let Some(remaining) = after_key.strip_prefix('=') {
        remaining
    } else {
        return None;
    };
    let token = after_separator
        .trim_start()
        .trim_matches(|character: char| character == '"' || character == '\'')
        .split(|character: char| {
            character.is_whitespace() || character == ',' || character == '}' || character == ']'
        })
        .next()?;
    parse_devicecheck_bit0_token(token).ok()
}

fn devicecheck_json_type(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "bool",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

fn summarize_devicecheck_body_for_log(body: &str) -> String {
    const MAX_CHARS: usize = 240;
    let mut result = String::new();
    let mut chars = body.chars();

    for _ in 0..MAX_CHARS {
        match chars.next() {
            Some(value) => result.push(value),
            None => return result,
        }
    }

    if chars.next().is_some() {
        result.push('…');
    }

    result
}

fn claim_consumes_unique_slot(claim: &GiftClaimRecord) -> bool {
    claim.tx_id.is_some()
        || matches!(
            claim.status,
            GiftClaimStatus::Reserved | GiftClaimStatus::PayoutSubmitted | GiftClaimStatus::Completed
        )
}

fn sompi_to_kas_decimal(amount_sompi: u64) -> String {
    let whole = amount_sompi / 100_000_000;
    let fraction = amount_sompi % 100_000_000;
    if fraction == 0 {
        return whole.to_string();
    }
    format!("{}.{:08}", whole, fraction)
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

async fn load_claims(path: &Path) -> anyhow::Result<HashMap<String, GiftClaimRecord>> {
    let data = match std::fs::read(path) {
        Ok(data) => data,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(error) => {
            return Err(anyhow::anyhow!("failed to read gift claims: {error}"));
        }
    };

    let snapshot: GiftClaimsSnapshot =
        serde_json::from_slice(&data).context("failed to parse gift claims file")?;

    Ok(snapshot
        .claims
        .into_iter()
        .map(|record| (record.claim_id.clone(), record))
        .collect())
}

async fn persist_claims(path: &Path, values: Vec<GiftClaimRecord>) -> anyhow::Result<()> {
    let snapshot = GiftClaimsSnapshot { claims: values };
    let encoded = serde_json::to_vec_pretty(&snapshot).context("failed to serialize gift claims")?;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create gift claims directory {}",
                parent.display()
            )
        })?;
    }

    std::fs::write(path, encoded)
        .with_context(|| format!("failed to write gift claims to {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::parse_devicecheck_query_bit0;

    #[test]
    fn parse_devicecheck_query_bit0_accepts_standard_json_shapes() {
        assert_eq!(
            parse_devicecheck_query_bit0(r#"{"bit0": true, "bit1": false}"#).unwrap(),
            true
        );
        assert_eq!(
            parse_devicecheck_query_bit0(r#"{"bit0": 0, "bit1": 1}"#).unwrap(),
            false
        );
        assert_eq!(
            parse_devicecheck_query_bit0(r#"{"bit0": "1", "bit1": "0"}"#).unwrap(),
            true
        );
        assert_eq!(
            parse_devicecheck_query_bit0(r#"{"bit0": 1.0, "bit1": 0.0}"#).unwrap(),
            true
        );
    }

    #[test]
    fn parse_devicecheck_query_bit0_accepts_wrapped_json_body() {
        assert_eq!(
            parse_devicecheck_query_bit0(
                "proxy-prefix<<<{\"bit0\": \"false\", \"bit1\": \"true\"}>>>proxy-suffix"
            )
            .unwrap(),
            false
        );
    }

    #[test]
    fn parse_devicecheck_query_bit0_accepts_plain_text_fallback() {
        assert_eq!(
            parse_devicecheck_query_bit0("bit0=1 bit1=0 last_update_time=2026-03-10").unwrap(),
            true
        );
    }

    #[test]
    fn parse_devicecheck_query_bit0_rejects_unparseable_body() {
        let result = parse_devicecheck_query_bit0("apple returned something unexpected");
        assert!(result.is_err());
    }
}

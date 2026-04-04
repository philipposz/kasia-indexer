use anyhow::{Context, bail};
use hmac::{Hmac, Mac};
use kaspa_addresses::{Address, Version};
use kaspa_rpc_core::RpcNetworkType;
use pbkdf2::pbkdf2_hmac_array;
use reqwest::Client;
use secp256k1::ffi;
use secp256k1::ffi::CPtr;
use secp256k1::{Keypair, PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha512;
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;
use std::ptr;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use unicode_normalization::UnicodeNormalization;
use uuid::Uuid;

type HmacSha512 = Hmac<Sha512>;

#[derive(Debug)]
struct Config {
    indexer_url: String,
    author_address: Option<String>,
    author_display_name: String,
    private_key_hex: Option<String>,
    mnemonic: Option<String>,
    network: String,
    input_file: Option<PathBuf>,
    state_file: Option<PathBuf>,
    allow_duplicates: bool,
    dry_run: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NormalizedImportItem {
    source_key: String,
    source_label: Option<String>,
    external_item_id: String,
    external_author_id: Option<String>,
    external_author_name: String,
    external_author_url: Option<String>,
    title: Option<String>,
    body_text: Option<String>,
    primary_url: Option<String>,
    canonical_source_url: Option<String>,
    published_at: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
    source_metadata: Option<Value>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct BoardCreatePostSignablePayload {
    author_address: String,
    author_display_name: String,
    content_text: String,
    attachments: Vec<BoardCreatePostAttachmentPayload>,
    reply_to_post_id: Option<String>,
    primary_link_url: Option<String>,
    created_at: String,
    client_generated_id: String,
    network: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct BoardCreatePostRequest {
    author_address: String,
    author_display_name: String,
    content_text: String,
    attachments: Vec<BoardCreatePostAttachmentPayload>,
    reply_to_post_id: Option<String>,
    primary_link_url: Option<String>,
    created_at: String,
    client_generated_id: String,
    signature: String,
    network: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct BoardCreatePostAttachmentPayload {}

#[derive(Debug, Serialize, Deserialize, Default)]
struct ImportStateFile {
    #[serde(default)]
    entries: BTreeMap<String, ImportStateEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImportStateEntry {
    source_key: String,
    external_item_id: String,
    source_label: String,
    external_author_name: String,
    primary_url: Option<String>,
    canonical_source_url: Option<String>,
    pulse_post_id: Option<String>,
    publisher_address: String,
    imported_at: String,
}

#[derive(Debug)]
struct DerivedIdentity {
    author_address: String,
    private_key_hex: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = Config::from_env_and_args()?;
    let item = load_import_item(&config)?;
    let identity = resolve_identity(&config)?;
    let dedupe_key = import_dedupe_key(&item);

    let mut state = load_state(config.state_file.as_ref())?;
    if !config.allow_duplicates && state.entries.contains_key(&dedupe_key) {
        let existing = &state.entries[&dedupe_key];
        println!(
            "Skipping duplicate import for {} / {} (existing Pulse post id: {}).",
            existing.source_label,
            existing.external_item_id,
            existing.pulse_post_id.as_deref().unwrap_or("unknown")
        );
        return Ok(());
    }

    let request = build_request(&config, &item, &identity)?;
    let request_json = serde_json::to_string_pretty(&request).context("encode request JSON")?;
    println!("Pulse import-post request:");
    println!("{request_json}");

    if config.dry_run {
        println!("\nDry run only. No network request sent.");
        return Ok(());
    }

    let url = format!("{}/board/posts", config.indexer_url.trim_end_matches('/'));
    let client = Client::builder()
        .user_agent("kbeam-pulse-import-post/1")
        .build()
        .context("build HTTP client")?;

    let response = client
        .post(url)
        .header("Accept", "application/json")
        .header("Content-Type", "application/json")
        .header("X-KBeam-Client", "PulseImportPostCLI")
        .json(&request)
        .send()
        .await
        .context("send Pulse import-post request")?;

    let status = response.status();
    let body = response.text().await.context("read response body")?;
    println!("\nHTTP {}", status.as_u16());
    println!("{body}");

    if !status.is_success() {
        bail!("Pulse import-post failed with status {}", status.as_u16());
    }

    let imported_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .context("format importedAt timestamp")?;
    let pulse_post_id = extract_post_id_from_response(&body);
    state.entries.insert(
        dedupe_key,
        ImportStateEntry {
            source_key: item.source_key.clone(),
            external_item_id: item.external_item_id.clone(),
            source_label: import_source_label(&item),
            external_author_name: item.external_author_name.clone(),
            primary_url: normalized_optional(item.primary_url.clone()),
            canonical_source_url: normalized_optional(item.canonical_source_url.clone()),
            pulse_post_id,
            publisher_address: identity.author_address,
            imported_at,
        },
    );
    save_state(config.state_file.as_ref(), &state)?;

    Ok(())
}

impl Config {
    fn from_env_and_args() -> anyhow::Result<Self> {
        let mut args = env::args().skip(1);

        let mut indexer_url =
            env_value("PULSE_IMPORT_INDEXER_URL").unwrap_or_else(|| "https://indexer.kbeam.cloud".to_string());
        let mut author_address = env_value("PULSE_IMPORT_AUTHOR_ADDRESS");
        let mut author_display_name =
            env_value("PULSE_IMPORT_AUTHOR_DISPLAY_NAME").unwrap_or_else(|| "OpenClaw on Pulse".to_string());
        let mut private_key_hex = env_value("PULSE_IMPORT_PRIVATE_KEY_HEX");
        let mut mnemonic = env_value("PULSE_IMPORT_MNEMONIC");
        let mut network = env_value("PULSE_IMPORT_NETWORK").unwrap_or_else(|| "mainnet".to_string());
        let mut input_file = env_value("PULSE_IMPORT_INPUT_FILE").map(PathBuf::from);
        let mut state_file = env_value("PULSE_IMPORT_STATE_FILE").map(PathBuf::from);
        let mut allow_duplicates = false;
        let mut dry_run = false;

        while let Some(flag) = args.next() {
            match flag.as_str() {
                "--indexer-url" => indexer_url = required_arg_value(&flag, args.next())?,
                "--author-address" => author_address = Some(required_arg_value(&flag, args.next())?),
                "--author-display-name" => author_display_name = required_arg_value(&flag, args.next())?,
                "--private-key-hex" => private_key_hex = Some(required_arg_value(&flag, args.next())?),
                "--mnemonic" => mnemonic = Some(required_arg_value(&flag, args.next())?),
                "--network" => network = required_arg_value(&flag, args.next())?,
                "--input-file" => input_file = Some(PathBuf::from(required_arg_value(&flag, args.next())?)),
                "--state-file" => state_file = Some(PathBuf::from(required_arg_value(&flag, args.next())?)),
                "--allow-duplicates" => allow_duplicates = true,
                "--dry-run" => dry_run = true,
                "--help" | "-h" => {
                    print_help();
                    std::process::exit(0);
                }
                other => bail!("unknown argument: {other}"),
            }
        }

        if private_key_hex.is_none() && mnemonic.is_none() {
            bail!("missing signing material (--private-key-hex / --mnemonic or matching env vars)");
        }

        Ok(Self {
            indexer_url,
            author_address: normalized_optional(author_address),
            author_display_name: author_display_name.trim().to_string(),
            private_key_hex: normalized_optional(private_key_hex),
            mnemonic: normalized_optional(mnemonic),
            network,
            input_file,
            state_file,
            allow_duplicates,
            dry_run,
        })
    }
}

fn load_import_item(config: &Config) -> anyhow::Result<NormalizedImportItem> {
    let raw = if let Some(path) = &config.input_file {
        fs::read_to_string(path).with_context(|| format!("read import item file {}", path.display()))?
    } else {
        let mut buffer = String::new();
        io::stdin()
            .read_to_string(&mut buffer)
            .context("read import item JSON from stdin")?;
        buffer
    };

    let item: NormalizedImportItem = serde_json::from_str(&raw).context("decode normalized import item JSON")?;
    validate_import_item(&item)?;
    Ok(item)
}

fn validate_import_item(item: &NormalizedImportItem) -> anyhow::Result<()> {
    if item.source_key.trim().is_empty() {
        bail!("normalized import item is missing sourceKey");
    }
    if item.external_item_id.trim().is_empty() {
        bail!("normalized import item is missing externalItemId");
    }
    if item.external_author_name.trim().is_empty() {
        bail!("normalized import item is missing externalAuthorName");
    }
    if item.title.as_deref().unwrap_or("").trim().is_empty()
        && item.body_text.as_deref().unwrap_or("").trim().is_empty()
        && item.primary_url.as_deref().unwrap_or("").trim().is_empty()
        && item.canonical_source_url.as_deref().unwrap_or("").trim().is_empty()
    {
        bail!("normalized import item must contain title, bodyText, primaryUrl, or canonicalSourceUrl");
    }
    Ok(())
}

fn build_request(
    config: &Config,
    item: &NormalizedImportItem,
    identity: &DerivedIdentity,
) -> anyhow::Result<BoardCreatePostRequest> {
    let created_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .context("format createdAt timestamp")?;
    let client_generated_id = Uuid::new_v4().to_string().to_lowercase();
    let content_text = build_import_content(item);
    let attachments = Vec::<BoardCreatePostAttachmentPayload>::new();

    let signable = BoardCreatePostSignablePayload {
        author_address: identity.author_address.clone(),
        author_display_name: config.author_display_name.clone(),
        content_text,
        attachments,
        reply_to_post_id: None,
        primary_link_url: preferred_primary_url(item),
        created_at: created_at.clone(),
        client_generated_id: client_generated_id.clone(),
        network: config.network.trim().to_string(),
    };

    let canonical_bytes = canonical_json_bytes(&signable)?;
    let signature = sign_raw_message(&identity.private_key_hex, &canonical_bytes)?;

    Ok(BoardCreatePostRequest {
        author_address: signable.author_address,
        author_display_name: signable.author_display_name,
        content_text: signable.content_text,
        attachments: signable.attachments,
        reply_to_post_id: signable.reply_to_post_id,
        primary_link_url: signable.primary_link_url,
        created_at,
        client_generated_id,
        signature,
        network: signable.network,
    })
}

fn build_import_content(item: &NormalizedImportItem) -> String {
    let mut sections = Vec::<String>::new();

    let title = item.title.as_deref().unwrap_or("").trim();
    let body = item.body_text.as_deref().unwrap_or("").trim();

    if !title.is_empty() {
        sections.push(title.to_string());
    }
    if !body.is_empty() {
        if sections.last().map(|last| last.trim()) != Some(body) {
            sections.push(body.to_string());
        }
    }

    let mut attribution = Vec::<String>::new();
    attribution.push(format!("Imported from {}", import_source_label(item)));
    attribution.push(format!("Author: {}", item.external_author_name.trim()));

    if let Some(published_at) = item
        .published_at
        .as_deref()
        .map(str::trim)
        .and_then(|value| (!value.is_empty()).then_some(value))
    {
        attribution.push(format!("Published: {published_at}"));
    }

    if !item.tags.is_empty() {
        let rendered_tags = item
            .tags
            .iter()
            .map(|tag| tag.trim())
            .filter(|tag| !tag.is_empty())
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        if !rendered_tags.is_empty() {
            attribution.push(format!("Tags: {}", rendered_tags.join(", ")));
        }
    }

    sections.push(attribution.join("\n"));
    sections.join("\n\n")
}

fn import_source_label(item: &NormalizedImportItem) -> String {
    item.source_label
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .unwrap_or_else(|| title_case_source_key(&item.source_key))
}

fn title_case_source_key(source_key: &str) -> String {
    source_key
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => {
                    let mut output = String::new();
                    output.extend(first.to_uppercase());
                    output.push_str(chars.as_str());
                    output
                }
                None => String::new(),
            }
        })
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

fn preferred_primary_url(item: &NormalizedImportItem) -> Option<String> {
    normalized_optional(item.canonical_source_url.clone())
        .or_else(|| normalized_optional(item.primary_url.clone()))
}

fn import_dedupe_key(item: &NormalizedImportItem) -> String {
    format!(
        "{}::{}",
        item.source_key.trim().to_ascii_lowercase(),
        item.external_item_id.trim().to_ascii_lowercase()
    )
}

fn extract_post_id_from_response(body: &str) -> Option<String> {
    let value: Value = serde_json::from_str(body).ok()?;
    if let Some(id) = value.get("id").and_then(Value::as_str) {
        return Some(id.to_string());
    }
    value.get("post")
        .and_then(|post| post.get("id"))
        .and_then(Value::as_str)
        .map(ToString::to_string)
}

fn load_state(state_file: Option<&PathBuf>) -> anyhow::Result<ImportStateFile> {
    let Some(path) = state_file else {
        return Ok(ImportStateFile::default());
    };
    if !path.exists() {
        return Ok(ImportStateFile::default());
    }
    let raw = fs::read_to_string(path).with_context(|| format!("read state file {}", path.display()))?;
    let state = serde_json::from_str(&raw).with_context(|| format!("decode state file {}", path.display()))?;
    Ok(state)
}

fn save_state(state_file: Option<&PathBuf>, state: &ImportStateFile) -> anyhow::Result<()> {
    let Some(path) = state_file else {
        return Ok(());
    };
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create state directory {}", parent.display()))?;
    }
    let encoded = serde_json::to_vec_pretty(state).context("encode import state JSON")?;
    fs::write(path, encoded).with_context(|| format!("write state file {}", path.display()))?;
    Ok(())
}

fn resolve_identity(config: &Config) -> anyhow::Result<DerivedIdentity> {
    match (&config.private_key_hex, &config.mnemonic) {
        (Some(private_key_hex), _) => {
            let author_address = config
                .author_address
                .clone()
                .context("missing author address (--author-address or PULSE_IMPORT_AUTHOR_ADDRESS)")?;
            Ok(DerivedIdentity {
                author_address,
                private_key_hex: private_key_hex.clone(),
            })
        }
        (None, Some(mnemonic)) => derive_identity_from_mnemonic(mnemonic, config.author_address.clone(), &config.network),
        _ => bail!("missing signing material"),
    }
}

fn derive_identity_from_mnemonic(
    mnemonic: &str,
    override_address: Option<String>,
    network: &str,
) -> anyhow::Result<DerivedIdentity> {
    let seed = mnemonic_to_seed(mnemonic, "");
    let master = derive_master_key(&seed)?;
    let purpose = derive_child_key(master, 44 | 0x8000_0000)?;
    let coin_type = derive_child_key(purpose, 111_111 | 0x8000_0000)?;
    let account = derive_child_key(coin_type, 0 | 0x8000_0000)?;
    let change = derive_child_key(account, 0)?;
    let address_index = derive_child_key(change, 0)?;
    let private_key_hex = hex_string(&address_index.key);
    let derived_address = kaspa_address_from_private_key(&private_key_hex, network)?;

    Ok(DerivedIdentity {
        author_address: override_address.unwrap_or(derived_address),
        private_key_hex,
    })
}

fn mnemonic_to_seed(mnemonic: &str, passphrase: &str) -> [u8; 64] {
    let normalized_mnemonic: String = mnemonic.nfkd().collect();
    let normalized_salt: String = format!("mnemonic{passphrase}").nfkd().collect();
    pbkdf2_hmac_array::<Sha512, 64>(normalized_mnemonic.as_bytes(), normalized_salt.as_bytes(), 2048)
}

fn derive_master_key(seed: &[u8]) -> anyhow::Result<DerivedKey> {
    let mut mac = HmacSha512::new_from_slice(b"Bitcoin seed").context("create BIP32 master HMAC")?;
    mac.update(seed);
    let output = mac.finalize().into_bytes();
    Ok(DerivedKey {
        key: output[0..32].try_into().context("master key length")?,
        chain_code: output[32..64].try_into().context("master chain code length")?,
    })
}

fn derive_child_key(parent: DerivedKey, index: u32) -> anyhow::Result<DerivedKey> {
    let mut data = Vec::with_capacity(37);
    if index >= 0x8000_0000 {
        data.push(0);
        data.extend_from_slice(&parent.key);
    } else {
        let secret_key = SecretKey::from_slice(&parent.key).context("parse parent private key")?;
        let secp = Secp256k1::signing_only();
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        data.extend_from_slice(&public_key.serialize());
    }
    data.extend_from_slice(&index.to_be_bytes());

    let mut mac = HmacSha512::new_from_slice(&parent.chain_code).context("create BIP32 child HMAC")?;
    mac.update(&data);
    let output = mac.finalize().into_bytes();
    let il: [u8; 32] = output[0..32].try_into().context("child IL length")?;
    let ir: [u8; 32] = output[32..64].try_into().context("child IR length")?;

    Ok(DerivedKey {
        key: add_mod_n(&il, &parent.key),
        chain_code: ir,
    })
}

fn add_mod_n(lhs: &[u8; 32], rhs: &[u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 33];
    let mut carry: u16 = 0;

    for index in (0..32).rev() {
        let sum = lhs[index] as u16 + rhs[index] as u16 + carry;
        result[index + 1] = (sum & 0xFF) as u8;
        carry = sum >> 8;
    }
    result[0] = carry as u8;

    if result[0] > 0 || bytes_ge(&result[1..], &SECP256K1_N) {
        let mut borrow: i16 = 0;
        for index in (0..32).rev() {
            let value = result[index + 1] as i16 - SECP256K1_N[index] as i16 - borrow;
            if value < 0 {
                result[index + 1] = (value + 256) as u8;
                borrow = 1;
            } else {
                result[index + 1] = value as u8;
                borrow = 0;
            }
        }
    }

    let mut reduced = [0u8; 32];
    reduced.copy_from_slice(&result[1..]);
    reduced
}

fn bytes_ge(lhs: &[u8], rhs: &[u8; 32]) -> bool {
    for (left, right) in lhs.iter().zip(rhs.iter()) {
        if left > right {
            return true;
        }
        if left < right {
            return false;
        }
    }
    true
}

fn kaspa_address_from_private_key(private_key_hex: &str, network: &str) -> anyhow::Result<String> {
    let secret_key_bytes = decode_fixed_hex::<32>(private_key_hex.trim(), "private key")?;
    let secret_key = SecretKey::from_slice(&secret_key_bytes).context("parse private key")?;
    let secp = Secp256k1::signing_only();
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let (xonly_public_key, _) = keypair.x_only_public_key();
    let rpc_network = parse_network(network)?;
    let address = Address::new(rpc_network.into(), Version::PubKey, &xonly_public_key.serialize());
    Ok(address.to_string())
}

fn parse_network(network: &str) -> anyhow::Result<RpcNetworkType> {
    match network.trim().to_ascii_lowercase().as_str() {
        "mainnet" | "main" => Ok(RpcNetworkType::Mainnet),
        "testnet" | "testnet11" | "test" => Ok(RpcNetworkType::Testnet),
        "devnet" | "dev" => Ok(RpcNetworkType::Devnet),
        "simnet" | "sim" => Ok(RpcNetworkType::Simnet),
        other => bail!("unsupported network: {other}"),
    }
}

fn sign_raw_message(private_key_hex: &str, message_bytes: &[u8]) -> anyhow::Result<String> {
    let secret_key_bytes = decode_fixed_hex::<32>(private_key_hex.trim(), "private key")?;
    let secret_key = SecretKey::from_slice(&secret_key_bytes).context("parse private key")?;
    let secp = Secp256k1::signing_only();
    let keypair = Keypair::from_secret_key(&secp, &secret_key);

    let mut signature = [0u8; 64];
    let ok = unsafe {
        ffi::secp256k1_schnorrsig_sign_custom(
            secp.ctx().as_ptr(),
            signature.as_mut_ptr(),
            message_bytes.as_ptr(),
            message_bytes.len(),
            keypair.as_c_ptr(),
            ptr::null(),
        )
    };

    if ok != 1 {
        bail!("failed to create Schnorr signature");
    }

    Ok(hex_string(&signature))
}

fn canonical_json_bytes<T: Serialize>(value: &T) -> anyhow::Result<Vec<u8>> {
    let value = serde_json::to_value(value).context("encode Pulse signing payload")?;
    let value = recursively_sorted_json(value);
    serde_json::to_vec(&value).context("encode canonical Pulse signing payload")
}

fn recursively_sorted_json(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut sorted = serde_json::Map::with_capacity(map.len());
            let mut entries = map.into_iter().collect::<Vec<_>>();
            entries.sort_by(|lhs, rhs| lhs.0.cmp(&rhs.0));
            for (key, value) in entries {
                sorted.insert(key, recursively_sorted_json(value));
            }
            Value::Object(sorted)
        }
        Value::Array(items) => Value::Array(items.into_iter().map(recursively_sorted_json).collect()),
        other => other,
    }
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

fn env_value(key: &str) -> Option<String> {
    env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn normalized_optional(value: Option<String>) -> Option<String> {
    value
        .map(|inner| inner.trim().to_string())
        .filter(|inner| !inner.is_empty())
}

fn required_arg_value(flag: &str, value: Option<String>) -> anyhow::Result<String> {
    let Some(value) = value else {
        bail!("missing value for {flag}");
    };
    let trimmed = value.trim();
    if trimmed.is_empty() {
        bail!("empty value for {flag}");
    }
    Ok(trimmed.to_string())
}

fn hex_string(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{:02x}", byte);
    }
    output
}

fn print_help() {
    println!(
        "pulse_import_post\n\
         \n\
         Publishes one normalized external import item as a wallet-signed Pulse post.\n\
         \n\
         Usage:\n\
           cargo run -p indexer --bin pulse_import_post -- \\\n\
             --mnemonic '<mnemonic words>' \\\n\
             --author-display-name 'OpenClaw on Pulse' \\\n\
             --input-file ./openclaw-item.json\n\
         \n\
         The input JSON must match the normalized import-item schema used by the open-import plan.\n\
         \n\
         Optional flags:\n\
           --indexer-url <url>         default: https://indexer.kbeam.cloud\n\
           --author-address <address>  required for raw private-key mode\n\
           --author-display-name <n>   default: OpenClaw on Pulse\n\
           --mnemonic <words>          derive m/44'/111111'/0'/0/0 automatically\n\
           --private-key-hex <hex>     sign with an explicit private key\n\
           --network <name>            default: mainnet\n\
           --input-file <path>         read the normalized import item from a JSON file\n\
           --state-file <path>         optional dedupe-state JSON file\n\
           --allow-duplicates          bypass local sourceKey+externalItemId dedupe\n\
           --dry-run                   print the signed request without sending\n\
         \n\
         Environment fallbacks:\n\
           PULSE_IMPORT_INDEXER_URL\n\
           PULSE_IMPORT_AUTHOR_ADDRESS\n\
           PULSE_IMPORT_AUTHOR_DISPLAY_NAME\n\
           PULSE_IMPORT_PRIVATE_KEY_HEX\n\
           PULSE_IMPORT_MNEMONIC\n\
           PULSE_IMPORT_NETWORK\n\
           PULSE_IMPORT_INPUT_FILE\n\
           PULSE_IMPORT_STATE_FILE"
    );
}

#[derive(Clone, Copy)]
struct DerivedKey {
    key: [u8; 32],
    chain_code: [u8; 32],
}

const SECP256K1_N: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
    0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

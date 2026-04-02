use anyhow::{Context, bail};
use reqwest::Client;
use secp256k1::ffi;
use secp256k1::ffi::CPtr;
use secp256k1::{Keypair, Secp256k1, SecretKey};
use serde::Serialize;
use serde_json::Value;
use std::env;
use std::ptr;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

#[derive(Debug)]
struct Config {
    indexer_url: String,
    author_address: String,
    author_display_name: String,
    private_key_hex: String,
    content_text: String,
    primary_link_url: Option<String>,
    reply_to_post_id: Option<String>,
    network: String,
    dry_run: bool,
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = Config::from_env_and_args()?;
    let request = build_request(&config)?;

    let request_json = serde_json::to_string_pretty(&request).context("encode request JSON")?;
    println!("Pulse smoke-post request:");
    println!("{request_json}");

    if config.dry_run {
        println!("\nDry run only. No network request sent.");
        return Ok(());
    }

    let url = format!("{}/board/posts", config.indexer_url.trim_end_matches('/'));
    let client = Client::builder()
        .user_agent("kbeam-pulse-smoke-post/1")
        .build()
        .context("build HTTP client")?;

    let response = client
        .post(url)
        .header("Accept", "application/json")
        .header("Content-Type", "application/json")
        .header("X-KBeam-Client", "PulseSmokePostCLI")
        .json(&request)
        .send()
        .await
        .context("send Pulse smoke-post request")?;

    let status = response.status();
    let body = response.text().await.context("read response body")?;
    println!("\nHTTP {}", status.as_u16());
    println!("{body}");

    if !status.is_success() {
        bail!("Pulse smoke-post failed with status {}", status.as_u16());
    }

    Ok(())
}

impl Config {
    fn from_env_and_args() -> anyhow::Result<Self> {
        let mut args = env::args().skip(1);

        let mut indexer_url = env_value("PULSE_POST_INDEXER_URL").unwrap_or_else(|| "https://indexer.kbeam.cloud".to_string());
        let mut author_address = env_value("PULSE_POST_AUTHOR_ADDRESS").unwrap_or_default();
        let mut author_display_name = env_value("PULSE_POST_AUTHOR_DISPLAY_NAME").unwrap_or_else(|| "Pulse Smoke Test".to_string());
        let mut private_key_hex = env_value("PULSE_POST_PRIVATE_KEY_HEX").unwrap_or_default();
        let mut content_text = env_value("PULSE_POST_CONTENT").unwrap_or_default();
        let mut primary_link_url = env_value("PULSE_POST_LINK");
        let mut reply_to_post_id = env_value("PULSE_POST_REPLY_TO");
        let mut network = env_value("PULSE_POST_NETWORK").unwrap_or_else(|| "mainnet".to_string());
        let mut dry_run = false;

        while let Some(flag) = args.next() {
            match flag.as_str() {
                "--indexer-url" => indexer_url = required_arg_value(&flag, args.next())?,
                "--author-address" => author_address = required_arg_value(&flag, args.next())?,
                "--author-display-name" => author_display_name = required_arg_value(&flag, args.next())?,
                "--private-key-hex" => private_key_hex = required_arg_value(&flag, args.next())?,
                "--content" => content_text = required_arg_value(&flag, args.next())?,
                "--link" => primary_link_url = Some(required_arg_value(&flag, args.next())?),
                "--reply-to-post-id" => reply_to_post_id = Some(required_arg_value(&flag, args.next())?),
                "--network" => network = required_arg_value(&flag, args.next())?,
                "--dry-run" => dry_run = true,
                "--help" | "-h" => {
                    print_help();
                    std::process::exit(0);
                }
                other => bail!("unknown argument: {other}"),
            }
        }

        if content_text.trim().is_empty() && primary_link_url.as_deref().unwrap_or("").trim().is_empty() {
            bail!("provide --content or --link (or PULSE_POST_CONTENT / PULSE_POST_LINK)");
        }
        if author_address.trim().is_empty() {
            bail!("missing author address (--author-address or PULSE_POST_AUTHOR_ADDRESS)");
        }
        if private_key_hex.trim().is_empty() {
            bail!("missing private key hex (--private-key-hex or PULSE_POST_PRIVATE_KEY_HEX)");
        }

        Ok(Self {
            indexer_url,
            author_address,
            author_display_name,
            private_key_hex,
            content_text,
            primary_link_url: normalized_optional(primary_link_url),
            reply_to_post_id: normalized_optional(reply_to_post_id),
            network,
            dry_run,
        })
    }
}

fn build_request(config: &Config) -> anyhow::Result<BoardCreatePostRequest> {
    let created_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .context("format createdAt timestamp")?;
    let client_generated_id = Uuid::new_v4().to_string().to_lowercase();
    let content_text = config.content_text.trim().to_string();
    let attachments = Vec::<BoardCreatePostAttachmentPayload>::new();

    let signable = BoardCreatePostSignablePayload {
        author_address: config.author_address.trim().to_string(),
        author_display_name: config.author_display_name.trim().to_string(),
        content_text,
        attachments,
        reply_to_post_id: config.reply_to_post_id.clone(),
        primary_link_url: config.primary_link_url.clone(),
        created_at: created_at.clone(),
        client_generated_id: client_generated_id.clone(),
        network: config.network.trim().to_string(),
    };

    let canonical_bytes = canonical_json_bytes(&signable)?;
    let signature = sign_raw_message(&config.private_key_hex, &canonical_bytes)?;

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

fn hex_string(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{:02x}", byte);
    }
    output
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

fn print_help() {
    println!(
        "pulse_smoke_post\n\
         \n\
         Sends a wallet-signed Pulse smoke-test post to the configured indexer.\n\
         \n\
         Usage:\n\
           cargo run -p indexer --bin pulse_smoke_post -- \\\n\
             --author-address kaspa:... \\\n\
             --author-display-name 'Pulse Smoke Test' \\\n\
             --private-key-hex <64-byte-hex> \\\n\
             --content 'hello pulse'\n\
         \n\
         Optional flags:\n\
           --indexer-url <url>         default: https://indexer.kbeam.cloud\n\
           --link <url>                optional primary link URL\n\
           --reply-to-post-id <id>     optional reply target\n\
           --network <name>            default: mainnet\n\
           --dry-run                   print the signed request without sending\n\
         \n\
         Environment fallbacks:\n\
           PULSE_POST_INDEXER_URL\n\
           PULSE_POST_AUTHOR_ADDRESS\n\
           PULSE_POST_AUTHOR_DISPLAY_NAME\n\
           PULSE_POST_PRIVATE_KEY_HEX\n\
           PULSE_POST_CONTENT\n\
           PULSE_POST_LINK\n\
           PULSE_POST_REPLY_TO\n\
           PULSE_POST_NETWORK"
    );
}

use anyhow::{Context, bail};
use hmac::{Hmac, Mac};
use kaspa_addresses::{Address, Version};
use kaspa_rpc_core::RpcNetworkType;
use pbkdf2::pbkdf2_hmac_array;
use reqwest::Client;
use secp256k1::ffi;
use secp256k1::ffi::CPtr;
use secp256k1::{Keypair, PublicKey, Secp256k1, SecretKey};
use serde::Serialize;
use serde_json::Value;
use sha2::Sha512;
use std::env;
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

struct DerivedIdentity {
    author_address: String,
    private_key_hex: String,
}

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

        let mut indexer_url =
            env_value("PULSE_POST_INDEXER_URL").unwrap_or_else(|| "https://indexer.kbeam.cloud".to_string());
        let mut author_address = env_value("PULSE_POST_AUTHOR_ADDRESS");
        let mut author_display_name =
            env_value("PULSE_POST_AUTHOR_DISPLAY_NAME").unwrap_or_else(|| "Pulse Smoke Test".to_string());
        let mut private_key_hex = env_value("PULSE_POST_PRIVATE_KEY_HEX");
        let mut mnemonic = env_value("PULSE_POST_MNEMONIC");
        let mut content_text = env_value("PULSE_POST_CONTENT").unwrap_or_default();
        let mut primary_link_url = env_value("PULSE_POST_LINK");
        let mut reply_to_post_id = env_value("PULSE_POST_REPLY_TO");
        let mut network = env_value("PULSE_POST_NETWORK").unwrap_or_else(|| "mainnet".to_string());
        let mut dry_run = false;

        while let Some(flag) = args.next() {
            match flag.as_str() {
                "--indexer-url" => indexer_url = required_arg_value(&flag, args.next())?,
                "--author-address" => author_address = Some(required_arg_value(&flag, args.next())?),
                "--author-display-name" => author_display_name = required_arg_value(&flag, args.next())?,
                "--private-key-hex" => private_key_hex = Some(required_arg_value(&flag, args.next())?),
                "--mnemonic" => mnemonic = Some(required_arg_value(&flag, args.next())?),
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
        if private_key_hex.is_none() && mnemonic.is_none() {
            bail!("missing signing material (--private-key-hex / --mnemonic or matching env vars)");
        }

        Ok(Self {
            indexer_url,
            author_address: normalized_optional(author_address),
            author_display_name: author_display_name.trim().to_string(),
            private_key_hex: normalized_optional(private_key_hex),
            mnemonic: normalized_optional(mnemonic),
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
    let identity = resolve_identity(config)?;

    let signable = BoardCreatePostSignablePayload {
        author_address: identity.author_address,
        author_display_name: config.author_display_name.clone(),
        content_text,
        attachments,
        reply_to_post_id: config.reply_to_post_id.clone(),
        primary_link_url: config.primary_link_url.clone(),
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

fn resolve_identity(config: &Config) -> anyhow::Result<DerivedIdentity> {
    match (&config.private_key_hex, &config.mnemonic) {
        (Some(private_key_hex), _) => {
            let author_address = config
                .author_address
                .clone()
                .context("missing author address (--author-address or PULSE_POST_AUTHOR_ADDRESS)")?;
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
        "pulse_smoke_post\n\
         \n\
         Sends a wallet-signed Pulse smoke-test post to the configured indexer.\n\
         \n\
         Usage:\n\
           cargo run -p indexer --bin pulse_smoke_post -- \\\n\
             --mnemonic '<mnemonic words>' \\\n\
             --author-display-name 'Pulse Smoke Test' \\\n\
             --content 'hello pulse'\n\
         \n\
         Or with an explicit key:\n\
           cargo run -p indexer --bin pulse_smoke_post -- \\\n\
             --author-address kaspa:... \\\n\
             --private-key-hex <64-byte-hex> \\\n\
             --content 'hello pulse'\n\
         \n\
         Optional flags:\n\
           --indexer-url <url>         default: https://indexer.kbeam.cloud\n\
           --author-address <address>  required for raw private-key mode\n\
           --author-display-name <n>   default: Pulse Smoke Test\n\
           --mnemonic <words>          derive m/44'/111111'/0'/0/0 automatically\n\
           --private-key-hex <hex>     sign with an explicit private key\n\
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
           PULSE_POST_MNEMONIC\n\
           PULSE_POST_CONTENT\n\
           PULSE_POST_LINK\n\
           PULSE_POST_REPLY_TO\n\
           PULSE_POST_NETWORK"
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

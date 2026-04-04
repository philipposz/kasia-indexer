use anyhow::{Context, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hmac::{Hmac, Mac};
use kaspa_addresses::{Address, Version};
use kaspa_rpc_core::RpcNetworkType;
use pbkdf2::pbkdf2_hmac_array;
use secp256k1::{Keypair, PublicKey, Secp256k1, SecretKey};
use serde::Serialize;
use sha2::{Digest, Sha256, Sha512};
use std::env;
use unicode_normalization::UnicodeNormalization;

type HmacSha512 = Hmac<Sha512>;

#[derive(Debug)]
struct Config {
    command: Command,
}

#[derive(Debug)]
enum Command {
    DeriveWallet {
        mnemonic: String,
        network: String,
        account_index: u32,
        address_index: u32,
    },
    DeriveMyAlias {
        private_key_hex: String,
        their_address: String,
    },
    DeriveTheirAlias {
        private_key_hex: String,
        their_address: String,
    },
    Encrypt {
        private_key_hex: String,
        recipient_address: String,
        message: String,
    },
    Decrypt {
        private_key_hex: String,
        encrypted_hex: String,
    },
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct WalletIdentityOutput {
    network: String,
    derivation_path: String,
    account_index: u32,
    address_index: u32,
    address: String,
    private_key_hex: String,
    xonly_public_key_hex: String,
    compressed_public_key_hex: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AliasOutput {
    alias: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct EncryptOutput {
    recipient_address: String,
    their_alias: String,
    encrypted_hex: String,
    encrypted_base64: String,
    contextual_payload: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DecryptOutput {
    plaintext: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = Config::from_args()?;

    match config.command {
        Command::DeriveWallet {
            mnemonic,
            network,
            account_index,
            address_index,
        } => {
            let identity = derive_wallet_identity(&mnemonic, &network, account_index, address_index)?;
            print_json(&identity)?;
        }
        Command::DeriveMyAlias {
            private_key_hex,
            their_address,
        } => {
            let alias = derive_my_alias(&private_key_hex, &their_address)?;
            print_json(&AliasOutput { alias })?;
        }
        Command::DeriveTheirAlias {
            private_key_hex,
            their_address,
        } => {
            let alias = derive_their_alias(&private_key_hex, &their_address)?;
            print_json(&AliasOutput { alias })?;
        }
        Command::Encrypt {
            private_key_hex,
            recipient_address,
            message,
        } => {
            let their_alias = derive_their_alias(&private_key_hex, &recipient_address)?;
            let encrypted_bytes = encrypt_for_recipient(&private_key_hex, &recipient_address, &message)?;
            let encrypted_hex = hex_string(&encrypted_bytes);
            let encrypted_base64 = BASE64_STANDARD.encode(&encrypted_bytes);
            let contextual_payload = format!("ciph_msg:1:comm:{their_alias}:{encrypted_base64}");
            print_json(&EncryptOutput {
                recipient_address,
                their_alias,
                encrypted_hex,
                encrypted_base64,
                contextual_payload,
            })?;
        }
        Command::Decrypt {
            private_key_hex,
            encrypted_hex,
        } => {
            let plaintext = decrypt_encrypted_hex(&private_key_hex, &encrypted_hex)?;
            print_json(&DecryptOutput { plaintext })?;
        }
    }

    Ok(())
}

impl Config {
    fn from_args() -> anyhow::Result<Self> {
        let mut args = env::args().skip(1);
        let Some(command) = args.next() else {
            print_help();
            std::process::exit(2);
        };

        let parsed = match command.as_str() {
            "derive-wallet" => {
                let mut mnemonic = env_value("OPENCLAW_KBEAM_MNEMONIC");
                let mut network = env_value("OPENCLAW_KBEAM_NETWORK").unwrap_or_else(|| "mainnet".to_string());
                let mut account_index = env_u32("OPENCLAW_KBEAM_ACCOUNT_INDEX").unwrap_or(0);
                let mut address_index = env_u32("OPENCLAW_KBEAM_ADDRESS_INDEX").unwrap_or(0);

                while let Some(flag) = args.next() {
                    match flag.as_str() {
                        "--mnemonic" => mnemonic = Some(required_arg_value(&flag, args.next())?),
                        "--network" => network = required_arg_value(&flag, args.next())?,
                        "--account-index" => account_index = required_arg_value(&flag, args.next())?.parse().context("parse --account-index")?,
                        "--address-index" => address_index = required_arg_value(&flag, args.next())?.parse().context("parse --address-index")?,
                        "--help" | "-h" => {
                            print_help();
                            std::process::exit(0);
                        }
                        other => bail!("unknown argument for derive-wallet: {other}"),
                    }
                }

                let Some(mnemonic) = normalized_optional(mnemonic) else {
                    bail!("missing mnemonic for derive-wallet (--mnemonic or OPENCLAW_KBEAM_MNEMONIC)");
                };

                Command::DeriveWallet {
                    mnemonic,
                    network,
                    account_index,
                    address_index,
                }
            }
            "derive-my-alias" | "derive-their-alias" => {
                let mut private_key_hex = env_value("OPENCLAW_KBEAM_PRIVATE_KEY_HEX");
                let mut their_address = None;

                while let Some(flag) = args.next() {
                    match flag.as_str() {
                        "--private-key-hex" => private_key_hex = Some(required_arg_value(&flag, args.next())?),
                        "--their-address" => their_address = Some(required_arg_value(&flag, args.next())?),
                        "--help" | "-h" => {
                            print_help();
                            std::process::exit(0);
                        }
                        other => bail!("unknown argument for {command}: {other}"),
                    }
                }

                let Some(private_key_hex) = normalized_optional(private_key_hex) else {
                    bail!("missing private key hex for {command}");
                };
                let Some(their_address) = normalized_optional(their_address) else {
                    bail!("missing --their-address for {command}");
                };

                if command == "derive-my-alias" {
                    Command::DeriveMyAlias {
                        private_key_hex,
                        their_address,
                    }
                } else {
                    Command::DeriveTheirAlias {
                        private_key_hex,
                        their_address,
                    }
                }
            }
            "encrypt" => {
                let mut private_key_hex = env_value("OPENCLAW_KBEAM_PRIVATE_KEY_HEX");
                let mut recipient_address = None;
                let mut message = None;

                while let Some(flag) = args.next() {
                    match flag.as_str() {
                        "--private-key-hex" => private_key_hex = Some(required_arg_value(&flag, args.next())?),
                        "--recipient-address" => recipient_address = Some(required_arg_value(&flag, args.next())?),
                        "--message" => message = Some(required_arg_value(&flag, args.next())?),
                        "--help" | "-h" => {
                            print_help();
                            std::process::exit(0);
                        }
                        other => bail!("unknown argument for encrypt: {other}"),
                    }
                }

                Command::Encrypt {
                    private_key_hex: required_option(private_key_hex, "missing private key for encrypt")?,
                    recipient_address: required_option(recipient_address, "missing --recipient-address for encrypt")?,
                    message: required_option(message, "missing --message for encrypt")?,
                }
            }
            "decrypt" => {
                let mut private_key_hex = env_value("OPENCLAW_KBEAM_PRIVATE_KEY_HEX");
                let mut encrypted_hex = None;

                while let Some(flag) = args.next() {
                    match flag.as_str() {
                        "--private-key-hex" => private_key_hex = Some(required_arg_value(&flag, args.next())?),
                        "--encrypted-hex" => encrypted_hex = Some(required_arg_value(&flag, args.next())?),
                        "--help" | "-h" => {
                            print_help();
                            std::process::exit(0);
                        }
                        other => bail!("unknown argument for decrypt: {other}"),
                    }
                }

                Command::Decrypt {
                    private_key_hex: required_option(private_key_hex, "missing private key for decrypt")?,
                    encrypted_hex: required_option(encrypted_hex, "missing --encrypted-hex for decrypt")?,
                }
            }
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            other => bail!("unknown command: {other}"),
        };

        Ok(Self { command: parsed })
    }
}

fn derive_wallet_identity(
    mnemonic: &str,
    network: &str,
    account_index: u32,
    address_index: u32,
) -> anyhow::Result<WalletIdentityOutput> {
    let seed = mnemonic_to_seed(mnemonic, "");
    let master = derive_master_key(&seed)?;
    let purpose = derive_child_key(master, 44 | HARDENED_OFFSET)?;
    let coin_type = derive_child_key(purpose, 111_111 | HARDENED_OFFSET)?;
    let account = derive_child_key(coin_type, account_index | HARDENED_OFFSET)?;
    let change = derive_child_key(account, 0)?;
    let leaf = derive_child_key(change, address_index)?;

    let secret_key = SecretKey::from_slice(&leaf.key).context("parse derived private key")?;
    let secp = Secp256k1::signing_only();
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let (xonly_public_key, _) = keypair.x_only_public_key();
    let rpc_network = parse_network(network)?;
    let address = Address::new(rpc_network.into(), Version::PubKey, &xonly_public_key.serialize());

    Ok(WalletIdentityOutput {
        network: network.trim().to_ascii_lowercase(),
        derivation_path: format!("m/44'/111111'/{}'/0/{}", account_index, address_index),
        account_index,
        address_index,
        address: address.to_string(),
        private_key_hex: hex_string(&leaf.key),
        xonly_public_key_hex: hex_string(&xonly_public_key.serialize()),
        compressed_public_key_hex: hex_string(&public_key.serialize()),
    })
}

fn derive_my_alias(private_key_hex: &str, their_address: &str) -> anyhow::Result<String> {
    let private_key = decode_fixed_hex::<32>(private_key_hex, "private key")?;
    let my_xonly = xonly_public_key_from_private_key(&private_key)?;
    derive_alias_with_context(&private_key, their_address, &my_xonly)
}

fn derive_their_alias(private_key_hex: &str, their_address: &str) -> anyhow::Result<String> {
    let private_key = decode_fixed_hex::<32>(private_key_hex, "private key")?;
    let their_xonly = xonly_pubkey_from_address(their_address)?;
    derive_alias_with_context(&private_key, their_address, &their_xonly)
}

fn derive_alias_with_context(
    private_key: &[u8; 32],
    their_address: &str,
    context_pubkey: &[u8; 32],
) -> anyhow::Result<String> {
    let their_xonly = xonly_pubkey_from_address(their_address)?;
    let shared_secret = derive_shared_secret(private_key, &their_xonly)?;

    let mut info = Vec::with_capacity(4 + 32 + 32);
    info.extend_from_slice(b"chat");
    info.extend_from_slice(&shared_secret);
    info.extend_from_slice(context_pubkey);
    let alias = hkdf_sha256(&shared_secret, &info, 6)?;
    Ok(hex_string(&alias))
}

fn encrypt_for_recipient(
    private_key_hex: &str,
    recipient_address: &str,
    message: &str,
) -> anyhow::Result<Vec<u8>> {
    let recipient_xonly = xonly_pubkey_from_address(recipient_address)?;
    let recipient_public_key = compressed_pubkey_from_xonly(&recipient_xonly)?;
    let ephemeral_secret = derive_ephemeral_secret(private_key_hex, recipient_address, message);
    let ephemeral_secret_key =
        SecretKey::from_slice(&ephemeral_secret).context("build deterministic ephemeral secret key")?;
    let secp = Secp256k1::signing_only();
    let ephemeral_public_key = PublicKey::from_secret_key(&secp, &ephemeral_secret_key);

    let shared_secret = derive_shared_secret_from_public_key(&ephemeral_secret, &recipient_public_key)?;
    let derived_key = hkdf_sha256(&shared_secret, &[], 32)?;
    let nonce_seed = sha256_bytes(
        [
            b"kbeam-contextual-nonce-v1".as_slice(),
            ephemeral_public_key.serialize().as_slice(),
            message.as_bytes(),
        ]
        .concat()
        .as_slice(),
    );
    let nonce_bytes = &nonce_seed[..12];

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&derived_key));
    let encrypted = cipher
        .encrypt(Nonce::from_slice(nonce_bytes), message.as_bytes())
        .map_err(|_| anyhow::anyhow!("encrypt plaintext for recipient"))?;

    let mut output = Vec::with_capacity(12 + 33 + encrypted.len());
    output.extend_from_slice(nonce_bytes);
    output.extend_from_slice(&ephemeral_public_key.serialize());
    output.extend_from_slice(&encrypted);
    Ok(output)
}

fn decrypt_encrypted_hex(private_key_hex: &str, encrypted_hex: &str) -> anyhow::Result<String> {
    let private_key = decode_fixed_hex::<32>(private_key_hex, "private key")?;
    let encrypted_bytes = decode_hex_dynamic(encrypted_hex, "encrypted payload")?;
    if encrypted_bytes.len() <= 45 {
        bail!("encrypted payload too short");
    }

    let nonce = &encrypted_bytes[..12];
    let key_tag = encrypted_bytes[12];
    let public_key_len = if key_tag == 0x02 || key_tag == 0x03 { 33 } else { 32 };
    if encrypted_bytes.len() < 12 + public_key_len + 16 {
        bail!("encrypted payload missing public key or auth tag");
    }

    let ephemeral_public_key = &encrypted_bytes[12..12 + public_key_len];
    let ciphertext = &encrypted_bytes[12 + public_key_len..];
    let shared_secret = derive_shared_secret_from_public_key(&private_key, ephemeral_public_key)?;
    let derived_key = hkdf_sha256(&shared_secret, &[], 32)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&derived_key));
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| anyhow::anyhow!("decrypt payload"))?;
    String::from_utf8(plaintext).context("decode plaintext as UTF-8")
}

fn derive_shared_secret(private_key: &[u8; 32], xonly_pubkey: &[u8; 32]) -> anyhow::Result<[u8; 32]> {
    let compressed = compressed_pubkey_from_xonly(xonly_pubkey)?;
    derive_shared_secret_from_public_key(private_key, &compressed)
}

fn derive_shared_secret_from_public_key(
    private_key: &[u8; 32],
    public_key_bytes: &[u8],
) -> anyhow::Result<[u8; 32]> {
    let public_key = PublicKey::from_slice(public_key_bytes).context("parse public key")?;
    let secret_key = SecretKey::from_slice(private_key).context("parse secret key")?;
    let shared_point = secp256k1::ecdh::shared_secret_point(&public_key, &secret_key);
    let mut shared_secret = [0u8; 32];
    shared_secret.copy_from_slice(&shared_point[1..33]);
    Ok(shared_secret)
}

fn xonly_public_key_from_private_key(private_key: &[u8; 32]) -> anyhow::Result<[u8; 32]> {
    let secret_key = SecretKey::from_slice(private_key).context("parse private key")?;
    let secp = Secp256k1::signing_only();
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let (xonly_public_key, _) = keypair.x_only_public_key();
    Ok(xonly_public_key.serialize())
}

fn xonly_pubkey_from_address(address: &str) -> anyhow::Result<[u8; 32]> {
    let rpc_address =
        kaspa_rpc_core::RpcAddress::try_from(address).with_context(|| format!("parse address {address}"))?;
    let payload = rpc_address.payload;
    if payload.len() != 32 {
        bail!("address payload must be 32 bytes x-only pubkey");
    }
    let mut xonly = [0u8; 32];
    xonly.copy_from_slice(payload.as_slice());
    Ok(xonly)
}

fn compressed_pubkey_from_xonly(xonly_pubkey: &[u8; 32]) -> anyhow::Result<[u8; 33]> {
    let mut compressed = [0u8; 33];
    compressed[0] = 0x02;
    compressed[1..].copy_from_slice(xonly_pubkey);
    Ok(compressed)
}

fn hkdf_sha256(ikm: &[u8], info: &[u8], output_len: usize) -> anyhow::Result<Vec<u8>> {
    let mut prk_mac = <Hmac<Sha256> as Mac>::new_from_slice(&[0u8; 32]).context("create HKDF extract HMAC")?;
    prk_mac.update(ikm);
    let prk = prk_mac.finalize().into_bytes();

    let mut output = Vec::with_capacity(output_len);
    let mut previous = Vec::new();
    let mut counter: u8 = 1;

    while output.len() < output_len {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(prk.as_slice()).context("create HKDF expand HMAC")?;
        mac.update(&previous);
        mac.update(info);
        mac.update(&[counter]);
        previous = mac.finalize().into_bytes().to_vec();
        output.extend_from_slice(&previous);
        counter = counter.checked_add(1).context("HKDF counter overflow")?;
    }

    output.truncate(output_len);
    Ok(output)
}

fn derive_ephemeral_secret(private_key_hex: &str, recipient_address: &str, message: &str) -> [u8; 32] {
    let digest = sha256_bytes(
        [
            b"kbeam-contextual-ephemeral-v1".as_slice(),
            private_key_hex.trim().as_bytes(),
            recipient_address.trim().as_bytes(),
            message.as_bytes(),
        ]
        .concat()
        .as_slice(),
    );
    let mut candidate = [0u8; 32];
    candidate.copy_from_slice(&digest);
    if candidate.iter().all(|byte| *byte == 0) {
        candidate[31] = 1;
    }
    candidate
}

fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut output = [0u8; 32];
    output.copy_from_slice(digest.as_slice());
    output
}

fn mnemonic_to_seed(mnemonic: &str, passphrase: &str) -> [u8; 64] {
    let normalized_mnemonic: String = mnemonic.nfkd().collect();
    let normalized_salt: String = format!("mnemonic{passphrase}").nfkd().collect();
    pbkdf2_hmac_array::<Sha512, 64>(normalized_mnemonic.as_bytes(), normalized_salt.as_bytes(), 2048)
}

fn derive_master_key(seed: &[u8]) -> anyhow::Result<DerivedKey> {
    let mut mac = <HmacSha512 as Mac>::new_from_slice(b"Bitcoin seed").context("create BIP32 master HMAC")?;
    mac.update(seed);
    let output = mac.finalize().into_bytes();
    Ok(DerivedKey {
        key: output[0..32].try_into().context("master key length")?,
        chain_code: output[32..64].try_into().context("master chain code length")?,
    })
}

fn derive_child_key(parent: DerivedKey, index: u32) -> anyhow::Result<DerivedKey> {
    let mut data = Vec::with_capacity(37);
    if index >= HARDENED_OFFSET {
        data.push(0);
        data.extend_from_slice(&parent.key);
    } else {
        let secret_key = SecretKey::from_slice(&parent.key).context("parse parent private key")?;
        let secp = Secp256k1::signing_only();
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        data.extend_from_slice(&public_key.serialize());
    }
    data.extend_from_slice(&index.to_be_bytes());

    let mut mac = <HmacSha512 as Mac>::new_from_slice(&parent.chain_code).context("create BIP32 child HMAC")?;
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

fn parse_network(network: &str) -> anyhow::Result<RpcNetworkType> {
    match network.trim().to_ascii_lowercase().as_str() {
        "mainnet" | "main" => Ok(RpcNetworkType::Mainnet),
        "testnet" | "testnet11" | "test" => Ok(RpcNetworkType::Testnet),
        "devnet" | "dev" => Ok(RpcNetworkType::Devnet),
        "simnet" | "sim" => Ok(RpcNetworkType::Simnet),
        other => bail!("unsupported network: {other}"),
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

fn decode_hex_dynamic(value: &str, label: &str) -> anyhow::Result<Vec<u8>> {
    let hex = value.trim();
    if hex.is_empty() || hex.len() % 2 != 0 {
        bail!("{label} must be non-empty even-length hex");
    }
    let mut bytes = vec![0u8; hex.len() / 2];
    faster_hex::hex_decode(hex.as_bytes(), &mut bytes).with_context(|| format!("decode {label} hex"))?;
    Ok(bytes)
}

fn env_value(key: &str) -> Option<String> {
    env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn env_u32(key: &str) -> Option<u32> {
    env_value(key).and_then(|value| value.parse().ok())
}

fn normalized_optional(value: Option<String>) -> Option<String> {
    value.map(|inner| inner.trim().to_string()).filter(|inner| !inner.is_empty())
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

fn required_option(value: Option<String>, message: &str) -> anyhow::Result<String> {
    normalized_optional(value).context(message.to_string())
}

fn hex_string(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{:02x}", byte);
    }
    output
}

fn print_json<T: Serialize>(value: &T) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(value).context("encode JSON output")?);
    Ok(())
}

fn print_help() {
    println!(
        "openclaw_kbeam_crypto\n\
         \n\
         Helper for KBeam/OpenClaw bridge wallet derivation, alias routing and message crypto.\n\
         \n\
         Commands:\n\
           derive-wallet      derive m/44'/111111'/<account>'/0/<index>\n\
           derive-my-alias    derive incoming/watch alias for a peer address\n\
           derive-their-alias derive outgoing/send alias for a peer address\n\
           encrypt            encrypt a contextual KBeam message for a peer address\n\
           decrypt            decrypt a contextual KBeam payload hex\n\
         \n\
         Examples:\n\
           cargo run -p indexer --bin openclaw_kbeam_crypto -- \\\n\
             derive-wallet --mnemonic '<words>' --network mainnet\n\
         \n\
           cargo run -p indexer --bin openclaw_kbeam_crypto -- \\\n\
             derive-my-alias --private-key-hex <hex> --their-address kaspa:...\n\
         \n\
           cargo run -p indexer --bin openclaw_kbeam_crypto -- \\\n\
             encrypt --private-key-hex <hex> --recipient-address kaspa:... --message 'hi'\n\
         \n\
         Environment fallbacks:\n\
           OPENCLAW_KBEAM_MNEMONIC\n\
           OPENCLAW_KBEAM_NETWORK\n\
           OPENCLAW_KBEAM_ACCOUNT_INDEX\n\
           OPENCLAW_KBEAM_ADDRESS_INDEX\n\
           OPENCLAW_KBEAM_PRIVATE_KEY_HEX"
    );
}

#[derive(Clone, Copy)]
struct DerivedKey {
    key: [u8; 32],
    chain_code: [u8; 32],
}

const HARDENED_OFFSET: u32 = 0x8000_0000;

const SECP256K1_N: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
    0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

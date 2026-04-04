use anyhow::{Context, bail};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, aead::{Aead, KeyInit}};
use hmac::{Hmac, Mac};
use kaspa_addresses::{Address, Version};
use kaspa_consensus_core::{
    config::params::Params,
    mass::{ContextualMasses, MassCalculator, NonContextualMasses},
    network::NetworkType as ConsensusNetworkType,
    sign::sign_with_multiple_v2,
    subnets::SUBNETWORK_ID_NATIVE,
    tx::{MutableTransaction, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry},
};
use kaspa_rpc_core::{
    RpcNetworkType,
    api::rpc::RpcApi,
};
use kaspa_txscript::pay_to_address_script;
use kaspa_wrpc_client::{
    KaspaRpcClient, Resolver, WrpcEncoding,
    client::{ConnectOptions, ConnectStrategy},
    prelude::{NetworkId, NetworkType},
};
use pbkdf2::pbkdf2_hmac_array;
use secp256k1::{Keypair, PublicKey, Secp256k1, SecretKey};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256, Sha512};
use std::{env, time::Duration};
use tokio::time::sleep;
use unicode_normalization::UnicodeNormalization;

type HmacSha512 = Hmac<Sha512>;

#[derive(Debug)]
struct Config {
    mnemonic: String,
    network: String,
    account_index: u32,
    address_index: u32,
    sender_address: Option<String>,
    recipient_address: String,
    alias: String,
    conversation_id: String,
    is_response: bool,
    node_url: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SendOutput {
    sender_address: String,
    recipient_address: String,
    tx_id: String,
    selected_input_count: usize,
    total_input_amount: u64,
    recipient_amount: u64,
    change_amount: u64,
    fee: u64,
    compute_mass: u64,
    transient_mass: u64,
    storage_mass: u64,
}

#[derive(Clone, Copy)]
struct DerivedKey {
    key: [u8; 32],
    chain_code: [u8; 32],
}

#[derive(Clone)]
struct SelectedUtxo {
    outpoint: TransactionOutpoint,
    entry: UtxoEntry,
}

struct EstimatedTransaction {
    tx: Transaction,
    change_amount: u64,
    fee: u64,
    total_input_amount: u64,
    non_contextual: NonContextualMasses,
    contextual: ContextualMasses,
}

struct HandshakeSelection {
    total_input_amount: u64,
    fee: u64,
    change_amount: u64,
    outputs: Vec<TransactionOutput>,
}

struct WalletIdentity {
    address: String,
    private_key: [u8; 32],
}

const HARDENED_OFFSET: u32 = 0x8000_0000;
const FEE_BUFFER_SOMPI: u64 = 3;
const MINIMUM_RELAY_FEE: u64 = 1_000;
const HANDSHAKE_AMOUNT: u64 = 20_000_000;
const DUST_THRESHOLD: u64 = 10_000;

const SECP256K1_N: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = Config::from_args()?;
    let identity = derive_wallet_identity(
        &config.mnemonic,
        &config.network,
        config.account_index,
        config.address_index,
    )?;

    let sender_address = if let Some(expected) = config.sender_address.as_ref() {
        let normalized_expected = normalize_address(expected)?;
        let normalized_actual = normalize_address(&identity.address)?;
        if normalized_expected != normalized_actual {
            bail!(
                "derived wallet address {} does not match expected sender address {}",
                identity.address,
                expected
            );
        }
        expected.clone()
    } else {
        identity.address.clone()
    };

    let rpc_client = create_rpc_client(config.node_url.as_deref(), parse_network(&config.network)?)?;
    let options = ConnectOptions {
        block_async_connect: true,
        connect_timeout: Some(Duration::from_millis(10_000)),
        strategy: ConnectStrategy::Retry,
        ..Default::default()
    };
    rpc_client
        .connect(Some(options))
        .await
        .map_err(|error| anyhow::anyhow!("connect wRPC client: {error}"))?;
    wait_for_rpc_connection(&rpc_client).await?;

    let send_result = send_handshake(
        &rpc_client,
        &identity.private_key,
        &sender_address,
        &config.recipient_address,
        &config.alias,
        &config.conversation_id,
        config.is_response,
        parse_consensus_network(&config.network)?,
    )
    .await;

    let disconnect_result = rpc_client.disconnect().await;
    let output = send_result?;
    disconnect_result.map_err(|error| anyhow::anyhow!("disconnect wRPC client: {error}"))?;

    print_json(&output)?;
    Ok(())
}

impl Config {
    fn from_args() -> anyhow::Result<Self> {
        let mut args = env::args().skip(1);
        let mut mnemonic = env_value("OPENCLAW_KBEAM_MNEMONIC");
        let mut network = env_value("OPENCLAW_KBEAM_NETWORK").unwrap_or_else(|| "mainnet".to_string());
        let mut account_index = env_u32("OPENCLAW_KBEAM_ACCOUNT_INDEX").unwrap_or(0);
        let mut address_index = env_u32("OPENCLAW_KBEAM_ADDRESS_INDEX").unwrap_or(0);
        let mut sender_address = None;
        let mut recipient_address = None;
        let mut alias = None;
        let mut conversation_id = env_value("OPENCLAW_KBEAM_CONVERSATION_ID");
        let mut is_response = false;
        let mut node_url = env_value("OPENCLAW_KBEAM_NODE_URL");

        while let Some(flag) = args.next() {
            match flag.as_str() {
                "--mnemonic" => mnemonic = Some(required_arg_value(&flag, args.next())?),
                "--network" => network = required_arg_value(&flag, args.next())?,
                "--account-index" => {
                    account_index = required_arg_value(&flag, args.next())?
                        .parse()
                        .context("parse --account-index")?
                }
                "--address-index" => {
                    address_index = required_arg_value(&flag, args.next())?
                        .parse()
                        .context("parse --address-index")?
                }
                "--sender-address" => sender_address = Some(required_arg_value(&flag, args.next())?),
                "--recipient-address" => recipient_address = Some(required_arg_value(&flag, args.next())?),
                "--alias" => alias = Some(required_arg_value(&flag, args.next())?),
                "--conversation-id" => conversation_id = Some(required_arg_value(&flag, args.next())?),
                "--is-response" => is_response = true,
                "--node-url" => node_url = Some(required_arg_value(&flag, args.next())?),
                "-h" | "--help" => {
                    print_help();
                    std::process::exit(0);
                }
                other => bail!("unknown argument: {other}"),
            }
        }

        Ok(Self {
            mnemonic: required_option(mnemonic, "missing mnemonic (--mnemonic or OPENCLAW_KBEAM_MNEMONIC)")?,
            network,
            account_index,
            address_index,
            sender_address: normalized_optional(sender_address),
            recipient_address: required_option(recipient_address, "missing --recipient-address")?,
            alias: required_option(alias, "missing --alias")?,
            conversation_id: normalized_optional(conversation_id).unwrap_or_else(generate_conversation_id),
            is_response,
            node_url: normalized_optional(node_url),
        })
    }
}

async fn send_handshake(
    rpc_client: &KaspaRpcClient,
    private_key: &[u8; 32],
    sender_address: &str,
    recipient_address: &str,
    alias: &str,
    conversation_id: &str,
    is_response: bool,
    network: ConsensusNetworkType,
) -> anyhow::Result<SendOutput> {
    let sender_rpc_address = kaspa_rpc_core::RpcAddress::try_from(sender_address)
        .with_context(|| format!("parse sender address {sender_address}"))?;
    let recipient_rpc_address = kaspa_rpc_core::RpcAddress::try_from(recipient_address)
        .with_context(|| format!("parse recipient address {recipient_address}"))?;
    let sender_spk = pay_to_address_script(&sender_rpc_address);
    let recipient_spk = pay_to_address_script(&recipient_rpc_address);
    let payload = build_handshake_payload(private_key, recipient_address, alias, conversation_id, is_response)?;
    let utxos = fetch_utxos_with_retry(rpc_client, sender_rpc_address.clone(), sender_address).await?;

    let mut spendable = utxos
        .into_iter()
        .filter(|entry| entry.utxo_entry.amount > 0)
        .map(|entry| SelectedUtxo {
            outpoint: entry.outpoint.into(),
            entry: entry.utxo_entry.into(),
        })
        .collect::<Vec<_>>();

    if spendable.is_empty() {
        bail!("no spendable UTXOs for {sender_address}");
    }

    spendable.sort_by(|left, right| {
        right
            .entry
            .amount
            .cmp(&left.entry.amount)
            .then_with(|| left.outpoint.index.cmp(&right.outpoint.index))
    });

    let params = Params::from(network);
    let mass_calculator = MassCalculator::new_with_consensus_params(&params);
    let estimated =
        estimate_handshake_transaction(&spendable, &sender_spk, &recipient_spk, &payload, &mass_calculator)?;

    let mut signed = sign_with_multiple_v2(
        MutableTransaction::with_entries(
            estimated.tx.clone(),
            spendable_entries(&spendable[..estimated.tx.inputs.len()]),
        ),
        &[*private_key],
    )
    .fully_signed()
    .map_err(|error| anyhow::anyhow!("sign transaction: {error}"))?;
    signed.tx.finalize();

    let rpc_transaction = kaspa_rpc_core::RpcTransaction::from(&signed.tx);
    let tx_id = rpc_client
        .submit_transaction(rpc_transaction, false)
        .await
        .map_err(|error| anyhow::anyhow!("submit transaction: {error}"))?;

    Ok(SendOutput {
        sender_address: sender_address.to_string(),
        recipient_address: recipient_address.to_string(),
        tx_id: tx_id.to_string(),
        selected_input_count: signed.tx.inputs.len(),
        total_input_amount: estimated.total_input_amount,
        recipient_amount: HANDSHAKE_AMOUNT,
        change_amount: estimated.change_amount,
        fee: estimated.fee,
        compute_mass: estimated.non_contextual.compute_mass,
        transient_mass: estimated.non_contextual.transient_mass,
        storage_mass: estimated.contextual.storage_mass,
    })
}

fn build_handshake_payload(
    private_key: &[u8; 32],
    recipient_address: &str,
    alias: &str,
    conversation_id: &str,
    is_response: bool,
) -> anyhow::Result<Vec<u8>> {
    let timestamp = chrono_like_now_ms();
    let payload = json!({
        "type": "handshake",
        "alias": alias,
        "timestamp": timestamp,
        "conversationId": conversation_id,
        "conversation_id": conversation_id,
        "version": 1,
        "recipientAddress": recipient_address,
        "recipient_address": recipient_address,
        "sendToRecipient": true,
        "send_to_recipient": true,
        "isResponse": if is_response { Some(true) } else { None::<bool> },
        "is_response": if is_response { Some(true) } else { None::<bool> }
    });
    let plaintext = serde_json::to_string(&payload).context("encode handshake payload")?;
    let private_key_hex = hex_string(private_key);
    let encrypted_hex = encrypt_for_recipient(&private_key_hex, recipient_address, &plaintext)?;
    let encrypted_bytes = decode_hex_dynamic(&encrypted_hex, "encrypted handshake")?;

    let mut output = b"ciph_msg:1:handshake:".to_vec();
    output.extend_from_slice(&encrypted_bytes);
    Ok(output)
}

fn estimate_handshake_transaction(
    spendable: &[SelectedUtxo],
    sender_spk: &kaspa_consensus_core::tx::ScriptPublicKey,
    recipient_spk: &kaspa_consensus_core::tx::ScriptPublicKey,
    payload: &[u8],
    mass_calculator: &MassCalculator,
) -> anyhow::Result<EstimatedTransaction> {
    let mut selected = Vec::new();
    let mut total_input_amount = 0u64;

    for utxo in spendable {
        total_input_amount = total_input_amount
            .checked_add(utxo.entry.amount)
            .context("selected UTXO amount overflow")?;
        selected.push(utxo.clone());

        if let Some(estimated) = try_estimate_handshake_transaction(
            &selected,
            total_input_amount,
            sender_spk,
            recipient_spk,
            payload,
            mass_calculator,
        )? {
            return Ok(estimated);
        }
    }

    bail!("insufficient funds to send handshake")
}

fn try_estimate_handshake_transaction(
    selected: &[SelectedUtxo],
    total_input_amount: u64,
    sender_spk: &kaspa_consensus_core::tx::ScriptPublicKey,
    recipient_spk: &kaspa_consensus_core::tx::ScriptPublicKey,
    payload: &[u8],
    mass_calculator: &MassCalculator,
) -> anyhow::Result<Option<EstimatedTransaction>> {
    let mut fee = MINIMUM_RELAY_FEE;

    for _ in 0..6 {
        let Some(selection) =
            build_handshake_selection(total_input_amount, fee, sender_spk, recipient_spk) else {
                return Ok(None);
            };

        let tx = build_estimation_transaction(selected, payload, selection.outputs);
        let signable = MutableTransaction::with_entries(tx.clone(), spendable_entries(selected));
        let contextual = mass_calculator
            .calc_contextual_masses(&signable.as_verifiable())
            .context("calculate contextual mass")?;
        tx.set_mass(contextual.storage_mass);
        let non_contextual = mass_calculator.calc_non_contextual_masses(&tx);
        let required_fee = contextual.max(non_contextual).max(MINIMUM_RELAY_FEE) + FEE_BUFFER_SOMPI;

        if required_fee == selection.fee {
            return Ok(Some(EstimatedTransaction {
                tx,
                change_amount: selection.change_amount,
                fee: selection.fee,
                total_input_amount: selection.total_input_amount,
                non_contextual,
                contextual,
            }));
        }

        fee = required_fee;
    }

    bail!("could not stabilize fee estimation for handshake")
}

fn build_handshake_selection(
    total_input_amount: u64,
    fee: u64,
    sender_spk: &kaspa_consensus_core::tx::ScriptPublicKey,
    recipient_spk: &kaspa_consensus_core::tx::ScriptPublicKey,
) -> Option<HandshakeSelection> {
    let required = HANDSHAKE_AMOUNT.checked_add(fee)?;
    if total_input_amount <= required {
        return None;
    }

    let change_amount = total_input_amount - required;
    let mut outputs = vec![TransactionOutput::new(HANDSHAKE_AMOUNT, recipient_spk.clone())];
    let effective_change = if change_amount > DUST_THRESHOLD {
        outputs.push(TransactionOutput::new(change_amount, sender_spk.clone()));
        change_amount
    } else {
        0
    };

    Some(HandshakeSelection {
        total_input_amount,
        fee: if effective_change == 0 { total_input_amount - HANDSHAKE_AMOUNT } else { fee },
        change_amount: effective_change,
        outputs,
    })
}

fn build_estimation_transaction(
    selected: &[SelectedUtxo],
    payload: &[u8],
    outputs: Vec<TransactionOutput>,
) -> Transaction {
    let inputs = selected
        .iter()
        .map(|utxo| TransactionInput::new(utxo.outpoint, vec![0u8; 66], 0, 1))
        .collect::<Vec<_>>();
    Transaction::new_non_finalized(0, inputs, outputs, 0, SUBNETWORK_ID_NATIVE, 0, payload.to_vec())
}

async fn wait_for_rpc_connection(rpc_client: &KaspaRpcClient) -> anyhow::Result<()> {
    for _ in 0..40 {
        if rpc_client.is_connected() {
            sleep(Duration::from_millis(500)).await;
            return Ok(());
        }
        sleep(Duration::from_millis(250)).await;
    }
    bail!("wRPC client did not become connected in time");
}

async fn fetch_utxos_with_retry(
    rpc_client: &KaspaRpcClient,
    sender_rpc_address: kaspa_rpc_core::RpcAddress,
    sender_address: &str,
) -> anyhow::Result<Vec<kaspa_rpc_core::RpcUtxosByAddressesEntry>> {
    let mut last_error = None;

    for _ in 0..5 {
        match rpc_client.get_utxos_by_addresses(vec![sender_rpc_address.clone()]).await {
            Ok(utxos) => return Ok(utxos),
            Err(error) => {
                let message = error.to_string();
                last_error = Some(message.clone());
                if message.to_ascii_lowercase().contains("not connected") {
                    sleep(Duration::from_millis(500)).await;
                    continue;
                }
                return Err(anyhow::anyhow!("fetch UTXOs for {sender_address}: {error}"));
            }
        }
    }

    let detail = last_error.unwrap_or_else(|| "unknown wRPC fetch error".to_string());
    bail!("fetch UTXOs for {sender_address}: {detail}");
}

fn spendable_entries(selected: &[SelectedUtxo]) -> Vec<UtxoEntry> {
    selected.iter().map(|utxo| utxo.entry.clone()).collect()
}

fn create_rpc_client(node_url: Option<&str>, network_type: NetworkType) -> anyhow::Result<KaspaRpcClient> {
    let resolver = if node_url.is_some() {
        None
    } else {
        Some(Resolver::default())
    };
    let selected_network = Some(match network_type {
        NetworkType::Mainnet => NetworkId::new(NetworkType::Mainnet),
        other => NetworkId::with_suffix(other, 10),
    });

    KaspaRpcClient::new(
        WrpcEncoding::Borsh,
        node_url,
        resolver,
        selected_network,
        None,
    )
    .map_err(|error| anyhow::anyhow!("create wRPC client: {error}"))
}

fn derive_wallet_identity(
    mnemonic: &str,
    network: &str,
    account_index: u32,
    address_index: u32,
) -> anyhow::Result<WalletIdentity> {
    let seed = mnemonic_to_seed(mnemonic, "");
    let master = derive_master_key(&seed)?;
    let purpose = derive_child_key(master, 44 | HARDENED_OFFSET)?;
    let coin_type = derive_child_key(purpose, 111_111 | HARDENED_OFFSET)?;
    let account = derive_child_key(coin_type, account_index | HARDENED_OFFSET)?;
    let change = derive_child_key(account, 0)?;
    let leaf = derive_child_key(change, address_index)?;

    let secret_key = SecretKey::from_slice(&leaf.key).context("parse derived private key")?;
    let secp = Secp256k1::signing_only();
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let (xonly_public_key, _) = keypair.x_only_public_key();
    let rpc_network = parse_rpc_network(network)?;
    let address = Address::new(rpc_network.into(), Version::PubKey, &xonly_public_key.serialize());

    Ok(WalletIdentity {
        address: address.to_string(),
        private_key: leaf.key,
    })
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

fn encrypt_for_recipient(
    private_key_hex: &str,
    recipient_address: &str,
    message: &str,
) -> anyhow::Result<String> {
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
    Ok(hex_string(&output))
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

fn decode_hex_dynamic(hex: &str, label: &str) -> anyhow::Result<Vec<u8>> {
    let normalized = hex.trim();
    if normalized.is_empty() || normalized.len() % 2 != 0 {
        bail!("{label} must be non-empty even-length hex");
    }
    let mut output = vec![0u8; normalized.len() / 2];
    faster_hex::hex_decode(normalized.as_bytes(), &mut output)
        .with_context(|| format!("decode {label} hex"))?;
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

fn parse_rpc_network(network: &str) -> anyhow::Result<RpcNetworkType> {
    match network.trim().to_ascii_lowercase().as_str() {
        "mainnet" | "main" => Ok(RpcNetworkType::Mainnet),
        "testnet" | "testnet11" | "test" => Ok(RpcNetworkType::Testnet),
        "devnet" | "dev" => Ok(RpcNetworkType::Devnet),
        "simnet" | "sim" => Ok(RpcNetworkType::Simnet),
        other => bail!("unsupported network: {other}"),
    }
}

fn parse_network(network: &str) -> anyhow::Result<NetworkType> {
    match network.trim().to_ascii_lowercase().as_str() {
        "mainnet" | "main" => Ok(NetworkType::Mainnet),
        "testnet" | "testnet11" | "test" => Ok(NetworkType::Testnet),
        "devnet" | "dev" => Ok(NetworkType::Devnet),
        "simnet" | "sim" => Ok(NetworkType::Simnet),
        other => bail!("unsupported network: {other}"),
    }
}

fn parse_consensus_network(network: &str) -> anyhow::Result<ConsensusNetworkType> {
    match network.trim().to_ascii_lowercase().as_str() {
        "mainnet" | "main" => Ok(ConsensusNetworkType::Mainnet),
        "testnet" | "testnet11" | "test" => Ok(ConsensusNetworkType::Testnet),
        "devnet" | "dev" => Ok(ConsensusNetworkType::Devnet),
        "simnet" | "sim" => Ok(ConsensusNetworkType::Simnet),
        other => bail!("unsupported network: {other}"),
    }
}

fn normalize_address(address: &str) -> anyhow::Result<String> {
    let parsed = Address::try_from(address).with_context(|| format!("parse address {address}"))?;
    Ok(parsed.to_string())
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

fn generate_conversation_id() -> String {
    let raw = uuid::Uuid::new_v4().simple().to_string();
    raw.chars().take(12).collect()
}

fn chrono_like_now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn hex_string(bytes: &[u8]) -> String {
    faster_hex::hex_string(bytes)
}

fn print_json<T: Serialize>(value: &T) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(value).context("encode JSON output")?);
    Ok(())
}

fn print_help() {
    println!(
        "openclaw_kbeam_send_handshake\n\
         \n\
         Build, sign and submit a KBeam handshake transaction.\n\
         \n\
         Required:\n\
           --recipient-address kaspa:...\n\
           --alias <string>\n\
         \n\
         Optional:\n\
           --mnemonic <words>            or OPENCLAW_KBEAM_MNEMONIC\n\
           --network mainnet             or OPENCLAW_KBEAM_NETWORK\n\
           --account-index 0             or OPENCLAW_KBEAM_ACCOUNT_INDEX\n\
           --address-index 1             or OPENCLAW_KBEAM_ADDRESS_INDEX\n\
           --sender-address kaspa:...    verify derived wallet matches this address\n\
           --conversation-id <id>        default random 12-char id\n\
           --is-response                 send handshake response instead of request\n\
           --node-url ws://...           explicit wRPC endpoint\n"
    );
}

use anyhow::{Context, bail};
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
use sha2::Sha512;
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
    recipient_address: Option<String>,
    contextual_payload: Option<String>,
    handshake_encrypted_hex: Option<String>,
    node_url: Option<String>,
    fee_multiplier: Option<f64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SendOutput {
    sender_address: String,
    tx_id: String,
    selected_input_count: usize,
    total_input_amount: u64,
    output_amount: u64,
    fee: u64,
    fee_multiplier: f64,
    fee_reason: String,
    mempool_size_hint: Option<u64>,
    compute_mass: u64,
    transient_mass: u64,
    storage_mass: u64,
}

#[derive(Clone)]
struct FeeDecision {
    multiplier: f64,
    reason: String,
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
    output_amount: u64,
    fee: u64,
    total_input_amount: u64,
    non_contextual: NonContextualMasses,
    contextual: ContextualMasses,
}

const HARDENED_OFFSET: u32 = 0x8000_0000;
const FEE_BUFFER_SOMPI: u64 = 3;
const MINIMUM_RELAY_FEE: u64 = 1_000;
const HANDSHAKE_AMOUNT_SOMPI: u64 = 20_000_000;
const DUST_THRESHOLD_SOMPI: u64 = 10_000;
const DEFAULT_ADAPTIVE_FEE_MAX_MULTIPLIER: f64 = 5.0;
const DEFAULT_PROACTIVE_FEE_BOOST_PERCENTAGE: f64 = 30.0;
const DEFAULT_PROACTIVE_FEE_BOOST_MEMPOOL_THRESHOLD: u64 = 1_000;

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
    let mempool_size_hint = fetch_mempool_size_hint(&rpc_client).await;
    let fee_decision = fee_decision(mempool_size_hint, config.fee_multiplier);

    let send_result = if let Some(contextual_payload) = config.contextual_payload.as_ref() {
        send_contextual_message(
            &rpc_client,
            &identity.private_key,
            &sender_address,
            contextual_payload.as_bytes(),
            parse_consensus_network(&config.network)?,
            &fee_decision,
            mempool_size_hint,
        )
        .await
    } else {
        send_handshake_response(
            &rpc_client,
            &identity.private_key,
            &sender_address,
            required_ref(
                config.recipient_address.as_ref(),
                "missing --recipient-address for handshake send",
            )?,
            required_ref(
                config.handshake_encrypted_hex.as_ref(),
                "missing --handshake-encrypted-hex for handshake send",
            )?,
            parse_consensus_network(&config.network)?,
            &fee_decision,
            mempool_size_hint,
        )
        .await
    };

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
        let mut contextual_payload = None;
        let mut handshake_encrypted_hex = None;
        let mut recipient_address = None;
        let mut node_url = env_value("OPENCLAW_KBEAM_NODE_URL");
        let mut fee_multiplier = env_f64("OPENCLAW_KBEAM_FEE_MULTIPLIER");

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
                "--contextual-payload" => contextual_payload = Some(required_arg_value(&flag, args.next())?),
                "--handshake-encrypted-hex" => {
                    handshake_encrypted_hex = Some(required_arg_value(&flag, args.next())?)
                }
                "--node-url" => node_url = Some(required_arg_value(&flag, args.next())?),
                "--fee-multiplier" => {
                    fee_multiplier = Some(
                        required_arg_value(&flag, args.next())?
                            .parse()
                            .context("parse --fee-multiplier")?
                    )
                }
                "-h" | "--help" => {
                    print_help();
                    std::process::exit(0);
                }
                other => bail!("unknown argument: {other}"),
            }
        }

        let contextual_payload = normalized_optional(contextual_payload);
        let handshake_encrypted_hex = normalized_optional(handshake_encrypted_hex);
        let recipient_address = normalized_optional(recipient_address);

        match (contextual_payload.is_some(), handshake_encrypted_hex.is_some()) {
            (true, true) => bail!("choose either --contextual-payload or --handshake-encrypted-hex"),
            (false, false) => bail!("missing send mode (--contextual-payload or --handshake-encrypted-hex)"),
            _ => {}
        }
        if handshake_encrypted_hex.is_some() && recipient_address.is_none() {
            bail!("--recipient-address is required with --handshake-encrypted-hex");
        }

        Ok(Self {
            mnemonic: required_option(mnemonic, "missing mnemonic (--mnemonic or OPENCLAW_KBEAM_MNEMONIC)")?,
            network,
            account_index,
            address_index,
            sender_address: normalized_optional(sender_address),
            recipient_address,
            contextual_payload,
            handshake_encrypted_hex,
            node_url: normalized_optional(node_url),
            fee_multiplier,
        })
    }
}

async fn send_contextual_message(
    rpc_client: &KaspaRpcClient,
    private_key: &[u8; 32],
    sender_address: &str,
    payload: &[u8],
    network: ConsensusNetworkType,
    fee_decision: &FeeDecision,
    mempool_size_hint: Option<u64>,
) -> anyhow::Result<SendOutput> {
    let sender_rpc_address = kaspa_rpc_core::RpcAddress::try_from(sender_address)
        .with_context(|| format!("parse sender address {sender_address}"))?;
    let sender_spk = pay_to_address_script(&sender_rpc_address);
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
    let estimated = estimate_contextual_self_spend(
        &spendable,
        &sender_spk,
        payload,
        &mass_calculator,
        fee_decision.multiplier,
    )?;

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
        tx_id: tx_id.to_string(),
        selected_input_count: signed.tx.inputs.len(),
        total_input_amount: estimated.total_input_amount,
        output_amount: estimated.output_amount,
        fee: estimated.fee,
        fee_multiplier: fee_decision.multiplier,
        fee_reason: fee_decision.reason.clone(),
        mempool_size_hint,
        compute_mass: estimated.non_contextual.compute_mass,
        transient_mass: estimated.non_contextual.transient_mass,
        storage_mass: estimated.contextual.storage_mass,
    })
}

async fn send_handshake_response(
    rpc_client: &KaspaRpcClient,
    private_key: &[u8; 32],
    sender_address: &str,
    recipient_address: &str,
    encrypted_hex: &str,
    network: ConsensusNetworkType,
    fee_decision: &FeeDecision,
    mempool_size_hint: Option<u64>,
) -> anyhow::Result<SendOutput> {
    let sender_rpc_address = kaspa_rpc_core::RpcAddress::try_from(sender_address)
        .with_context(|| format!("parse sender address {sender_address}"))?;
    let recipient_rpc_address = kaspa_rpc_core::RpcAddress::try_from(recipient_address)
        .with_context(|| format!("parse recipient address {recipient_address}"))?;
    let sender_spk = pay_to_address_script(&sender_rpc_address);
    let recipient_spk = pay_to_address_script(&recipient_rpc_address);
    let encrypted_bytes = decode_hex_payload(encrypted_hex)?;
    let mut payload = b"ciph_msg:1:handshake:".to_vec();
    payload.extend_from_slice(&encrypted_bytes);
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
        estimate_handshake_response(
            &spendable,
            &sender_spk,
            &recipient_spk,
            &payload,
            &mass_calculator,
            fee_decision.multiplier,
        )?;

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
        tx_id: tx_id.to_string(),
        selected_input_count: signed.tx.inputs.len(),
        total_input_amount: estimated.total_input_amount,
        output_amount: HANDSHAKE_AMOUNT_SOMPI,
        fee: estimated.fee,
        fee_multiplier: fee_decision.multiplier,
        fee_reason: fee_decision.reason.clone(),
        mempool_size_hint,
        compute_mass: estimated.non_contextual.compute_mass,
        transient_mass: estimated.non_contextual.transient_mass,
        storage_mass: estimated.contextual.storage_mass,
    })
}

async fn fetch_mempool_size_hint(rpc_client: &KaspaRpcClient) -> Option<u64> {
    rpc_client.get_info().await.ok().map(|info| info.mempool_size)
}

fn fee_decision(mempool_size_hint: Option<u64>, override_multiplier: Option<f64>) -> FeeDecision {
    if let Some(multiplier) = override_multiplier {
        return FeeDecision {
            multiplier: normalize_fee_multiplier(multiplier),
            reason: "manual_override".to_string(),
        };
    }

    let congestion = congestion_multiplier(mempool_size_hint);
    let proactive = proactive_fee_boost_multiplier(mempool_size_hint);
    let mut multiplier = 1.0f64;
    let mut reasons: Vec<&str> = Vec::new();

    if congestion > multiplier {
        multiplier = congestion;
        reasons.push("congestion");
    }

    if let Some(proactive_multiplier) = proactive {
        if proactive_multiplier > multiplier {
            multiplier = proactive_multiplier;
        }
        reasons.push("proactive_mempool_boost");
    }

    multiplier = normalize_fee_multiplier(multiplier);

    FeeDecision {
        multiplier,
        reason: if reasons.is_empty() {
            "base".to_string()
        } else {
            reasons.join("+")
        },
    }
}

fn normalize_fee_multiplier(value: f64) -> f64 {
    if !value.is_finite() {
        return 1.0;
    }
    let stepped = (value * 20.0).round() / 20.0;
    stepped.clamp(1.0, DEFAULT_ADAPTIVE_FEE_MAX_MULTIPLIER)
}

fn proactive_fee_boost_multiplier(mempool_size_hint: Option<u64>) -> Option<f64> {
    let mempool_size_hint = mempool_size_hint?;
    if mempool_size_hint < DEFAULT_PROACTIVE_FEE_BOOST_MEMPOOL_THRESHOLD {
        return None;
    }
    Some(1.0 + (DEFAULT_PROACTIVE_FEE_BOOST_PERCENTAGE / 100.0))
}

fn congestion_multiplier(mempool_size_hint: Option<u64>) -> f64 {
    let Some(mempool_size_hint) = mempool_size_hint else {
        return 1.0;
    };

    match mempool_size_hint {
        0..=999 => 1.0,
        1_000..=4_999 => 1.1,
        5_000..=14_999 => 1.25,
        15_000..=49_999 => 1.5,
        50_000..=99_999 => 2.0,
        _ => 2.5,
    }
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

fn estimate_contextual_self_spend(
    spendable: &[SelectedUtxo],
    sender_spk: &kaspa_consensus_core::tx::ScriptPublicKey,
    payload: &[u8],
    mass_calculator: &MassCalculator,
    fee_multiplier: f64,
) -> anyhow::Result<EstimatedTransaction> {
    let mut selected = Vec::new();
    let mut total_input_amount = 0u64;

    for utxo in spendable {
        total_input_amount = total_input_amount
            .checked_add(utxo.entry.amount)
            .context("selected UTXO amount overflow")?;
        selected.push(utxo.clone());

        if let Some(estimated) =
            try_estimate_contextual_self_spend(
                &selected,
                total_input_amount,
                sender_spk,
                payload,
                mass_calculator,
                fee_multiplier,
            )?
        {
            return Ok(estimated);
        }
    }

    bail!("insufficient funds to send contextual payload")
}

fn estimate_handshake_response(
    spendable: &[SelectedUtxo],
    sender_spk: &kaspa_consensus_core::tx::ScriptPublicKey,
    recipient_spk: &kaspa_consensus_core::tx::ScriptPublicKey,
    payload: &[u8],
    mass_calculator: &MassCalculator,
    fee_multiplier: f64,
) -> anyhow::Result<EstimatedTransaction> {
    let mut selected = Vec::new();
    let mut total_input_amount = 0u64;

    for utxo in spendable {
        total_input_amount = total_input_amount
            .checked_add(utxo.entry.amount)
            .context("selected UTXO amount overflow")?;
        selected.push(utxo.clone());

        if let Some(estimated) = try_estimate_handshake_response(
            &selected,
            total_input_amount,
            sender_spk,
            recipient_spk,
            payload,
            mass_calculator,
            fee_multiplier,
        )? {
            return Ok(estimated);
        }
    }

    bail!("insufficient funds to send handshake response")
}

fn try_estimate_contextual_self_spend(
    selected: &[SelectedUtxo],
    total_input_amount: u64,
    sender_spk: &kaspa_consensus_core::tx::ScriptPublicKey,
    payload: &[u8],
    mass_calculator: &MassCalculator,
    fee_multiplier: f64,
) -> anyhow::Result<Option<EstimatedTransaction>> {
    let mut fee = MINIMUM_RELAY_FEE;

    for _ in 0..6 {
        if total_input_amount <= fee {
            return Ok(None);
        }

        let output_amount = total_input_amount - fee;
        if output_amount == 0 {
            return Ok(None);
        }

        let tx = build_estimation_transaction(selected, sender_spk, payload, output_amount);
        let signable = MutableTransaction::with_entries(tx.clone(), spendable_entries(selected));
        let contextual = mass_calculator
            .calc_contextual_masses(&signable.as_verifiable())
            .context("calculate contextual mass")?;
        tx.set_mass(contextual.storage_mass);
        let non_contextual = mass_calculator.calc_non_contextual_masses(&tx);
        let required_fee = adjusted_fee(
            contextual.max(non_contextual).max(MINIMUM_RELAY_FEE),
            fee_multiplier,
        );

        if required_fee == fee {
            return Ok(Some(EstimatedTransaction {
                tx,
                output_amount,
                fee,
                total_input_amount,
                non_contextual,
                contextual,
            }));
        }

        fee = required_fee;
    }

    bail!("could not stabilize fee estimation for contextual self-spend")
}

fn try_estimate_handshake_response(
    selected: &[SelectedUtxo],
    total_input_amount: u64,
    sender_spk: &kaspa_consensus_core::tx::ScriptPublicKey,
    recipient_spk: &kaspa_consensus_core::tx::ScriptPublicKey,
    payload: &[u8],
    mass_calculator: &MassCalculator,
    fee_multiplier: f64,
) -> anyhow::Result<Option<EstimatedTransaction>> {
    let mut fee = MINIMUM_RELAY_FEE;

    for _ in 0..6 {
        if total_input_amount <= HANDSHAKE_AMOUNT_SOMPI + fee {
            return Ok(None);
        }

        let mut outputs = vec![TransactionOutput::new(HANDSHAKE_AMOUNT_SOMPI, recipient_spk.clone())];
        let change = total_input_amount - HANDSHAKE_AMOUNT_SOMPI - fee;
        if change > DUST_THRESHOLD_SOMPI {
            outputs.push(TransactionOutput::new(change, sender_spk.clone()));
        }

        let tx = build_estimation_transaction_with_outputs(selected, outputs, payload);
        let signable = MutableTransaction::with_entries(tx.clone(), spendable_entries(selected));
        let contextual = mass_calculator
            .calc_contextual_masses(&signable.as_verifiable())
            .context("calculate contextual mass")?;
        tx.set_mass(contextual.storage_mass);
        let non_contextual = mass_calculator.calc_non_contextual_masses(&tx);
        let required_fee = adjusted_fee(
            contextual.max(non_contextual).max(MINIMUM_RELAY_FEE),
            fee_multiplier,
        );

        if required_fee == fee {
            return Ok(Some(EstimatedTransaction {
                tx,
                output_amount: HANDSHAKE_AMOUNT_SOMPI,
                fee,
                total_input_amount,
                non_contextual,
                contextual,
            }));
        }

        fee = required_fee;
    }

    bail!("could not stabilize fee estimation for handshake response")
}

fn build_estimation_transaction(
    selected: &[SelectedUtxo],
    sender_spk: &kaspa_consensus_core::tx::ScriptPublicKey,
    payload: &[u8],
    output_amount: u64,
) -> Transaction {
    build_estimation_transaction_with_outputs(
        selected,
        vec![TransactionOutput::new(output_amount, sender_spk.clone())],
        payload,
    )
}

fn build_estimation_transaction_with_outputs(
    selected: &[SelectedUtxo],
    outputs: Vec<TransactionOutput>,
    payload: &[u8],
) -> Transaction {
    let inputs = selected
        .iter()
        .map(|utxo| TransactionInput::new(utxo.outpoint, vec![0u8; 66], 0, 1))
        .collect::<Vec<_>>();
    Transaction::new_non_finalized(0, inputs, outputs, 0, SUBNETWORK_ID_NATIVE, 0, payload.to_vec())
}

fn adjusted_fee(base_fee: u64, fee_multiplier: f64) -> u64 {
    let normalized_multiplier = if fee_multiplier.is_finite() {
        fee_multiplier.max(1.0)
    } else {
        1.0
    };
    let scaled_double = (base_fee as f64) * normalized_multiplier;
    let bounded_scaled = scaled_double.min((u64::MAX - FEE_BUFFER_SOMPI) as f64);
    let scaled = bounded_scaled.ceil() as u64;
    scaled.saturating_add(FEE_BUFFER_SOMPI)
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
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let (xonly_public_key, _) = keypair.x_only_public_key();
    let rpc_network = parse_rpc_network(network)?;
    let address = Address::new(rpc_network.into(), Version::PubKey, &xonly_public_key.serialize());

    Ok(WalletIdentity {
        address: address.to_string(),
        private_key: leaf.key,
        compressed_public_key: public_key.serialize(),
    })
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

fn env_f64(key: &str) -> Option<f64> {
    env_value(key).and_then(|value| value.parse().ok())
}

fn normalized_optional(value: Option<String>) -> Option<String> {
    value.map(|inner| inner.trim().to_string()).filter(|inner| !inner.is_empty())
}

fn required_ref<'a>(value: Option<&'a String>, message: &str) -> anyhow::Result<&'a str> {
    value.map(|inner| inner.as_str()).context(message.to_string())
}

fn decode_hex_payload(value: &str) -> anyhow::Result<Vec<u8>> {
    let normalized = value.trim();
    if normalized.len() % 2 != 0 {
        bail!("hex payload has odd length");
    }

    let mut decoded = Vec::with_capacity(normalized.len() / 2);
    for index in (0..normalized.len()).step_by(2) {
        let byte = u8::from_str_radix(&normalized[index..index + 2], 16)
            .with_context(|| format!("decode hex payload at byte {}", index / 2))?;
        decoded.push(byte);
    }
    Ok(decoded)
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

fn print_json<T: Serialize>(value: &T) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(value).context("encode JSON output")?);
    Ok(())
}

fn print_help() {
    println!(
        "openclaw_kbeam_send\n\
         \n\
         Directly build, sign and submit a KBeam contextual message transaction.\n\
         \n\
         Required:\n\
           choose one mode:\n\
             --contextual-payload 'ciph_msg:1:comm:...'\n\
             --handshake-encrypted-hex '<encrypted hex>' --recipient-address kaspa:...\n\
         \n\
         Optional:\n\
           --mnemonic <words>            or OPENCLAW_KBEAM_MNEMONIC\n\
           --network mainnet             or OPENCLAW_KBEAM_NETWORK\n\
           --account-index 0             or OPENCLAW_KBEAM_ACCOUNT_INDEX\n\
           --address-index 1             or OPENCLAW_KBEAM_ADDRESS_INDEX\n\
           --fee-multiplier 1.30         or OPENCLAW_KBEAM_FEE_MULTIPLIER\n\
           --sender-address kaspa:...    verify derived wallet matches this address\n\
           --recipient-address kaspa:... recipient for handshake response mode\n\
           --node-url wss://...          use explicit wRPC endpoint instead of resolver\n"
    );
}

struct WalletIdentity {
    address: String,
    private_key: [u8; 32],
    #[allow(dead_code)]
    compressed_public_key: [u8; 33],
}

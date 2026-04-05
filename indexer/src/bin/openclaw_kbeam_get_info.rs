use anyhow::{Context, bail};
use kaspa_rpc_core::api::rpc::RpcApi;
use kaspa_wrpc_client::{
    KaspaRpcClient, Resolver, WrpcEncoding,
    client::{ConnectOptions, ConnectStrategy},
    prelude::{NetworkId, NetworkType},
};
use serde::Serialize;
use std::{env, time::Duration};
use tokio::time::sleep;

#[derive(Debug)]
struct Config {
    network: String,
    node_url: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct InfoOutput {
    node_url: Option<String>,
    network: String,
    server_version: String,
    is_synced: bool,
    is_utxo_indexed: bool,
    mempool_size: u64,
    p2p_id: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = Config::from_args()?;
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

    let info = rpc_client
        .get_info()
        .await
        .map_err(|error| anyhow::anyhow!("get_info: {error}"))?;

    let output = InfoOutput {
        node_url: config.node_url,
        network: config.network,
        server_version: info.server_version,
        is_synced: info.is_synced,
        is_utxo_indexed: info.is_utxo_indexed,
        mempool_size: info.mempool_size,
        p2p_id: info.p2p_id,
    };

    rpc_client
        .disconnect()
        .await
        .map_err(|error| anyhow::anyhow!("disconnect wRPC client: {error}"))?;

    println!("{}", serde_json::to_string_pretty(&output).context("encode JSON output")?);
    Ok(())
}

impl Config {
    fn from_args() -> anyhow::Result<Self> {
        let mut args = env::args().skip(1);
        let mut network = env_value("OPENCLAW_KBEAM_NETWORK").unwrap_or_else(|| "mainnet".to_string());
        let mut node_url = env_value("OPENCLAW_KBEAM_NODE_URL");

        while let Some(flag) = args.next() {
            match flag.as_str() {
                "--network" => network = required_arg_value(&flag, args.next())?,
                "--node-url" => node_url = Some(required_arg_value(&flag, args.next())?),
                "-h" | "--help" => {
                    print_help();
                    std::process::exit(0);
                }
                other => bail!("unknown argument: {other}"),
            }
        }

        Ok(Self {
            network,
            node_url: normalized_optional(node_url),
        })
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

fn parse_network(network: &str) -> anyhow::Result<NetworkType> {
    match network.trim().to_ascii_lowercase().as_str() {
        "mainnet" | "main" => Ok(NetworkType::Mainnet),
        "testnet" | "testnet11" | "test" => Ok(NetworkType::Testnet),
        "devnet" | "dev" => Ok(NetworkType::Devnet),
        "simnet" | "sim" => Ok(NetworkType::Simnet),
        other => bail!("unsupported network: {other}"),
    }
}

fn env_value(key: &str) -> Option<String> {
    env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
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

fn print_help() {
    println!(
        "openclaw_kbeam_get_info\n\
         \n\
         Query a Kaspa wRPC node with get_info and print the current mempool snapshot.\n\
         \n\
         Optional:\n\
           --network mainnet             or OPENCLAW_KBEAM_NETWORK\n\
           --node-url ws://host:17110    or OPENCLAW_KBEAM_NODE_URL\n"
    );
}

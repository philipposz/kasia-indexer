# Kasia Messenger Indexer

A lightweight, specialized indexer for the Kasia messenger application built on Kaspa BlockDAG. This indexer only processes and stores messaging-related transaction data, making it highly efficient and resource-optimized for messenger-specific use cases.

## ⚠️ Development Status

**This project is currently in active development and is NOT ready for production use.**

## Features

- **Real-time BlockDAG Indexing**: Efficiently processes Kaspa blocks and transactions
- **Scalable Architecture**: Modular design with separate processing pipelines
- **Gap Detection & Recovery**: Automatic handling of missing blocks and chain reorganizations
- **Metrics & Monitoring**: Built-in metrics collection for operational visibility

## Architecture

The indexer consists of several key components:

### Core Modules

- **Block Processor**: Extracts and parses encrypted messages from transaction data
- **Virtual Chain Processor**: Handles Virtual Chain Changed (VCC) notifications and transaction acceptance
- **Periodic Processor**: Manages resolution of unknown transactions and DAA scores
- **Historical Syncer**: Syncs historical blockchain data from a specified starting point
- **Chain Subscriber**: Real-time subscription to new blocks and chain updates

### Database Organization

- **Headers**: Block compact headers and gap tracking
- **Messages**: Protocol message storage (handshakes, payments, contextual messages)
- **Processing**: Transaction processing state and resolution workflows

### Message Types

- **Handshakes**: Initial connection establishment between parties
- **Payments**: Payment transactions with optional attached messages
- **Contextual Messages**: Application-specific encrypted messages

Useful commands:

- run locally: `RUST_LOG=info cargo run -r -p indexer`
- build docker image `docker build -t kkluster/kasia-indexer:ios-first .`
- run as docker-compose: `docker compose up -d`

## Docker deployment (iOS-first)

The default `docker-compose.yaml` is configured for an iOS-first push profile:

- APNs as primary provider (`PUSH_PROVIDER=apns`)
- FCM disabled by default (`PUSH_FCM_ENABLED=false`)
- APNs `.p8` key mounted from host into container at `/app/secrets/apns/AuthKey.p8`

### 1) Prepare env file

```bash
cp .env.example .env
```

Run deploy preflight checks (required keys, basic formats, mounted key files):

```bash
./scripts/check-env.sh --env-file .env
```

Set at minimum:

- `KASPA_NODE_WBORSH_URL`
- `PUSH_APNS_TEAM_ID`
- `PUSH_APNS_KEY_ID`
- `PUSH_APNS_BUNDLE_ID` (for KaChat/KBeam typically `com.kbeam.app`)

### 2) Place APNs key on host

```bash
mkdir -p secrets/apns
cp /path/to/AuthKey_XXXXXX.p8 secrets/apns/AuthKey.p8
chmod 600 secrets/apns/AuthKey.p8
```

### 3) Start service

```bash
docker compose up -d --build
```

### 4) Check health/logs

```bash
docker compose ps
docker compose logs -f kasia-indexer
```

### DeviceCheck debug endpoints (admin-only)

Set in `.env`:

```bash
GIFT_DEVICECHECK_DEBUG_SECRET=<your_secret>
```

Then call:

```bash
# Query bit0
curl -sS -X POST "http://127.0.0.1:8080/v1/gift/debug/query-bit0" \
  -H "Content-Type: application/json" \
  -H "x-gift-debug-secret: ${GIFT_DEVICECHECK_DEBUG_SECRET}" \
  --data '{"deviceToken":"<BASE64_DEVICE_TOKEN>"}'

# Update bit0=true and verify
curl -sS -X POST "http://127.0.0.1:8080/v1/gift/debug/update-bit0" \
  -H "Content-Type: application/json" \
  -H "x-gift-debug-secret: ${GIFT_DEVICECHECK_DEBUG_SECRET}" \
  --data '{"deviceToken":"<BASE64_DEVICE_TOKEN>"}'
```

Helper script:

```bash
INDEXER_BASE_URL=http://127.0.0.1:8080 \
GIFT_DEVICECHECK_DEBUG_SECRET=<your_secret> \
./scripts/devicecheck_query_bit0.sh --action query --token-file /tmp/device_token.txt

INDEXER_BASE_URL=http://127.0.0.1:8080 \
GIFT_DEVICECHECK_DEBUG_SECRET=<your_secret> \
./scripts/devicecheck_query_bit0.sh --action update --token-file /tmp/device_token.txt
```

## API

- http://localhost:8080/swagger-ui/

## Env vars

```bash
# debug, info, warn, error
RUST_LOG=info

# default to home_dir/.kasia-indexer/mainnet, must be an existing directory with read/write permissions
#KASIA_INDEXER_DB_ROOT=

# default to mainnet, allowed values: mainnet, testnet
NETWORK_TYPE=mainnet

# if not defined, fallback to public kaspa network, if specified, the `ws://{ip}:{port}` node url
#KASPA_NODE_WBORSH_URL=

# DAA-score depth used for periodic pruning and in-memory processed-block cache.
# Lower values keep less historical data. For ~1 day retention, use ~86400.
INDEXER_PRUNING_DEPTH=3000000

# iOS-first push profile
PUSH_PROVIDER=apns
PUSH_IOS_ENABLED=true
PUSH_FCM_ENABLED=false

# APNs auth
PUSH_APNS_ENVIRONMENT=auto
PUSH_APNS_TEAM_ID=
PUSH_APNS_KEY_ID=
PUSH_APNS_BUNDLE_ID=com.kbeam.app
PUSH_APNS_KEY_PATH=/app/secrets/apns/AuthKey.p8

# Optional APNs dispatch tuning
PUSH_INLINE_PAYLOAD_LIMIT=3500
PUSH_APNS_TIMEOUT_MS=15000
```

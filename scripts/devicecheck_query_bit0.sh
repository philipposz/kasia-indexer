#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  devicecheck_query_bit0.sh [--action query|update] --token <BASE64_TOKEN>
  devicecheck_query_bit0.sh [--action query|update] --token-file <FILE_WITH_BASE64_TOKEN>

Env vars:
  INDEXER_BASE_URL             Optional. Default: http://127.0.0.1:8080
  GIFT_DEVICECHECK_DEBUG_SECRET Required. Admin secret for debug endpoint.
USAGE
}

if [[ $# -lt 2 ]]; then
  usage
  exit 1
fi

INDEXER_BASE_URL="${INDEXER_BASE_URL:-http://127.0.0.1:8080}"
DEBUG_SECRET="${GIFT_DEVICECHECK_DEBUG_SECRET:-}"
ACTION="query"

if [[ -z "${DEBUG_SECRET}" ]]; then
  echo "[error] GIFT_DEVICECHECK_DEBUG_SECRET is required" >&2
  exit 1
fi

TOKEN=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --action)
      ACTION="${2:-}"
      shift 2
      ;;
    --token)
      TOKEN="${2:-}"
      shift 2
      ;;
    --token-file)
      TOKEN_FILE="${2:-}"
      if [[ -z "${TOKEN_FILE}" || ! -f "${TOKEN_FILE}" ]]; then
        echo "[error] token file not found: ${TOKEN_FILE}" >&2
        exit 1
      fi
      TOKEN="$(tr -d '[:space:]' < "${TOKEN_FILE}")"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "[error] unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ -z "${TOKEN}" ]]; then
  echo "[error] device token is empty" >&2
  exit 1
fi

if [[ "${ACTION}" != "query" && "${ACTION}" != "update" ]]; then
  echo "[error] invalid --action value: ${ACTION} (expected query|update)" >&2
  exit 1
fi

REQUEST_BODY="$(printf '{"deviceToken":"%s"}' "$TOKEN")"
if [[ "${ACTION}" == "update" ]]; then
  ENDPOINT="${INDEXER_BASE_URL%/}/v1/gift/debug/update-bit0"
else
  ENDPOINT="${INDEXER_BASE_URL%/}/v1/gift/debug/query-bit0"
fi

if command -v jq >/dev/null 2>&1; then
  curl -sS -X POST "$ENDPOINT" \
    -H "Content-Type: application/json" \
    -H "x-gift-debug-secret: ${DEBUG_SECRET}" \
    --data "$REQUEST_BODY" | jq .
else
  curl -sS -X POST "$ENDPOINT" \
    -H "Content-Type: application/json" \
    -H "x-gift-debug-secret: ${DEBUG_SECRET}" \
    --data "$REQUEST_BODY"
fi

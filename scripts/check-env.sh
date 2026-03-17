#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/check-env.sh [--env-file <path>] [--skip-file-checks]

Options:
  --env-file <path>     Path to env file. Default: .env
  --skip-file-checks    Skip checks for mounted key files on disk.
  -h, --help            Show this help.

This script validates deploy-critical env keys for kasia-indexer.
It never prints secret values.
USAGE
}

ENV_FILE=".env"
SKIP_FILE_CHECKS="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --env-file)
      ENV_FILE="${2:-}"
      shift 2
      ;;
    --skip-file-checks)
      SKIP_FILE_CHECKS="true"
      shift
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

if [[ -z "${ENV_FILE}" || ! -f "${ENV_FILE}" ]]; then
  echo "[error] env file not found: ${ENV_FILE}" >&2
  exit 1
fi

ENV_DIR="$(cd "$(dirname "${ENV_FILE}")" >/dev/null 2>&1 && pwd)"

trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

key_exists() {
  local key="$1"
  grep -Eq "^[[:space:]]*${key}=" "${ENV_FILE}"
}

get_env_value() {
  local key="$1"
  local line
  line="$(grep -E "^[[:space:]]*${key}=" "${ENV_FILE}" | tail -n 1 || true)"
  line="${line#*=}"
  line="$(trim "${line}")"

  if [[ "${line}" == \"*\" && "${line}" == *\" ]]; then
    line="${line:1:${#line}-2}"
  elif [[ "${line}" == \'*\' ]]; then
    line="${line:1:${#line}-2}"
  fi

  printf '%s' "${line}"
}

is_true() {
  local value
  value="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  [[ "${value}" == "1" || "${value}" == "true" || "${value}" == "yes" || "${value}" == "y" || "${value}" == "on" ]]
}

is_bool() {
  local value
  value="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  [[ "${value}" == "1" || "${value}" == "true" || "${value}" == "yes" || "${value}" == "y" || "${value}" == "on" || "${value}" == "0" || "${value}" == "false" || "${value}" == "no" || "${value}" == "n" || "${value}" == "off" ]]
}

map_container_path_to_host() {
  local path="$1"
  if [[ "${path}" == /app/secrets/* ]]; then
    printf '%s%s' "${ENV_DIR}" "${path#/app}"
  elif [[ "${path}" == /* ]]; then
    printf '%s' "${path}"
  else
    printf '%s/%s' "${ENV_DIR}" "${path}"
  fi
}

errors=0
warnings=0

fail() {
  errors=$((errors + 1))
  echo "[error] $*" >&2
}

warn() {
  warnings=$((warnings + 1))
  echo "[warn] $*" >&2
}

require_non_empty() {
  local key="$1"
  if ! key_exists "${key}"; then
    fail "missing key: ${key}"
    return
  fi

  local value
  value="$(get_env_value "${key}")"
  if [[ -z "${value}" ]]; then
    fail "empty value: ${key}"
  fi
}

validate_bool_if_present() {
  local key="$1"
  if key_exists "${key}"; then
    local value
    value="$(get_env_value "${key}")"
    if [[ -n "${value}" ]] && ! is_bool "${value}"; then
      fail "invalid boolean for ${key}: expected true/false style value"
    fi
  fi
}

require_non_empty "NETWORK_TYPE"
require_non_empty "KASPA_NODE_WBORSH_URL"
require_non_empty "INDEXER_PRUNING_DEPTH"
require_non_empty "PUSH_PROVIDER"
require_non_empty "PUSH_APNS_ENVIRONMENT"
require_non_empty "PUSH_APNS_TEAM_ID"
require_non_empty "PUSH_APNS_KEY_ID"
require_non_empty "PUSH_APNS_BUNDLE_ID"
require_non_empty "PUSH_APNS_KEY_PATH"

validate_bool_if_present "PUSH_IOS_ENABLED"
validate_bool_if_present "PUSH_FCM_ENABLED"
validate_bool_if_present "GIFT_ENABLED"
validate_bool_if_present "GIFT_REQUIRE_APPATTEST"
validate_bool_if_present "GIFT_REQUIRE_DEVICECHECK"
validate_bool_if_present "GIFT_ALLOW_SIMULATOR_CLAIMS"
validate_bool_if_present "PUSH_CONTEXTUAL_ALLOW_LEGACY_SUFFIX"

if key_exists "NETWORK_TYPE"; then
  network_type="$(printf '%s' "$(get_env_value "NETWORK_TYPE")" | tr '[:upper:]' '[:lower:]')"
  if [[ "${network_type}" != "mainnet" && "${network_type}" != "testnet" ]]; then
    fail "NETWORK_TYPE must be mainnet or testnet"
  fi
fi

if key_exists "INDEXER_PRUNING_DEPTH"; then
  pruning_depth="$(get_env_value "INDEXER_PRUNING_DEPTH")"
  if [[ ! "${pruning_depth}" =~ ^[0-9]+$ ]]; then
    fail "INDEXER_PRUNING_DEPTH must be a positive integer"
  fi
fi

if key_exists "PUSH_APNS_ENVIRONMENT"; then
  apns_env="$(printf '%s' "$(get_env_value "PUSH_APNS_ENVIRONMENT")" | tr '[:upper:]' '[:lower:]')"
  if [[ "${apns_env}" != "auto" && "${apns_env}" != "development" && "${apns_env}" != "production" ]]; then
    fail "PUSH_APNS_ENVIRONMENT must be auto, development, or production"
  fi
fi

if [[ "${SKIP_FILE_CHECKS}" != "true" ]]; then
  if key_exists "PUSH_APNS_KEY_PATH"; then
    apns_key_path="$(get_env_value "PUSH_APNS_KEY_PATH")"
    if [[ -n "${apns_key_path}" ]]; then
      host_apns_path="$(map_container_path_to_host "${apns_key_path}")"
      if [[ ! -f "${host_apns_path}" ]]; then
        fail "APNs key file not found: ${host_apns_path} (from PUSH_APNS_KEY_PATH=${apns_key_path})"
      fi
    fi
  fi

  gift_enabled_value="$(get_env_value "GIFT_ENABLED")"
  gift_enabled_value="${gift_enabled_value:-true}"
  if is_true "${gift_enabled_value}"; then
    require_non_empty "GIFT_AMOUNT_SOMPI"
    require_non_empty "GIFT_CLAIMS_PATH"
    require_non_empty "GIFT_REQUIRE_APPATTEST"
    require_non_empty "GIFT_APPATTEST_ENVIRONMENT"
    require_non_empty "GIFT_APPATTEST_TEAM_ID"
    require_non_empty "GIFT_APPATTEST_BUNDLE_ID"
    require_non_empty "GIFT_REQUIRE_DEVICECHECK"
    require_non_empty "GIFT_DEVICECHECK_ENVIRONMENT"
    require_non_empty "GIFT_DEVICECHECK_TEAM_ID"
    require_non_empty "GIFT_DEVICECHECK_KEY_ID"
    require_non_empty "GIFT_DEVICECHECK_KEY_PATH"

    if key_exists "GIFT_DEVICECHECK_KEY_PATH"; then
      dc_key_path="$(get_env_value "GIFT_DEVICECHECK_KEY_PATH")"
      if [[ -n "${dc_key_path}" ]]; then
        host_dc_path="$(map_container_path_to_host "${dc_key_path}")"
        if [[ ! -f "${host_dc_path}" ]]; then
          fail "DeviceCheck key file not found: ${host_dc_path} (from GIFT_DEVICECHECK_KEY_PATH=${dc_key_path})"
        fi
      fi
    fi

    if key_exists "GIFT_PAYOUT_COMMAND"; then
      payout_command="$(get_env_value "GIFT_PAYOUT_COMMAND")"
      if [[ -z "${payout_command}" ]]; then
        warn "GIFT_ENABLED=true but GIFT_PAYOUT_COMMAND is empty"
      fi
    fi
  fi
fi

if [[ ${errors} -gt 0 ]]; then
  echo
  echo "[result] env check failed: ${errors} error(s), ${warnings} warning(s)" >&2
  exit 1
fi

echo "[result] env check passed: 0 error(s), ${warnings} warning(s)"

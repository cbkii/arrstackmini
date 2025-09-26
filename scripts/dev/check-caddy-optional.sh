#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

compose_path="${REPO_ROOT}/docker-compose.yml"
if [[ ! -f "$compose_path" ]]; then
  echo "[check-caddy-optional] docker-compose.yml not found at ${compose_path}. Run ./arrstack.sh first." >&2
  exit 1
fi

env_source="${REPO_ROOT}/.env"
if [[ ! -f "$env_source" ]]; then
  env_source="${REPO_ROOT}/.env.example"
  if [[ ! -f "$env_source" ]]; then
    echo "[check-caddy-optional] No .env or .env.example found in ${REPO_ROOT}." >&2
    exit 1
  fi
fi

tmp_env="$(mktemp "${REPO_ROOT}/.env.caddy-check.XXXXXX")"
trap 'rm -f "$tmp_env"' EXIT
cp "$env_source" "$tmp_env"

if grep -q '^ENABLE_CADDY=' "$tmp_env"; then
  sed -i '' -e 's/^ENABLE_CADDY=.*/ENABLE_CADDY=0/' "$tmp_env" 2>/dev/null || sed -i -e 's/^ENABLE_CADDY=.*/ENABLE_CADDY=0/' "$tmp_env"
else
  printf '\nENABLE_CADDY=0\n' >>"$tmp_env"
fi

if grep -q '^ENABLE_LOCAL_DNS=' "$tmp_env"; then
  :
else
  printf 'ENABLE_LOCAL_DNS=0\n' >>"$tmp_env"
fi

if grep -q '^[[:space:]]*caddy:' "$compose_path"; then
  echo "[check-caddy-optional] Expected caddy service to be absent when ENABLE_CADDY=0." >&2
  exit 1
fi

if grep -q '":80:80"' "$compose_path"; then
  echo "[check-caddy-optional] Found an 80:80 port mapping with Caddy disabled." >&2
  exit 1
fi

if grep -q '":443:443"' "$compose_path"; then
  echo "[check-caddy-optional] Found a 443:443 port mapping with Caddy disabled." >&2
  exit 1
fi

ARR_STACK_DIR="${ARR_STACK_DIR:-${REPO_ROOT}}"
ARR_ENV_FILE="${tmp_env}"
ARR_DOCKER_DIR="${ARR_STACK_DIR}/docker-data"
ARRCONF_DIR="${ARR_STACK_DIR}/arrconf"
export ARR_STACK_DIR ARR_ENV_FILE ARR_DOCKER_DIR ARRCONF_DIR

# shellcheck source=/dev/null
set +e
. "${REPO_ROOT}/.arraliases"
set -e

alias_output="$(arr.open 2>&1)"

if [[ "$alias_output" != *"Caddy disabled"* ]]; then
  echo "[check-caddy-optional] arr.open did not mention that Caddy is disabled." >&2
  printf '%s\n' "$alias_output"
  exit 1
fi

if [[ "$alias_output" != *"qBittorrent -> http://"* ]]; then
  echo "[check-caddy-optional] arr.open did not list direct http:// LAN URLs." >&2
  printf '%s\n' "$alias_output"
  exit 1
fi

echo "[check-caddy-optional] PASS: Caddy disabled path looks clean."

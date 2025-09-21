#!/usr/bin/env bash
# qBittorrent Helper - Manage authentication and access defaults

set -euo pipefail

log() {
  printf '[%s] %s\n' "$(date '+%H:%M:%S')" "$*"
}

warn() {
  printf '[%s] WARNING: %s\n' "$(date '+%H:%M:%S')" "$*" >&2
}

die() {
  warn "$1"
  exit 1
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STACK_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${STACK_DIR}/.env"
CONTAINER_NAME="qbittorrent"

load_env() {
  if [[ -f "$ENV_FILE" ]]; then
    set -a
    # shellcheck source=/dev/null
    source "$ENV_FILE"
    set +a
  fi
}

resolve_docker_data() {
  local candidates=()

  if [[ -n "${ARR_DOCKER_DIR:-}" ]]; then
    candidates+=("$ARR_DOCKER_DIR")
  fi
  candidates+=("${HOME}/srv/docker-data" "${STACK_DIR}/docker-data")

  local path
  for path in "${candidates[@]}"; do
    if [[ -n "$path" && -d "$path" ]]; then
      printf '%s\n' "$path"
      return 0
    fi
  done

  return 1
}

temporary_password() {
  docker logs "$CONTAINER_NAME" 2>&1 |
    grep "temporary password" |
    tail -1 |
    sed 's/.*temporary password[^:]*: *//' |
    awk '{print $1}'
}

webui_host() {
  if [[ -n "${LAN_IP:-}" && "$LAN_IP" != "0.0.0.0" ]]; then
    printf '%s' "$LAN_IP"
  else
    printf '%s' "127.0.0.1"
  fi
}

webui_port() {
  printf '%s' "${QBT_HTTP_PORT_HOST:-8080}"
}

config_file_path() {
  printf '%s/qbittorrent/qBittorrent/qBittorrent.conf' "$DOCKER_DATA"
}

stop_container() {
  docker stop "$CONTAINER_NAME" >/dev/null 2>&1 || true
}

start_container() {
  docker start "$CONTAINER_NAME" >/dev/null 2>&1 || true
}

derive_subnet() {
  if [[ -n "${LAN_IP:-}" && "$LAN_IP" != "0.0.0.0" ]]; then
    echo "$LAN_IP" | sed 's/\.[0-9]*$/.0\/24/'
  fi
}

show_info() {
  log "qBittorrent Access Information:"
  log "================================"
  log "URL: http://$(webui_host):$(webui_port)/"
  log ""

  local temp_pass
  temp_pass=$(temporary_password || true)

  if [[ -n "$temp_pass" ]]; then
    log "Username: admin"
    log "Password: ${temp_pass} (temporary - change this!)"
  else
    log "Username: ${QBT_USER:-admin}"
    log "Password: ${QBT_PASS:-Check logs or use 'reset' command}"
  fi
}

reset_auth() {
  log "Resetting qBittorrent authentication..."
  stop_container

  local cfg
  cfg=$(config_file_path)
  if [[ -f "$cfg" ]]; then
    local backup="${cfg}.bak.$(date +%Y%m%d_%H%M%S)"
    cp "$cfg" "$backup"
    log "  Backed up config to $backup"
    sed -i '/WebUI\\Password_PBKDF2/d' "$cfg" || true
  else
    warn "Config file not found at $cfg; proceeding without backup"
  fi

  start_container
  sleep 5

  local temp_pass
  temp_pass=$(temporary_password || true)

  if [[ -n "$temp_pass" ]]; then
    log "Authentication reset. New temporary password: ${temp_pass}"
  else
    warn "Unable to detect temporary password automatically. Check 'docker logs qbittorrent'."
  fi
}

update_whitelist() {
  local subnet
  subnet=$(derive_subnet)

  if [[ -z "$subnet" ]]; then
    die "LAN_IP is not set to a private address; cannot derive whitelist subnet"
  fi

  log "Enabling LAN whitelist for passwordless access..."
  stop_container

  local cfg
  cfg=$(config_file_path)
  if [[ -f "$cfg" ]]; then
    local tmp
    tmp=$(mktemp)
    awk '!(/^WebUI\\AuthSubnetWhitelistEnabled=/ || /^WebUI\\AuthSubnetWhitelist=/)' "$cfg" >"$tmp"
    {
      printf 'WebUI\\AuthSubnetWhitelistEnabled=true\n'
      printf 'WebUI\\AuthSubnetWhitelist=%s\n' "$subnet"
    } >>"$tmp"
    mv "$tmp" "$cfg"
  else
    warn "Config file not found at $cfg; whitelist not updated"
  fi

  start_container
  log "LAN whitelist enabled for: $subnet"
}

usage() {
  cat <<'USAGE'
Usage: qbt-helper.sh {show|reset|whitelist}
  show       Display current access information
  reset      Reset authentication (generates a new temporary password)
  whitelist  Enable passwordless access from the LAN subnet
USAGE
}

main() {
  load_env

  DOCKER_DATA=$(resolve_docker_data) || die "Cannot find docker-data directory"
  export DOCKER_DATA

  case "${1:-show}" in
    show)
      show_info
      ;;
    reset)
      reset_auth
      ;;
    whitelist)
      update_whitelist
      ;;
    *)
      usage
      exit 1
      ;;
  esac
}

main "$@"

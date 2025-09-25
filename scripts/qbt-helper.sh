#!/usr/bin/env bash
# qBittorrent Helper - Manage authentication and access defaults

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STACK_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# shellcheck source=scripts/common.sh
. "${STACK_DIR}/scripts/common.sh"

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
  docker logs "$CONTAINER_NAME" 2>&1 \
    | grep "temporary password" \
    | tail -1 \
    | sed 's/.*temporary password[^:]*: *//' \
    | awk '{print $1}'
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

webui_domain() {
  local suffix="${CADDY_DOMAIN_SUFFIX:-home.arpa}"
  suffix="${suffix#.}"
  printf 'qbittorrent.%s' "$suffix"
}

config_file_path() {
  printf '%s/qbittorrent/qBittorrent.conf' "$DOCKER_DATA"
}

stop_container() {
  docker stop "$CONTAINER_NAME" >/dev/null 2>&1 || true
}

start_container() {
  docker start "$CONTAINER_NAME" >/dev/null 2>&1 || true
}

derive_subnet() {
  if [[ -n "${LAN_IP:-}" && "$LAN_IP" != "0.0.0.0" ]]; then
    local IFS='.'
    read -r oct1 oct2 oct3 _ <<<"$LAN_IP"
    case "$oct1" in
      10)
        printf '%s.%s.%s.0/24\n' "$oct1" "$oct2" "$oct3"
        ;;
      192)
        if [[ "$oct2" == "168" ]]; then
          printf '%s.%s.%s.0/24\n' "$oct1" "$oct2" "$oct3"
        fi
        ;;
      172)
        if [[ "$oct2" =~ ^[0-9]+$ ]] && [ "$oct2" -ge 16 ] && [ "$oct2" -le 31 ]; then
          printf '%s.%s.%s.0/24\n' "$oct1" "$oct2" "$oct3"
        fi
        ;;
    esac
  fi
}

show_info() {
  log_info "qBittorrent Access Information:"
  log_info "================================"
  log_info "LAN URL:  http://$(webui_domain)/"
  log_info "HTTPS:    https://$(webui_domain)/ (trust the Caddy internal CA)"
  log_info ""

  local temp_pass
  temp_pass=$(temporary_password || true)

  if [[ -n "$temp_pass" ]]; then
    log_info "Username: admin"
    log_info "Password: ${temp_pass} (temporary - change this!)"
  else
    log_info "Username: ${QBT_USER:-admin}"
    log_info "Password: ${QBT_PASS:-Check logs or use 'reset' command}"
  fi

  log_info ""
  log_info "Remote clients must authenticate through Caddy using user '${CADDY_BASIC_AUTH_USER:-user}' and the password hashed in ${ARR_DOCKER_DIR}/caddy/Caddyfile."
}

reset_auth() {
  log_info "Resetting qBittorrent authentication..."
  stop_container

  local cfg
  cfg=$(config_file_path)
  if [[ -f "$cfg" ]]; then
    local backup
    backup="${cfg}.bak.$(date +%Y%m%d_%H%M%S)"
    cp "$cfg" "$backup"
    log_info "  Backed up config to $backup"
    sed -i '/WebUI\\Password_PBKDF2/d' "$cfg" || true
  else
    log_warn "Config file not found at $cfg; proceeding without backup"
  fi

  start_container
  sleep 5

  local temp_pass
  temp_pass=$(temporary_password || true)

  if [[ -n "$temp_pass" ]]; then
    log_info "Authentication reset. New temporary password: ${temp_pass}"
  else
    log_warn "Unable to detect temporary password automatically. Check 'docker logs qbittorrent'."
  fi
}

update_whitelist() {
  local subnet
  subnet=$(derive_subnet)

  if [[ -z "$subnet" ]]; then
    die "LAN_IP is not set to a private address; cannot derive whitelist subnet"
  fi

  log_info "Enabling LAN whitelist for passwordless access..."
  stop_container

  local cfg
  cfg=$(config_file_path)
  if [[ -f "$cfg" ]]; then
    local tmp
    if ! tmp=$(arrstack_mktemp_file); then
      die "Failed to create temporary whitelist file"
    fi
    awk '!(/^WebUI\\AuthSubnetWhitelistEnabled=/ || /^WebUI\\AuthSubnetWhitelist=/)' "$cfg" >"$tmp"
    {
      printf 'WebUI\\AuthSubnetWhitelistEnabled=true\n'
      printf 'WebUI\\AuthSubnetWhitelist=%s\n' "$subnet"
    } >>"$tmp"
    mv "$tmp" "$cfg"
  else
    log_warn "Config file not found at $cfg; whitelist not updated"
  fi

  start_container
  log_info "LAN whitelist enabled for: $subnet"
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

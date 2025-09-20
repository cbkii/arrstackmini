#!/usr/bin/env bash
set -Euo pipefail
IFS=$'\n\t'

REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
[ -f "${REPO_ROOT}/arrconf/userconf.defaults.sh" ] && . "${REPO_ROOT}/arrconf/userconf.defaults.sh"
[ -f "${REPO_ROOT}/arrconf/userconf.sh" ] && . "${REPO_ROOT}/arrconf/userconf.sh"

ARR_ENV_FILE="${ARR_ENV_FILE:-${ARR_STACK_DIR}/.env}"
ASSUME_YES="${ASSUME_YES:-0}"
FORCE_ROTATE_API_KEY="${FORCE_ROTATE_API_KEY:-0}"
LOCALHOST_IP="${LOCALHOST_IP:-127.0.0.1}"
SERVER_COUNTRIES="${SERVER_COUNTRIES:-Netherlands,Switzerland}"

: "${PUID:=$(id -u)}"
: "${PGID:=$(id -g)}"
: "${TIMEZONE:=Australia/Sydney}"
: "${GLUETUN_CONTROL_PORT:=8000}"
: "${QBT_HTTP_PORT_HOST:=8081}"
: "${SONARR_PORT:=8989}"
: "${RADARR_PORT:=7878}"
: "${PROWLARR_PORT:=9696}"
: "${BAZARR_PORT:=6767}"
: "${FLARESOLVERR_PORT:=8191}"
: "${QBT_USER:=admin}"
: "${QBT_PASS:=adminadmin}"

: "${GLUETUN_IMAGE:=qmcgaw/gluetun:v3.39.1}"
: "${QBITTORRENT_IMAGE:=lscr.io/linuxserver/qbittorrent:5.1.2-r2-ls415}"
: "${SONARR_IMAGE:=lscr.io/linuxserver/sonarr:4.0.15.2941-ls291}"
: "${RADARR_IMAGE:=lscr.io/linuxserver/radarr:5.27.5.10198-ls283}"
: "${PROWLARR_IMAGE:=lscr.io/linuxserver/prowlarr:1.28.2-ls207}"
: "${BAZARR_IMAGE:=lscr.io/linuxserver/bazarr:1.5.1-ls288}"
: "${FLARESOLVERR_IMAGE:=ghcr.io/flaresolverr/flaresolverr:v3.3.21}"

DOCKER_COMPOSE_CMD=()

help() {
  cat <<'USAGE'
Usage: ./arrstack.sh [options]

Options:
  --yes                 Run non-interactively and assume yes to prompts
  --rotate-api-key      Force regeneration of the Gluetun API key
  --help                Show this help message
USAGE
}

msg() {
  printf '%s\n' "$*"
}

warn() {
  printf 'WARN: %s\n' "$*" >&2
}

die() {
  warn "$1"
  exit 1
}

detect_lan_ip() {
  local candidate
  if command -v ip >/dev/null 2>&1; then
    candidate=$(ip -4 addr show scope global | awk '/inet / {print $2}' | cut -d/ -f1 | grep -E '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)' | head -n1 || true)
  else
    candidate=$(hostname -I 2>/dev/null | awk '{for (i=1;i<=NF;i++) print $i}' | grep -E '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)' | head -n1 || true)
  fi

  if [[ -z "$candidate" ]]; then
    warn "================================================"
    warn "WARNING: Unable to detect a private LAN IP automatically"
    warn "Services will bind to 0.0.0.0 (all interfaces) until LAN_IP is set"
    warn "Edit arrconf/userconf.sh and set LAN_IP to a specific address"
    warn "================================================"
    echo "0.0.0.0"
  else
    echo "$candidate"
  fi
}

install_missing() {
  msg "🔧 Checking dependencies"
  local required=(docker curl jq openssl python3)
  local missing=()

  for cmd in "${required[@]}"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      missing+=("$cmd")
    fi
  done

  if docker compose version >/dev/null 2>&1; then
    DOCKER_COMPOSE_CMD=(docker compose)
  elif command -v docker-compose >/dev/null 2>&1; then
    DOCKER_COMPOSE_CMD=(docker-compose)
  else
    missing+=("docker compose")
  fi

  if ((${#missing[@]} > 0)); then
    die "Missing required tools: ${missing[*]}. Please install them and re-run."
  fi
}

ensure_dir() {
  local dir="$1"
  mkdir -p "$dir"
}

preflight() {
  msg "🚀 Preflight checks"

  if [[ ! -f "${ARRCONF_DIR}/proton.auth" ]]; then
    die "Missing ${ARRCONF_DIR}/proton.auth - create it with PROTON_USER and PROTON_PASS"
  fi

  install_missing

  if [[ "$ASSUME_YES" != 1 ]]; then
    printf 'Continue with ProtonVPN OpenVPN setup? [y/N]: '
    read -r a
    [[ "$a" =~ ^[Yy]$ ]] || die "Aborted"
  fi
}

mkdirs() {
  msg "📁 Creating directories"
  ensure_dir "$ARR_STACK_DIR"
  ensure_dir "$ARR_DOCKER_DIR/gluetun"
  ensure_dir "$ARR_DOCKER_DIR/qbittorrent"
  ensure_dir "$ARR_DOCKER_DIR/sonarr"
  ensure_dir "$ARR_DOCKER_DIR/radarr"
  ensure_dir "$ARR_DOCKER_DIR/prowlarr"
  ensure_dir "$ARR_DOCKER_DIR/bazarr"
  ensure_dir "$ARR_DOCKER_DIR/flaresolverr"
  ensure_dir "$DOWNLOADS_DIR"
  ensure_dir "$COMPLETED_DIR"
  ensure_dir "$TV_DIR"
  ensure_dir "$MOVIES_DIR"
  ensure_dir "$ARR_STACK_DIR/scripts"
}

generate_api_key() {
  msg "🔐 Generating API key"

  if [[ -f "$ARR_ENV_FILE" ]] && [[ "$FORCE_ROTATE_API_KEY" != 1 ]]; then
    local existing
    existing="$(grep '^GLUETUN_API_KEY=' "$ARR_ENV_FILE" 2>/dev/null | cut -d= -f2- || true)"
    if [[ -n "$existing" ]]; then
      GLUETUN_API_KEY="$existing"
      msg "Using existing API key"
      return
    fi
  fi

  GLUETUN_API_KEY="$(openssl rand -base64 48 | tr -d '\n/')"
  msg "Generated new API key"
}

write_env() {
  msg "📝 Writing .env file"

  if [[ -z "${LAN_IP:-}" ]]; then
    LAN_IP=$(detect_lan_ip)
    if [[ "$LAN_IP" != "0.0.0.0" ]]; then
      msg "Detected LAN IP: $LAN_IP"
    else
      warn "Using LAN_IP=0.0.0.0; services will listen on all interfaces"
    fi
  elif [[ "$LAN_IP" == "0.0.0.0" ]]; then
    warn "LAN_IP explicitly set to 0.0.0.0; services will bind to all interfaces"
    warn "Consider using a specific RFC1918 address to limit exposure"
  fi

  local PU PW
  PU=$(grep '^PROTON_USER=' "$ARRCONF_DIR/proton.auth" | cut -d= -f2-)
  PW=$(grep '^PROTON_PASS=' "$ARRCONF_DIR/proton.auth" | cut -d= -f2-)

  [[ -n "$PU" && -n "$PW" ]] || die "Empty PROTON_USER/PROTON_PASS in proton.auth"

  [[ "$PU" == *"+pmp" ]] || PU="${PU}+pmp"

  cat >"$ARR_ENV_FILE" <<ENV
# Core settings
VPN_TYPE=openvpn
PUID=${PUID}
PGID=${PGID}
TIMEZONE=${TIMEZONE}
LAN_IP=${LAN_IP}
LOCALHOST_IP=${LOCALHOST_IP}

# ProtonVPN credentials
OPENVPN_USER=${PU}
OPENVPN_PASS=${PW}

# Gluetun settings
GLUETUN_API_KEY=${GLUETUN_API_KEY}
GLUETUN_CONTROL_PORT=${GLUETUN_CONTROL_PORT}
SERVER_COUNTRIES=${SERVER_COUNTRIES}

# Service ports
QBT_HTTP_PORT_HOST=${QBT_HTTP_PORT_HOST}
SONARR_PORT=${SONARR_PORT}
RADARR_PORT=${RADARR_PORT}
PROWLARR_PORT=${PROWLARR_PORT}
BAZARR_PORT=${BAZARR_PORT}
FLARESOLVERR_PORT=${FLARESOLVERR_PORT}

# qBittorrent credentials (change in WebUI after install, then update here)
QBT_USER=${QBT_USER}
QBT_PASS=${QBT_PASS}

# Paths
ARR_DOCKER_DIR=${ARR_DOCKER_DIR}
DOWNLOADS_DIR=${DOWNLOADS_DIR}
COMPLETED_DIR=${COMPLETED_DIR}
TV_DIR=${TV_DIR}
MOVIES_DIR=${MOVIES_DIR}

# Images
GLUETUN_IMAGE=${GLUETUN_IMAGE}
QBITTORRENT_IMAGE=${QBITTORRENT_IMAGE}
SONARR_IMAGE=${SONARR_IMAGE}
RADARR_IMAGE=${RADARR_IMAGE}
PROWLARR_IMAGE=${PROWLARR_IMAGE}
BAZARR_IMAGE=${BAZARR_IMAGE}
FLARESOLVERR_IMAGE=${FLARESOLVERR_IMAGE}
ENV

  chmod 600 "$ARR_ENV_FILE"
}

write_compose() {
  msg "🐳 Writing docker-compose.yml"

  cat >"$ARR_STACK_DIR/docker-compose.yml" <<'YAML'
services:
  gluetun:
    image: ${GLUETUN_IMAGE}
    container_name: gluetun
    cap_add:
      - NET_ADMIN
    devices:
      - /dev/net/tun
    environment:
      VPN_SERVICE_PROVIDER: protonvpn
      VPN_TYPE: openvpn
      OPENVPN_USER: ${OPENVPN_USER}
      OPENVPN_PASSWORD: ${OPENVPN_PASS}
      SERVER_COUNTRIES: ${SERVER_COUNTRIES}
      VPN_PORT_FORWARDING: "on"
      VPN_PORT_FORWARDING_PROVIDER: protonvpn
      HTTP_CONTROL_SERVER_ADDRESS: :${GLUETUN_CONTROL_PORT}
      HTTP_CONTROL_SERVER_AUTH: "apikey"
      HTTP_CONTROL_SERVER_APIKEY: ${GLUETUN_API_KEY}
      FIREWALL_OUTBOUND_SUBNETS: "192.168.0.0/16,10.0.0.0/8,172.16.0.0/12"
      DOT: "off"
      UPDATER_PERIOD: "24h"
      PUID: ${PUID}
      PGID: ${PGID}
      TZ: ${TIMEZONE}
    volumes:
      - ${ARR_DOCKER_DIR}/gluetun:/gluetun
    ports:
      - "${LOCALHOST_IP}:${GLUETUN_CONTROL_PORT}:${GLUETUN_CONTROL_PORT}"
      - "${LAN_IP}:${QBT_HTTP_PORT_HOST}:8080"
      - "${LAN_IP}:${SONARR_PORT}:${SONARR_PORT}"
      - "${LAN_IP}:${RADARR_PORT}:${RADARR_PORT}"
      - "${LAN_IP}:${PROWLARR_PORT}:${PROWLARR_PORT}"
      - "${LAN_IP}:${BAZARR_PORT}:${BAZARR_PORT}"
      - "${LAN_IP}:${FLARESOLVERR_PORT}:${FLARESOLVERR_PORT}"
    healthcheck:
      test: /gluetun-entrypoint healthcheck
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 30s
    restart: unless-stopped

  qbittorrent:
    image: ${QBITTORRENT_IMAGE}
    container_name: qbittorrent
    network_mode: "service:gluetun"
    environment:
      PUID: ${PUID}
      PGID: ${PGID}
      TZ: ${TIMEZONE}
      WEBUI_PORT: 8080
    volumes:
      - ${ARR_DOCKER_DIR}/qbittorrent:/config
      - ${DOWNLOADS_DIR}:/downloads
      - ${COMPLETED_DIR}:/completed
    depends_on:
      gluetun:
        condition: service_healthy
    restart: unless-stopped

  sonarr:
    image: ${SONARR_IMAGE}
    container_name: sonarr
    network_mode: "service:gluetun"
    environment:
      PUID: ${PUID}
      PGID: ${PGID}
      TZ: ${TIMEZONE}
    volumes:
      - ${ARR_DOCKER_DIR}/sonarr:/config
      - ${DOWNLOADS_DIR}:/downloads
      - ${COMPLETED_DIR}:/completed
      - ${TV_DIR}:/tv
    depends_on:
      gluetun:
        condition: service_healthy
    restart: unless-stopped

  radarr:
    image: ${RADARR_IMAGE}
    container_name: radarr
    network_mode: "service:gluetun"
    environment:
      PUID: ${PUID}
      PGID: ${PGID}
      TZ: ${TIMEZONE}
    volumes:
      - ${ARR_DOCKER_DIR}/radarr:/config
      - ${DOWNLOADS_DIR}:/downloads
      - ${COMPLETED_DIR}:/completed
      - ${MOVIES_DIR}:/movies
    depends_on:
      gluetun:
        condition: service_healthy
    restart: unless-stopped

  prowlarr:
    image: ${PROWLARR_IMAGE}
    container_name: prowlarr
    network_mode: "service:gluetun"
    environment:
      PUID: ${PUID}
      PGID: ${PGID}
      TZ: ${TIMEZONE}
    volumes:
      - ${ARR_DOCKER_DIR}/prowlarr:/config
    depends_on:
      gluetun:
        condition: service_healthy
    restart: unless-stopped

  bazarr:
    image: ${BAZARR_IMAGE}
    container_name: bazarr
    network_mode: "service:gluetun"
    environment:
      PUID: ${PUID}
      PGID: ${PGID}
      TZ: ${TIMEZONE}
    volumes:
      - ${ARR_DOCKER_DIR}/bazarr:/config
      - ${TV_DIR}:/tv
      - ${MOVIES_DIR}:/movies
    depends_on:
      gluetun:
        condition: service_healthy
    restart: unless-stopped

  flaresolverr:
    image: ${FLARESOLVERR_IMAGE}
    container_name: flaresolverr
    network_mode: "service:gluetun"
    environment:
      LOG_LEVEL: info
    depends_on:
      gluetun:
        condition: service_healthy
    restart: unless-stopped

  port-sync:
    image: alpine:3.20.3
    container_name: port-sync
    network_mode: "service:gluetun"
    environment:
      GLUETUN_API_KEY: ${GLUETUN_API_KEY}
      GLUETUN_ADDR: "http://localhost:${GLUETUN_CONTROL_PORT}"
      QBITTORRENT_ADDR: "http://localhost:8080"
      UPDATE_INTERVAL: 300
      QBT_USER: ${QBT_USER}
      QBT_PASS: ${QBT_PASS}
    volumes:
      - ./scripts/port-sync.sh:/port-sync.sh:ro
    command: /port-sync.sh
    depends_on:
      - gluetun
      - qbittorrent
    restart: unless-stopped
YAML

  chmod 600 "$ARR_STACK_DIR/docker-compose.yml"
}

write_port_sync_script() {
  msg "📜 Writing port sync script"

  ensure_dir "$ARR_STACK_DIR/scripts"

  cat >"$ARR_STACK_DIR/scripts/port-sync.sh" <<'SCRIPT'
#!/bin/sh
set -e

# Install required packages
apk add --no-cache curl jq >/dev/null 2>&1 || true

GLUETUN_ADDR="${GLUETUN_ADDR:-http://localhost:8000}"
QBITTORRENT_ADDR="${QBITTORRENT_ADDR:-http://localhost:8080}"
UPDATE_INTERVAL="${UPDATE_INTERVAL:-300}"
QBT_USER="${QBT_USER:-}"
QBT_PASS="${QBT_PASS:-}"
RETRY_DELAY=10

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [PORT-SYNC] $1"
}

get_gluetun_port() {
    local port_json
    port_json=$(curl -fsS -H "X-Api-Key: ${GLUETUN_API_KEY}" \
        "${GLUETUN_ADDR}/v1/openvpn/portforwarded" || echo '{}')
    echo "$port_json" | sed -n 's/.*"port":\s*\([0-9]\+\).*/\1/p'
}

set_preferences_payload() {
    local port="$1"
    printf 'json={"listen_port":%s,"upnp":false}' "$port"
}

update_qbittorrent_port() {
    local port="$1"
    local payload
    payload=$(set_preferences_payload "$port")

    # Try without authentication first (allowed when localhost auth bypass is enabled)
    if curl -fsS \
        "${QBITTORRENT_ADDR}/api/v2/app/setPreferences" \
        -d "$payload" >/dev/null 2>&1; then
        return 0
    fi

    # Fallback to cookie-based auth if credentials are available
    if [ -n "$QBT_USER" ] && [ -n "$QBT_PASS" ]; then
        local cookie_file="/tmp/.qbt_cookies.$$"
        if curl -fsS -c "$cookie_file" \
            "${QBITTORRENT_ADDR}/api/v2/auth/login" \
            -d "username=${QBT_USER}&password=${QBT_PASS}" >/dev/null 2>&1; then
            if curl -fsS -b "$cookie_file" \
                "${QBITTORRENT_ADDR}/api/v2/app/setPreferences" \
                -d "$payload" >/dev/null 2>&1; then
                rm -f "$cookie_file"
                return 0
            fi
        fi
        rm -f "$cookie_file"
    fi

    log "Warning: Failed to update qBittorrent port via API"
    log "         Verify WebUI credentials and permissions"
    return 1
}

log "Waiting for services to start..."
sleep 30

while true; do
    port=$(get_gluetun_port)

    if [ -n "$port" ] && [ "$port" != "0" ]; then
        log "Forwarded port: $port"
        if update_qbittorrent_port "$port"; then
            log "Successfully updated qBittorrent port to $port"
        else
            log "Failed to update qBittorrent port"
        fi
    else
        log "No forwarded port available yet"
    fi

    sleep "$UPDATE_INTERVAL"
done
SCRIPT

  chmod +x "$ARR_STACK_DIR/scripts/port-sync.sh"
}

write_qbt_config() {
  msg "🧩 Writing qBittorrent config"
  local conf_dir="${ARR_DOCKER_DIR}/qbittorrent"
  local conf_file="${conf_dir}/qBittorrent.conf"

  ensure_dir "$conf_dir"

  if [[ ! -f "$conf_file" ]]; then
    cat >"$conf_file" <<'QBT'
[AutoRun]
enabled=false

[BitTorrent]
Session\Port=8080

[Preferences]
General\UseRandomPort=false
Connection\PortRangeMin=8080
Connection\UPnP=false
WebUI\Port=8080
WebUI\UseUPnP=false
WebUI\LocalHostAuth=false
WebUI\AuthSubnetWhitelist=127.0.0.1/32
QBT
    chmod 600 "$conf_file"
  fi
}

cleanup_existing() {
  msg "🧹 Cleaning up old services"
  if [[ -f "$ARR_STACK_DIR/docker-compose.yml" ]]; then
    "${DOCKER_COMPOSE_CMD[@]}" down --remove-orphans >/dev/null 2>&1 || true
  fi
  rm -f "$ARR_DOCKER_DIR/gluetun/forwarded_port" "$ARR_DOCKER_DIR/gluetun/forwarded_port.json" 2>/dev/null || true
}

start_stack() {
  msg "🚀 Starting services"

  cd "$ARR_STACK_DIR" || die "Failed to change to $ARR_STACK_DIR"

  cleanup_existing

  msg "Starting Gluetun..."
  "${DOCKER_COMPOSE_CMD[@]}" up -d gluetun

  msg "Waiting for VPN connection (up to 5 minutes)..."
  local tries=0
  while ! docker inspect gluetun --format '{{.State.Health.Status}}' 2>/dev/null | grep -q healthy; do
    sleep 5
    ((tries++))
    if ((tries % 12 == 0)); then
      msg "   Still waiting for Gluetun... (${tries}/60)"
    fi
    if ((tries > 60)); then
      warn "Gluetun is taking longer than expected to report healthy"
      warn "Continuing startup; inspect logs with: docker logs gluetun"
      break
    fi
  done

  local ip
  ip=$(curl -fsS -H "X-Api-Key: ${GLUETUN_API_KEY}" \
    "http://localhost:${GLUETUN_CONTROL_PORT}/v1/publicip/ip" 2>/dev/null | \
    jq -r '.public_ip // empty' || true)

  if [[ -n "$ip" ]]; then
    msg "✅ VPN connected! Public IP: $ip"
  else
    warn "Could not verify VPN connection automatically"
    warn "Check: docker logs gluetun --tail 100"
  fi

  msg "Starting all services..."
  "${DOCKER_COMPOSE_CMD[@]}" up -d

  msg "Waiting for services to initialize..."
  sleep 15

  msg "Service status summary:"
  docker ps --format 'table {{.Names}}\t{{.Status}}' | grep -E 'gluetun|qbittorrent|sonarr|radarr|prowlarr|bazarr|flaresolverr|port-sync' || true
}

install_aliases() {
  local bashrc="${HOME}/.bashrc"
  local alias_line="alias arrstack='cd ${REPO_ROOT} && ./arrstack.sh'"
  local source_line="# source ${ARR_STACK_DIR}/.arraliases  # Optional helper functions"

  if [[ -w "$bashrc" ]]; then
    if ! grep -Fq "$alias_line" "$bashrc" 2>/dev/null; then
      {
        printf '\n# ARR Stack helper aliases\n'
        printf '%s\n' "$alias_line"
        printf "alias arrstack-logs='docker logs -f gluetun'\n"
        printf '%s\n' "$source_line"
      } >>"$bashrc"
      msg "Added aliases to ${bashrc}"
    fi
  fi
}

write_aliases_file() {
  msg "📄 Generating helper aliases file"

  local template_file="${REPO_ROOT}/.arraliases"
  local aliases_file="${ARR_STACK_DIR}/.arraliases"
  local configured_template="${REPO_ROOT}/.arraliases.configured"

  if [[ ! -f "$template_file" ]]; then
    warn "Alias template ${template_file} not found"
    return 0
  fi

  if ! python3 - "$template_file" "$aliases_file" "$ARR_STACK_DIR" "$ARR_ENV_FILE" "$ARR_DOCKER_DIR" "$ARRCONF_DIR" <<'PY'; then
import pathlib
import sys

template_path, output_path, stack_dir, env_file, docker_dir, conf_dir = sys.argv[1:7]
content = pathlib.Path(template_path).read_text()
content = content.replace("__ARR_STACK_DIR__", stack_dir)
content = content.replace("__ARR_ENV_FILE__", env_file)
content = content.replace("__ARR_DOCKER_DIR__", docker_dir)
content = content.replace("__ARRCONF_DIR__", conf_dir)
pathlib.Path(output_path).write_text(content)
PY
    warn "Failed to render aliases file"
    return 0
  fi

  chmod 600 "$aliases_file"
  cp "$aliases_file" "$configured_template"
  msg "✅ Helper aliases written to: $aliases_file"
  msg "   Source them with: source $aliases_file"
  msg "   Repo copy updated: $configured_template"
}

show_summary() {
  cat <<SUMMARY

🎉 Setup complete!

SUMMARY

  if [[ "${LAN_IP}" == "0.0.0.0" ]]; then
    cat <<'WARNING'
⚠️  SECURITY WARNING
   LAN_IP is 0.0.0.0 so services listen on all interfaces.
   Update arrconf/userconf.sh with a specific LAN_IP to limit exposure.

WARNING
  fi

  if [[ "${QBT_USER}" == "admin" && "${QBT_PASS}" == "adminadmin" ]]; then
    cat <<'WARNING'
⚠️  DEFAULT CREDENTIALS
   qBittorrent is using admin/adminadmin.
   Change this in the WebUI and update QBT_USER/QBT_PASS in .env.

WARNING
  fi

  cat <<SUMMARY
Access your services at:
  qBittorrent:   http://${LAN_IP}:${QBT_HTTP_PORT_HOST}
  Sonarr:        http://${LAN_IP}:${SONARR_PORT}
  Radarr:        http://${LAN_IP}:${RADARR_PORT}
  Prowlarr:      http://${LAN_IP}:${PROWLARR_PORT}
  Bazarr:        http://${LAN_IP}:${BAZARR_PORT}
  FlareSolverr:  http://${LAN_IP}:${FLARESOLVERR_PORT}

Gluetun control server (local only): http://${LOCALHOST_IP}:${GLUETUN_CONTROL_PORT}

Helper commands:
  source ${ARR_STACK_DIR}/.arraliases
  pvpn.status    # Check VPN status
  arr.health     # Container health summary
  arr.logs       # Follow container logs via docker compose

SUMMARY
}

main() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --yes)
        ASSUME_YES=1
        shift
        ;;
      --rotate-api-key)
        FORCE_ROTATE_API_KEY=1
        shift
        ;;
      --help|-h)
        help
        exit 0
        ;;
      *)
        die "Unknown option: $1"
        ;;
    esac
  done

  preflight
  mkdirs
  generate_api_key
  write_env
  write_compose
  write_port_sync_script
  write_qbt_config
  write_aliases_file
  install_aliases
  start_stack
  show_summary
}

main "$@"

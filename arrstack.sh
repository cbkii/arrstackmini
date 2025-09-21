#!/usr/bin/env bash
set -Euo pipefail
IFS=$'\n\t'

REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
[ -f "${REPO_ROOT}/arrconf/userconf.defaults.sh" ] && . "${REPO_ROOT}/arrconf/userconf.defaults.sh"
[ -f "${REPO_ROOT}/arrconf/userconf.sh" ] && . "${REPO_ROOT}/arrconf/userconf.sh"

# Handle case where docker-data is in ~/srv instead of repo
if [[ -z "${ARR_DOCKER_DIR}" && -d "${HOME}/srv/docker-data" ]]; then
  ARR_DOCKER_DIR="${HOME}/srv/docker-data"
  ARR_STACK_DIR="${ARR_STACK_DIR:-${PWD}/arrstack}"
fi

ARR_ENV_FILE="${ARR_ENV_FILE:-${ARR_STACK_DIR}/.env}"
ASSUME_YES="${ASSUME_YES:-0}"
FORCE_ROTATE_API_KEY="${FORCE_ROTATE_API_KEY:-0}"
LOCALHOST_IP="${LOCALHOST_IP:-127.0.0.1}"
# Restrict to ProtonVPN servers supporting port forwarding by default
SERVER_COUNTRIES="${SERVER_COUNTRIES:-Switzerland,Iceland,Romania,Czech Republic,Netherlands}"

: "${PUID:=$(id -u)}"
: "${PGID:=$(id -g)}"
: "${TIMEZONE:=Australia/Sydney}"
: "${GLUETUN_CONTROL_PORT:=8000}"
: "${QBT_HTTP_PORT_HOST:=8080}"
: "${SONARR_PORT:=8989}"
: "${RADARR_PORT:=7878}"
: "${PROWLARR_PORT:=9696}"
: "${BAZARR_PORT:=6767}"
: "${FLARESOLVERR_PORT:=8191}"

: "${QBT_USER:=admin}"
: "${QBT_PASS:=adminadmin}"
: "${QBT_DOCKER_MODS:=ghcr.io/vuetorrent/vuetorrent-lsio-mod:latest}"
: "${QBT_AUTH_WHITELIST:=127.0.0.1/8,::1/128}"

: "${GLUETUN_IMAGE:=qmcgaw/gluetun:v3.39.1}"
: "${QBITTORRENT_IMAGE:=lscr.io/linuxserver/qbittorrent:5.1.2-r2-ls415}"
: "${SONARR_IMAGE:=lscr.io/linuxserver/sonarr:4.0.15.2941-ls291}"
: "${RADARR_IMAGE:=lscr.io/linuxserver/radarr:5.27.5.10198-ls283}"
: "${PROWLARR_IMAGE:=lscr.io/linuxserver/prowlarr:latest}"
: "${BAZARR_IMAGE:=lscr.io/linuxserver/bazarr:latest}"
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
  local required=(docker curl jq openssl)
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

escape_sed_replacement() {
  printf '%s' "$1" | sed -e 's/[&/]/\\&/g'
}

set_qbt_conf_value() {
  local file="$1"
  local key="$2"
  local value="$3"
  local tmp

  tmp="$(mktemp)"

  if [[ -f "$file" ]]; then
    local replaced=0
    while IFS= read -r line || [[ -n "$line" ]]; do
      if [[ "$line" == "$key="* ]]; then
        printf '%s=%s\n' "$key" "$value" >>"$tmp"
        replaced=1
      else
        printf '%s\n' "$line" >>"$tmp"
      fi
    done <"$file"
    if (( ! replaced )); then
      printf '%s=%s\n' "$key" "$value" >>"$tmp"
    fi
  else
    printf '%s=%s\n' "$key" "$value" >>"$tmp"
  fi

  mv "$tmp" "$file"
}

persist_env_var() {
  local key="$1"
  local value="$2"

  if [[ -z "$key" ]]; then
    return
  fi

  if [[ -f "$ARR_ENV_FILE" ]]; then
    if grep -q "^${key}=" "$ARR_ENV_FILE"; then
      local escaped
      escaped=$(escape_sed_replacement "$value")
      sed -i "s/^${key}=.*/${key}=${escaped}/" "$ARR_ENV_FILE"
    else
      printf '%s=%s\n' "$key" "$value" >>"$ARR_ENV_FILE"
    fi
  fi
}

obfuscate_sensitive() {
  local value="${1-}"
  if [[ -z "$value" ]]; then
    printf '(not set)'
    return
  fi

  local length=${#value}

  if (( length <= 4 )); then
    printf '%*s' "$length" '' | tr ' ' '*'
    return
  fi

  local visible=2
  local prefix="${value:0:visible}"
  local suffix="${value: -visible}"
  local hidden_len=$((length - visible * 2))
  local mask
  mask=$(printf '%*s' "$hidden_len" '' | tr ' ' '*')

  printf '%s%s%s' "$prefix" "$mask" "$suffix"
}

calculate_qbt_auth_whitelist() {
  local auth_whitelist=""

  append_whitelist_entry() {
    local entry="$1"
    entry="${entry//[[:space:]]/}"
    if [[ -z "$entry" ]]; then
      return
    fi
    if [[ ",${auth_whitelist}," == *",${entry},"* ]]; then
      return
    fi
    if [[ -z "$auth_whitelist" ]]; then
      auth_whitelist="$entry"
    else
      auth_whitelist="${auth_whitelist},${entry}"
    fi
  }

  if [[ -n "${QBT_AUTH_WHITELIST:-}" ]]; then
    local sanitized="${QBT_AUTH_WHITELIST//[[:space:]]/}"
    if [[ -n "$sanitized" ]]; then
      local -a entries=()
      IFS=',' read -ra entries <<<"$sanitized"
      local entry
      for entry in "${entries[@]}"; do
        append_whitelist_entry "$entry"
      done
    fi
  fi

  append_whitelist_entry "127.0.0.1/8"
  append_whitelist_entry "::1/128"

  if [[ -n "${LAN_IP:-}" && "$LAN_IP" != "0.0.0.0" && "$LAN_IP" == *.*.*.* ]]; then
    append_whitelist_entry "${LAN_IP%.*}.0/24"
  fi

  if [[ -z "$auth_whitelist" ]]; then
    auth_whitelist="127.0.0.1/8,::1/128"
  fi

  printf '%s' "$auth_whitelist"
  unset -f append_whitelist_entry || true
}

show_configuration_preview() {
  msg "🔎 Configuration preview"

  local proton_file="${ARRCONF_DIR}/proton.auth"
  local proton_user=""
  local proton_pass=""

  if [[ -f "$proton_file" ]]; then
    proton_user="$(grep '^PROTON_USER=' "$proton_file" | head -n1 | cut -d= -f2- || true)"
    proton_pass="$(grep '^PROTON_PASS=' "$proton_file" | head -n1 | cut -d= -f2- || true)"
  fi

  local proton_user_display="${proton_user:-'(not set)'}"
  local proton_pass_display
  proton_pass_display="$(obfuscate_sensitive "$proton_pass")"

  local qbt_pass_display
  qbt_pass_display="$(obfuscate_sensitive "${QBT_PASS:-}")"

  local openvpn_user_display
  if [[ -n "$proton_user" ]]; then
    openvpn_user_display="$proton_user"
    [[ "$openvpn_user_display" == *"+pmp" ]] || openvpn_user_display="${openvpn_user_display}+pmp"
  else
    openvpn_user_display="(not set)"
  fi

  local gluetun_api_key_display
  if [[ -n "${GLUETUN_API_KEY:-}" ]]; then
    gluetun_api_key_display="$(obfuscate_sensitive "$GLUETUN_API_KEY")"
  else
    gluetun_api_key_display="(will be generated during setup)"
  fi

  local qbt_auth_whitelist_preview
  qbt_auth_whitelist_preview="$(calculate_qbt_auth_whitelist)"
  local lan_ip_display
  if [[ -n "${LAN_IP:-}" ]]; then
    lan_ip_display="$LAN_IP"
  else
    lan_ip_display="(auto-detect during setup)"
  fi

  cat <<CONFIG
------------------------------------------------------------
ARR Stack configuration preview
------------------------------------------------------------
Paths
  • Stack directory: ${ARR_STACK_DIR}
  • Docker data root: ${ARR_DOCKER_DIR}
  • Downloads: ${DOWNLOADS_DIR}
  • Completed downloads: ${COMPLETED_DIR}
  • TV library: ${TV_DIR}
  • Movies library: ${MOVIES_DIR}

Network & system
  • Timezone: ${TIMEZONE}
  • LAN IP: ${lan_ip_display}
  • Localhost IP override: ${LOCALHOST_IP}
  • Server countries: ${SERVER_COUNTRIES}
  • User/Group IDs: ${PUID}/${PGID}

Credentials & secrets
  • Proton username: ${proton_user_display}
  • Proton OpenVPN username: ${openvpn_user_display}
  • Proton password: ${proton_pass_display}
  • Gluetun API key: ${gluetun_api_key_display}
  • qBittorrent username: ${QBT_USER}
  • qBittorrent password: ${qbt_pass_display}
  • qBittorrent auth whitelist (final): ${qbt_auth_whitelist_preview}
  • qBittorrent auth whitelist: ${QBT_AUTH_WHITELIST}

Ports
  • Gluetun control: ${GLUETUN_CONTROL_PORT}
  • qBittorrent WebUI (host): ${QBT_HTTP_PORT_HOST}
  • Sonarr: ${SONARR_PORT}
  • Radarr: ${RADARR_PORT}
  • Prowlarr: ${PROWLARR_PORT}
  • Bazarr: ${BAZARR_PORT}
  • FlareSolverr: ${FLARESOLVERR_PORT}

Files that will be created/updated
  • Environment file: ${ARR_ENV_FILE}
  • Compose file: ${ARR_STACK_DIR}/docker-compose.yml

If anything looks incorrect, edit arrconf/userconf.sh before continuing.
------------------------------------------------------------
CONFIG
}


GLUETUN_LIB="${REPO_ROOT}/scripts/lib/gluetun.sh"
if [[ -f "$GLUETUN_LIB" ]]; then
  # shellcheck source=scripts/lib/gluetun.sh
  . "$GLUETUN_LIB"
else
  warn "Gluetun helper library not found at $GLUETUN_LIB"
fi

preflight() {
  msg "🚀 Preflight checks"

  if [[ ! -f "${ARRCONF_DIR}/proton.auth" ]]; then
    die "Missing ${ARRCONF_DIR}/proton.auth - create it with PROTON_USER and PROTON_PASS"
  fi

  install_missing

  show_configuration_preview

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
  ensure_dir "$ARR_STACK_DIR/scripts"

  if [[ ! -d "$TV_DIR" ]]; then
    warn "TV directory does not exist: $TV_DIR"
    warn "Creating it now (may fail if parent directory is missing)"
    mkdir -p "$TV_DIR" 2>/dev/null || warn "Could not create TV directory"
  fi

  if [[ ! -d "$MOVIES_DIR" ]]; then
    warn "Movies directory does not exist: $MOVIES_DIR"
    warn "Creating it now (may fail if parent directory is missing)"
    mkdir -p "$MOVIES_DIR" 2>/dev/null || warn "Could not create Movies directory"
  fi
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
QBT_DOCKER_MODS=${QBT_DOCKER_MODS}

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
      VPN_PORT_FORWARDING_STATUS_FILE: /tmp/gluetun/forwarded_port
      PORT_FORWARD_ONLY: "yes"
      FIREWALL_OUTBOUND_SUBNETS: "192.168.0.0/16,10.0.0.0/8,172.16.0.0/12"
      FIREWALL_INPUT_PORTS: "${QBT_HTTP_PORT_HOST},${SONARR_PORT},${RADARR_PORT},${PROWLARR_PORT},${BAZARR_PORT},${FLARESOLVERR_PORT}"
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
      DOCKER_MODS: ${QBT_DOCKER_MODS}
    volumes:
      - ${ARR_DOCKER_DIR}/qbittorrent:/config
      - ${DOWNLOADS_DIR}:/downloads
      - ${COMPLETED_DIR}:/completed
    depends_on:
      gluetun:
        condition: service_healthy
    restart: unless-stopped

  vuetorrent-monthly-update:
    image: alpine:3.20.3
    container_name: vuetorrent-monthly-update
    network_mode: none
    entrypoint: ["/bin/sh","-c"]
    command: |
      set -e
      if ! command -v docker >/dev/null 2>&1; then
        apk add --no-cache docker-cli docker-cli-compose >/dev/null
      fi
      cat >/usr/local/bin/runner.sh <<'EOF'
      #!/bin/sh
      set -e
      while :; do
        docker compose -f /stack/docker-compose.yml up -d qbittorrent || true
        sleep $((30*24*60*60))
      done
      EOF
      chmod +x /usr/local/bin/runner.sh
      exec /usr/local/bin/runner.sh
    volumes:
      - ${ARR_STACK_DIR}:/stack:ro
      - /var/run/docker.sock:/var/run/docker.sock:ro
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
      VPN_PORT_FORWARDING_STATUS_FILE: /tmp/gluetun/forwarded_port
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

sync_gluetun_library() {
  msg "📚 Syncing Gluetun helper library"

  ensure_dir "$ARR_STACK_DIR/scripts"
  ensure_dir "$ARR_STACK_DIR/scripts/lib"

  cp "${REPO_ROOT}/scripts/lib/gluetun.sh" "$ARR_STACK_DIR/scripts/lib/gluetun.sh"
  chmod 644 "$ARR_STACK_DIR/scripts/lib/gluetun.sh"
}

write_port_sync_script() {
  msg "📜 Writing port sync script"

  ensure_dir "$ARR_STACK_DIR/scripts"

  cat >"$ARR_STACK_DIR/scripts/port-sync.sh" <<'SCRIPT'
#!/bin/sh
set -e

log() {
    printf '[%s] [port-sync] %s\n' "$(date '+%Y-%m-%dT%H:%M:%S%z')" "$1" >&2
}

ensure_curl() {
    if ! command -v curl >/dev/null 2>&1; then
        if command -v apk >/dev/null 2>&1; then
            apk add --no-cache curl >/dev/null 2>&1 || log 'warn: unable to install curl via apk'
        else
            log 'warn: curl is required but not available'
        fi
    fi
}

GLUETUN_ADDR="${GLUETUN_ADDR:-http://localhost:8000}"
GLUETUN_API_KEY="${GLUETUN_API_KEY:-}"
QBITTORRENT_ADDR="${QBITTORRENT_ADDR:-http://localhost:8080}"
UPDATE_INTERVAL="${UPDATE_INTERVAL:-300}"
QBT_USER="${QBT_USER:-}"
QBT_PASS="${QBT_PASS:-}"
STATUS_FILE="${VPN_PORT_FORWARDING_STATUS_FILE:-}"
COOKIE_JAR="/tmp/qbt.cookies"

ensure_curl

api_get() {
    local path="$1"
    if [ -n "$GLUETUN_API_KEY" ]; then
        curl -fsSL -H "X-Api-Key: ${GLUETUN_API_KEY}" "${GLUETUN_ADDR}${path}" 2>/dev/null || true
    else
        curl -fsSL "${GLUETUN_ADDR}${path}" 2>/dev/null || true
    fi
}

login_qbt() {
    # Use provided credentials when available; otherwise rely on localhost bypass
    if [ -z "$QBT_USER" ] || [ -z "$QBT_PASS" ]; then
        return 0
    fi

    if curl -fsSL -c "$COOKIE_JAR" \
        --data-urlencode "username=${QBT_USER}" \
        --data-urlencode "password=${QBT_PASS}" \
        "${QBITTORRENT_ADDR}/api/v2/auth/login" >/dev/null 2>&1; then
        return 0
    fi

    rm -f "$COOKIE_JAR"
    log 'warn: login failed; relying on localhost bypass (ensure LocalHostAuth=true)'
    return 0
}

ensure_qbt_session() { [ -s "$COOKIE_JAR" ] || login_qbt; }

get_pf_port() {
    local response port

    response="$(api_get '/v1/openvpn/portforwarded')"
    if [ -n "$response" ]; then
        port=$(printf '%s' "$response" | sed -n 's/.*"port":\([0-9]\+\).*/\1/p')
        if [ -n "$port" ]; then
            printf '%s' "$port"
            return 0
        fi
    fi

    port="$(api_get '/v1/forwardedport' | tr -d '[:space:]')"
    if printf '%s' "$port" | grep -Eq '^[0-9]+$'; then
        printf '%s' "$port"
        return 0
    fi

    response="$(api_get '/v1/portforwarded' | tr -d '[:space:]')"
    if [ "$response" = 'true' ] && [ -n "$STATUS_FILE" ] && [ -f "$STATUS_FILE" ]; then
        port=$(tr -d '[:space:]' <"$STATUS_FILE" 2>/dev/null || true)
        if printf '%s' "$port" | grep -Eq '^[0-9]+$'; then
            printf '%s' "$port"
            return 0
        fi
    fi

    if [ -n "$STATUS_FILE" ] && [ -f "$STATUS_FILE" ]; then
        port=$(tr -d '[:space:]' <"$STATUS_FILE" 2>/dev/null || true)
        if printf '%s' "$port" | grep -Eq '^[0-9]+$'; then
            printf '%s' "$port"
            return 0
        fi
    fi

    return 1
}

get_qbt_listen_port() {
    local response
    response=$(curl -fsSL -b "$COOKIE_JAR" "${QBITTORRENT_ADDR}/api/v2/app/preferences" 2>/dev/null \
        || curl -fsSL "${QBITTORRENT_ADDR}/api/v2/app/preferences" 2>/dev/null || true)
    if [ -z "$response" ]; then
        rm -f "$COOKIE_JAR"
        return 1
    fi
    printf '%s' "$response" | tr -d ' \n\r' | sed -n 's/.*"listen_port":\([0-9]\+\).*/\1/p'
}

set_qbt_listen_port() {
    local port="$1" payload
    payload="json={\"listen_port\":${port},\"random_port\":false}"
    if curl -fsSL -b "$COOKIE_JAR" --data "$payload" \
        "${QBITTORRENT_ADDR}/api/v2/app/setPreferences" >/dev/null 2>&1; then
        return 0
    fi
    if curl -fsSL --data "$payload" \
        "${QBITTORRENT_ADDR}/api/v2/app/setPreferences" >/dev/null 2>&1; then
        return 0
    fi
    rm -f "$COOKIE_JAR"
    return 1
}

cleanup() {
    rm -f "$COOKIE_JAR"
}

trap cleanup EXIT HUP INT TERM

log "starting port-sync against ${GLUETUN_ADDR} -> ${QBITTORRENT_ADDR}"
if ! ensure_qbt_session; then
    log 'warn: waiting for valid qBittorrent credentials'
fi

last_reported=""

while :; do
    if pf_port=$(get_pf_port); then
        if [ -n "$pf_port" ]; then
            if ! ensure_qbt_session; then
                log 'warn: unable to authenticate with qBittorrent; retrying'
                sleep "$UPDATE_INTERVAL"
                continue
            fi
            current_port=$(get_qbt_listen_port || true)
            if [ -z "$current_port" ]; then
                if ! ensure_qbt_session; then
                    log 'warn: unable to authenticate with qBittorrent; retrying'
                    sleep "$UPDATE_INTERVAL"
                    continue
                fi
                current_port=$(get_qbt_listen_port || true)
            fi
            if [ "$current_port" != "$pf_port" ]; then
                log "applying forwarded port ${pf_port} (current: ${current_port:-unset})"
                if set_qbt_listen_port "$pf_port"; then
                    log "updated qBittorrent listen_port to ${pf_port}"
                    last_reported="$pf_port"
                else
                    log "warn: failed to set qBittorrent listen_port to ${pf_port}"
                fi
            elif [ "$last_reported" != "$pf_port" ]; then
                log "qBittorrent already listening on forwarded port ${pf_port}"
                last_reported="$pf_port"
            fi
        fi
    else
        log 'forwarded port not reported yet'
    fi
    sleep "$UPDATE_INTERVAL"
done
SCRIPT

  chmod +x "$ARR_STACK_DIR/scripts/port-sync.sh"

  msg "🆘 Writing version recovery script"

  cat >"$ARR_STACK_DIR/scripts/fix-versions.sh" <<'FIXVER'
#!/usr/bin/env bash
set -euo pipefail

msg() { printf '[%s] %s\n' "$(date '+%H:%M:%S')" "$*"; }
warn() { printf '[%s] WARNING: %s\n' "$(date '+%H:%M:%S')" "$*" >&2; }
die() { warn "$1"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STACK_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${STACK_DIR}/.env"

if [[ ! -f "$ENV_FILE" ]]; then
  die ".env file not found at $ENV_FILE"
fi

if ! command -v docker >/dev/null 2>&1; then
  die "Docker CLI not found on PATH"
fi

msg "🔧 Fixing Docker image versions..."

USE_LATEST=(
  "lscr.io/linuxserver/prowlarr"
  "lscr.io/linuxserver/bazarr"
)

backup="${ENV_FILE}.bak.$(date +%Y%m%d_%H%M%S)"
cp "$ENV_FILE" "$backup"
msg "Backed up .env to $backup"

for base_image in "${USE_LATEST[@]}"; do
  msg "Checking $base_image..."

  case "$base_image" in
    *prowlarr) var_name="PROWLARR_IMAGE" ;;
    *bazarr) var_name="BAZARR_IMAGE" ;;
    *) continue ;;
  esac

  current_image=$(grep "^${var_name}=" "$ENV_FILE" | cut -d= -f2- || true)

  if [[ -z "$current_image" ]]; then
    warn "  No ${var_name} entry found in .env; skipping"
    continue
  fi

  if ! docker manifest inspect "$current_image" >/dev/null 2>&1; then
    warn "  Current tag doesn't exist: $current_image"
    latest_image="${base_image}:latest"
    msg "  Updating to: $latest_image"
    sed -i "s|^${var_name}=.*|${var_name}=${latest_image}|" "$ENV_FILE"
  else
    msg "  ✅ Current tag is valid: $current_image"
  fi
done

msg "✅ Version fixes complete"
msg "Run './arrstack.sh --yes' to apply changes"
FIXVER

  chmod +x "$ARR_STACK_DIR/scripts/fix-versions.sh"

}

write_qbt_helper_script() {
  msg "🧰 Writing qBittorrent helper script"

  ensure_dir "$ARR_STACK_DIR/scripts"

  cp "${REPO_ROOT}/scripts/qbt-helper.sh" "$ARR_STACK_DIR/scripts/qbt-helper.sh"
  chmod +x "$ARR_STACK_DIR/scripts/qbt-helper.sh"

  msg "  qBittorrent helper: ${ARR_STACK_DIR}/scripts/qbt-helper.sh"
}

write_qbt_config() {
  msg "🧩 Writing qBittorrent config"
  local config_dir="${ARR_DOCKER_DIR}/qbittorrent/qBittorrent"
  local conf_file="${config_dir}/qBittorrent.conf"
  ensure_dir "$config_dir"
  local auth_whitelist
  auth_whitelist="$(calculate_qbt_auth_whitelist)"
  msg "  Stored WebUI auth whitelist entries: ${auth_whitelist}"

  if [[ ! -f "$conf_file" ]]; then
    cat >"$conf_file" <<EOF
[AutoRun]
enabled=false

[BitTorrent]
Session\AddTorrentStopped=false
Session\DefaultSavePath=/completed/
Session\TempPath=/downloads/incomplete/
Session\TempPathEnabled=true

[Meta]
MigrationVersion=8

[Network]
PortForwardingEnabled=false

[Preferences]
General\UseRandomPort=false
Connection\UPnP=false
Connection\UseNAT-PMP=false
WebUI\UseUPnP=false
Downloads\SavePath=/completed/
Downloads\TempPath=/downloads/incomplete/
Downloads\TempPathEnabled=true
WebUI\Address=0.0.0.0
WebUI\AlternativeUIEnabled=true
WebUI\RootFolder=/vuetorrent
WebUI\Port=8080
WebUI\Username=${QBT_USER}
WebUI\LocalHostAuth=true
WebUI\AuthSubnetWhitelistEnabled=true
WebUI\AuthSubnetWhitelist=${auth_whitelist}
WebUI\CSRFProtection=true
WebUI\ClickjackingProtection=true
WebUI\HostHeaderValidation=true
WebUI\HTTPS\Enabled=false
WebUI\ServerDomains=*
EOF
    chmod 600 "$conf_file"
  fi
  set_qbt_conf_value "$conf_file" 'WebUI\AlternativeUIEnabled' 'true'
  set_qbt_conf_value "$conf_file" 'WebUI\RootFolder' '/vuetorrent'
  set_qbt_conf_value "$conf_file" 'WebUI\ServerDomains' '*'
  set_qbt_conf_value "$conf_file" 'WebUI\LocalHostAuth' 'true'
  set_qbt_conf_value "$conf_file" 'WebUI\AuthSubnetWhitelistEnabled' 'true'
  set_qbt_conf_value "$conf_file" 'WebUI\AuthSubnetWhitelist' "$auth_whitelist"
}

cleanup_existing() {
  msg "🧹 Cleaning up old services"
  if [[ -f "$ARR_STACK_DIR/docker-compose.yml" ]]; then
    "${DOCKER_COMPOSE_CMD[@]}" down --remove-orphans >/dev/null 2>&1 || true
  fi
  rm -f "$ARR_DOCKER_DIR/gluetun/forwarded_port" "$ARR_DOCKER_DIR/gluetun/forwarded_port.json" 2>/dev/null || true
}

update_env_image_var() {
  local var_name="$1"
  local new_value="$2"

  if [[ -z "$var_name" || -z "$new_value" ]]; then
    return
  fi

  printf -v "$var_name" '%s' "$new_value"

  if [[ -f "$ARR_ENV_FILE" ]] && grep -q "^${var_name}=" "$ARR_ENV_FILE"; then
    sed -i "s|^${var_name}=.*|${var_name}=${new_value}|" "$ARR_ENV_FILE"
  fi
}

validate_images() {
  msg "🔍 Validating Docker images..."

  local image_vars=(
    GLUETUN_IMAGE
    QBITTORRENT_IMAGE
    SONARR_IMAGE
    RADARR_IMAGE
    PROWLARR_IMAGE
    BAZARR_IMAGE
    FLARESOLVERR_IMAGE
  )

  local failed_images=()

  for var_name in "${image_vars[@]}"; do
    local image="${!var_name:-}"
    [[ -z "$image" ]] && continue

    msg "  Checking $image..."

    if ! docker manifest inspect "$image" >/dev/null 2>&1; then
      if ! docker pull "$image" >/dev/null 2>&1; then
        local base_image="$image"
        local tag=""
        if [[ "$image" == *:* ]]; then
          base_image="${image%:*}"
          tag="${image##*:}"
        fi

        if [[ "$tag" != "latest" && "$base_image" == lscr.io/linuxserver/* ]]; then
          warn "    Version $tag not found, trying :latest..."
          local latest_image="${base_image}:latest"

          if docker pull "$latest_image" >/dev/null 2>&1; then
            msg "    ✅ Using fallback: $latest_image"

            case "$base_image" in
              *qbittorrent) update_env_image_var QBITTORRENT_IMAGE "$latest_image" ;;
              *sonarr) update_env_image_var SONARR_IMAGE "$latest_image" ;;
              *radarr) update_env_image_var RADARR_IMAGE "$latest_image" ;;
              *prowlarr) update_env_image_var PROWLARR_IMAGE "$latest_image" ;;
              *bazarr) update_env_image_var BAZARR_IMAGE "$latest_image" ;;
            esac
            continue
          else
            warn "  ❌ Failed to validate: $image (and :latest fallback)"
            failed_images+=("$image")
          fi
        else
          warn "  ❌ Failed to validate: $image"
          failed_images+=("$image")
        fi
      else
        msg "  ✅ Pulled: $image"
      fi
    else
      msg "  ✅ Valid: $image"
    fi
  done

  if ((${#failed_images[@]} > 0)); then
    warn "================================================"
    warn "Some images could not be validated:"
    for img in "${failed_images[@]}"; do
      warn "  - $img"
    done
    warn "Check the image names and tags in .env or arrconf/userconf.sh"
    warn "================================================"
  fi
}

compose_up_service() {
  local service="$1"
  local output=""

  msg "  Starting $service..."
  if output=$("${DOCKER_COMPOSE_CMD[@]}" up -d "$service" 2>&1); then
    if [[ "$output" == *"is up-to-date"* ]]; then
      msg "  $service is up-to-date"
    elif [[ -n "$output" ]]; then
      while IFS= read -r line; do
        printf '    %s\n' "$line"
      done <<<"$output"
    fi
  else
    warn "  Failed to start $service"
    if [[ -n "$output" ]]; then
      while IFS= read -r line; do
        printf '    %s\n' "$line"
      done <<<"$output"
    fi
  fi
  sleep 2
}

sync_qbt_password_from_logs() {
  if [[ "$QBT_PASS" != "adminadmin" ]]; then
    return
  fi

  msg "  Detecting qBittorrent temporary password..."
  local attempts=0
  local detected=""

  while (( attempts < 60 )); do
    detected=$(docker logs qbittorrent 2>&1 | grep -i "temporary password" | tail -1 | sed 's/.*temporary password[^:]*: *//' | awk '{print $1}')
    if [[ -n "$detected" ]]; then
      QBT_PASS="$detected"
      persist_env_var QBT_PASS "$QBT_PASS"
      msg "  Saved qBittorrent temporary password to .env (QBT_PASS)"
      return
    fi
    sleep 2
    ((attempts++))
  done

  warn "  Unable to automatically determine the qBittorrent password. Update QBT_PASS in .env manually."
}

start_stack() {
  msg "🚀 Starting services"

  cd "$ARR_STACK_DIR" || die "Failed to change to $ARR_STACK_DIR"

  cleanup_existing

  validate_images

  msg "Starting Gluetun..."
  "${DOCKER_COMPOSE_CMD[@]}" up -d gluetun

  sleep 2
  local gluetun_status
  gluetun_status=$(docker inspect gluetun --format '{{.State.Status}}' 2>/dev/null || echo "not found")
  if [[ "$gluetun_status" != "running" && "$gluetun_status" != "restarting" && "$gluetun_status" != "starting" && "$gluetun_status" != "created" ]]; then
    warn "Gluetun container failed to start (status: $gluetun_status)"
    warn "Check logs with: docker logs gluetun"
    warn "Common issues: invalid ProtonVPN credentials or network conflicts"
    die "Cannot continue without a running VPN container"
  fi

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
  ip=$(fetch_public_ip)

  if [[ -n "$ip" ]]; then
    msg "✅ VPN connected! Public IP: $ip"
  else
    warn "Could not verify VPN connection automatically"
    warn "Check: docker logs gluetun --tail 100"
  fi

  msg "Checking port forwarding status..."
  local pf_port
  pf_port=$(fetch_forwarded_port)

  if [[ "$pf_port" == "0" ]]; then
    warn "================================================"
    warn "Port forwarding is not active yet. Services will still start."
    warn "Monitor 'docker logs gluetun' and 'docker logs port-sync' for updates"
    warn "================================================"
  else
    msg "✅ Port forwarding active: Port $pf_port"
  fi

  msg "Starting qBittorrent..."
  compose_up_service qbittorrent
  sync_qbt_password_from_logs

  msg "Starting supporting services..."
  for service in sonarr radarr prowlarr bazarr flaresolverr vuetorrent-monthly-update; do
    compose_up_service "$service"
  done

  msg "Starting port-sync..."
  compose_up_service port-sync

  msg "Waiting for services to initialize..."
  sleep 20

  msg "Service status summary:"
  for service in gluetun qbittorrent sonarr radarr prowlarr bazarr flaresolverr port-sync; do
    local status
    status=$(docker inspect "$service" --format '{{.State.Status}}' 2>/dev/null || echo "not found")
    printf '  %-15s: %s\n' "$service" "$status"
  done
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

  local diag_script="${ARR_STACK_DIR}/diagnose-vpn.sh"
  cat >"$diag_script" <<'DIAG'
#!/bin/bash
set -euo pipefail

msg() { printf '[%s] %s\n' "$(date '+%H:%M:%S')" "$*"; }
warn() { printf '[%s] WARNING: %s\n' "$(date '+%H:%M:%S')" "$*" >&2; }

ARR_STACK_DIR="__ARR_STACK_DIR__"
ARR_ENV_FILE="${ARR_STACK_DIR}/.env"

if [[ -f "$ARR_ENV_FILE" ]]; then
  set -a
  # shellcheck disable=SC1090
  . "$ARR_ENV_FILE"
  set +a
fi

GLUETUN_LIB="${ARR_STACK_DIR}/scripts/lib/gluetun.sh"
if [[ -f "$GLUETUN_LIB" ]]; then
  # shellcheck source=/dev/null
  . "$GLUETUN_LIB"
else
  warn "Gluetun helper library missing at $GLUETUN_LIB"
  fetch_forwarded_port() { printf '0'; }
  fetch_public_ip() { printf ''; }
fi

msg "🔍 VPN Diagnostics Starting..."

GLUETUN_STATUS=$(docker inspect gluetun --format '{{.State.Status}}' 2>/dev/null || echo "not found")
msg "Gluetun container: $GLUETUN_STATUS"

if [[ "$GLUETUN_STATUS" != "running" ]]; then
  warn "Gluetun is not running. Attempting to start..."
  if docker compose version >/dev/null 2>&1; then
    docker compose up -d gluetun
  elif command -v docker-compose >/dev/null 2>&1; then
    docker-compose up -d gluetun
  else
    warn "Docker Compose not available; please start Gluetun manually."
  fi
  sleep 30
fi

msg "Checking VPN connection..."
PUBLIC_IP=$(fetch_public_ip)

if [[ -n "$PUBLIC_IP" ]]; then
  msg "✅ VPN Connected: $PUBLIC_IP"
else
  warn "VPN not connected"
fi

msg "Checking port forwarding..."
PF_PORT=$(fetch_forwarded_port)

if [[ "$PF_PORT" != "0" ]]; then
  msg "✅ Port forwarding active: Port $PF_PORT"
else
  warn "Port forwarding not working"
  warn "Attempting fix: Restarting Gluetun..."
  if docker restart gluetun >/dev/null 2>&1; then
    sleep 60
    PF_PORT=$(fetch_forwarded_port)
    if [[ "$PF_PORT" != "0" ]]; then
      msg "✅ Port forwarding recovered: Port $PF_PORT"
    else
      warn "Port forwarding still not working"
      warn "Review 'docker logs gluetun' and 'docker logs port-sync' for details"
    fi
  else
    warn "Docker restart command failed; restart Gluetun manually."
  fi
fi

msg "Checking service health..."
for service in qbittorrent sonarr radarr prowlarr bazarr; do
  STATUS=$(docker inspect "$service" --format '{{.State.Status}}' 2>/dev/null || echo "not found")
  if [[ "$STATUS" == "running" ]]; then
    msg "  $service: ✅ running"
  else
    warn "  $service: ❌ $STATUS"
  fi
done

msg "Diagnostics complete!"
DIAG

  local diag_tmp
  diag_tmp="$(mktemp "${diag_script}.XXXX")"
  local diag_dir_escaped
  diag_dir_escaped=${ARR_STACK_DIR//\\/\\\\}
  diag_dir_escaped=${diag_dir_escaped//&/\&}
  diag_dir_escaped=${diag_dir_escaped//|/\|}
  sed -e "s|__ARR_STACK_DIR__|${diag_dir_escaped}|g" "$diag_script" >"$diag_tmp"
  mv "$diag_tmp" "$diag_script"
  chmod +x "$diag_script"
  msg "Diagnostic script: ${diag_script}"
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

  local tmp_file
  tmp_file="$(mktemp "${aliases_file}.XXXX")"

  local stack_dir_escaped env_file_escaped docker_dir_escaped arrconf_dir_escaped
  stack_dir_escaped=${ARR_STACK_DIR//\\/\\\\}
  stack_dir_escaped=${stack_dir_escaped//&/\&}
  stack_dir_escaped=${stack_dir_escaped//|/\|}
  env_file_escaped=${ARR_ENV_FILE//\\/\\\\}
  env_file_escaped=${env_file_escaped//&/\&}
  env_file_escaped=${env_file_escaped//|/\|}
  docker_dir_escaped=${ARR_DOCKER_DIR//\\/\\\\}
  docker_dir_escaped=${docker_dir_escaped//&/\&}
  docker_dir_escaped=${docker_dir_escaped//|/\|}
  arrconf_dir_escaped=${ARRCONF_DIR//\\/\\\\}
  arrconf_dir_escaped=${arrconf_dir_escaped//&/\&}
  arrconf_dir_escaped=${arrconf_dir_escaped//|/\|}

  sed -e "s|__ARR_STACK_DIR__|${stack_dir_escaped}|g" \
      -e "s|__ARR_ENV_FILE__|${env_file_escaped}|g" \
      -e "s|__ARR_DOCKER_DIR__|${docker_dir_escaped}|g" \
      -e "s|__ARRCONF_DIR__|${arrconf_dir_escaped}|g" \
      "$template_file" >"$tmp_file"

  if grep -q "__ARR_" "$tmp_file"; then
    warn "Failed to replace all template placeholders in aliases file"
    rm -f "$tmp_file"
    return 1
  fi

  mv "$tmp_file" "$aliases_file"

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

  # Always show qBittorrent access information prominently
  local qbt_pass_msg=""
  if [[ -f "$ARR_ENV_FILE" ]]; then
    local configured_pass
    configured_pass=$(grep "^QBT_PASS=" "$ARR_ENV_FILE" | cut -d= -f2-)
    if [[ -n "$configured_pass" && "$configured_pass" != "adminadmin" ]]; then
      qbt_pass_msg="Password: ${configured_pass} (from .env)"
    else
      qbt_pass_msg="Password: Check docker logs qbittorrent"
    fi
  fi

  cat <<QBT_INFO
================================================
qBittorrent Access Information:
================================================
URL: http://${LAN_IP}:${QBT_HTTP_PORT_HOST}/
Username: ${QBT_USER}
${qbt_pass_msg}

If you see "Unauthorized":
1. Get the current password:
   docker logs qbittorrent | grep "temporary password" | tail -1

2. Login and set a permanent password in:
   Tools → Options → Web UI

3. Update .env with your new credentials:
   QBT_USER=yournewusername
   QBT_PASS=yournewpassword
================================================

QBT_INFO

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
  sync_gluetun_library
  write_port_sync_script
  write_qbt_helper_script
  write_qbt_config
  if ! write_aliases_file; then
    warn "Helper aliases file could not be generated"
  fi
  install_aliases
  start_stack
  show_summary
}

main "$@"

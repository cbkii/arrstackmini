#!/usr/bin/env bash
set -Euo pipefail
IFS=$'\n\t'

REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
[ -f "${REPO_ROOT}/arrconf/userconf.defaults.sh" ] && . "${REPO_ROOT}/arrconf/userconf.defaults.sh"
[ -f "${REPO_ROOT}/arrconf/userconf.sh" ] && . "${REPO_ROOT}/arrconf/userconf.sh"

umask 077
export HISTFILE=/dev/null

: "${DEBUG:=0}" : "${ARR_NONINTERACTIVE:=0}" : "${FORCE_ROTATE_API_KEY:=0}"
: "${PURGE_NATIVE:=0}" : "${CHOWN_TREE:=0}" : "${PRUNE_VOLUMES:=0}" : "${BACKUP_EXISTING:=0}"
: "${GLUETUN_CONTROL_HOST:=${LOCALHOST_IP}}"
: "${GLUETUN_FIREWALL_OUTBOUND_SUBNETS:=192.168.0.0/16,10.0.0.0/8}"
: "${GLUETUN_HEALTH_TARGET_ADDRESS:=1.1.1.1:443}"
LOG_FILE=/dev/null

is_rfc1918_ipv4(){
  [[ "$1" =~ ^10\. ]] && return 0
  [[ "$1" =~ ^192\.168\. ]] && return 0
  [[ "$1" =~ ^172\.((1[6-9])|(2[0-9])|(3[0-1]))\. ]] && return 0
  return 1
}

detect_lan_ip_candidate(){
  local ip
  local source_cmd
  if command -v ip >/dev/null 2>&1; then
    source_cmd="ip -4 addr show scope global"
  else
    source_cmd="hostname -I"
  fi
  while read -r ip; do
    [[ -z "$ip" ]] && continue
    if is_rfc1918_ipv4 "$ip"; then
      echo "$ip"
      return 0
    fi
  done < <(eval "$source_cmd" | awk '{for (i=1;i<=NF;i++) print $i}' | cut -d/ -f1)
  return 1
}

warn_lan_ip(){
  warn "LAN_IP is set to $1. Services bound to this address may be accessible from untrusted networks."
}

ensure_lan_ip_binding(){
  local candidate
  if [[ -z "${LAN_IP:-}" || "$LAN_IP" == 0.0.0.0 ]]; then
    if candidate=$(detect_lan_ip_candidate); then
      LAN_IP="$candidate"
      msg "Detected LAN_IP=${LAN_IP}"
    else
      LAN_IP="0.0.0.0"
      warn "Unable to detect a LAN IP address automatically; continuing with LAN_IP=0.0.0.0 (all interfaces)."
    fi
  elif ! is_rfc1918_ipv4 "$LAN_IP"; then
    warn_lan_ip "$LAN_IP"
  fi
}

is_tty() { [[ -t 1 && "${NO_COLOR:-0}" -eq 0 ]]; }
color() { is_tty && printf '\033[%sm' "$1" || true; }
msg() { printf '%b%s%b\n' "$(color 36; color 1)" "$1" "$(color 0)"; }
warn(){ printf '%b%s%b\n' "$(color 33)" "$1" "$(color 0)" >&2; }
die(){ printf '%b%s%b\n' "$(color 31)" "$1" "$(color 0)" >&2; exit 1; }

redact() { sed -E 's/(GLUETUN_API_KEY|OPENVPN_PASSWORD|OPENVPN_USER|QBT_PASS|PROTON_PASS|PROTON_USER)=[^[:space:]]+/\1=<REDACTED>/g'; }
run(){ local -a c=("$@"); [[ "$DEBUG" == 1 ]] && printf '+ %s\n' "$(printf '%q ' "${c[@]}")" | redact >>"$LOG_FILE"; "${c[@]}"; }

# lib/env.sh equivalent (inline for now)
require_env() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    echo "ERROR: required env var $name is not set" >&2
    exit 1
  fi
}

setup_logging(){ if [[ "$DEBUG" == 1 ]]; then mkdir -p "$ARR_STACK_DIR"; LOG_FILE="$ARR_STACK_DIR/arrstack-$(date +%Y%m%d-%H%M%S).log"; : >"$LOG_FILE"; chmod 600 "$LOG_FILE"; ln -sfn "$(basename "$LOG_FILE")" "$ARR_STACK_DIR/arrstack-install.log"; fi; }

help(){ cat <<'H'
Usage: ./arrstack.sh [-y|--yes] [--debug] [--rotate-apikey]
       [--purge-native] [--chown-tree] [--prune-volumes] [--backup-existing]
H
}

VPN_TYPE="openvpn"; ASSUME_YES=0
while [ $# -gt 0 ]; do case "$1" in
  --debug) DEBUG=1;;
  -y|--yes) ASSUME_YES=1; ARR_NONINTERACTIVE=1;; --rotate-apikey) FORCE_ROTATE_API_KEY=1;;
  --purge-native) PURGE_NATIVE=1;; --chown-tree) CHOWN_TREE=1;; --prune-volumes) PRUNE_VOLUMES=1;; --backup-existing) BACKUP_EXISTING=1;;
  -h|--help) help; exit 0;; *) warn "Unknown option: $1";; esac; shift; done

setup_logging
export ARR_ENV_FILE="${ARR_ENV_FILE:-${ARR_STACK_DIR}/.env}"

need(){ command -v "$1" >/dev/null 2>&1 || die "Missing dependency: $1"; }
install_missing(){ local pkgs=(); command -v docker >/dev/null || pkgs+=(docker.io); docker compose version >/dev/null 2>&1 || pkgs+=(docker-compose-plugin); command -v curl >/dev/null || pkgs+=(curl); command -v openssl >/dev/null || pkgs+=(openssl); command -v python3 >/dev/null || pkgs+=(python3); (( ${#pkgs[@]} )) && { run sudo apt-get update -y; run sudo apt-get install -y "${pkgs[@]}"; }; }

ensure_dir(){ [[ -d "$1" ]] || { mkdir -p "$1" || { sudo mkdir -p "$1" && sudo chown "${USER}:${USER}" "$1"; }; }; }

preflight(){ msg "Preflight"; install_missing
  [[ -f "${ARRCONF_DIR}/proton.auth" ]] || die "arrconf/proton.auth missing"
  [[ "$ASSUME_YES" == 1 ]] || { printf 'Continue with ProtonVPN OpenVPN setup? [y/N]: '; read -r a; [[ "$a" =~ ^[Yy]$ ]] || die Aborted; }
}

mkdirs(){ msg "Create dirs"; for d in "$ARR_STACK_DIR" "$ARR_DOCKER_DIR"/gluetun "$ARR_DOCKER_DIR"/{qbittorrent,sonarr,radarr,prowlarr,bazarr} "$DOWNLOADS_DIR" "$DOWNLOADS_DIR"/incomplete "$COMPLETED_DIR" "$MEDIA_DIR" "$TV_DIR" "$MOVIES_DIR" "$ARRCONF_DIR" "$ARR_DOCKER_DIR"/gluetun/auth; do ensure_dir "$d"; done; chmod 700 "$ARRCONF_DIR"; }

api_key(){ msg "API key"; local exist=""; [[ -f "$ARR_ENV_FILE" ]] && exist="$(grep '^GLUETUN_API_KEY=' "$ARR_ENV_FILE" 2>/dev/null | cut -d= -f2-)" || true
  if [[ -n "$exist" && "$FORCE_ROTATE_API_KEY" != 1 ]]; then GLUETUN_API_KEY="$exist"; else GLUETUN_API_KEY="$(openssl rand -base64 48 | tr -d '\n')"; fi
  cat > "$ARR_DOCKER_DIR/gluetun/auth/config.toml" <<EOF
[[roles]]
name="readonly"
auth="basic"
username="gluetun"
password="${GLUETUN_API_KEY}"
routes=[
  "GET /v1/openvpn/status",
  "GET /v1/publicip/ip",
  "GET /v1/openvpn/portforwarded",
  "POST /v1/openvpn/forwardport"
]
EOF
  chmod 600 "$ARR_DOCKER_DIR/gluetun/auth/config.toml"
}

write_env(){ msg ".env"; ensure_lan_ip_binding; local PU PW; if [[ "$VPN_TYPE" == openvpn ]]; then PU=$(grep '^PROTON_USER=' "$ARRCONF_DIR/proton.auth" | cut -d= -f2-); PW=$(grep '^PROTON_PASS=' "$ARRCONF_DIR/proton.auth" | cut -d= -f2-); [[ "$PU" == *"+pmp" ]] || PU="${PU}+pmp"; cat > "$ARRCONF_DIR/proton.env" <<E
OPENVPN_USER=${PU}
OPENVPN_PASSWORD=${PW}
E
chmod 600 "$ARRCONF_DIR/proton.env"; fi
  : "${TIMEZONE:=Australia/Sydney}"; : "${LAN_IP:=0.0.0.0}"; : "${SERVER_COUNTRIES:=Netherlands,Germany,Switzerland}"
  : "${GLUETUN_CONTROL_HOST:=${LOCALHOST_IP}}"
  : "${QBT_HTTP_PORT_CONTAINER:=8080}"
  : "${GLUETUN_FIREWALL_OUTBOUND_SUBNETS:=192.168.0.0/16,10.0.0.0/8}"
  : "${GLUETUN_HEALTH_TARGET_ADDRESS:=1.1.1.1:443}"
  : "${GLUETUN_VPN_INPUT_PORTS:=${QBT_HTTP_PORT_HOST},${SONARR_PORT:-8989},${RADARR_PORT:-7878},${PROWLARR_PORT:-9696},${BAZARR_PORT:-6767},${FLARESOLVERR_PORT:-8191}}"
  [[ "$LAN_IP" == 0.0.0.0 ]] && warn "LAN_IP is 0.0.0.0 – services will bind on all interfaces."
  cat > "$ARR_ENV_FILE" <<E
VPN_TYPE=${VPN_TYPE}
PUID=$(id -u)
PGID=$(id -g)
TIMEZONE=${TIMEZONE}
LAN_IP=${LAN_IP}
LOCALHOST_IP=${LOCALHOST_IP}
GLUETUN_LOOPBACK_HOST=${GLUETUN_LOOPBACK_HOST}
GLUETUN_API_KEY=${GLUETUN_API_KEY}
GLUETUN_IMAGE=${GLUETUN_IMAGE:-qmcgaw/gluetun:v3.39.1}
QBITTORRENT_IMAGE=${QBITTORRENT_IMAGE:-lscr.io/linuxserver/qbittorrent:latest}
SONARR_IMAGE=${SONARR_IMAGE:-lscr.io/linuxserver/sonarr:latest}
RADARR_IMAGE=${RADARR_IMAGE:-lscr.io/linuxserver/radarr:latest}
PROWLARR_IMAGE=${PROWLARR_IMAGE:-lscr.io/linuxserver/prowlarr:latest}
BAZARR_IMAGE=${BAZARR_IMAGE:-lscr.io/linuxserver/bazarr:latest}
FLARESOLVERR_IMAGE=${FLARESOLVERR_IMAGE:-ghcr.io/flaresolverr/flaresolverr:latest}
SERVER_COUNTRIES=${SERVER_COUNTRIES}
QBT_HTTP_PORT_HOST=${QBT_HTTP_PORT_HOST:-8081}
QBT_HTTP_PORT_CONTAINER=${QBT_HTTP_PORT_CONTAINER:-8080}
SONARR_PORT=${SONARR_PORT:-8989}
RADARR_PORT=${RADARR_PORT:-7878}
PROWLARR_PORT=${PROWLARR_PORT:-9696}
BAZARR_PORT=${BAZARR_PORT:-6767}
FLARESOLVERR_PORT=${FLARESOLVERR_PORT:-8191}
GLUETUN_CONTROL_HOST=${GLUETUN_CONTROL_HOST}
GLUETUN_CONTROL_PORT=${GLUETUN_CONTROL_PORT:-8000}
GLUETUN_FIREWALL_OUTBOUND_SUBNETS=${GLUETUN_FIREWALL_OUTBOUND_SUBNETS}
GLUETUN_VPN_INPUT_PORTS=${GLUETUN_VPN_INPUT_PORTS}
GLUETUN_HEALTH_TARGET_ADDRESS=${GLUETUN_HEALTH_TARGET_ADDRESS}
ARR_DOCKER_DIR=${ARR_DOCKER_DIR}
ARRCONF_DIR=${ARRCONF_DIR}
DOWNLOADS_DIR=${DOWNLOADS_DIR}
COMPLETED_DIR=${COMPLETED_DIR}
TV_DIR=${TV_DIR}
MOVIES_DIR=${MOVIES_DIR}
E
  chmod 600 "$ARR_ENV_FILE"
}

ensure_qbt_conf_base(){
  msg "qBittorrent.conf"
  local conf="${ARR_DOCKER_DIR}/qbittorrent/qBittorrent.conf"
  ensure_dir "${ARR_DOCKER_DIR}/qbittorrent"
  local py="$(command -v python3 || command -v python || true)"
  if [[ -z "$py" ]]; then
    warn "Python is unavailable; skipping qBittorrent.conf generation."
    return 0
  fi
  "$py" - "$conf" <<'PY'
import configparser
import os
import sys
from pathlib import Path

conf_path = Path(sys.argv[1])
conf_path.parent.mkdir(parents=True, exist_ok=True)

cfg = configparser.RawConfigParser()
cfg.optionxform = str
if conf_path.exists():
    with conf_path.open('r', encoding='utf-8', errors='ignore') as handle:
        cfg.read_file(handle)

if not cfg.has_section('Preferences'):
    cfg.add_section('Preferences')

prefs = cfg['Preferences']
defaults = {
    'Connection\\UPnP': 'false',
    'Connection\\UseUPnP': 'false',
    'Connection\\UseNAT-PMP': 'false',
    'Connection\\PortRangeMin': '0',
    'Connection\\PortRangeMax': '0',
    'Downloads\\SavePath': '/completed/',
    'Downloads\\TempPath': '/downloads/incomplete/',
    'Downloads\\TempPathEnabled': 'true',
    'WebUI\\CSRFProtection': 'true',
    'WebUI\\ClickjackingProtection': 'true',
    'WebUI\\HostHeaderValidation': 'true',
    'WebUI\\HTTPS\\Enabled': 'false',
    'WebUI\\LocalHostAuth': 'false',
    'WebUI\\AuthSubnetWhitelistEnabled': 'false',
    'WebUI\\Password_PBKDF2': '',
    'WebUI\\Username': 'admin',
    'WebUI\\Address': '0.0.0.0',
}

for key, value in defaults.items():
    prefs[key] = value

with conf_path.open('w', encoding='utf-8') as handle:
    cfg.write(handle)

os.chmod(conf_path, 0o600)
PY
}

compose_write() {
  msg "Generating docker-compose.yml dynamically"
  ensure_dir "$ARR_STACK_DIR"

  [[ -f "$ARR_ENV_FILE" ]] || die "Expected env file at $ARR_ENV_FILE"
  # shellcheck disable=SC1090
  . "$ARR_ENV_FILE"

  local required_vars=(
    VPN_TYPE
    SERVER_COUNTRIES
    TIMEZONE
    LAN_IP
    GLUETUN_CONTROL_HOST
    GLUETUN_CONTROL_PORT
    GLUETUN_API_KEY
    GLUETUN_LOOPBACK_HOST
    GLUETUN_FIREWALL_OUTBOUND_SUBNETS
    GLUETUN_VPN_INPUT_PORTS
    GLUETUN_HEALTH_TARGET_ADDRESS
    QBT_HTTP_PORT_CONTAINER
    QBT_HTTP_PORT_HOST
    SONARR_PORT
    RADARR_PORT
    PROWLARR_PORT
    BAZARR_PORT
    FLARESOLVERR_PORT
    ARR_DOCKER_DIR
    ARRCONF_DIR
    DOWNLOADS_DIR
    COMPLETED_DIR
    TV_DIR
    MOVIES_DIR
    PUID
    PGID
    GLUETUN_IMAGE
    QBITTORRENT_IMAGE
    SONARR_IMAGE
    RADARR_IMAGE
    PROWLARR_IMAGE
    BAZARR_IMAGE
    FLARESOLVERR_IMAGE
  )

  local var
  for var in "${required_vars[@]}"; do
    require_env "$var"
  done

  cat > "$ARR_STACK_DIR/docker-compose.yml" <<'YAML'
services:
  gluetun:
    image: ${GLUETUN_IMAGE}
    container_name: gluetun
    cap_add: ["NET_ADMIN"]
    devices: ["/dev/net/tun"]
    environment:
      VPN_SERVICE_PROVIDER: protonvpn
      VPN_TYPE: ${VPN_TYPE}
      SERVER_COUNTRIES: "${SERVER_COUNTRIES}"
      VPN_PORT_FORWARDING: "on"
      VPN_PORT_FORWARDING_PROVIDER: "protonvpn"
      PORT_FORWARD_ONLY: "on"
      # Keep internal callback strictly via loopback variable (no literals)
      VPN_PORT_FORWARDING_UP_COMMAND: >-
        /bin/sh -c 'sleep 5 && curl -fsS --retry 3 --max-time 10 -X POST
        "http://${GLUETUN_LOOPBACK_HOST}:${QBT_HTTP_PORT_CONTAINER}/api/v2/app/setPreferences"
        --data "json={\"listen_port\":{{FORWARDED_PORT}},\"upnp\":false}"'
      HTTP_CONTROL_SERVER_ADDRESS: "${GLUETUN_CONTROL_HOST}:${GLUETUN_CONTROL_PORT}"
      HTTP_CONTROL_SERVER_AUTH_FILE: /gluetun/auth/config.toml
      FIREWALL_OUTBOUND_SUBNETS: "${GLUETUN_FIREWALL_OUTBOUND_SUBNETS}"
      FIREWALL_VPN_INPUT_PORTS: "${GLUETUN_VPN_INPUT_PORTS}"
      DOT: "off"
      UPDATER_PERIOD: "24h"
      HEALTH_TARGET_ADDRESS: "${GLUETUN_HEALTH_TARGET_ADDRESS}"
      HEALTH_VPN_DURATION_INITIAL: 30s
      PUID: ${PUID}
      PGID: ${PGID}
      TZ: ${TIMEZONE}
      GLUETUN_API_KEY: "${GLUETUN_API_KEY}"
    env_file:
      - ${ARRCONF_DIR}/proton.env
    volumes:
      - ${ARR_DOCKER_DIR}/gluetun:/gluetun
    ports:
      - "${GLUETUN_CONTROL_HOST}:${GLUETUN_CONTROL_PORT}:${GLUETUN_CONTROL_PORT}"
      - "${LAN_IP}:${QBT_HTTP_PORT_HOST}:${QBT_HTTP_PORT_CONTAINER}"
      - "${LAN_IP}:${SONARR_PORT}:${SONARR_PORT}"
      - "${LAN_IP}:${RADARR_PORT}:${RADARR_PORT}"
      - "${LAN_IP}:${PROWLARR_PORT}:${PROWLARR_PORT}"
      - "${LAN_IP}:${BAZARR_PORT}:${BAZARR_PORT}"
      - "${LAN_IP}:${FLARESOLVERR_PORT}:${FLARESOLVERR_PORT}"
    healthcheck:
      test:
        - CMD-SHELL
        - >
          curl -fsS --user gluetun:$${GLUETUN_API_KEY} -H "X-API-Key: $${GLUETUN_API_KEY}"
          "http://${GLUETUN_CONTROL_HOST}:${GLUETUN_CONTROL_PORT}/v1/publicip/ip" >/dev/null
          && curl -fsS --user gluetun:$${GLUETUN_API_KEY} -H "X-API-Key: $${GLUETUN_API_KEY}"
          "http://${GLUETUN_CONTROL_HOST}:${GLUETUN_CONTROL_PORT}/v1/openvpn/status" | grep -qi running
      interval: 30s
      timeout: 10s
      retries: 10
      start_period: 300s
    restart: unless-stopped
    deploy:
      resources:
        limits:
          memory: 256M
          cpus: '0.5'

  qbittorrent:
    image: ${QBITTORRENT_IMAGE}
    container_name: qbittorrent
    network_mode: "service:gluetun"
    environment:
      WEBUI_PORT: "${QBT_HTTP_PORT_CONTAINER}"
      PUID: ${PUID}
      PGID: ${PGID}
      TZ: ${TIMEZONE}
    volumes:
      - ${ARR_DOCKER_DIR}/qbittorrent:/config
      - ${DOWNLOADS_DIR}:/downloads
      - ${COMPLETED_DIR}:/completed
    depends_on:
      gluetun:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "curl", "-fsS", "http://${GLUETUN_LOOPBACK_HOST}:${QBT_HTTP_PORT_CONTAINER}/api/v2/app/version"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 60s
    restart: unless-stopped

  sonarr:
    image: ${SONARR_IMAGE}
    container_name: sonarr
    network_mode: "service:gluetun"
    environment: { PUID: ${PUID}, PGID: ${PGID}, TZ: ${TIMEZONE} }
    volumes:
      - ${ARR_DOCKER_DIR}/sonarr:/config
      - ${TV_DIR}:/tv
      - ${DOWNLOADS_DIR}:/downloads
      - ${COMPLETED_DIR}:/completed
    depends_on: { gluetun: { condition: service_healthy } }
    healthcheck:
      test: ["CMD", "curl", "-fsS", "http://${GLUETUN_LOOPBACK_HOST}:${SONARR_PORT}"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 90s
    restart: unless-stopped

  radarr:
    image: ${RADARR_IMAGE}
    container_name: radarr
    network_mode: "service:gluetun"
    environment: { PUID: ${PUID}, PGID: ${PGID}, TZ: ${TIMEZONE} }
    volumes:
      - ${ARR_DOCKER_DIR}/radarr:/config
      - ${MOVIES_DIR}:/movies
      - ${DOWNLOADS_DIR}:/downloads
      - ${COMPLETED_DIR}:/completed
    depends_on: { gluetun: { condition: service_healthy } }
    healthcheck:
      test: ["CMD", "curl", "-fsS", "http://${GLUETUN_LOOPBACK_HOST}:${RADARR_PORT}"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 90s
    restart: unless-stopped

  prowlarr:
    image: ${PROWLARR_IMAGE}
    container_name: prowlarr
    network_mode: "service:gluetun"
    environment: { PUID: ${PUID}, PGID: ${PGID}, TZ: ${TIMEZONE} }
    volumes:
      - ${ARR_DOCKER_DIR}/prowlarr:/config
    depends_on: { gluetun: { condition: service_healthy } }
    healthcheck:
      test: ["CMD", "curl", "-fsS", "http://${GLUETUN_LOOPBACK_HOST}:${PROWLARR_PORT}"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 90s
    restart: unless-stopped

  bazarr:
    image: ${BAZARR_IMAGE}
    container_name: bazarr
    network_mode: "service:gluetun"
    environment: { PUID: ${PUID}, PGID: ${PGID}, TZ: ${TIMEZONE} }
    volumes:
      - ${ARR_DOCKER_DIR}/bazarr:/config
      - ${TV_DIR}:/tv
      - ${MOVIES_DIR}:/movies
    depends_on: { gluetun: { condition: service_healthy } }
    healthcheck:
      test: ["CMD", "curl", "-fsS", "http://${GLUETUN_LOOPBACK_HOST}:${BAZARR_PORT}"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 90s
    restart: unless-stopped

  flaresolverr:
    image: ${FLARESOLVERR_IMAGE}
    container_name: flaresolverr
    network_mode: "service:gluetun"
    environment: { LOG_LEVEL: info }
    depends_on: { gluetun: { condition: service_healthy } }
    healthcheck:
      test: ["CMD", "curl", "-fsS", "http://${GLUETUN_LOOPBACK_HOST}:${FLARESOLVERR_PORT}"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 90s
    restart: unless-stopped
YAML

  chmod 600 "$ARR_STACK_DIR/docker-compose.yml"
}

gluetun_api(){
  curl -fsS -u "gluetun:${GLUETUN_API_KEY}" -H "X-API-Key: ${GLUETUN_API_KEY}" \
    "http://${GLUETUN_CONTROL_HOST}:${GLUETUN_CONTROL_PORT}$1"
}

wait_for_vpn_connected(){
  msg "Wait for VPN session"
  local attempts=0 status
  while true; do
    status=$(gluetun_api "/v1/${VPN_TYPE}/status" || true)
    if [[ "$status" =~ "status"[[:space:]]*:[[:space:]]*"connected" ]] || [[ "$status" =~ "connected"[[:space:]]*:[[:space:]]*true ]]; then
      msg "VPN reports connected."
      break
    fi
    sleep 5
    ((attempts++))
    ((attempts>60)) && die "VPN failed to reach connected state"
  done
}

wait_for_port_forwarding(){
  [[ "$VPN_TYPE" == openvpn ]] || return 0
  msg "Wait for forwarded port"
  local attempts=0 pf port
  while true; do
    pf=$(gluetun_api "/v1/openvpn/portforwarded" || true)
    if [[ "$pf" =~ ([0-9]{4,5}) ]]; then
      port="${BASH_REMATCH[1]}"
    else
      port=""
    fi
    if [[ -n "$port" ]]; then
      msg "Forwarded port acquired: $port"
      echo "$port"
      return 0
    fi
    sleep 5
    ((attempts++))
    ((attempts>60)) && die "Forwarded port was not assigned"
  done
}

validate_native_port_forwarding(){
  [[ "$VPN_TYPE" == openvpn ]] || return 0
  local raw port
  raw=$(gluetun_api "/v1/openvpn/portforwarded" || true)
  if [[ -z "$raw" ]]; then
    warn "Port forwarding API did not return a port"
    return 0
  fi
  if [[ "$raw" =~ ([0-9]{4,5}) ]]; then
    port="${BASH_REMATCH[1]}"
  else
    port=""
  fi
  if [[ -n "$port" ]]; then
    msg "Current forwarded port: $port"
  else
    warn "Port forwarding API did not return a port"
  fi
}

validate_lan_access(){
  msg "Validate LAN"
  local host="$LAN_IP"; [[ "$host" == 0.0.0.0 ]] && host="${LOCALHOST_IP}"
  local -a checks=(
    "qBittorrent:${QBT_HTTP_PORT_HOST:-8081}:http"
    "Sonarr:${SONARR_PORT:-8989}:http"
    "Radarr:${RADARR_PORT:-7878}:http"
    "Prowlarr:${PROWLARR_PORT:-9696}:http"
    "Bazarr:${BAZARR_PORT:-6767}:http"
    "FlareSolverr:${FLARESOLVERR_PORT:-8191}:http"
  )
  local item name port proto
  for item in "${checks[@]}"; do
    name=${item%%:*}
    proto=${item##*:}
    port=${item%:*}; port=${port##*:}
    if curl -fsS "${proto}://${host}:${port}" >/dev/null 2>&1; then
      msg "OK ${name}@${port}"
    else
      warn "${name}@${port} not reachable on ${host}"
    fi
  done
}

cleanup_existing(){
  local -a containers=(gluetun qbittorrent sonarr radarr prowlarr bazarr flaresolverr)
  local removed=0 c
  for c in "${containers[@]}"; do
    if docker inspect "$c" >/dev/null 2>&1; then
      if (( removed == 0 )); then
        msg "Cleanup containers"
      fi
      if ! run docker rm -f "$c"; then
        warn "Failed to remove container $c"
      fi
      removed=1
    fi
  done
}

start_stack(){
  cd "$ARR_STACK_DIR" || die "Failed to change to $ARR_STACK_DIR"
  cleanup_existing
  msg "Start Gluetun"
  run docker compose up -d gluetun
  msg "Wait for health (≤5m)"
  local tries=0
  while ! docker inspect gluetun --format '{{.State.Health.Status}}' 2>/dev/null | grep -q healthy; do
    sleep 10
    ((tries++))
    ((tries>30)) && die "Gluetun not healthy"
  done
  wait_for_vpn_connected
  local pf=""
  if [[ "$VPN_TYPE" == openvpn ]]; then
    pf=$(wait_for_port_forwarding || true)
  fi
  local ip
  ip=$(gluetun_api "/v1/publicip/ip" || true)
  [[ -n "$ip" ]] && msg "Public IP: $ip" || warn "IP unknown"
  msg "Start services"
  run docker compose up -d
  if [[ "$VPN_TYPE" == openvpn && -n "$pf" ]]; then
    sleep 8
    validate_native_port_forwarding
  fi
}

validate(){
  validate_lan_access
  validate_native_port_forwarding
}

install_aliases(){
  msg "Aliases"
  local template="${REPO_ROOT}/.arraliases"
  if [[ ! -f "$template" ]]; then
    warn "Alias template missing at $template"
    return 0
  fi
  local dest="${ARR_STACK_DIR}/.arraliases"
  local py
  py=$(command -v python3 || command -v python || true)
  if [[ -z "$py" ]]; then
    warn "Python unavailable; skipping alias installation."
    return 0
  fi
  "$py" - "$template" "$dest" <<'ALIASES_PY'
import os
import shlex
import sys
from pathlib import Path

src = Path(sys.argv[1])
dest = Path(sys.argv[2])
data = src.read_text(encoding="utf-8")
mapping = {
    "__ARR_STACK_DIR__": shlex.quote(os.environ.get("ARR_STACK_DIR", "")),
    "__ARR_ENV_FILE__": shlex.quote(os.environ.get("ARR_ENV_FILE", "")),
    "__ARR_DOCKER_DIR__": shlex.quote(os.environ.get("ARR_DOCKER_DIR", "")),
    "__ARRCONF_DIR__": shlex.quote(os.environ.get("ARRCONF_DIR", "")),
}
for key, value in mapping.items():
    data = data.replace(key, value)
dest.parent.mkdir(parents=True, exist_ok=True)
dest.write_text(data, encoding="utf-8")
dest.chmod(0o600)
ALIASES_PY
  local rc
  for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
    if [[ "$rc" == "$HOME/.bashrc" ]] && [[ ! -f "$rc" ]]; then
      touch "$rc"
    fi
    [[ -f "$rc" ]] || continue
    if ! grep -Fq ".arraliases" "$rc" 2>/dev/null; then
      {
        printf '\n'
        printf '[ -f %q ] && source %q\n' "$ARR_STACK_DIR/.arraliases" "$ARR_STACK_DIR/.arraliases"
      } >> "$rc"
    fi
  done
}


backup(){ [[ "$BACKUP_EXISTING" == 1 ]] || return 0; msg "Backup"; local bdir="${ARR_BASE}/backups/$(date +%Y%m%d-%H%M%S)"; mkdir -p "$bdir"; for a in gluetun qbittorrent sonarr radarr prowlarr bazarr; do [[ -d "$ARR_DOCKER_DIR/$a" ]] && tar -czf "$bdir/$a.tgz" -C "$ARR_DOCKER_DIR" "$a"; done; }

purge(){ [[ "$PURGE_NATIVE" == 1 ]] || return 0; msg "Purge native"; for p in sonarr radarr prowlarr bazarr qbittorrent transmission-daemon; do dpkg -l | grep -q "^ii.*$p" && run sudo apt-get purge -y "$p"; done; run sudo apt-get autoremove -y; }

fixperms(){ [[ "$CHOWN_TREE" == 1 ]] || return 0; msg "Permissions"; run sudo chown -R "${USER}:${USER}" "$ARR_BASE"; find "$ARR_BASE" -type d -exec chmod 755 {} +; find "$ARR_BASE" -type f -exec chmod 644 {} +; }

prunev(){ [[ "$PRUNE_VOLUMES" == 1 ]] || return 0; msg "Prune volumes"; docker volume prune -f; }

main(){ preflight; mkdirs; api_key; write_env; ensure_qbt_conf_base; compose_write; backup; purge; fixperms; prunev; start_stack; validate; install_aliases; msg "Done."; }
main "$@"

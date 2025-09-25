#!/usr/bin/env bash
# Default configuration for ARR Stack
# This file is sourced *before* arrconf/userconf.sh.
# Keep assignments idempotent and avoid relying on side effects so overrides
# behave predictably when userconf.sh runs afterwards.
# Override these in arrconf/userconf.sh (git-ignored).

# Guard helpers for shells that source these defaults alongside other scripts
if ! declare -f arrstack_var_is_readonly >/dev/null 2>&1; then
  arrstack_var_is_readonly() {
    local var="$1"
    local declaration=""

    if ! declaration=$(declare -p "$var" 2>/dev/null); then
      return 1
    fi

    case $declaration in
      declare\ -r*)
        return 0
        ;;
    esac

    return 1
  }
fi

# Base paths
ARR_BASE="${ARR_BASE:-${HOME}/srv}"
ARR_STACK_DIR="${ARR_STACK_DIR:-${ARR_BASE}/arrstack}"
ARR_ENV_FILE="${ARR_ENV_FILE:-${ARR_STACK_DIR}/.env}"
ARR_LOG_DIR="${ARR_LOG_DIR:-${ARR_STACK_DIR}/logs}"
ARR_INSTALL_LOG="${ARR_INSTALL_LOG:-${ARR_LOG_DIR}/arrstack-install.log}"
ARR_DOCKER_DIR="${ARR_DOCKER_DIR:-${ARR_BASE}/docker-data}"
ARRCONF_DIR="${ARRCONF_DIR:-${REPO_ROOT:-${PWD}}/arrconf}"

# File/dir permissions (strict keeps secrets 600/700, collaborative loosens group access)
if ! arrstack_var_is_readonly ARR_PERMISSION_PROFILE; then
  ARR_PERMISSION_PROFILE="${ARR_PERMISSION_PROFILE:-strict}"
fi

# Download paths
DOWNLOADS_DIR="${DOWNLOADS_DIR:-${HOME}/Downloads}"
COMPLETED_DIR="${COMPLETED_DIR:-${DOWNLOADS_DIR}/completed}"

# Media library
MEDIA_DIR="${MEDIA_DIR:-/media/mediasmb}"
TV_DIR="${TV_DIR:-${MEDIA_DIR}/Shows}"
MOVIES_DIR="${MOVIES_DIR:-${MEDIA_DIR}/Movies}"
# SUBS_DIR="${SUBS_DIR:-${MEDIA_DIR}/subs}"

# Container identity (current user by default)
PUID="${PUID:-$(id -u)}"
PGID="${PGID:-$(id -g)}"

# Location
TIMEZONE="${TIMEZONE:-Australia/Sydney}"
LAN_IP="${LAN_IP:-}"
LOCALHOST_IP="${LOCALHOST_IP:-127.0.0.1}"
SERVER_COUNTRIES="${SERVER_COUNTRIES:-Netherlands}"
# SERVER_NAMES=""  # Optionally pin Proton server hostnames if PF keeps returning 0 (comma-separated list)
PVPN_ROTATE_COUNTRIES="${PVPN_ROTATE_COUNTRIES:-${SERVER_COUNTRIES}}"

# Domain suffix used by optional DNS/Caddy hostnames (default to RFC 8375 recommendation)
LAN_DOMAIN_SUFFIX="${LAN_DOMAIN_SUFFIX:-home.arpa}"

# Helper utilities for defaults that may also be sourced by other scripts
if ! declare -f arrstack_trim_whitespace >/dev/null 2>&1; then
  arrstack_trim_whitespace() {
    local value="$1"
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    printf '%s' "$value"
  }
fi

if ! declare -f arrstack_parse_csv >/dev/null 2>&1; then
  arrstack_parse_csv() {
    local raw="$1"
    local item

    IFS=',' read -r -a _arrstack_csv_items <<<"$raw"
    for item in "${_arrstack_csv_items[@]}"; do
      item="$(arrstack_trim_whitespace "$item")"
      [[ -z "$item" ]] && continue
      printf '%s\n' "$item"
    done
  }
fi

if ! declare -f arrstack_join_by >/dev/null 2>&1; then
  arrstack_join_by() {
    local delimiter="$1"
    shift || true
    local first=1
    local piece
    for piece in "$@"; do
      if ((first)); then
        printf '%s' "$piece"
        first=0
      else
        printf '%s%s' "$delimiter" "$piece"
      fi
    done
  }
fi

# Upstream DNS resolvers for fallback (support legacy *_1/*_2 and new list form)
ARRSTACK_DEFAULT_UPSTREAM_DNS=("1.1.1.1" "1.0.0.1")

arrstack__dns_candidates=()

if [[ -n "${UPSTREAM_DNS_1:-}" ]]; then
  arrstack__dns_candidates+=("$(arrstack_trim_whitespace "$UPSTREAM_DNS_1")")
fi

if [[ -n "${UPSTREAM_DNS_2:-}" ]]; then
  arrstack__dns_candidates+=("$(arrstack_trim_whitespace "$UPSTREAM_DNS_2")")
fi

if [[ -n "${UPSTREAM_DNS_SERVERS:-}" ]]; then
  while IFS= read -r server; do
    arrstack__dns_candidates+=("$server")
  done < <(arrstack_parse_csv "$UPSTREAM_DNS_SERVERS")
fi

if ((${#arrstack__dns_candidates[@]} == 0)); then
  arrstack__dns_candidates=("${ARRSTACK_DEFAULT_UPSTREAM_DNS[@]}")
fi

mapfile -t ARRSTACK_UPSTREAM_DNS_CHAIN < <(
  printf '%s\n' "${arrstack__dns_candidates[@]}" | awk 'NF && !seen[$0]++'
)

if ((${#ARRSTACK_UPSTREAM_DNS_CHAIN[@]} == 0)); then
  ARRSTACK_UPSTREAM_DNS_CHAIN=("${ARRSTACK_DEFAULT_UPSTREAM_DNS[@]}")
fi

UPSTREAM_DNS_SERVERS="${UPSTREAM_DNS_SERVERS:-$(arrstack_join_by ',' "${ARRSTACK_UPSTREAM_DNS_CHAIN[@]}")}"

if [[ -z "${UPSTREAM_DNS_1:-}" ]]; then
  UPSTREAM_DNS_1="${ARRSTACK_UPSTREAM_DNS_CHAIN[0]}"
fi

if [[ -z "${UPSTREAM_DNS_2:-}" ]]; then
  UPSTREAM_DNS_2="${ARRSTACK_UPSTREAM_DNS_CHAIN[1]:-}"
fi

# Enable internal local DNS resolver service
ENABLE_LOCAL_DNS="${ENABLE_LOCAL_DNS:-0}"
ENABLE_CADDY="${ENABLE_CADDY:-0}"

# How LAN clients learn the resolver address
#   router     – configure DHCP Option 6 on your router to ${LAN_IP}
#   per-device – leave router DNS untouched and set DNS=${LAN_IP} on important clients
DNS_DISTRIBUTION_MODE="${DNS_DISTRIBUTION_MODE:-router}"

# Reverse proxy hostnames (Caddy defaults to LAN suffix when unset)
CADDY_DOMAIN_SUFFIX="${CADDY_DOMAIN_SUFFIX:-${LAN_DOMAIN_SUFFIX}}"
CADDY_LAN_CIDRS="${CADDY_LAN_CIDRS:-127.0.0.1/32,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16}"

# Gluetun control server
GLUETUN_CONTROL_PORT="${GLUETUN_CONTROL_PORT:-8000}"
GLUETUN_API_KEY="${GLUETUN_API_KEY:-}"

# Service ports
QBT_HTTP_PORT_HOST="${QBT_HTTP_PORT_HOST:-8080}"
SONARR_PORT="${SONARR_PORT:-8989}"
RADARR_PORT="${RADARR_PORT:-7878}"
PROWLARR_PORT="${PROWLARR_PORT:-9696}"
BAZARR_PORT="${BAZARR_PORT:-6767}"
FLARESOLVERR_PORT="${FLARESOLVERR_PORT:-8191}"

# Expose application ports directly on the host alongside Caddy's reverse proxy
EXPOSE_DIRECT_PORTS="${EXPOSE_DIRECT_PORTS:-1}"

# qBittorrent credentials (override after first login)
QBT_USER="${QBT_USER:-admin}"
QBT_PASS="${QBT_PASS:-adminadmin}"
QBT_DOCKER_MODS="${QBT_DOCKER_MODS:-ghcr.io/vuetorrent/vuetorrent-lsio-mod:latest}"

# Comma-separated CIDR list that can bypass the qBittorrent WebUI login
QBT_AUTH_WHITELIST="${QBT_AUTH_WHITELIST:-127.0.0.1/32,::1/128}"

# Caddy Basic Auth credentials (bcrypt hash generated automatically when empty)
CADDY_BASIC_AUTH_USER="${CADDY_BASIC_AUTH_USER:-user}"
CADDY_BASIC_AUTH_HASH="${CADDY_BASIC_AUTH_HASH:-}"

# Images
GLUETUN_IMAGE="${GLUETUN_IMAGE:-qmcgaw/gluetun:v3.39.1}"
QBITTORRENT_IMAGE="${QBITTORRENT_IMAGE:-lscr.io/linuxserver/qbittorrent:5.1.2-r2-ls415}"
SONARR_IMAGE="${SONARR_IMAGE:-lscr.io/linuxserver/sonarr:4.0.15.2941-ls291}"
RADARR_IMAGE="${RADARR_IMAGE:-lscr.io/linuxserver/radarr:5.27.5.10198-ls283}"
PROWLARR_IMAGE="${PROWLARR_IMAGE:-lscr.io/linuxserver/prowlarr:latest}"
BAZARR_IMAGE="${BAZARR_IMAGE:-lscr.io/linuxserver/bazarr:latest}"
FLARESOLVERR_IMAGE="${FLARESOLVERR_IMAGE:-ghcr.io/flaresolverr/flaresolverr:v3.3.21}"
CADDY_IMAGE="${CADDY_IMAGE:-caddy:2.8.4}"
#
# Behaviour flags
ASSUME_YES="${ASSUME_YES:-0}"
FORCE_ROTATE_API_KEY="${FORCE_ROTATE_API_KEY:-0}"
FORCE_REGEN_CADDY_AUTH="${FORCE_REGEN_CADDY_AUTH:-0}"
SETUP_HOST_DNS="${SETUP_HOST_DNS:-0}"
REFRESH_ALIASES="${REFRESH_ALIASES:-0}"

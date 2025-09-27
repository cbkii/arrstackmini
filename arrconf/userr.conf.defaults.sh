#!/usr/bin/env bash
# Default configuration for ARR Stack
# This file is sourced *before* ${ARR_BASE}/userr.conf.
# Keep assignments idempotent and avoid relying on side effects so overrides
# behave predictably when the user configuration runs afterwards.
# Override these in ${ARR_BASE}/userr.conf (git-ignored; defaults to ${HOME}/srv/userr.conf).

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
ARR_USERCONF_PATH="${ARR_USERCONF_PATH:-${ARR_BASE}/userr.conf}"
ARRCONF_DIR="${ARRCONF_DIR:-${REPO_ROOT:-${PWD}}/arrconf}"
ARR_COLOR_OUTPUT="${ARR_COLOR_OUTPUT:-1}"

# File/dir permissions (strict keeps secrets 600/700, collab enables group read/write 660/770)
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
SUBS_DIR="${SUBS_DIR:-}"

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

    local IFS=','
    read -r -a _arrstack_csv_items <<<"$raw"
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
ENABLE_CONFIGARR="${ENABLE_CONFIGARR:-1}"

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

# ProtonVPN port forwarding tuning (seconds)
PF_MAX_TOTAL_WAIT="${PF_MAX_TOTAL_WAIT:-60}"
PF_POLL_INTERVAL="${PF_POLL_INTERVAL:-5}"
PF_CYCLE_AFTER="${PF_CYCLE_AFTER:-30}"
PF_ASYNC_MAX_TOTAL_WAIT="${PF_ASYNC_MAX_TOTAL_WAIT:-45}"
PF_ASYNC_POLL_INTERVAL="${PF_ASYNC_POLL_INTERVAL:-5}"
PF_ASYNC_CYCLE_AFTER="${PF_ASYNC_CYCLE_AFTER:-30}"

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
if [[ -z "${QBT_DOCKER_MODS+x}" ]]; then
  QBT_DOCKER_MODS="ghcr.io/vuetorrent/vuetorrent-lsio-mod:latest"
fi

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
CONFIGARR_IMAGE="${CONFIGARR_IMAGE:-ghcr.io/raydak-labs/configarr:latest}"
CADDY_IMAGE="${CADDY_IMAGE:-caddy:2.8.4}"
#
# ConfigArr quality/profile defaults
ARR_VIDEO_MIN_RES="${ARR_VIDEO_MIN_RES:-720p}"
ARR_VIDEO_MAX_RES="${ARR_VIDEO_MAX_RES:-1080p}"
ARR_EP_MIN_MB="${ARR_EP_MIN_MB:-250}"
ARR_EP_MAX_GB="${ARR_EP_MAX_GB:-5}"
ARR_TV_RUNTIME_MIN="${ARR_TV_RUNTIME_MIN:-45}"
ARR_SEASON_MAX_GB="${ARR_SEASON_MAX_GB:-30}"
ARR_LANG_PRIMARY="${ARR_LANG_PRIMARY:-en}"
ARR_ENGLISH_ONLY="${ARR_ENGLISH_ONLY:-1}"
ARR_DISCOURAGE_MULTI="${ARR_DISCOURAGE_MULTI:-1}"
ARR_PENALIZE_HD_X265="${ARR_PENALIZE_HD_X265:-1}"
ARR_STRICT_JUNK_BLOCK="${ARR_STRICT_JUNK_BLOCK:-1}"
ARR_JUNK_NEGATIVE_SCORE="${ARR_JUNK_NEGATIVE_SCORE:--1000}"
ARR_X265_HD_NEGATIVE_SCORE="${ARR_X265_HD_NEGATIVE_SCORE:--200}"
ARR_MULTI_NEGATIVE_SCORE="${ARR_MULTI_NEGATIVE_SCORE:--50}"
ARR_ENGLISH_POSITIVE_SCORE="${ARR_ENGLISH_POSITIVE_SCORE:-50}"
SONARR_TRASH_TEMPLATE="${SONARR_TRASH_TEMPLATE:-sonarr-v4-quality-profile-web-1080p}"
RADARR_TRASH_TEMPLATE="${RADARR_TRASH_TEMPLATE:-radarr-v5-quality-profile-hd-bluray-web}"
ARR_MBMIN_DECIMALS="${ARR_MBMIN_DECIMALS:-1}"
#
# Behaviour flags
ASSUME_YES="${ASSUME_YES:-0}"
FORCE_ROTATE_API_KEY="${FORCE_ROTATE_API_KEY:-0}"
FORCE_REGEN_CADDY_AUTH="${FORCE_REGEN_CADDY_AUTH:-0}"
SETUP_HOST_DNS="${SETUP_HOST_DNS:-0}"
REFRESH_ALIASES="${REFRESH_ALIASES:-0}"

# -----------------------------------------------------------------------------
# User configuration example template
# -----------------------------------------------------------------------------

ARRSTACK_USERCONF_TEMPLATE_VARS=(
  ARR_USERCONF_PATH
  ARR_LOG_DIR
  ARR_INSTALL_LOG
  ARR_COLOR_OUTPUT
  TIMEZONE
  LAN_DOMAIN_SUFFIX
  CADDY_DOMAIN_SUFFIX
  SERVER_COUNTRIES
  PVPN_ROTATE_COUNTRIES
  GLUETUN_CONTROL_PORT
  ENABLE_LOCAL_DNS
  ENABLE_CADDY
  ENABLE_CONFIGARR
  DNS_DISTRIBUTION_MODE
  UPSTREAM_DNS_SERVERS
  UPSTREAM_DNS_1
  UPSTREAM_DNS_2
  UPSTREAM_DNS_2_DISPLAY
  CADDY_LAN_CIDRS
  EXPOSE_DIRECT_PORTS
  QBT_DOCKER_MODS
  QBT_AUTH_WHITELIST
  CADDY_BASIC_AUTH_USER
  QBT_HTTP_PORT_HOST
  SONARR_PORT
  RADARR_PORT
  PROWLARR_PORT
  BAZARR_PORT
  FLARESOLVERR_PORT
  PF_MAX_TOTAL_WAIT
  PF_POLL_INTERVAL
  PF_CYCLE_AFTER
  PF_ASYNC_MAX_TOTAL_WAIT
  PF_ASYNC_POLL_INTERVAL
  PF_ASYNC_CYCLE_AFTER
  GLUETUN_IMAGE
  QBITTORRENT_IMAGE
  SONARR_IMAGE
  RADARR_IMAGE
  PROWLARR_IMAGE
  BAZARR_IMAGE
  FLARESOLVERR_IMAGE
  CONFIGARR_IMAGE
  CADDY_IMAGE
  ARR_VIDEO_MIN_RES
  ARR_VIDEO_MAX_RES
  ARR_EP_MIN_MB
  ARR_EP_MAX_GB
  ARR_TV_RUNTIME_MIN
  ARR_SEASON_MAX_GB
  ARR_LANG_PRIMARY
  ARR_ENGLISH_ONLY
  ARR_DISCOURAGE_MULTI
  ARR_PENALIZE_HD_X265
  ARR_STRICT_JUNK_BLOCK
  ARR_JUNK_NEGATIVE_SCORE
  ARR_X265_HD_NEGATIVE_SCORE
  ARR_MULTI_NEGATIVE_SCORE
  ARR_ENGLISH_POSITIVE_SCORE
  SONARR_TRASH_TEMPLATE
  RADARR_TRASH_TEMPLATE
  ARR_MBMIN_DECIMALS
)

ARRSTACK_USERCONF_IMPLICIT_VARS=(
  ARR_BASE
  ARR_STACK_DIR
  ARR_ENV_FILE
  ARR_DOCKER_DIR
  CADDY_IMAGE
  ARR_PERMISSION_PROFILE
  DOWNLOADS_DIR
  COMPLETED_DIR
  MEDIA_DIR
  TV_DIR
  MOVIES_DIR
  SUBS_DIR
  LAN_IP
  LOCALHOST_IP
  PUID
  PGID
  QBT_USER
  QBT_PASS
  GLUETUN_API_KEY
)

# Derived (non-user) environment keys written into .env by write_env; kept here
# so tooling can validate compose interpolation without needing .env.example.
ARRSTACK_DERIVED_ENV_VARS=(
  VPN_TYPE
  DNS_HOST_ENTRY
  OPENVPN_USER
  OPENVPN_PASSWORD
  OPENVPN_USER_ENFORCED
  COMPOSE_PROJECT_NAME
  COMPOSE_PROFILES
  VPN_SERVICE_PROVIDER
  GLUETUN_API_KEY
  GLUETUN_FIREWALL_INPUT_PORTS
  GLUETUN_FIREWALL_OUTBOUND_SUBNETS
  CADDY_BASIC_AUTH_HASH
)

# shellcheck disable=SC2034  # exported for template rendering via envsubst
UPSTREAM_DNS_2_DISPLAY="${UPSTREAM_DNS_2:-<unset>}"

arrstack_export_userconf_template_vars() {
  local var=""
  local value=""

  for var in "${ARRSTACK_USERCONF_TEMPLATE_VARS[@]}"; do
    value="${!var-}"
    export "${var}=${value}"
  done
}

arrstack_userconf_envsubst_spec() {
  local var=""
  local spec=""

  for var in "${ARRSTACK_USERCONF_TEMPLATE_VARS[@]}"; do
    spec+=" \${${var}}"
  done

  printf '%s\n' "${spec# }"
}

arrstack_collect_all_expected_env_keys() {
  local -A seen=()
  local -a ordered=()
  local var=""

  for var in "${ARRSTACK_USERCONF_TEMPLATE_VARS[@]:-}"; do
    if [[ -n "$var" && -z "${seen[$var]:-}" ]]; then
      ordered+=("$var")
      seen["$var"]=1
    fi
  done

  for var in "${ARRSTACK_USERCONF_IMPLICIT_VARS[@]:-}"; do
    if [[ -n "$var" && -z "${seen[$var]:-}" ]]; then
      ordered+=("$var")
      seen["$var"]=1
    fi
  done

  for var in "${ARRSTACK_DERIVED_ENV_VARS[@]:-}"; do
    if [[ -n "$var" && -z "${seen[$var]:-}" ]]; then
      ordered+=("$var")
      seen["$var"]=1
    fi
  done

  printf '%s\n' "${ordered[@]}"
}

arrstack_render_userconf_template() {
  cat <<'EOF'
#!/usr/bin/env bash
# shellcheck disable=SC2034
# Auto-generated by scripts/dev/sync-userconf-example.sh. Run that helper to refresh.
# Copy to ${ARR_BASE}/userr.conf (default: ${HOME}/srv/userr.conf) and edit as needed.
# Values here override the defaults from arrconf/userr.conf.defaults.sh, which loads first.

# --- Stack paths ---
ARR_BASE="${HOME}/srv"                 # Root directory for generated stack files
ARR_STACK_DIR="${ARR_BASE}/arrstack"  # Location for docker-compose.yml, scripts, and aliases
ARR_ENV_FILE="${ARR_STACK_DIR}/.env"  # Path to the generated .env secrets file
ARR_DOCKER_DIR="${ARR_BASE}/docker-data"  # Docker volumes and persistent data storage
# ARR_USERCONF_PATH="${ARR_USERCONF_PATH}"  # Optional: relocate this file outside ${ARR_BASE}
# ARRCONF_DIR="${HOME}/.config/arrstack"  # Optional: relocate Proton creds outside the repo

# --- Logging and output ---
ARR_LOG_DIR="${ARR_LOG_DIR}"           # Directory for runtime/service logs (default: ${ARR_LOG_DIR})
ARR_INSTALL_LOG="${ARR_INSTALL_LOG}"   # Installer run log location (default: ${ARR_INSTALL_LOG})
ARR_COLOR_OUTPUT="${ARR_COLOR_OUTPUT}"       # 1 keeps colorful CLI output, set 0 to disable ANSI colors

# --- Permissions ---
ARR_PERMISSION_PROFILE="strict"        # strict keeps secrets 600/700, collab enables group read/write (660/770)

# --- Downloads and media ---
DOWNLOADS_DIR="${HOME}/Downloads"      # Active qBittorrent download folder
COMPLETED_DIR="${DOWNLOADS_DIR}/completed"  # Destination for completed downloads
MEDIA_DIR="/media/mediasmb"            # Root of the media library share
TV_DIR="${MEDIA_DIR}/Shows"            # Sonarr TV library path
MOVIES_DIR="${MEDIA_DIR}/Movies"       # Radarr movie library path
# SUBS_DIR="${MEDIA_DIR}/subs"         # Optional Bazarr subtitles directory

# --- User identity ---
PUID="$(id -u)"                        # Numeric user ID containers should run as
PGID="$(id -g)"                        # Numeric group ID with write access (match your media group when using collab)
TIMEZONE="${TIMEZONE}"            # Timezone for container logs and schedules (default: ${TIMEZONE})

# --- Networking ---
LAN_IP=""                              # Bind services to one LAN IP (set a DHCP reservation or static IP before install)
LOCALHOST_IP="127.0.0.1"               # Loopback used by the Gluetun control API
LAN_DOMAIN_SUFFIX="${LAN_DOMAIN_SUFFIX}"          # Suffix appended to service hostnames (default: ${LAN_DOMAIN_SUFFIX})
CADDY_DOMAIN_SUFFIX="${CADDY_DOMAIN_SUFFIX}"  # Override Caddy hostname suffix independently of LAN DNS (default: ${CADDY_DOMAIN_SUFFIX})
SERVER_COUNTRIES="${SERVER_COUNTRIES}"              # ProtonVPN exit country list (default: ${SERVER_COUNTRIES})
# SERVER_NAMES=""                          # Optionally pin Proton server hostnames (comma-separated) if PF stays at 0
PVPN_ROTATE_COUNTRIES="${PVPN_ROTATE_COUNTRIES}"  # Optional rotation order for arr.vpn switch (default mirrors SERVER_COUNTRIES)
GLUETUN_CONTROL_PORT="${GLUETUN_CONTROL_PORT}"            # Host port that exposes the Gluetun control API (default: ${GLUETUN_CONTROL_PORT})
ENABLE_LOCAL_DNS="${ENABLE_LOCAL_DNS}"                   # Advanced: enable the optional dnsmasq container (0/1, default: ${ENABLE_LOCAL_DNS})
ENABLE_CADDY="${ENABLE_CADDY}"                       # Optional Caddy reverse proxy (run ./arrstack.sh --enable-caddy or set 1 to add HTTPS hostnames)
ENABLE_CONFIGARR="${ENABLE_CONFIGARR}"             # Configarr one-shot sync for TRaSH-Guides profiles (set 0 to omit the container)
DNS_DISTRIBUTION_MODE="${DNS_DISTRIBUTION_MODE}"         # router (DHCP Option 6) or per-device DNS settings (default: ${DNS_DISTRIBUTION_MODE})
UPSTREAM_DNS_SERVERS="${UPSTREAM_DNS_SERVERS}"          # Comma-separated resolver list used by dnsmasq (default chain shown)
UPSTREAM_DNS_1="${UPSTREAM_DNS_1}"               # Legacy primary resolver override (default derived: ${UPSTREAM_DNS_1})
UPSTREAM_DNS_2="${UPSTREAM_DNS_2}"               # Legacy secondary resolver override (default derived: ${UPSTREAM_DNS_2_DISPLAY})
CADDY_LAN_CIDRS="${CADDY_LAN_CIDRS}"  # Clients allowed to skip Caddy auth (default: ${CADDY_LAN_CIDRS})
EXPOSE_DIRECT_PORTS="${EXPOSE_DIRECT_PORTS}"                # Keep 1 so WebUIs publish on http://${LAN_IP}:PORT (requires LAN_IP set to your private IPv4)

# --- Credentials ---
QBT_USER="admin"                       # Initial qBittorrent username (change after first login)
QBT_PASS="adminadmin"                  # Initial qBittorrent password (update immediately after install)
GLUETUN_API_KEY=""                     # Pre-seed a Gluetun API key or leave empty to auto-generate
QBT_DOCKER_MODS="${QBT_DOCKER_MODS}"  # Vuetorrent WebUI mod (set empty to disable)
QBT_AUTH_WHITELIST="${QBT_AUTH_WHITELIST}"  # CIDRs allowed to bypass the qBittorrent login prompt (default: ${QBT_AUTH_WHITELIST})
CADDY_BASIC_AUTH_USER="${CADDY_BASIC_AUTH_USER}"           # Username clients outside CADDY_LAN_CIDRS must use (default: ${CADDY_BASIC_AUTH_USER})
CADDY_BASIC_AUTH_HASH=""               # Bcrypt hash for the Basic Auth password (regen when empty)

# --- Service ports ---
QBT_HTTP_PORT_HOST="${QBT_HTTP_PORT_HOST}"              # qBittorrent WebUI port exposed on the LAN (default: ${QBT_HTTP_PORT_HOST})
SONARR_PORT="${SONARR_PORT}"                     # Sonarr WebUI port exposed on the LAN (default: ${SONARR_PORT})
RADARR_PORT="${RADARR_PORT}"                     # Radarr WebUI port exposed on the LAN (default: ${RADARR_PORT})
PROWLARR_PORT="${PROWLARR_PORT}"                   # Prowlarr WebUI port exposed on the LAN (default: ${PROWLARR_PORT})
BAZARR_PORT="${BAZARR_PORT}"                     # Bazarr WebUI port exposed on the LAN (default: ${BAZARR_PORT})
FLARESOLVERR_PORT="${FLARESOLVERR_PORT}"               # FlareSolverr service port exposed on the LAN (default: ${FLARESOLVERR_PORT})

# --- ProtonVPN port-forward timing (advanced) ---
PF_MAX_TOTAL_WAIT="${PF_MAX_TOTAL_WAIT}"          # Max seconds to wait for a forwarded port before failing (default: ${PF_MAX_TOTAL_WAIT})
PF_POLL_INTERVAL="${PF_POLL_INTERVAL}"            # Seconds between Proton API checks while waiting (default: ${PF_POLL_INTERVAL})
PF_CYCLE_AFTER="${PF_CYCLE_AFTER}"                # Seconds before retrying with a new Proton server (default: ${PF_CYCLE_AFTER})
PF_ASYNC_MAX_TOTAL_WAIT="${PF_ASYNC_MAX_TOTAL_WAIT}"    # Async helper max wait time when rotating (default: ${PF_ASYNC_MAX_TOTAL_WAIT})
PF_ASYNC_POLL_INTERVAL="${PF_ASYNC_POLL_INTERVAL}"      # Async helper polling interval in seconds (default: ${PF_ASYNC_POLL_INTERVAL})
PF_ASYNC_CYCLE_AFTER="${PF_ASYNC_CYCLE_AFTER}"          # Async helper retry interval for fresh ports (default: ${PF_ASYNC_CYCLE_AFTER})

# --- Container images (advanced) ---
# GLUETUN_IMAGE="${GLUETUN_IMAGE}"                     # Override the Gluetun container tag
# QBITTORRENT_IMAGE="${QBITTORRENT_IMAGE}"  # Override the qBittorrent container tag
# SONARR_IMAGE="${SONARR_IMAGE}"         # Override the Sonarr container tag
# RADARR_IMAGE="${RADARR_IMAGE}"        # Override the Radarr container tag
# PROWLARR_IMAGE="${PROWLARR_IMAGE}"                # Override the Prowlarr container tag
# BAZARR_IMAGE="${BAZARR_IMAGE}"                    # Override the Bazarr container tag
# FLARESOLVERR_IMAGE="${FLARESOLVERR_IMAGE}"      # Override the FlareSolverr container tag
# CONFIGARR_IMAGE="${CONFIGARR_IMAGE}"            # Override the Configarr container tag
# CADDY_IMAGE="${CADDY_IMAGE}"                      # Override the Caddy reverse-proxy container tag

# --- ConfigArr quality/profile defaults ---
ARR_VIDEO_MIN_RES="${ARR_VIDEO_MIN_RES}"         # Minimum allowed resolution (default: ${ARR_VIDEO_MIN_RES})
ARR_VIDEO_MAX_RES="${ARR_VIDEO_MAX_RES}"         # Maximum allowed resolution (default: ${ARR_VIDEO_MAX_RES})
ARR_EP_MIN_MB="${ARR_EP_MIN_MB}"                 # Minimum episode size in MB (default: ${ARR_EP_MIN_MB})
ARR_EP_MAX_GB="${ARR_EP_MAX_GB}"                 # Maximum episode size in GB (default: ${ARR_EP_MAX_GB})
ARR_TV_RUNTIME_MIN="${ARR_TV_RUNTIME_MIN}"       # Minimum runtime to treat content as standard TV (default: ${ARR_TV_RUNTIME_MIN})
ARR_SEASON_MAX_GB="${ARR_SEASON_MAX_GB}"         # Cap on total season size in GB (default: ${ARR_SEASON_MAX_GB})
ARR_LANG_PRIMARY="${ARR_LANG_PRIMARY}"           # Preferred audio/subtitle language (default: ${ARR_LANG_PRIMARY})
ARR_ENGLISH_ONLY="${ARR_ENGLISH_ONLY}"           # 1 prefers English-only releases (default: ${ARR_ENGLISH_ONLY})
ARR_DISCOURAGE_MULTI="${ARR_DISCOURAGE_MULTI}"   # 1 penalises multi-audio releases (default: ${ARR_DISCOURAGE_MULTI})
ARR_PENALIZE_HD_X265="${ARR_PENALIZE_HD_X265}"   # 1 lowers HD x265 release scores (default: ${ARR_PENALIZE_HD_X265})
ARR_STRICT_JUNK_BLOCK="${ARR_STRICT_JUNK_BLOCK}" # 1 fully blocks junk releases (default: ${ARR_STRICT_JUNK_BLOCK})
ARR_JUNK_NEGATIVE_SCORE="${ARR_JUNK_NEGATIVE_SCORE}"         # Score applied to junk terms (default: ${ARR_JUNK_NEGATIVE_SCORE})
ARR_X265_HD_NEGATIVE_SCORE="${ARR_X265_HD_NEGATIVE_SCORE}"   # Score penalty for HD x265 (default: ${ARR_X265_HD_NEGATIVE_SCORE})
ARR_MULTI_NEGATIVE_SCORE="${ARR_MULTI_NEGATIVE_SCORE}"       # Score penalty for multi-audio releases (default: ${ARR_MULTI_NEGATIVE_SCORE})
ARR_ENGLISH_POSITIVE_SCORE="${ARR_ENGLISH_POSITIVE_SCORE}"   # Score bonus for English releases (default: ${ARR_ENGLISH_POSITIVE_SCORE})
SONARR_TRASH_TEMPLATE="${SONARR_TRASH_TEMPLATE}" # TRaSH template slug ConfigArr applies to Sonarr (default: ${SONARR_TRASH_TEMPLATE})
RADARR_TRASH_TEMPLATE="${RADARR_TRASH_TEMPLATE}" # TRaSH template slug ConfigArr applies to Radarr (default: ${RADARR_TRASH_TEMPLATE})
ARR_MBMIN_DECIMALS="${ARR_MBMIN_DECIMALS}"       # Decimals precision for minimum size rules (default: ${ARR_MBMIN_DECIMALS})

# --- Behaviour toggles ---
# ASSUME_YES="0"                         # Skip confirmation prompts when scripting installs
# FORCE_ROTATE_API_KEY="0"               # Force regeneration of the Gluetun API key on next run
# FORCE_REGEN_CADDY_AUTH="0"             # Rotate the Caddy username/password on next run
# SETUP_HOST_DNS="0"                      # Automate host DNS takeover helper (or call with --setup-host-dns)
# REFRESH_ALIASES="0"                     # Regenerate helper aliases without running the installer
EOF
}

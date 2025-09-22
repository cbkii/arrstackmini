#!/usr/bin/env bash
# shellcheck enable=require-variable-braces
# shellcheck enable=quote-safe-variables
set -Euo pipefail
IFS=$'\n\t'

REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
[ -f "${REPO_ROOT}/arrconf/userconf.defaults.sh" ] && . "${REPO_ROOT}/arrconf/userconf.defaults.sh"
[ -f "${REPO_ROOT}/arrconf/userconf.sh" ] && . "${REPO_ROOT}/arrconf/userconf.sh"

# Ensure arrconf defaults resolve relative to the repository even when the
# installer is invoked via an absolute path (for example `~/arrstack/arrstack.sh`).
ARRCONF_DIR="${ARRCONF_DIR:-${REPO_ROOT}/arrconf}"

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
: "${SUBS_DIR:=}"

: "${LAN_DOMAIN_SUFFIX:=home.arpa}"
LAN_DOMAIN_SUFFIX="${LAN_DOMAIN_SUFFIX#.}"
if [[ -z "${LAN_DOMAIN_SUFFIX}" ]]; then
  LAN_DOMAIN_SUFFIX="lan"
fi

: "${UPSTREAM_DNS_1:=1.1.1.1}"
: "${UPSTREAM_DNS_2:=1.0.0.1}"
: "${ENABLE_LOCAL_DNS:=1}"
: "${SETUP_HOST_DNS:=0}"

: "${FORCE_REGEN_CADDY_AUTH:=0}"
: "${CADDY_IMAGE:=caddy:2.8.4}"
: "${CADDY_LAN_CIDRS:=192.168.0.0/16 10.0.0.0/8 172.16.0.0/12}"
: "${CADDY_BASIC_AUTH_USER:=user}"
: "${CADDY_BASIC_AUTH_HASH:=}"

: "${QBT_USER:=admin}"
: "${QBT_PASS:=adminadmin}"
: "${QBT_DOCKER_MODS:=ghcr.io/vuetorrent/vuetorrent-lsio-mod:latest}"
: "${QBT_AUTH_WHITELIST:=127.0.0.1/32,127.0.0.0/8,::1/128}"

: "${GLUETUN_IMAGE:=qmcgaw/gluetun:v3.39.1}"
: "${QBITTORRENT_IMAGE:=lscr.io/linuxserver/qbittorrent:5.1.2-r2-ls415}"
: "${SONARR_IMAGE:=lscr.io/linuxserver/sonarr:4.0.15.2941-ls291}"
: "${RADARR_IMAGE:=lscr.io/linuxserver/radarr:5.27.5.10198-ls283}"
: "${PROWLARR_IMAGE:=lscr.io/linuxserver/prowlarr:latest}"
: "${BAZARR_IMAGE:=lscr.io/linuxserver/bazarr:latest}"
: "${FLARESOLVERR_IMAGE:=ghcr.io/flaresolverr/flaresolverr:v3.3.21}"
: "${PORT_SYNC_IMAGE:=alpine:3.20.3}"

# Derived / normalized
if [[ -n "${CADDY_DOMAIN_SUFFIX:-}" ]]; then
  CADDY_DOMAIN_SUFFIX="${CADDY_DOMAIN_SUFFIX#.}"
fi

if [[ -z "${CADDY_DOMAIN_SUFFIX:-}" ]]; then
  CADDY_DOMAIN_SUFFIX="${LAN_DOMAIN_SUFFIX}" 
fi

if [[ -z "${CADDY_DOMAIN_SUFFIX:-}" ]]; then
  CADDY_DOMAIN_SUFFIX="lan"
fi

ARR_DOMAIN_SUFFIX_CLEAN="${CADDY_DOMAIN_SUFFIX#.}"
ARR_DOMAIN_SUFFIX_CLEAN="${ARR_DOMAIN_SUFFIX_CLEAN:-lan}"

export CADDY_DOMAIN_SUFFIX
export LAN_DOMAIN_SUFFIX

PROTON_USER_VALUE=""
PROTON_PASS_VALUE=""
OPENVPN_USER_VALUE=""
PROTON_USER_PMP_ADDED=0

DOCKER_COMPOSE_CMD=()
ARRSTACK_LOCKFILE=""
LOG_FILE=""

help() {
  cat <<'USAGE'
Usage: ./arrstack.sh [options]

Options:
  --yes                 Run non-interactively and assume yes to prompts
  --rotate-api-key      Force regeneration of the Gluetun API key
  --rotate-caddy-auth   Force regeneration of the Caddy basic auth credentials
  --setup-host-dns      Run the host DNS takeover helper during installation
  --help                Show this help message
USAGE
}

have_command() {
  command -v "$1" >/dev/null 2>&1
}

init_logging() {
  local log_dir="${ARR_STACK_DIR}/logs"
  mkdir -p "$log_dir"

  LOG_FILE="${log_dir}/arrstack-$(date +%Y%m%d-%H%M%S).log"
  ln -sf "$LOG_FILE" "${log_dir}/latest.log"

  exec > >(tee -a "$LOG_FILE")
  exec 2>&1

  msg "Installation started at $(date)"
  msg "Log file: $LOG_FILE"
}

# --- Colour setup ---
CYAN='\033[0;36m'
YELLOW='\033[0;33m'
RESET='\033[0m'

msg_color_supported() {
  if [ -n "${NO_COLOR:-}" ]; then
    return 1
  fi
  if [ -n "${FORCE_COLOR:-}" ]; then
    return 0
  fi
  if [ -t 1 ]; then
    return 0
  fi
  return 1
}

msg() {
  if msg_color_supported; then
    printf '%b%s%b\n' "$CYAN" "$*" "$RESET"
  else
    printf '%s\n' "$*"
  fi
}

warn() {
  if msg_color_supported; then
    printf '%bWARN: %s%b\n' "$YELLOW" "$*" "$RESET" >&2
  else
    printf 'WARN: %s\n' "$*" >&2
  fi
}

die() {
  printf '[%s] ERROR: %s\n' "$(date '+%H:%M:%S')" "$*" >&2
  exit 1
}

check_network_requirements() {
  msg "🔍 Checking Gluetun control prerequisites"

  if ! have_command curl; then
    warn "curl not installed; install it so the stack can query the Gluetun control API"
  fi

  if ! have_command jq; then
    warn "jq not installed; helper scripts rely on it when parsing Gluetun responses"
  fi

  msg "  Skipping legacy NAT-PMP probe; Gluetun readiness is now verified via /v1/openvpn/status once the container starts"
}

ARR_PERMISSION_PROFILE="${ARR_PERMISSION_PROFILE:-strict}"
SECRET_FILE_MODE=600
LOCK_FILE_MODE=644
NONSECRET_FILE_MODE=600
DATA_DIR_MODE=700

case "${ARR_PERMISSION_PROFILE}" in
  collaborative)
    umask 0027
    NONSECRET_FILE_MODE=640
    DATA_DIR_MODE=750
    ;;
  strict | "")
    umask 0077
    ARR_PERMISSION_PROFILE="strict"
    ;;
  *)
    warn "Unknown ARR_PERMISSION_PROFILE='${ARR_PERMISSION_PROFILE}' - defaulting to strict"
    ARR_PERMISSION_PROFILE="strict"
    umask 0077
    ;;
esac

readonly ARR_PERMISSION_PROFILE SECRET_FILE_MODE LOCK_FILE_MODE NONSECRET_FILE_MODE DATA_DIR_MODE
ARR_DOCKER_SERVICES=(gluetun qbittorrent sonarr radarr prowlarr bazarr flaresolverr caddy local_dns)
readonly -a ARR_DOCKER_SERVICES

atomic_write() {
  local target="$1"
  local content="$2"
  local mode="${3:-600}"
  local tmp

  tmp="$(mktemp "${target}.XXXXXX.tmp" 2>/dev/null)" || die "Failed to create temp file for ${target}"

  if ! printf '%s\n' "$content" >"$tmp" 2>/dev/null; then
    rm -f "$tmp"
    die "Failed to write to temporary file for ${target}"
  fi

  if ! chmod "$mode" "$tmp" 2>/dev/null; then
    rm -f "$tmp"
    die "Failed to set permissions on ${target}"
  fi

  if ! mv -f "$tmp" "$target" 2>/dev/null; then
    rm -f "$tmp"
    die "Failed to atomically write ${target}"
  fi
}

acquire_lock() {
  local lock_dir="${ARR_STACK_DIR:-/tmp}"
  local timeout=30
  local elapsed=0

  if [ ! -d "$lock_dir" ]; then
    if ! mkdir -p "$lock_dir" 2>/dev/null; then
      lock_dir="/tmp"
    fi
  fi

  local lockfile="${lock_dir}/.arrstack.lock"

  while ! (
    set -C
    printf '%s' "$$" >"$lockfile"
  ) 2>/dev/null; do
    if [ "$elapsed" -ge "$timeout" ]; then
      die "Could not acquire lock after ${timeout}s. Another instance may be running."
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done

  chmod "$LOCK_FILE_MODE" "$lockfile" 2>/dev/null || true

  ARRSTACK_LOCKFILE="$lockfile"
  trap 'rm -f -- "$ARRSTACK_LOCKFILE"' EXIT INT TERM
}

portable_sed() {
  local expr="$1"
  local file="$2"
  local tmp

  tmp="$(mktemp "${file}.XXXXXX.tmp" 2>/dev/null)" || die "Failed to create temp file for sed"
  chmod 600 "$tmp" 2>/dev/null || true

  local perms=""
  if [ -e "$file" ]; then
    perms="$(stat -c '%a' "$file" 2>/dev/null || stat -f '%Lp' "$file" 2>/dev/null || echo '')"
  fi

  if sed -e "$expr" "$file" >"$tmp" 2>/dev/null; then
    if [ -f "$file" ] && cmp -s "$file" "$tmp" 2>/dev/null; then
      rm -f "$tmp"
      return 0
    fi

    if ! mv -f "$tmp" "$file" 2>/dev/null; then
      rm -f "$tmp"
      die "Failed to update ${file}"
    fi

    if [ -n "$perms" ]; then
      chmod "$perms" "$file" 2>/dev/null || true
    fi
  else
    rm -f "$tmp"
    die "sed operation failed on ${file}"
  fi
}

check_and_fix_mode() {
  local target="$1"
  local desired="$2"
  local issue_label="$3"

  [[ -e "$target" ]] || return 0

  local perms
  perms="$(stat -c '%a' "$target" 2>/dev/null || stat -f '%OLp' "$target" 2>/dev/null || echo 'unknown')"

  if [[ "$perms" != "$desired" ]]; then
    warn "  ${issue_label} on $target: $perms (should be $desired)"
    chmod "$desired" "$target" 2>/dev/null || warn "  Could not fix permissions on $target"
    return 1
  fi

  return 0
}

verify_permissions() {
  local issues=0

  msg "🔒 Verifying file permissions"

  local -a secret_files=(
    "${ARR_ENV_FILE}"
    "${ARRCONF_DIR}/proton.auth"
    "${ARR_DOCKER_DIR}/qbittorrent/qBittorrent.conf"
    "${ARR_STACK_DIR}/.arraliases"
  )

  local file
  for file in "${secret_files[@]}"; do
    if [[ -f "$file" ]]; then
      if ! check_and_fix_mode "$file" "$SECRET_FILE_MODE" "Insecure permissions"; then
        ((issues++))
      fi
    fi
  done

  local -a nonsecret_files=(
    "${ARR_STACK_DIR}/docker-compose.yml"
    "${REPO_ROOT}/.arraliases.configured"
  )

  for file in "${nonsecret_files[@]}"; do
    if [[ -f "$file" ]]; then
      if ! check_and_fix_mode "$file" "$NONSECRET_FILE_MODE" "Unexpected permissions"; then
        ((issues++))
      fi
    fi
  done

  local -a data_dirs=("${ARR_DOCKER_DIR}")
  local service
  for service in "${ARR_DOCKER_SERVICES[@]}"; do
    if [[ "$service" == "local_dns" && "${ENABLE_LOCAL_DNS:-1}" -ne 1 ]]; then
      continue
    fi
    data_dirs+=("${ARR_DOCKER_DIR}/${service}")
  done

  local dir
  for dir in "${data_dirs[@]}"; do
    if [[ -d "$dir" ]]; then
      if ! check_and_fix_mode "$dir" "$DATA_DIR_MODE" "Loose permissions"; then
        ((issues++))
      fi
    fi
  done

  if [[ -d "$ARRCONF_DIR" ]]; then
    if ! check_and_fix_mode "$ARRCONF_DIR" 700 "Loose permissions"; then
      ((issues++))
    fi
  fi

  if ((issues > 0)); then
    warn "$issues permission issues detected (corrected where possible)"
  else
    msg "  All permissions verified ✓"
  fi
}

validate_ipv4() {
  local ip="$1"
  local regex='^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'
  [[ "$ip" =~ $regex ]]
}

validate_port() {
  local port="$1"
  [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]
}

validate_proton_creds() {
  local user="$1"
  local pass="$2"

  if [ ${#user} -lt 3 ] || [ ${#pass} -lt 6 ]; then
    return 1
  fi

  if [[ "$user" =~ [[:space:]] ]] || [[ "$pass" =~ [[:space:]] ]]; then
    return 1
  fi

  return 0
}

validate_config() {
  if [ -n "${LAN_IP:-}" ] && [ "${LAN_IP}" != "0.0.0.0" ]; then
    validate_ipv4 "$LAN_IP" || die "Invalid LAN_IP: ${LAN_IP}"
  fi
  validate_port "$GLUETUN_CONTROL_PORT" || die "Invalid GLUETUN_CONTROL_PORT: ${GLUETUN_CONTROL_PORT}"
  validate_port "$QBT_HTTP_PORT_HOST" || die "Invalid QBT_HTTP_PORT_HOST: ${QBT_HTTP_PORT_HOST}"
  validate_port "$SONARR_PORT" || die "Invalid SONARR_PORT: ${SONARR_PORT}"
  validate_port "$RADARR_PORT" || die "Invalid RADARR_PORT: ${RADARR_PORT}"
  validate_port "$PROWLARR_PORT" || die "Invalid PROWLARR_PORT: ${PROWLARR_PORT}"
  validate_port "$BAZARR_PORT" || die "Invalid BAZARR_PORT: ${BAZARR_PORT}"
  validate_port "$FLARESOLVERR_PORT" || die "Invalid FLARESOLVERR_PORT: ${FLARESOLVERR_PORT}"

  validate_proton_creds "$PU" "$PW" || die "Invalid ProtonVPN credentials format"
}

docker_retry() {
  local cmd=("$@")
  # Simple single attempt - let Docker handle its own retries
  "${cmd[@]}" >/dev/null 2>&1
  return $?
}

wait_for_healthy() {
  local service="$1"
  local timeout="${2:-300}"
  local quiet="${3:-false}"
  local interval=5
  local elapsed=0
  local unhealthy_logged=false

  if [[ "$quiet" != "true" ]]; then
    msg "Waiting for $service (timeout: ${timeout}s)..."
  fi

  while ((elapsed < timeout)); do
    local health=""
    local state=""

    health="$(docker inspect "$service" --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' 2>/dev/null || true)"
    state="$(docker inspect "$service" --format '{{.State.Status}}' 2>/dev/null || echo "not_found")"

    if [[ "$state" == "exited" || "$state" == "dead" ]]; then
      warn "  $service is $state"
      return 1
    fi

    if [[ -n "$health" ]]; then
      case "$health" in
        healthy)
          msg "  ✅ $service is healthy"
          return 0
          ;;
        unhealthy)
          if [[ "$unhealthy_logged" != "true" ]]; then
            warn "  $service reports unhealthy; will keep retrying"
            unhealthy_logged=true
          fi
          ;;
        *)
          :
          ;;
      esac
    else
      if [[ "$state" == "running" ]]; then
        msg "  ✅ $service is running"
        return 0
      fi
    fi

    if [[ "$quiet" != "true" ]] && ((elapsed > 0)) && ((elapsed % 15 == 0)); then
      msg "  ... still waiting (${elapsed}s elapsed)"
    fi

    sleep "$interval"
    elapsed=$((elapsed + interval))
  done

  if [[ "$quiet" != "true" ]]; then
    warn "  Timeout waiting for $service"
  fi

  return 1
}

detect_lan_ip() {
  local candidate
  if command -v ip >/dev/null 2>&1; then
    candidate="$(ip -4 addr show scope global | awk '/inet / {print $2}' | cut -d/ -f1 | grep -E '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)' | head -n1 || true)"
  else
    candidate="$(hostname -I 2>/dev/null | awk '{for (i=1;i<=NF;i++) print $i}' | grep -E '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)' | head -n1 || true)"
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

  if ! docker version --format '{{.Server.Version}}' >/dev/null 2>&1; then
    die "Docker daemon is not running or not accessible"
  fi

  local compose_cmd=""
  local compose_version=""

  if docker compose version >/dev/null 2>&1; then
    compose_version="$(docker compose version --short 2>/dev/null | sed 's/^v//')"
    local compose_major="${compose_version%%.*}"
    if [[ -n "$compose_major" ]] && ((compose_major >= 2)); then
      compose_cmd="docker compose"
      DOCKER_COMPOSE_CMD=(docker compose)
    fi
  fi

  if [[ -z "$compose_cmd" ]] && command -v docker-compose >/dev/null 2>&1; then
    compose_version="$(docker-compose version --short 2>/dev/null | sed 's/^v//')"
    local compose_major="${compose_version%%.*}"
    if [[ -n "$compose_major" ]] && ((compose_major >= 2)); then
      compose_cmd="docker-compose"
      DOCKER_COMPOSE_CMD=(docker-compose)
    fi
  fi

  if [[ -z "$compose_cmd" ]]; then
    die "Docker Compose v2+ is required but not found"
  fi

  local required=(curl jq openssl)
  local missing=()

  for cmd in "${required[@]}"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      missing+=("$cmd")
    fi
  done

  if ((${#missing[@]} > 0)); then
    die "Missing required tools: ${missing[*]}. Please install them and re-run."
  fi

  if ! command -v certutil >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
      msg "  Tip: install certutil for smoother Caddy TLS trust: sudo apt-get install -y libnss3-tools"
    elif command -v yum >/dev/null 2>&1; then
      msg "  Tip: install certutil for smoother Caddy TLS trust: sudo yum install -y nss-tools"
    elif command -v dnf >/dev/null 2>&1; then
      msg "  Tip: install certutil for smoother Caddy TLS trust: sudo dnf install -y nss-tools"
    else
      msg "  Tip: certutil not found (optional); Caddy may print a trust-store warning."
    fi
  fi

  msg "  Docker: $(docker version --format '{{.Server.Version}}')"
  local compose_version_display=""
  if ((${#DOCKER_COMPOSE_CMD[@]} > 0)); then
    if ! compose_version_display="$("${DOCKER_COMPOSE_CMD[@]}" version --short 2>/dev/null)"; then
      compose_version_display="(unknown)"
    fi
  fi
  msg "  Compose: ${compose_cmd} ${compose_version_display}"
}

ensure_dir() {
  local dir="$1"
  mkdir -p "$dir"
}

escape_sed_replacement() {
  printf '%s' "$1" | sed -e 's/[&/]/\\&/g'
}

escape_env_value_for_compose() {
  local value="${1-}"
  value="${value//\$/\$\$}"
  printf '%s' "$value"
}

unescape_env_value_from_compose() {
  local value="${1-}"
  value="${value//\$\$/\$}"
  printf '%s' "$value"
}

is_bcrypt_hash() {
  local candidate="${1-}"

  candidate="$(unescape_env_value_from_compose "$candidate")"

  valid_bcrypt "$candidate"
}

format_env_line() {
  local key="$1"
  local value="${2-}"
  printf '%s=%s\n' "$key" "$(escape_env_value_for_compose "$value")"
}

set_qbt_conf_value() {
  local file="$1"
  local key="$2"
  local value="$3"
  local tmp

  tmp="$(mktemp)"
  chmod 600 "$tmp" 2>/dev/null || true

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
    if ((!replaced)); then
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

  local escaped_value
  escaped_value="$(escape_env_value_for_compose "$value")"

  if [[ -f "$ARR_ENV_FILE" ]]; then
    if grep -q "^${key}=" "$ARR_ENV_FILE"; then
      local escaped
      escaped="$(escape_sed_replacement "$escaped_value")"
      portable_sed "s/^${key}=.*/${key}=${escaped}/" "$ARR_ENV_FILE"
    else
      printf '%s' "$(format_env_line "$key" "$value")" >>"$ARR_ENV_FILE"
    fi
  fi
}

obfuscate_sensitive() {
  local value="${1-}"
  local visible_prefix="${2:-2}"
  local visible_suffix="${3:-${visible_prefix}}"

  if [[ -z "$value" ]]; then
    printf '(not set)'
    return
  fi

  if ((visible_prefix < 0)); then
    visible_prefix=0
  fi
  if ((visible_suffix < 0)); then
    visible_suffix=0
  fi

  local length=${#value}
  if ((length <= visible_prefix + visible_suffix)); then
    printf '%*s' "$length" '' | tr ' ' '*'
    return
  fi

  local prefix=""
  local suffix=""
  ((visible_prefix > 0)) && prefix="${value:0:visible_prefix}"
  ((visible_suffix > 0)) && suffix="${value: -visible_suffix}"

  local hidden_len=$((length - visible_prefix - visible_suffix))
  local mask
  mask="$(printf '%*s' "$hidden_len" '' | tr ' ' '*')"

  printf '%s%s%s' "$prefix" "$mask" "$suffix"
}

# Generate a safe (shell/compose/caddy-friendly) password: alphanumeric only
gen_safe_password() {
  local len="${1:-20}"
  local password=""

  if ((len <= 0)); then
    len=20
  fi

  if command -v tr >/dev/null 2>&1 && [ -r /dev/urandom ]; then
    password="$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c "$len" || true)"
  fi

  if ((${#password} < len)) && command -v openssl >/dev/null 2>&1; then
    password="$(openssl rand -base64 $((len * 2)) | LC_ALL=C tr -dc 'A-Za-z0-9' | head -c "$len" || true)"
  fi

  if ((${#password} < len)); then
    password="$(printf '%s' "$(date +%s%N)$$" | sha256sum | LC_ALL=C tr -dc 'A-Za-z0-9' | head -c "$len" || true)"
  fi

  if ((${#password} < len)); then
    password="$(printf '%*s' "$len" '' | tr ' ' 'A')"
  fi

  printf '%s' "$password"
}

# Sanitize a username into a safe token (alnum, dot, underscore, hyphen)
sanitize_user() {
  local input="${1:-user}"
  local sanitized
  sanitized="$(printf '%s' "$input" | tr -cd 'A-Za-z0-9._-' || true)"
  if [[ -z "$sanitized" ]]; then
    sanitized="user"
  fi
  printf '%s' "$sanitized"
}

valid_bcrypt() {
  local candidate="${1-}"

  if [[ "$candidate" =~ ^\$2[aby]\$([0-3][0-9])\$[./A-Za-z0-9]{53}$ ]]; then
    local cost="${BASH_REMATCH[1]}"
    if ((10#$cost >= 4 && 10#$cost <= 31)); then
      return 0
    fi
  fi

  return 1
}

# Produce a bcrypt hash using the configured Caddy image
caddy_bcrypt() {
  local plaintext="${1-}"

  if [[ -z "$plaintext" ]]; then
    return 1
  fi

  docker run --rm "${CADDY_IMAGE}" caddy hash-password --algorithm bcrypt --plaintext "$plaintext" 2>/dev/null
}

ensure_caddy_auth() {
  msg "🔐 Ensuring Caddy Basic Auth"

  if [[ -f "$ARR_ENV_FILE" ]]; then
    if [[ -z "${CADDY_BASIC_AUTH_USER:-}" || "${CADDY_BASIC_AUTH_USER}" == "user" ]]; then
      local env_user_line env_user_value
      env_user_line="$(grep '^CADDY_BASIC_AUTH_USER=' "$ARR_ENV_FILE" | head -n1 || true)"
      if [[ -n "$env_user_line" ]]; then
        env_user_value="${env_user_line#CADDY_BASIC_AUTH_USER=}"
        env_user_value="$(unescape_env_value_from_compose "$env_user_value")"
        if [[ -n "$env_user_value" ]]; then
          CADDY_BASIC_AUTH_USER="$env_user_value"
        fi
      fi
    fi

    if [[ -z "${CADDY_BASIC_AUTH_HASH:-}" ]]; then
      local env_hash_line env_hash_value
      env_hash_line="$(grep '^CADDY_BASIC_AUTH_HASH=' "$ARR_ENV_FILE" | head -n1 || true)"
      if [[ -n "$env_hash_line" ]]; then
        env_hash_value="${env_hash_line#CADDY_BASIC_AUTH_HASH=}"
        env_hash_value="$(unescape_env_value_from_compose "$env_hash_value")"
        if [[ -n "$env_hash_value" ]]; then
          CADDY_BASIC_AUTH_HASH="$env_hash_value"
        fi
      fi
    fi
  fi

  local sanitized_user
  sanitized_user="$(sanitize_user "${CADDY_BASIC_AUTH_USER}")"
  if [[ "$sanitized_user" != "$CADDY_BASIC_AUTH_USER" ]]; then
    CADDY_BASIC_AUTH_USER="$sanitized_user"
    persist_env_var "CADDY_BASIC_AUTH_USER" "$CADDY_BASIC_AUTH_USER"
    msg "  Caddy user sanitized → ${CADDY_BASIC_AUTH_USER}"
  fi

  local current_hash
  current_hash="$(unescape_env_value_from_compose "${CADDY_BASIC_AUTH_HASH:-}")"
  CADDY_BASIC_AUTH_HASH="$current_hash"

  local need_regen=0
  if [[ "${FORCE_REGEN_CADDY_AUTH:-0}" == "1" ]]; then
    need_regen=1
  elif [[ -z "$current_hash" ]] || ! valid_bcrypt "$current_hash"; then
    need_regen=1
  fi

  local cred_dir="${ARR_DOCKER_DIR}/caddy"
  local cred_file="${cred_dir}/credentials"

  if [[ "$need_regen" == "1" ]]; then
    local plaintext
    plaintext="$(gen_safe_password 20)"

    local hash_output
    hash_output="$(caddy_bcrypt "$plaintext" || true)"
    local new_hash
    new_hash="$(printf '%s\n' "$hash_output" | awk '/^\$2[aby]\$/{hash=$0} END {if (hash) print hash}')"

    if [[ -z "$new_hash" ]] || ! valid_bcrypt "$new_hash"; then
      die "Failed to generate Caddy bcrypt hash (docker or ${CADDY_IMAGE} unavailable?)"
    fi

    CADDY_BASIC_AUTH_HASH="$new_hash"
    persist_env_var "CADDY_BASIC_AUTH_HASH" "$CADDY_BASIC_AUTH_HASH"

    ensure_dir "$cred_dir"
    chmod 700 "$cred_dir" 2>/dev/null || true
    (
      umask 0077
      {
        printf 'username=%s\n' "$CADDY_BASIC_AUTH_USER"
        printf 'password=%s\n' "$plaintext"
      } >"$cred_file"
    )
    chmod 600 "$cred_file" 2>/dev/null || true

    local passmask
    passmask="$(obfuscate_sensitive "$plaintext" 2 2)"
    msg "  Generated new Caddy credentials → user: ${CADDY_BASIC_AUTH_USER}, pass: ${passmask}"
    msg "  Full credentials saved to: ${cred_file}"
  else
    ensure_dir "$cred_dir"
    chmod 700 "$cred_dir" 2>/dev/null || true
    local existing_plain=""
    if [[ -f "$cred_file" ]]; then
      existing_plain="$(grep '^password=' "$cred_file" | head -n1 | cut -d= -f2- || true)"
    fi
    if [[ -n "$existing_plain" ]]; then
      (
        umask 0077
        {
          printf 'username=%s\n' "$CADDY_BASIC_AUTH_USER"
          printf 'password=%s\n' "$existing_plain"
        } >"$cred_file"
      )
      chmod 600 "$cred_file" 2>/dev/null || true
    else
      warn "Caddy credentials file missing plaintext password; use --rotate-caddy-auth to recreate it."
    fi
    msg "  Existing Caddy bcrypt hash is valid ✓"
  fi
}

# Build the qBittorrent WebUI auth whitelist, ensuring LAN & localhost get no-auth
calculate_qbt_auth_whitelist() {
  local auth_whitelist=""

  append_whitelist_entry() {
    local entry="${1-}"
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

  if [[ -n "${CADDY_LAN_CIDRS:-}" ]]; then
    local lan_entries
    lan_entries="${CADDY_LAN_CIDRS//,/ }"
    lan_entries="${lan_entries//$'\n'/ }"
    for entry in $lan_entries; do
      append_whitelist_entry "$entry"
    done
  fi

  append_whitelist_entry "127.0.0.1/32"
  append_whitelist_entry "127.0.0.0/8"
  append_whitelist_entry "::1/128"

  if [[ -n "${LAN_IP:-}" && "$LAN_IP" != "0.0.0.0" && "$LAN_IP" == *.*.*.* ]]; then
    append_whitelist_entry "${LAN_IP%.*}.0/24"
  fi

  if [[ -z "$auth_whitelist" ]]; then
    auth_whitelist="127.0.0.1/32,127.0.0.0/8,::1/128"
  fi

  printf '%s' "$auth_whitelist"
  unset -f append_whitelist_entry || true
}

load_proton_credentials() {
  local proton_file="${ARRCONF_DIR}/proton.auth"

  PROTON_USER_VALUE=""
  PROTON_PASS_VALUE=""
  OPENVPN_USER_VALUE=""
  PROTON_USER_PMP_ADDED=0

  if [[ -f "$proton_file" ]]; then
    PROTON_USER_VALUE="$(grep '^PROTON_USER=' "$proton_file" | head -n1 | cut -d= -f2- | tr -d '\r' || true)"
    PROTON_PASS_VALUE="$(grep '^PROTON_PASS=' "$proton_file" | head -n1 | cut -d= -f2- | tr -d '\r' || true)"
  fi

  if [[ -z "$PROTON_USER_VALUE" || -z "$PROTON_PASS_VALUE" ]]; then
    die "Missing or empty PROTON_USER/PROTON_PASS in ${proton_file}"
  fi

  local enforced
  enforced="${PROTON_USER_VALUE%+pmp}+pmp"
  if [[ "$enforced" != "$PROTON_USER_VALUE" ]]; then
    PROTON_USER_PMP_ADDED=1
  fi

  OPENVPN_USER_VALUE="$enforced"
}

show_configuration_preview() {
  msg "🔎 Configuration preview"

  if [[ -z "$PROTON_USER_VALUE" || -z "$PROTON_PASS_VALUE" ]]; then
    load_proton_credentials
  fi

  local proton_user="${PROTON_USER_VALUE}"
  local proton_pass="${PROTON_PASS_VALUE}"
  local openvpn_user="${OPENVPN_USER_VALUE}"

  local proton_user_display="${proton_user:-'(not set)'}"
  local proton_pass_display
  proton_pass_display="$(obfuscate_sensitive "$proton_pass")"

  local qbt_pass_display
  qbt_pass_display="$(obfuscate_sensitive "${QBT_PASS:-}")"

  local openvpn_user_display
  if [[ -n "$openvpn_user" ]]; then
    openvpn_user_display="$(obfuscate_sensitive "$openvpn_user" 2 4)"
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
$([[ -n "${SUBS_DIR:-}" ]] && printf '  • Subtitles directory: %s\n' "${SUBS_DIR}")

Network & system
  • Timezone: ${TIMEZONE}
  • LAN IP: ${lan_ip_display}
  • Localhost IP override: ${LOCALHOST_IP}
  • Server countries: ${SERVER_COUNTRIES}
  • User/Group IDs: ${PUID}/${PGID}

Credentials & secrets
  • Proton username: ${proton_user_display}
  • Proton OpenVPN username (+pmp enforced): ${openvpn_user_display}
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

  acquire_lock

  msg "  Permission profile: ${ARR_PERMISSION_PROFILE} (umask $(umask))"

  if [[ ! -f "${ARRCONF_DIR}/proton.auth" ]]; then
    die "Missing ${ARRCONF_DIR}/proton.auth - create it with PROTON_USER and PROTON_PASS"
  fi

  load_proton_credentials

  # Make it explicit in logs what we will use for PF
  msg "  OpenVPN username (enforced '+pmp'): $(obfuscate_sensitive "$OPENVPN_USER_VALUE" 2 4)"

  if ((PROTON_USER_PMP_ADDED)); then
    warn "Proton username '${PROTON_USER_VALUE}' missing '+pmp'; using '${OPENVPN_USER_VALUE}'"
  fi

  install_missing

  if [[ -f "$ARR_ENV_FILE" ]]; then
    local existing_openvpn_user=""
    existing_openvpn_user="$(grep '^OPENVPN_USER=' "$ARR_ENV_FILE" | head -n1 | cut -d= -f2- | tr -d '\r' || true)"
    if [[ -n "$existing_openvpn_user" ]]; then
      local existing_unescaped
      existing_unescaped="$(unescape_env_value_from_compose "$existing_openvpn_user")"
      if [[ "$existing_unescaped" != *"+pmp" ]]; then
        warn "OPENVPN_USER in ${ARR_ENV_FILE} is '${existing_unescaped}' and will be updated to include '+pmp'."
      fi
    fi
  fi

  show_configuration_preview

  if [[ "$ASSUME_YES" != 1 ]]; then
    local response=""

    warn "Continue with ProtonVPN OpenVPN setup? [y/N]: "
    if ! IFS= read -r response; then
      response=""
    fi

    if ! [[ ${response,,} =~ ^[[:space:]]*(y|yes)[[:space:]]*$ ]]; then
      die "Aborted"
    fi
  fi
}

mkdirs() {
  msg "📁 Creating directories"
  ensure_dir "$ARR_STACK_DIR"
  chmod 755 "$ARR_STACK_DIR" 2>/dev/null || true

  ensure_dir "$ARR_DOCKER_DIR"
  chmod "$DATA_DIR_MODE" "$ARR_DOCKER_DIR" 2>/dev/null || true

  local service
  for service in "${ARR_DOCKER_SERVICES[@]}"; do
    if [[ "$service" == "local_dns" && "${ENABLE_LOCAL_DNS:-1}" -ne 1 ]]; then
      continue
    fi
    ensure_dir "${ARR_DOCKER_DIR}/${service}"
    chmod "$DATA_DIR_MODE" "${ARR_DOCKER_DIR}/${service}" 2>/dev/null || true
  done

  ensure_dir "$DOWNLOADS_DIR"
  ensure_dir "$COMPLETED_DIR"

  ensure_dir "$ARR_STACK_DIR/scripts"
  chmod 755 "$ARR_STACK_DIR/scripts" 2>/dev/null || true

  if [[ -d "$ARRCONF_DIR" ]]; then
    chmod 700 "$ARRCONF_DIR" 2>/dev/null || true
    if [[ -f "${ARRCONF_DIR}/proton.auth" ]]; then
      chmod 600 "${ARRCONF_DIR}/proton.auth" 2>/dev/null || true
    fi
  fi

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

  if [[ -n "${SUBS_DIR:-}" && ! -d "$SUBS_DIR" ]]; then
    warn "Subtitles directory does not exist: ${SUBS_DIR}"
    warn "Creating it now (may fail if parent directory is missing)"
    mkdir -p "$SUBS_DIR" 2>/dev/null || warn "Could not create subtitles directory"
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

  if [[ -f "$ARR_ENV_FILE" ]]; then
    if [[ -z "${CADDY_BASIC_AUTH_USER:-}" || "${CADDY_BASIC_AUTH_USER}" == "user" ]]; then
      local env_user_line env_user_value
      env_user_line="$(grep '^CADDY_BASIC_AUTH_USER=' "$ARR_ENV_FILE" | head -n1 || true)"
      if [[ -n "$env_user_line" ]]; then
        env_user_value="${env_user_line#CADDY_BASIC_AUTH_USER=}"
        env_user_value="$(unescape_env_value_from_compose "$env_user_value")"
        if [[ -n "$env_user_value" ]]; then
          CADDY_BASIC_AUTH_USER="$env_user_value"
        fi
      fi
    fi

    if [[ -z "${CADDY_BASIC_AUTH_HASH:-}" ]]; then
      local env_hash_line env_hash_value
      env_hash_line="$(grep '^CADDY_BASIC_AUTH_HASH=' "$ARR_ENV_FILE" | head -n1 || true)"
      if [[ -n "$env_hash_line" ]]; then
        env_hash_value="${env_hash_line#CADDY_BASIC_AUTH_HASH=}"
        env_hash_value="$(unescape_env_value_from_compose "$env_hash_value")"
        if [[ -n "$env_hash_value" ]]; then
          CADDY_BASIC_AUTH_HASH="$env_hash_value"
        fi
      fi
    fi
  fi

  CADDY_BASIC_AUTH_USER="$(sanitize_user "$CADDY_BASIC_AUTH_USER")"

  if [[ -z "${LAN_IP:-}" ]]; then
    LAN_IP="$(detect_lan_ip)"
    if [[ "$LAN_IP" != "0.0.0.0" ]]; then
      msg "Detected LAN IP: $LAN_IP"
    else
      warn "Using LAN_IP=0.0.0.0; services will listen on all interfaces"
    fi
  elif [[ "$LAN_IP" == "0.0.0.0" ]]; then
    warn "LAN_IP explicitly set to 0.0.0.0; services will bind to all interfaces"
    warn "Consider using a specific RFC1918 address to limit exposure"
  fi

  load_proton_credentials

  PU="$OPENVPN_USER_VALUE"
  PW="$PROTON_PASS_VALUE"
  OPENVPN_USER="$PU"

  validate_config

  local env_content
  env_content="$({
    printf '# Core settings\n'
    format_env_line "VPN_TYPE" "openvpn"
    format_env_line "PUID" "$PUID"
    format_env_line "PGID" "$PGID"
    format_env_line "TIMEZONE" "$TIMEZONE"
    format_env_line "LAN_IP" "$LAN_IP"
    format_env_line "LOCALHOST_IP" "$LOCALHOST_IP"
    printf '\n'

    printf '# Local DNS\n'
    format_env_line "LAN_DOMAIN_SUFFIX" "$LAN_DOMAIN_SUFFIX"
    format_env_line "ENABLE_LOCAL_DNS" "$ENABLE_LOCAL_DNS"
    format_env_line "UPSTREAM_DNS_1" "$UPSTREAM_DNS_1"
    format_env_line "UPSTREAM_DNS_2" "$UPSTREAM_DNS_2"
    printf '\n'

    # Derived, so downstream tools (and developers) can reference the normalized suffix directly
    format_env_line "CADDY_DOMAIN_SUFFIX" "$ARR_DOMAIN_SUFFIX_CLEAN"
    printf '\n'

    printf '# ProtonVPN OpenVPN credentials\n'
    format_env_line "OPENVPN_USER" "$PU"
    format_env_line "OPENVPN_PASSWORD" "$PW"
    printf '\n'

    # Also persist for clarity (helps compose templating & external tooling)
    format_env_line "OPENVPN_USER_ENFORCED" "$PU"
    printf '\n'

    printf '# Gluetun settings\n'
    format_env_line "VPN_SERVICE_PROVIDER" "protonvpn"
    format_env_line "GLUETUN_API_KEY" "$GLUETUN_API_KEY"
    format_env_line "GLUETUN_CONTROL_PORT" "$GLUETUN_CONTROL_PORT"
    format_env_line "SERVER_COUNTRIES" "$SERVER_COUNTRIES"
    printf '\n'

    printf '# Service ports\n'
    format_env_line "QBT_HTTP_PORT_HOST" "$QBT_HTTP_PORT_HOST"
    format_env_line "SONARR_PORT" "$SONARR_PORT"
    format_env_line "RADARR_PORT" "$RADARR_PORT"
    format_env_line "PROWLARR_PORT" "$PROWLARR_PORT"
    format_env_line "BAZARR_PORT" "$BAZARR_PORT"
    format_env_line "FLARESOLVERR_PORT" "$FLARESOLVERR_PORT"
    printf '\n'

    printf '# qBittorrent credentials (change in WebUI after install, then update here)\n'
    format_env_line "QBT_USER" "$QBT_USER"
    format_env_line "QBT_PASS" "$QBT_PASS"
    format_env_line "QBT_DOCKER_MODS" "$QBT_DOCKER_MODS"
    printf '\n'

    printf '# Reverse proxy defaults\n'
    format_env_line "CADDY_DOMAIN_SUFFIX" "$ARR_DOMAIN_SUFFIX_CLEAN"
    format_env_line "CADDY_LAN_CIDRS" "$CADDY_LAN_CIDRS"
    format_env_line "CADDY_BASIC_AUTH_USER" "$CADDY_BASIC_AUTH_USER"
    # Store the bcrypt hash and escape dollars so Compose does not expand them
    format_env_line "CADDY_BASIC_AUTH_HASH" "$(unescape_env_value_from_compose "$CADDY_BASIC_AUTH_HASH")"
    printf '\n'

    printf '# Paths\n'
    format_env_line "ARR_DOCKER_DIR" "$ARR_DOCKER_DIR"
    format_env_line "DOWNLOADS_DIR" "$DOWNLOADS_DIR"
    format_env_line "COMPLETED_DIR" "$COMPLETED_DIR"
    format_env_line "TV_DIR" "$TV_DIR"
    format_env_line "MOVIES_DIR" "$MOVIES_DIR"
    if [[ -n "${SUBS_DIR:-}" ]]; then
      format_env_line "SUBS_DIR" "$SUBS_DIR"
    fi
    printf '\n'

    printf '# Images\n'
    format_env_line "GLUETUN_IMAGE" "$GLUETUN_IMAGE"
    format_env_line "QBITTORRENT_IMAGE" "$QBITTORRENT_IMAGE"
    format_env_line "SONARR_IMAGE" "$SONARR_IMAGE"
    format_env_line "RADARR_IMAGE" "$RADARR_IMAGE"
    format_env_line "PROWLARR_IMAGE" "$PROWLARR_IMAGE"
    format_env_line "BAZARR_IMAGE" "$BAZARR_IMAGE"
    format_env_line "FLARESOLVERR_IMAGE" "$FLARESOLVERR_IMAGE"
    format_env_line "CADDY_IMAGE" "$CADDY_IMAGE"
    format_env_line "PORT_SYNC_IMAGE" "$PORT_SYNC_IMAGE"
  })"

  atomic_write "$ARR_ENV_FILE" "$env_content" 600

}

write_compose() {
  msg "🐳 Writing docker-compose.yml"

  local compose_path="${ARR_STACK_DIR}/docker-compose.yml"
  local compose_content

  compose_content="$(
    {
      cat <<'YAML'
services:
  gluetun:
    image: ${GLUETUN_IMAGE}
    container_name: gluetun
    cap_add:
      - NET_ADMIN
    devices:
      - /dev/net/tun
    environment:
      VPN_SERVICE_PROVIDER: ${VPN_SERVICE_PROVIDER}
      VPN_TYPE: openvpn
      OPENVPN_USER: ${OPENVPN_USER}
      OPENVPN_PASSWORD: ${OPENVPN_PASSWORD}
      SERVER_COUNTRIES: ${SERVER_COUNTRIES}
      VPN_PORT_FORWARDING: "on"
      VPN_PORT_FORWARDING_PROVIDER: protonvpn
      HTTP_CONTROL_SERVER_ADDRESS: 0.0.0.0:${GLUETUN_CONTROL_PORT}
      HTTP_CONTROL_SERVER_AUTH: "apikey"
      HTTP_CONTROL_SERVER_APIKEY: ${GLUETUN_API_KEY}
      VPN_PORT_FORWARDING_STATUS_FILE: /tmp/gluetun/forwarded_port
      VPN_PORT_FORWARDING_UP_COMMAND: "/gluetun/hooks/update-qbt-port.sh {{PORTS}}"
      QBT_USER: ${QBT_USER}
      QBT_PASS: ${QBT_PASS}
      QBITTORRENT_ADDR: "http://127.0.0.1:8080"
      PORT_FORWARD_ONLY: "yes"
      HEALTH_TARGET_ADDRESS: "1.1.1.1:443"
      HEALTH_VPN_DURATION_INITIAL: "30s"
      HEALTH_VPN_DURATION_ADDITION: "10s"
      HEALTH_SUCCESS_WAIT_DURATION: "10s"
      DNS_KEEP_NAMESERVER: "off"
      PORT_FORWARDING_STATUS_FILE_CLEANUP: "off"
      FIREWALL_OUTBOUND_SUBNETS: "192.168.0.0/16,10.0.0.0/8,172.16.0.0/12"
      FIREWALL_INPUT_PORTS: "80,443"
      UPDATER_PERIOD: "24h"
      PUID: ${PUID}
      PGID: ${PGID}
      TZ: ${TIMEZONE}
    volumes:
      - ${ARR_DOCKER_DIR}/gluetun:/gluetun
    ports:
      - "${LOCALHOST_IP}:${GLUETUN_CONTROL_PORT}:${GLUETUN_CONTROL_PORT}"
      - "${LAN_IP}:80:80"
      - "${LAN_IP}:443:443"
    healthcheck:
      test: /gluetun-entrypoint healthcheck
      interval: 30s
      timeout: 20s
      retries: 5
      start_period: 60s
    restart: unless-stopped
    logging:
      driver: json-file
      options:
        max-size: "1m"
        max-file: "3"
YAML

      if [[ "${ENABLE_LOCAL_DNS:-1}" -eq 1 ]]; then
        cat <<'YAML'
  local_dns:
    image: 4km3/dnsmasq:2.90-r3
    container_name: arr_local_dns
    cap_add:
      - NET_ADMIN
    ports:
      - "${LAN_IP}:53:53/udp"
      - "${LAN_IP}:53:53/tcp"
    command:
      - --log-facility=-
      - --no-resolv
      - --server=${UPSTREAM_DNS_1}
      - --server=${UPSTREAM_DNS_2}
      - --domain-needed
      - --bogus-priv
      - --domain=${LAN_DOMAIN_SUFFIX}
      - --local=/${LAN_DOMAIN_SUFFIX}/
      - --address=/${LAN_DOMAIN_SUFFIX}/${LAN_IP}
    restart: unless-stopped
    logging:
      driver: json-file
      options:
        max-size: "1m"
        max-file: "2"
YAML
      fi

      cat <<'YAML'
  qbittorrent:
    image: ${QBITTORRENT_IMAGE}
    container_name: qbittorrent
    network_mode: "service:gluetun"
    environment:
      PUID: ${PUID}
      PGID: ${PGID}
      TZ: ${TIMEZONE}
      LANG: en_US.UTF-8
    volumes:
      - ${ARR_DOCKER_DIR}/qbittorrent:/config
      - ${DOWNLOADS_DIR}:/downloads
      - ${COMPLETED_DIR}:/completed
    depends_on:
      gluetun:
        condition: service_healthy
        restart: true
    healthcheck:
      test: ["CMD", "curl", "-f", "http://127.0.0.1:8080/api/v2/app/version"]
      interval: 30s
      timeout: 10s
      retries: 3
    restart: unless-stopped
    logging:
      driver: json-file
      options:
        max-size: "1m"
        max-file: "2"

  sonarr:
    image: ${SONARR_IMAGE}
    container_name: sonarr
    network_mode: "service:gluetun"
    environment:
      PUID: ${PUID}
      PGID: ${PGID}
      TZ: ${TIMEZONE}
      LANG: en_US.UTF-8
    volumes:
      - ${ARR_DOCKER_DIR}/sonarr:/config
      - ${DOWNLOADS_DIR}:/downloads
      - ${COMPLETED_DIR}:/completed
      - ${TV_DIR}:/tv
    depends_on:
      gluetun:
        condition: service_healthy
    restart: unless-stopped
    logging:
      driver: json-file
      options:
        max-size: "1m"
        max-file: "2"

  radarr:
    image: ${RADARR_IMAGE}
    container_name: radarr
    network_mode: "service:gluetun"
    environment:
      PUID: ${PUID}
      PGID: ${PGID}
      TZ: ${TIMEZONE}
      LANG: en_US.UTF-8
    volumes:
      - ${ARR_DOCKER_DIR}/radarr:/config
      - ${DOWNLOADS_DIR}:/downloads
      - ${COMPLETED_DIR}:/completed
      - ${MOVIES_DIR}:/movies
    depends_on:
      gluetun:
        condition: service_healthy
    restart: unless-stopped
    logging:
      driver: json-file
      options:
        max-size: "1m"
        max-file: "2"

  prowlarr:
    image: ${PROWLARR_IMAGE}
    container_name: prowlarr
    network_mode: "service:gluetun"
    environment:
      PUID: ${PUID}
      PGID: ${PGID}
      TZ: ${TIMEZONE}
      LANG: en_US.UTF-8
    volumes:
      - ${ARR_DOCKER_DIR}/prowlarr:/config
    depends_on:
      gluetun:
        condition: service_healthy
    restart: unless-stopped
    logging:
      driver: json-file
      options:
        max-size: "1m"
        max-file: "2"

  bazarr:
    image: ${BAZARR_IMAGE}
    container_name: bazarr
    network_mode: "service:gluetun"
    environment:
      PUID: ${PUID}
      PGID: ${PGID}
      TZ: ${TIMEZONE}
      LANG: en_US.UTF-8
    volumes:
      - ${ARR_DOCKER_DIR}/bazarr:/config
      - ${TV_DIR}:/tv
      - ${MOVIES_DIR}:/movies
__BAZARR_OPTIONAL_SUBS__
    depends_on:
      gluetun:
        condition: service_healthy
    restart: unless-stopped
    logging:
      driver: json-file
      options:
        max-size: "1m"
        max-file: "2"

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
    logging:
      driver: json-file
      options:
        max-size: "1m"
        max-file: "2"

  port-sync:
    image: ${PORT_SYNC_IMAGE}
    container_name: port-sync
    network_mode: "service:gluetun"
    environment:
      GLUETUN_API_KEY: ${GLUETUN_API_KEY}
      GLUETUN_ADDR: "http://127.0.0.1:${GLUETUN_CONTROL_PORT}"
      QBITTORRENT_ADDR: "http://127.0.0.1:8080"
      UPDATE_INTERVAL: 300
      BACKOFF_MAX: 900
      QBT_USER: ${QBT_USER}
      QBT_PASS: ${QBT_PASS}
      VPN_PORT_FORWARDING_STATUS_FILE: /tmp/gluetun/forwarded_port
    volumes:
      - ./scripts/port-sync.sh:/port-sync.sh:ro
    command: /port-sync.sh
    depends_on:
      gluetun:
        condition: service_healthy
      qbittorrent:
        condition: service_started
    restart: unless-stopped
    init: true
    logging:
      driver: json-file
      options:
        max-size: "1m"
        max-file: "2"

  caddy:
    image: ${CADDY_IMAGE}
    container_name: caddy
    network_mode: "service:gluetun"
    volumes:
      - ${ARR_DOCKER_DIR}/caddy/Caddyfile:/etc/caddy/Caddyfile:ro
      - ${ARR_DOCKER_DIR}/caddy/data:/data
      - ${ARR_DOCKER_DIR}/caddy/config:/config
    depends_on:
      gluetun:
        condition: service_healthy
    healthcheck:
      test:
        - "CMD-SHELL"
        - >
          if command -v curl >/dev/null 2>&1; then
            curl -fsS http://127.0.0.1/healthz;
          elif command -v wget >/dev/null 2>&1; then
            wget -qO- http://127.0.0.1/healthz;
          else
            echo "missing http client" >&2;
            exit 1;
          fi
      interval: 15s
      timeout: 5s
      retries: 6
      start_period: 20s
    restart: unless-stopped
    logging:
      driver: json-file
      options:
        max-size: "1m"
        max-file: "2"

YAML
    }
  )"

  local bazarr_subs_volume=""
  if [[ -n "${SUBS_DIR:-}" ]]; then
    printf -v bazarr_subs_volume $'      - ${SUBS_DIR}:/subs\n'
  fi
  compose_content="${compose_content/__BAZARR_OPTIONAL_SUBS__/${bazarr_subs_volume}}"

  atomic_write "$compose_path" "$compose_content" "$NONSECRET_FILE_MODE"
}

write_gluetun_control_assets() {
  msg "🛡️ Preparing Gluetun control assets"

  local gluetun_root="${ARR_DOCKER_DIR}/gluetun"
  local hooks_dir="${gluetun_root}/hooks"

  ensure_dir "$gluetun_root"
  ensure_dir "$hooks_dir"
  chmod 700 "$hooks_dir" 2>/dev/null || true

  cat >"${hooks_dir}/update-qbt-port.sh" <<'HOOK'
#!/bin/sh
set -eu

QBITTORRENT_ADDR="${QBITTORRENT_ADDR:-http://127.0.0.1:8080}"
COOKIE_JAR="/tmp/qbt.hook.cookies"

PORT_SPEC="${1:-}"

if [ -z "$PORT_SPEC" ]; then
    exit 0
fi

PORT_VALUE="${PORT_SPEC%%,*}"
PORT_VALUE="${PORT_VALUE%%:*}"

case "$PORT_VALUE" in
    ''|*[!0-9]*)
        exit 0
        ;;
esac

payload=$(printf 'json={"listen_port":%s,"random_port":false}' "$PORT_VALUE")

touch "$COOKIE_JAR" 2>/dev/null || true
chmod 600 "$COOKIE_JAR" 2>/dev/null || true

post_setprefs_unauth() {
    curl --silent --show-error --max-time 8 \
        --data "$payload" \
        --output /dev/null "${QBITTORRENT_ADDR%/}/api/v2/app/setPreferences"
}

post_setprefs_auth() {
    if [ -z "${QBT_USER:-}" ] || [ -z "${QBT_PASS:-}" ]; then
        return 1
    fi

    if ! curl -fsS --max-time 5 -c "$COOKIE_JAR" \
        --data-urlencode "username=${QBT_USER}" \
        --data-urlencode "password=${QBT_PASS}" \
        "${QBITTORRENT_ADDR%/}/api/v2/auth/login" >/dev/null 2>&1; then
        return 1
    fi

    curl --silent --show-error --max-time 8 -b "$COOKIE_JAR" \
        --data "$payload" \
        --output /dev/null "${QBITTORRENT_ADDR%/}/api/v2/app/setPreferences"
}

if command -v curl >/dev/null 2>&1; then
    attempts=0
    while [ $attempts -lt 5 ]; do
        if post_setprefs_unauth; then
            exit 0
        fi
        if post_setprefs_auth; then
            exit 0
        fi
        attempts=$((attempts + 1))
        sleep 2
    done
fi

exit 0
HOOK

  chmod 700 "${hooks_dir}/update-qbt-port.sh" 2>/dev/null || true
}

write_caddy_assets() {
  msg "🌐 Writing Caddy reverse proxy config"

  local caddy_root="${ARR_DOCKER_DIR}/caddy"
  local data_dir="${caddy_root}/data"
  local config_dir="${caddy_root}/config"
  local caddyfile="${caddy_root}/Caddyfile"

  ensure_dir "$caddy_root"
  ensure_dir "$data_dir"
  ensure_dir "$config_dir"
  chmod "$DATA_DIR_MODE" "$caddy_root" 2>/dev/null || true
  chmod "$DATA_DIR_MODE" "$data_dir" 2>/dev/null || true
  chmod "$DATA_DIR_MODE" "$config_dir" 2>/dev/null || true

  # Normalize LAN CIDRs (commas, tabs, multiple spaces, and newlines → single spaces)
  local lan_cidrs
  lan_cidrs="$(printf '%s' "${CADDY_LAN_CIDRS}" | tr ',\t\r\n' '    ')"
  lan_cidrs="$(printf '%s\n' "$lan_cidrs" | xargs 2>/dev/null || printf '')"
  if [[ -z "$lan_cidrs" ]]; then
    lan_cidrs="127.0.0.1/32"
  fi

  local caddy_auth_hash
  caddy_auth_hash="$(unescape_env_value_from_compose "${CADDY_BASIC_AUTH_HASH}")"

  if ! is_bcrypt_hash "$caddy_auth_hash"; then
    warn "CADDY_BASIC_AUTH_HASH does not appear to be a valid bcrypt string; use --rotate-caddy-auth to regenerate."
  fi

  # Prefer normalized suffix if set via .env; fall back to computed value
  local domain_suffix="${ARR_DOMAIN_SUFFIX_CLEAN}"

  local -a services=(
    "qbittorrent 8080"
    "sonarr ${SONARR_PORT}"
    "radarr ${RADARR_PORT}"
    "prowlarr ${PROWLARR_PORT}"
    "bazarr ${BAZARR_PORT}"
    "flaresolverr ${FLARESOLVERR_PORT}"
  )

  local caddyfile_content
  caddyfile_content="$({
    printf '# Auto-generated by arrstack.sh\n'
    printf '# Adjust LAN CIDRs or add TLS settings via arrconf/userconf.sh overrides.\n\n'
    printf '{\n'
    printf '  admin off\n'
    printf '}\n\n'

    # Plain HTTP health endpoint for container healthcheck
    printf ':80 {\n'
    printf '    respond /healthz 200 {\n'
    printf '        body "ok"\n'
    printf '    }\n'
    printf '}\n\n'

    local entry name port host
    for entry in "${services[@]}"; do
      name="${entry%% *}"
      port="${entry##* }"
      host="${name}.${domain_suffix}"
      printf '%s {\n' "$host"
      printf '    tls internal\n'
      printf '    @lan remote_ip %s\n' "$lan_cidrs"
      printf '    handle @lan {\n'
      printf '        reverse_proxy 127.0.0.1:%s\n' "$port"
      printf '    }\n'
      printf '    handle {\n'
      printf '        basic_auth * {\n'
      printf '            %s %s\n' "$CADDY_BASIC_AUTH_USER" "$caddy_auth_hash"
      printf '        }\n'
      printf '        reverse_proxy 127.0.0.1:%s\n' "$port"
      printf '    }\n'
      printf '}\n\n'
    done
  })"

  atomic_write "$caddyfile" "$caddyfile_content" "$NONSECRET_FILE_MODE"

  if ! grep -Fq "${CADDY_BASIC_AUTH_USER}" "$caddyfile"; then
    warn "Caddyfile is missing the configured Basic Auth user; verify CADDY_BASIC_AUTH_USER"
  fi

  if ! grep -qE '\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}' "$caddyfile"; then
    warn "Caddyfile bcrypt string may be invalid; hash regeneration fixes this (use --rotate-caddy-auth)."
  fi
}

run_one_time_migrations() {
  local legacy_auth="${ARR_DOCKER_DIR}/gluetun/auth/config.toml"

  if [[ -f "$legacy_auth" ]]; then
    local legacy_backup
    legacy_backup="${legacy_auth}.bak.$(date +%s)"
    if mv "$legacy_auth" "$legacy_backup" 2>/dev/null; then
      warn "Removed legacy Gluetun auth config; backup saved to ${legacy_backup}"
    else
      rm -f "$legacy_auth" 2>/dev/null || true
      warn "Removed legacy Gluetun auth config"
    fi
  fi

  if [[ -f "$ARR_ENV_FILE" ]]; then
    local env_backup_created=0
    local env_backup_path=""

    ensure_env_backup() {
      if ((env_backup_created == 0)); then
        env_backup_path="${ARR_ENV_FILE}.bak.$(date +%s)"
        if cp "$ARR_ENV_FILE" "$env_backup_path" 2>/dev/null; then
          chmod 600 "$env_backup_path" 2>/dev/null || true
          warn "Backed up existing .env to ${env_backup_path} before applying migrations"
          env_backup_created=1
        else
          warn "Unable to create backup of ${ARR_ENV_FILE} before migrations"
        fi
      fi
    }

    local existing_line existing_value existing_unescaped fixed_value escaped_fixed sed_value

    existing_line="$(grep '^OPENVPN_USER=' "$ARR_ENV_FILE" | head -n1 || true)"
    if [[ -n "$existing_line" ]]; then
      existing_value="${existing_line#OPENVPN_USER=}"
      existing_unescaped="$(unescape_env_value_from_compose "$existing_value")"
      fixed_value="${existing_unescaped%+pmp}+pmp"
      if [[ "$fixed_value" != "$existing_unescaped" ]]; then
        ensure_env_backup
        escaped_fixed="$(escape_env_value_for_compose "$fixed_value")"
        sed_value="$(escape_sed_replacement "$escaped_fixed")"
        portable_sed "s|^OPENVPN_USER=.*$|OPENVPN_USER=${sed_value}|" "$ARR_ENV_FILE"
        warn "OPENVPN_USER was missing '+pmp'; updated automatically in ${ARR_ENV_FILE}"
      fi
    fi

    existing_line="$(grep '^CADDY_BASIC_AUTH_HASH=' "$ARR_ENV_FILE" | head -n1 || true)"
    if [[ -n "$existing_line" ]]; then
      existing_value="${existing_line#CADDY_BASIC_AUTH_HASH=}"
      existing_unescaped="$(unescape_env_value_from_compose "$existing_value")"
      escaped_fixed="$(escape_env_value_for_compose "$existing_unescaped")"
      if [[ "$existing_value" != "$escaped_fixed" ]]; then
        ensure_env_backup
        sed_value="$(escape_sed_replacement "$escaped_fixed")"
        portable_sed "s|^CADDY_BASIC_AUTH_HASH=.*$|CADDY_BASIC_AUTH_HASH=${sed_value}|" "$ARR_ENV_FILE"
        warn "Escaped dollar signs in CADDY_BASIC_AUTH_HASH for Docker Compose compatibility"
      fi
    fi

    unset -f ensure_env_backup || true
  fi
}

sync_gluetun_library() {
  msg "📚 Syncing Gluetun helper library"

  ensure_dir "$ARR_STACK_DIR/scripts"
  ensure_dir "$ARR_STACK_DIR/scripts/lib"
  chmod 755 "$ARR_STACK_DIR/scripts" 2>/dev/null || true
  chmod 755 "$ARR_STACK_DIR/scripts/lib" 2>/dev/null || true

  cp "${REPO_ROOT}/scripts/lib/gluetun.sh" "$ARR_STACK_DIR/scripts/lib/gluetun.sh"
  chmod 644 "$ARR_STACK_DIR/scripts/lib/gluetun.sh"
}

write_port_sync_script() {
  msg "📜 Writing port sync script"

  ensure_dir "$ARR_STACK_DIR/scripts"

  cat >"$ARR_STACK_DIR/scripts/port-sync.sh" <<'SCRIPT'
#!/bin/sh
set -eu

log() {
    printf '[%s] [port-sync] %s\n' "$(date '+%Y-%m-%dT%H:%M:%S')" "$1" >&2
}

ensure_curl() {
    if command -v curl >/dev/null 2>&1; then
        return
    fi

    log "curl not found, attempting to install..."

    if command -v apk >/dev/null 2>&1; then
        if apk update >/dev/null 2>&1 && apk add --no-cache curl ca-certificates >/dev/null 2>&1; then
            log "curl installed successfully"
            return
        fi
        log "warn: apk update/add failed; retrying simple add..."
        if apk add --no-cache curl >/dev/null 2>&1; then
            log "curl installed successfully (without update)"
            return
        fi
    fi

    if command -v wget >/dev/null 2>&1; then
        log "warn: curl unavailable; using wget shim as fallback"
        curl() {
            set -- "$@"
            headers=""
            url=""
            post_data=""
            method="GET"
            load_cookies=""
            save_cookies=""
            output_target="-"
            newline_store="$(printf '\n_')"
            newline="${newline_store%_}"

            while [ $# -gt 0 ]; do
                case "$1" in
                    -H)
                        [ $# -ge 2 ] || break
                        if [ -z "$headers" ]; then
                            headers="$2"
                        else
                            headers="${headers}${newline}$2"
                        fi
                        shift 2
                        ;;
                    -b)
                        [ $# -ge 2 ] || break
                        load_cookies="$2"
                        shift 2
                        ;;
                    -c)
                        [ $# -ge 2 ] || break
                        save_cookies="$2"
                        shift 2
                        ;;
                    --data|-d|--data-raw)
                        [ $# -ge 2 ] || break
                        method="POST"
                        post_data="$2"
                        shift 2
                        ;;
                    --data-urlencode)
                        [ $# -ge 2 ] || break
                        method="POST"
                        if [ -n "$post_data" ]; then
                            post_data="${post_data}&$2"
                        else
                            post_data="$2"
                        fi
                        shift 2
                        ;;
                    --output|-o)
                        [ $# -ge 2 ] || break
                        output_target="$2"
                        shift 2
                        ;;
                    --max-time)
                        shift
                        [ $# -gt 0 ] && shift
                        ;;
                    -fsS|-f|-s|-S|--silent|--show-error)
                        shift
                        ;;
                    -* )
                        shift
                        ;;
                    *)
                        if [ -z "$url" ]; then
                            url="$1"
                        fi
                        shift
                        ;;
                esac
            done

            if [ -z "$url" ]; then
                return 22
            fi

            set -- --quiet
            if [ "$output_target" = "-" ]; then
                set -- "$@" -O -
            else
                set -- "$@" -O "$output_target"
            fi
            if [ "$method" = "POST" ]; then
                set -- "$@" --post-data="$post_data"
            fi
            if [ -n "$load_cookies" ]; then
                set -- "$@" --load-cookies="$load_cookies"
            fi
            if [ -n "$save_cookies" ]; then
                set -- "$@" --save-cookies="$save_cookies"
            fi

            old_ifs=$IFS
            IFS="$newline"
            for header in $headers; do
                [ -n "$header" ] || continue
                set -- "$@" --header="$header"
            done
            IFS=$old_ifs
            unset newline_store newline

            set -- "$@" "$url"
            wget "$@"
        }
        export -f curl 2>/dev/null || true
        return
    fi

    log "ERROR: Neither curl nor wget available, and installation failed"
    exit 1
}

wait_for_gluetun() {
    local attempts=0
    local max_attempts=8
    local sleep_seconds=2
    local status_url="${GLUETUN_ADDR}/v1/openvpn/status"
    local response=""

    log "Waiting for Gluetun OpenVPN status endpoint (max ~$((max_attempts * sleep_seconds))s)..."

    while [ $attempts -lt $max_attempts ]; do
        if [ -n "$GLUETUN_API_KEY" ]; then
            response="$(curl -fsS --max-time 3 -H "X-Api-Key: $GLUETUN_API_KEY" "$status_url" 2>/dev/null || true)"
        else
            response="$(curl -fsS --max-time 3 "$status_url" 2>/dev/null || true)"
        fi

        if [ -n "$response" ]; then
            if printf '%s' "$response" | grep -q '"status"[[:space:]]*:[[:space:]]*"connected"'; then
                log "Gluetun reports OpenVPN status: connected"
                return 0
            fi

            if printf '%s' "$response" | grep -q '"status"[[:space:]]*:[[:space:]]*"completed"'; then
                log "Gluetun OpenVPN status endpoint is responding"
                return 0
            fi
        fi

        attempts=$((attempts + 1))
        if [ $attempts -lt $max_attempts ]; then
            sleep "$sleep_seconds"
        fi
    done

    log "ERROR: Gluetun OpenVPN status endpoint unavailable after ~$((max_attempts * sleep_seconds))s"
    return 1
}

: "${GLUETUN_ADDR:=http://127.0.0.1:8000}"
: "${GLUETUN_API_KEY:=}"
: "${QBITTORRENT_ADDR:=http://127.0.0.1:8080}"
: "${UPDATE_INTERVAL:=300}"
: "${BACKOFF_MAX:=900}"
: "${QBT_USER:=}"
: "${QBT_PASS:=}"
: "${VPN_PORT_FORWARDING_STATUS_FILE:=}"

COOKIE_JAR="/tmp/qbt.cookies"

if [ ! -f "$COOKIE_JAR" ]; then
    if ! touch "$COOKIE_JAR" 2>/dev/null; then
        log 'warn: unable to create cookie jar; continuing without persistence'
    fi
fi
chmod 600 "$COOKIE_JAR" 2>/dev/null || true

ensure_curl

api_get() {
    local path="$1"
    local url="${GLUETUN_ADDR}${path}"

    if [ -n "$GLUETUN_API_KEY" ]; then
        if ! curl -fsS --max-time 5 -H "X-Api-Key: $GLUETUN_API_KEY" "$url"; then
            log "ERROR: API call failed to $url (with API key)"
            return 1
        fi
    else
        log "WARNING: No API key provided, trying without authentication"
        if ! curl -fsS --max-time 5 "$url"; then
            log "ERROR: API call failed to $url (without API key)"
            return 1
        fi
    fi
}

get_pf() {
    local port=""

    if [ -n "$VPN_PORT_FORWARDING_STATUS_FILE" ] && [ -r "$VPN_PORT_FORWARDING_STATUS_FILE" ]; then
        port="$(awk 'NF {print $1; exit}' "$VPN_PORT_FORWARDING_STATUS_FILE" 2>/dev/null || printf '')"
        if printf '%s' "$port" | grep -Eq '^[0-9]+$'; then
            printf '%s' "$port"
            return 0
        fi
    fi

    local response=""
    response="$(api_get '/v1/forwardedport' || true)"
    if [ -n "$response" ]; then
        port="$(printf '%s' "$response" | tr -d '[:space:]')"
        if printf '%s' "$port" | grep -Eq '^[0-9]+$'; then
            printf '%s' "$port"
            return 0
        fi
    fi

    response="$(api_get '/v1/openvpn/portforwarded' || true)"
    if [ -n "$response" ]; then
        port="$(printf '%s
' "$response" | awk -F'"port":' 'NF>1 {sub(/[^0-9].*/, "", $2); if ($2 != "") {print $2; exit}}')"
        if printf '%s' "$port" | grep -Eq '^[0-9]+$'; then
            printf '%s' "$port"
            return 0
        fi
    fi

    return 1
}

login_qbt() {
    if [ -z "$QBT_USER" ] || [ -z "$QBT_PASS" ]; then
        return 0
    fi

    if curl -fsS --max-time 5 -c "$COOKIE_JAR"         --data-urlencode "username=${QBT_USER}"         --data-urlencode "password=${QBT_PASS}"         "${QBITTORRENT_ADDR}/api/v2/auth/login" >/dev/null 2>&1; then
        return 0
    fi

    rm -f "$COOKIE_JAR"
    log 'warn: login failed; relying on localhost bypass (ensure LocalHostAuth=true)'
    return 0
}

ensure_qbt_session() {
    if [ -s "$COOKIE_JAR" ]; then
        return 0
    fi

    login_qbt
}

get_qbt_listen_port() {
    local response=""

    response="$(curl -fsS --max-time 5 -b "$COOKIE_JAR" "${QBITTORRENT_ADDR}/api/v2/app/preferences" 2>/dev/null || true)"
    if [ -z "$response" ]; then
        response="$(curl -fsS --max-time 5 "${QBITTORRENT_ADDR}/api/v2/app/preferences" 2>/dev/null || true)"
    fi

    if [ -z "$response" ]; then
        rm -f "$COOKIE_JAR"
        return 1
    fi

    printf '%s
' "$response" | tr -d ' 

' | awk -F'"listen_port":' 'NF>1 {sub(/[^0-9].*/, "", $2); if ($2 != "") {print $2; exit}}'
    return 0
}

set_qbt_listen_port() {
    local port="$1"
    local payload="json={"listen_port":${port},"random_port":false}"

    if curl -fsS --max-time 5 -b "$COOKIE_JAR"         --data-raw "$payload" "${QBITTORRENT_ADDR}/api/v2/app/setPreferences" >/dev/null 2>&1; then
        return 0
    fi

    if curl -fsS --max-time 5         --data-raw "$payload" "${QBITTORRENT_ADDR}/api/v2/app/setPreferences" >/dev/null 2>&1; then
        return 0
    fi

    rm -f "$COOKIE_JAR"
    return 1
}

cleanup() {
    rm -f "$COOKIE_JAR"
}

trap 'cleanup' EXIT INT TERM

# Wait for Gluetun to be ready
if ! wait_for_gluetun; then
    log "FATAL: Cannot proceed without Gluetun API"
    exit 1
fi

log "starting port-sync against ${GLUETUN_ADDR} -> ${QBITTORRENT_ADDR}"
ensure_qbt_session || true

last_reported=""
backoff=30
consecutive_failures=0
max_consecutive_failures=5
extended_backoff=300  # 5 minutes

while :; do
    pf="$(get_pf || echo 0)"

    if [ -z "$pf" ] || [ "$pf" = "0" ]; then
        consecutive_failures=$((consecutive_failures + 1))

        if [ $consecutive_failures -ge $max_consecutive_failures ]; then
            log "Multiple failures detected, using extended backoff (${extended_backoff}s)"
            sleep "$extended_backoff"
            consecutive_failures=0
            backoff=30
        else
            sleep "$backoff"
            backoff=$((backoff * 2))
            if [ $backoff -gt "$BACKOFF_MAX" ]; then
                backoff="$BACKOFF_MAX"
            fi
        fi

        continue
    fi

    consecutive_failures=0
    if [ "$pf" != "$last_reported" ]; then
        log "Updating qBittorrent listen port to $pf"
        if set_qbt_listen_port "$pf"; then
            last_reported="$pf"
            backoff=30
        else
            log "warn: failed to update qBittorrent port"
        fi
    fi

    sleep "$UPDATE_INTERVAL"
done
SCRIPT

  chmod 755 "$ARR_STACK_DIR/scripts/port-sync.sh"

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

update_env_entry() {
  local key="$1"
  local value="$2"
  local tmp

  tmp="$(mktemp "${ENV_FILE}.XXXXXX.tmp")" || die "Failed to create temp file for ${key}"
  chmod 600 "$tmp" 2>/dev/null || true

  if sed "s|^${key}=.*|${key}=${value}|" "$ENV_FILE" >"$tmp" 2>/dev/null; then
    mv "$tmp" "$ENV_FILE"
  else
    rm -f "$tmp"
    die "Failed to update ${key} in ${ENV_FILE}"
  fi
}

if [[ ! -f "$ENV_FILE" ]]; then
  die ".env file not found at ${ENV_FILE}"
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

  current_image="$(grep "^${var_name}=" "$ENV_FILE" | cut -d= -f2- || true)"

  if [[ -z "$current_image" ]]; then
    warn "  No ${var_name} entry found in .env; skipping"
    continue
  fi

  if ! docker manifest inspect "$current_image" >/dev/null 2>&1; then
    warn "  Current tag doesn't exist: $current_image"
    latest_image="${base_image}:latest"
    msg "  Updating to: $latest_image"
    update_env_entry "$var_name" "$latest_image"
  else
    msg "  ✅ Current tag is valid: $current_image"
  fi
done

msg "✅ Version fixes complete"
msg "Run './arrstack.sh --yes' to apply changes"
FIXVER

  chmod 755 "$ARR_STACK_DIR/scripts/fix-versions.sh"

}

write_qbt_helper_script() {
  msg "🧰 Writing qBittorrent helper script"

  ensure_dir "$ARR_STACK_DIR/scripts"

  cp "${REPO_ROOT}/scripts/qbt-helper.sh" "$ARR_STACK_DIR/scripts/qbt-helper.sh"
  chmod 755 "$ARR_STACK_DIR/scripts/qbt-helper.sh"

  msg "  qBittorrent helper: ${ARR_STACK_DIR}/scripts/qbt-helper.sh"
}

write_qbt_config() {
  msg "🧩 Writing qBittorrent config"
  local config_dir="${ARR_DOCKER_DIR}/qbittorrent"
  local runtime_dir="${config_dir}/qBittorrent"
  local conf_file="${config_dir}/qBittorrent.conf"
  local legacy_conf="${runtime_dir}/qBittorrent.conf"

  ensure_dir "$config_dir"
  ensure_dir "$runtime_dir"

  if [[ -f "$legacy_conf" && ! -f "$conf_file" ]]; then
    msg "  Migrating legacy config from ${legacy_conf}"
    mv "$legacy_conf" "$conf_file"
    chmod 600 "$conf_file"
  fi

  if [[ -f "$legacy_conf" ]]; then
    msg "  Removing unused legacy config at ${legacy_conf}"
    rm -f "$legacy_conf"
  fi
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
WebUI\RootFolder=/config/vuetorrent
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
  set_qbt_conf_value "$conf_file" 'WebUI\RootFolder' '/config/vuetorrent'
  set_qbt_conf_value "$conf_file" 'WebUI\ServerDomains' '*'
  set_qbt_conf_value "$conf_file" 'WebUI\LocalHostAuth' 'true'
  set_qbt_conf_value "$conf_file" 'WebUI\AuthSubnetWhitelistEnabled' 'true'
  set_qbt_conf_value "$conf_file" 'WebUI\CSRFProtection' 'true'
  set_qbt_conf_value "$conf_file" 'WebUI\ClickjackingProtection' 'true'
  set_qbt_conf_value "$conf_file" 'WebUI\HostHeaderValidation' 'true'
  set_qbt_conf_value "$conf_file" 'WebUI\AuthSubnetWhitelist' "$auth_whitelist"
}

install_vuetorrent() {
  msg "🎨 Installing VueTorrent WebUI..."

  local vuetorrent_dir="${ARR_DOCKER_DIR}/qbittorrent/vuetorrent"
  local releases_url="https://api.github.com/repos/VueTorrent/VueTorrent/releases/latest"

  ensure_dir "$vuetorrent_dir"

  local download_url=""
  download_url=$(curl -sL "$releases_url" | jq -r '.assets[] | select(.name == "vuetorrent.zip") | .browser_download_url' 2>/dev/null || printf '')

  if [[ -z "$download_url" ]]; then
    warn "Could not find VueTorrent download URL, skipping..."
    return 0
  fi

  if ! command -v unzip >/dev/null 2>&1; then
    warn "unzip command not available; skipping VueTorrent installation"
    return 0
  fi

  local temp_zip="/tmp/vuetorrent-$$.zip"
  if ! curl -sL "$download_url" -o "$temp_zip"; then
    rm -f "$temp_zip"
    warn "  Failed to download VueTorrent, continuing without it"
    return 0
  fi

  local temp_extract=""
  temp_extract="$(mktemp -d "/tmp/vuetorrent.XXXX" 2>/dev/null || printf '')"
  if [[ -z "$temp_extract" ]]; then
    rm -f "$temp_zip"
    warn "  Failed to create temporary directory for VueTorrent, continuing without it"
    return 0
  fi

  if ! unzip -qo "$temp_zip" -d "$temp_extract"; then
    rm -f "$temp_zip"
    rm -rf "$temp_extract"
    warn "  Failed to extract VueTorrent archive, continuing without it"
    return 0
  fi

  rm -f "$temp_zip"

  local source_root="$temp_extract"
  if [[ ! -f "$source_root/index.html" ]]; then
    local nested_index=""
    nested_index="$(find "$temp_extract" -type f -name 'index.html' -print -quit 2>/dev/null || printf '')"
    if [[ -n "$nested_index" ]]; then
      source_root="$(dirname "$nested_index")"
    fi
  fi

  if [[ ! -f "$source_root/index.html" ]]; then
    rm -rf "$temp_extract"
    warn "  VueTorrent archive did not contain an index.html, skipping installation"
    return 0
  fi

  find "$vuetorrent_dir" -mindepth 1 -exec rm -rf {} + 2>/dev/null || true

  ensure_dir "$vuetorrent_dir"

  local copy_failed=0
  shopt -s dotglob nullglob
  if ! cp -a "$source_root"/* "$vuetorrent_dir"/ 2>/dev/null; then
    copy_failed=1
  fi
  shopt -u dotglob nullglob

  rm -rf "$temp_extract"

  if ((copy_failed)); then
    warn "  Failed to install VueTorrent files, continuing without it"
    return 0
  fi

  chown -R "${PUID}:${PGID}" "$vuetorrent_dir" 2>/dev/null || true
  # macOS ships BSD xargs which lacks -r (see POSIX spec)
  local -a stale_containers=()
  while IFS= read -r container_id; do
    stale_containers+=("$container_id")
  done < <(docker ps -a --filter "label=com.docker.compose.project=arrstack" --format "{{.ID}}" 2>/dev/null)

  if ((${#stale_containers[@]} > 0)); then
    docker rm -f "${stale_containers[@]}" >/dev/null 2>&1 || true
  fi
  msg "  ✅ VueTorrent installed successfully"
}

safe_cleanup() {
  msg "🧹 Safely stopping existing services..."

  if [[ -f "$ARR_STACK_DIR/docker-compose.yml" ]]; then
    "${DOCKER_COMPOSE_CMD[@]}" stop 2>/dev/null || true
    sleep 5
    "${DOCKER_COMPOSE_CMD[@]}" down --remove-orphans 2>/dev/null || true
  fi

  local temp_files=(
    "$ARR_DOCKER_DIR/gluetun/forwarded_port"
    "$ARR_DOCKER_DIR/gluetun/forwarded_port.json"
    "$ARR_DOCKER_DIR/gluetun/port-forwarding.json"
    "$ARR_DOCKER_DIR/qbittorrent/qBittorrent/BT_backup/.cleaning"
  )

  local file
  for file in "${temp_files[@]}"; do
    rm -f "$file" 2>/dev/null || true
  done

  docker ps -a --filter "label=com.docker.compose.project=arrstack" --format "{{.ID}}" \
    | xargs -r docker rm -f 2>/dev/null || true
}

update_env_image_var() {
  local var_name="$1"
  local new_value="$2"

  if [[ -z "$var_name" || -z "$new_value" ]]; then
    return
  fi

  printf -v "$var_name" '%s' "$new_value"

  if [[ -f "$ARR_ENV_FILE" ]] && grep -q "^${var_name}=" "$ARR_ENV_FILE"; then
    portable_sed "s|^${var_name}=.*|${var_name}=${new_value}|" "$ARR_ENV_FILE"
  fi
}

check_image_exists() {
  local image="$1"

  if docker manifest inspect "$image" >/dev/null 2>&1; then
    return 0
  fi

  if docker image inspect "$image" >/dev/null 2>&1; then
    return 0
  fi

  return 1
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
    CADDY_IMAGE
    PORT_SYNC_IMAGE
  )

  local failed_images=()

  for var_name in "${image_vars[@]}"; do
    local image="${!var_name:-}"
    [[ -z "$image" ]] && continue

    msg "  Checking $image..."

    # Check via manifest (remote) or local cache without pulling layers
    if check_image_exists "$image"; then
      msg "  ✅ Valid: $image"
      continue
    fi

    # If failed, try fallback for LinuxServer images only
    local base_image="$image"
    local tag=""
    if [[ "$image" == *:* ]]; then
      base_image="${image%:*}"
      tag="${image##*:}"
    fi

    if [[ "$tag" != "latest" && "$base_image" == lscr.io/linuxserver/* ]]; then
      local latest_image="${base_image}:latest"
      msg "    Trying fallback: $latest_image"

      if check_image_exists "$latest_image"; then
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
        warn "  ⚠️ Could not validate: $image"
        failed_images+=("$image")
      fi
    else
      warn "  ⚠️ Could not validate: $image"
      failed_images+=("$image")
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
  if output="$("${DOCKER_COMPOSE_CMD[@]}" up -d "$service" 2>&1)"; then
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

  while ((attempts < 60)); do
    detected="$(docker logs qbittorrent 2>&1 | grep -i "temporary password" | tail -1 | sed 's/.*temporary password[^:]*: *//' | awk '{print $1}' || true)"
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

wait_for_vpn_connection() {
  local max_wait="${1:-60}"
  local elapsed=0
  local check_interval=2
  local host="${LOCALHOST_IP:-localhost}"
  local vpn_status_url
  local public_ip_url

  if [[ $host == *:* && $host != [* ]]; then
    vpn_status_url="http://[$host]:${GLUETUN_CONTROL_PORT}/v1/openvpn/status"
    public_ip_url="http://[$host]:${GLUETUN_CONTROL_PORT}/v1/publicip/ip"
  else
    vpn_status_url="http://${host}:${GLUETUN_CONTROL_PORT}/v1/openvpn/status"
    public_ip_url="http://${host}:${GLUETUN_CONTROL_PORT}/v1/publicip/ip"
  fi

  msg "Waiting for VPN connection (max ${max_wait}s)..."

  while ((elapsed < max_wait)); do
    local health
    health="$(docker inspect gluetun --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' 2>/dev/null || true)"

    if [[ "$health" == "healthy" ]]; then
      msg "  ✅ Gluetun is healthy"
      return 0
    fi

    local -a curl_cmd=(curl -fsS --max-time 5)
    if [[ -n "${GLUETUN_API_KEY:-}" ]]; then
      curl_cmd+=(-H "X-Api-Key: ${GLUETUN_API_KEY}")
    fi

    if "${curl_cmd[@]}" "$vpn_status_url" >/dev/null 2>&1; then
      msg "  ✅ VPN API responding"
      local ip=""
      ip="$("${curl_cmd[@]}" "$public_ip_url" 2>/dev/null || true)"
      if [[ -n "$ip" ]]; then
        msg "  🌐 Public IP: $ip"
      fi
      return 0
    fi

    sleep "$check_interval"
    elapsed=$((elapsed + check_interval))
  done

  warn "VPN connection timeout after ${max_wait}s"
  return 1
}

show_service_status() {
  msg "Service status summary:"
  local service
  local -a services=(gluetun qbittorrent sonarr radarr prowlarr bazarr flaresolverr caddy)
  if [[ "${ENABLE_LOCAL_DNS:-1}" -eq 1 ]]; then
    services+=(local_dns)
  fi
  services+=(port-sync)

  local service
  for service in "${services[@]}"; do
    local status
    status="$(docker inspect "$service" --format '{{.State.Status}}' 2>/dev/null || echo "not found")"
    printf '  %-15s: %s\n' "$service" "$status"
  done
}

start_stack() {
  msg "🚀 Starting services"

  cd "$ARR_STACK_DIR" || die "Failed to change to ${ARR_STACK_DIR}"

  safe_cleanup

  validate_images

  install_vuetorrent

  local gluetun_attempts=0
  local gluetun_max_attempts=3
  local gluetun_started=0
  local output=""

  while ((gluetun_attempts < gluetun_max_attempts)); do
    local attempt=$((gluetun_attempts + 1))
    msg "Starting Gluetun VPN container (attempt ${attempt}/${gluetun_max_attempts})..."

    if output="$("${DOCKER_COMPOSE_CMD[@]}" up -d gluetun 2>&1)"; then
      if [[ -n "$output" ]]; then
        while IFS= read -r line; do
          printf '  %s\n' "$line"
        done <<<"$output"
      fi
      gluetun_started=1
      break
    fi

    warn "Failed to start Gluetun${output:+:}"
    if [[ -n "$output" ]]; then
      while IFS= read -r line; do
        printf '  %s\n' "$line"
      done <<<"$output"
    fi

    gluetun_attempts=$((gluetun_attempts + 1))
    if ((gluetun_attempts < gluetun_max_attempts)); then
      warn "Failed to start Gluetun, retrying in 10s..."
      sleep 10
    else
      warn "Failed to start Gluetun after ${gluetun_max_attempts} attempts"
    fi
  done

  if ((gluetun_started == 0)); then
    warn "Gluetun may not have started successfully"
  fi

  msg "Waiting for VPN connection..."
  local vpn_wait_levels=(60 120 180)
  local vpn_ready=0

  local max_wait
  for max_wait in "${vpn_wait_levels[@]}"; do
    if wait_for_vpn_connection "$max_wait"; then
      vpn_ready=1
      break
    fi

    warn "VPN not ready after ${max_wait}s, extending timeout..."
  done

  if ((vpn_ready == 0)); then
    warn "VPN connection not verified after extended wait"
    warn "Services will start anyway with potential connectivity issues"
  fi

  msg "Checking port forwarding status..."
  local pf_port
  pf_port="$(fetch_forwarded_port 2>/dev/null || printf '0')"

  if [[ -z "$pf_port" || "$pf_port" == "0" ]]; then
    warn "================================================"
    warn "Port forwarding is not active yet."
    warn "This is normal - it can take a few minutes."
    warn "================================================"
  else
    msg "✅ Port forwarding active: Port $pf_port"
  fi

  local services=()
  if [[ "${ENABLE_LOCAL_DNS:-1}" -eq 1 ]]; then
    services+=(local_dns)
  fi
  services+=(caddy qbittorrent sonarr radarr prowlarr bazarr flaresolverr)
  local service
  local qb_started=0
  local domain_suffix="${ARR_DOMAIN_SUFFIX_CLEAN}"

  for service in "${services[@]}"; do
    msg "Starting $service..."
    local service_started=0
    local start_output=""

    if start_output="$("${DOCKER_COMPOSE_CMD[@]}" up -d "$service" 2>&1)"; then
      if [[ -n "$start_output" ]]; then
        while IFS= read -r line; do
          printf '  %s\n' "$line"
        done <<<"$start_output"
      fi
      service_started=1
    else
      warn "Failed to start $service with normal dependencies"
      if [[ -n "$start_output" ]]; then
        while IFS= read -r line; do
          printf '  %s\n' "$line"
        done <<<"$start_output"
      fi

      local fallback_output=""
      if fallback_output="$("${DOCKER_COMPOSE_CMD[@]}" up -d --no-deps "$service" 2>&1)"; then
        msg "  Started $service without dependency checks"
        if [[ -n "$fallback_output" ]]; then
          while IFS= read -r line; do
            printf '    %s\n' "$line"
          done <<<"$fallback_output"
        fi
        service_started=1
      else
        warn "Failed to start $service even without dependencies, skipping..."
        if [[ -n "$fallback_output" ]]; then
          while IFS= read -r line; do
            printf '    %s\n' "$line"
          done <<<"$fallback_output"
        fi
        continue
      fi
    fi

    if [[ "$service" == "qbittorrent" && $service_started -eq 1 ]]; then
      qb_started=1
    fi

    sleep 3
  done

  if ((qb_started)); then
    sync_qbt_password_from_logs
  fi

  msg "Starting port synchronization..."
  local port_sync_output=""
  if port_sync_output="$("${DOCKER_COMPOSE_CMD[@]}" up -d port-sync 2>&1)"; then
    if [[ -n "$port_sync_output" ]]; then
      while IFS= read -r line; do
        printf '  %s\n' "$line"
      done <<<"$port_sync_output"
    fi
  else
    warn "Port-sync failed to start (non-critical)"
    if [[ -n "$port_sync_output" ]]; then
      while IFS= read -r line; do
        printf '  %s\n' "$line"
      done <<<"$port_sync_output"
    fi
  fi

  msg "Services started - they may take a minute to be fully ready"
  show_service_status
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

unescape_env_value_from_compose() {
  local value="${1-}"
  value="${value//\$\$/\$}"
  printf '%s' "$value"
}

load_env_file() {
  local file="$1"
  local line key value

  while IFS= read -r line || [[ -n "$line" ]]; do
    case "$line" in
      ''|\#*) continue ;;
    esac
    if [[ "$line" != *=* ]]; then
      continue
    fi
    key="${line%%=*}"
    value="${line#*=}"
    value="${value%$'\r'}"
    value="$(unescape_env_value_from_compose "$value")"
    printf -v "$key" '%s' "$value"
    export "$key"
  done <"$file"
}

if [[ -f "$ARR_ENV_FILE" ]]; then
  load_env_file "$ARR_ENV_FILE"
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

GLUETUN_STATUS="$(docker inspect gluetun --format '{{.State.Status}}' 2>/dev/null || echo "not found")"
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
PUBLIC_IP="$(fetch_public_ip)"

if [[ -n "$PUBLIC_IP" ]]; then
  msg "✅ VPN Connected: $PUBLIC_IP"
else
  warn "VPN not connected"
fi

msg "Checking port forwarding..."
PF_PORT="$(fetch_forwarded_port)"

if [[ "$PF_PORT" != "0" ]]; then
  msg "✅ Port forwarding active: Port $PF_PORT"
else
  warn "Port forwarding not working"
  warn "Attempting fix: Restarting Gluetun..."
  if docker restart gluetun >/dev/null 2>&1; then
    sleep 60
    PF_PORT="$(fetch_forwarded_port)"
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
  STATUS="$(docker inspect "$service" --format '{{.State.Status}}' 2>/dev/null || echo "not found")"
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
  chmod 600 "$diag_tmp" 2>/dev/null || true
  local diag_dir_escaped
  diag_dir_escaped=${ARR_STACK_DIR//\\/\\\\}
  diag_dir_escaped=${diag_dir_escaped//&/\&}
  diag_dir_escaped=${diag_dir_escaped//|/\|}
  sed -e "s|__ARR_STACK_DIR__|${diag_dir_escaped}|g" "$diag_script" >"$diag_tmp"
  mv "$diag_tmp" "$diag_script"
  chmod 755 "$diag_script"
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
  chmod 600 "$tmp_file" 2>/dev/null || true

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

  chmod "$SECRET_FILE_MODE" "$aliases_file"
  cp "$aliases_file" "$configured_template"
  chmod "$NONSECRET_FILE_MODE" "$configured_template" 2>/dev/null || true
  msg "✅ Helper aliases written to: $aliases_file"
  msg "   Source them with: source $aliases_file"
  msg "   Repo copy updated: $configured_template"
}

configure_local_dns_entries() {
  msg "🧭 Ensuring local DNS entries exist for Caddy hostnames"

  local helper_script="${REPO_ROOT}/scripts/setup-lan-dns.sh"

  if [[ ! -f "$helper_script" ]]; then
    warn "Local DNS helper script ${helper_script} not found"
    return 0
  fi

  if [[ ! -x "$helper_script" ]]; then
    warn "Local DNS helper script is not executable; fix permissions on ${helper_script}"
    return 0
  fi

  if [[ -z "${LAN_IP:-}" ]]; then
    warn "LAN_IP is unset; skipping local DNS helper"
    return 0
  fi

  if ! "$helper_script" "$ARR_DOMAIN_SUFFIX_CLEAN" "$LAN_IP"; then
    warn "Local DNS helper was unable to update host mappings; rerun arrstack.sh with sudo to grant access"
    return 0
  fi

  msg "✅ Local DNS helper completed"
}

run_host_dns_setup() {
  if [[ "${ENABLE_LOCAL_DNS:-1}" -ne 1 ]]; then
    msg "Skipping host DNS setup (--setup-host-dns) because ENABLE_LOCAL_DNS=0"
    return 0
  fi

  if [[ -z "${LAN_IP:-}" || "${LAN_IP}" == "0.0.0.0" ]]; then
    warn "Cannot run --setup-host-dns automatically: LAN_IP is ${LAN_IP:-<unset>}"
    warn "Set LAN_IP to a specific address and rerun arrstack.sh --setup-host-dns once available."
    return 0
  fi

  local helper_script="${REPO_ROOT}/scripts/host-dns-setup.sh"

  if [[ ! -f "$helper_script" ]]; then
    warn "Host DNS helper script not found at ${helper_script}; skipping --setup-host-dns"
    return 0
  fi

  if [[ ! -x "$helper_script" ]]; then
    warn "Host DNS helper script is not executable; fix permissions on ${helper_script} or rerun manually."
    return 0
  fi

  msg "🔧 Running host DNS setup helper (--setup-host-dns)"

  if (
    cd "$ARR_STACK_DIR" 2>/dev/null &&
      LAN_IP="${LAN_IP}" \
      LAN_DOMAIN_SUFFIX="${LAN_DOMAIN_SUFFIX}" \
      UPSTREAM_DNS_1="${UPSTREAM_DNS_1}" \
      UPSTREAM_DNS_2="${UPSTREAM_DNS_2}" \
      bash "$helper_script"
  ); then
    msg "✅ Host DNS setup helper completed"
  else
    warn "Host DNS setup helper reported an error; review the output above or run scripts/host-dns-setup.sh manually."
  fi
}

show_summary() {

  msg "🎉 Setup complete!!"
  warn "Check these details and revisit the README for any manual steps you may need to perform from here"

  # Always show qBittorrent access information prominently
  local qbt_pass_msg=""
  if [[ -f "$ARR_ENV_FILE" ]]; then
    local configured_pass
    configured_pass="$(grep "^QBT_PASS=" "$ARR_ENV_FILE" | cut -d= -f2- || true)"
    if [[ -n "$configured_pass" && "$configured_pass" != "adminadmin" ]]; then
      qbt_pass_msg="Password: ${configured_pass} (from .env)"
    else
      qbt_pass_msg="Password: Check docker logs qbittorrent"
    fi
  fi

  local domain_suffix="${ARR_DOMAIN_SUFFIX_CLEAN}"

  local lan_ip_display="${LAN_IP:-<unset>}"
  local lan_dns_hint
  if [[ "${ENABLE_LOCAL_DNS:-1}" -eq 1 ]]; then
    lan_dns_hint="LAN DNS hint: ensure clients use ${lan_ip_display} as their DNS server so *.${domain_suffix} resolves via local dnsmasq."
  else
    lan_dns_hint="LAN DNS hint: point qbittorrent.${domain_suffix} to ${lan_ip_display} (via DNS or /etc/hosts)."
  fi

  cat <<QBT_INFO
================================================
qBittorrent Access Information:
================================================
LAN URL:  http://qbittorrent.${domain_suffix}/
HTTPS:    https://qbittorrent.${domain_suffix}/  (trust the Caddy internal CA)
Username: ${QBT_USER}
${qbt_pass_msg}

${lan_dns_hint}
Remote clients must supply the Caddy Basic Auth user '${CADDY_BASIC_AUTH_USER}' with the password saved in ${ARR_DOCKER_DIR}/caddy/credentials.
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
Access your services via Caddy:
  qBittorrent:   http://qbittorrent.${domain_suffix}
  Sonarr:        http://sonarr.${domain_suffix}
  Radarr:        http://radarr.${domain_suffix}
  Prowlarr:      http://prowlarr.${domain_suffix}
  Bazarr:        http://bazarr.${domain_suffix}
  FlareSolverr:  http://flaresolverr.${domain_suffix}

HTTPS is also available on the same hostnames (Caddy issues an internal certificate).

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
      --rotate-caddy-auth)
        FORCE_REGEN_CADDY_AUTH=1
        shift
        ;;
      --setup-host-dns)
        SETUP_HOST_DNS=1
        shift
        ;;
      --help | -h)
        help
        exit 0
        ;;
      *)
        die "Unknown option: $1"
        ;;
    esac
  done

  # Initialize logging first
  init_logging

  preflight
  # Check network requirements without blocking
  check_network_requirements
  mkdirs
  run_one_time_migrations
  safe_cleanup
  generate_api_key
  write_env
  write_compose
  write_gluetun_control_assets
  ensure_caddy_auth
  write_caddy_assets
  sync_gluetun_library
  write_port_sync_script
  write_qbt_helper_script
  write_qbt_config
  if ! write_aliases_file; then
    warn "Helper aliases file could not be generated"
  fi
  configure_local_dns_entries
  if [[ "${SETUP_HOST_DNS:-0}" -eq 1 ]]; then
    run_host_dns_setup
  fi
  verify_permissions
  install_aliases
  start_stack

  if [[ "${ENABLE_LOCAL_DNS:-1}" -eq 1 ]]; then
    local doctor_script="${REPO_ROOT}/scripts/doctor.sh"
    if [[ -x "$doctor_script" ]]; then
      msg "🩺 Running LAN diagnostics"
      if ! LAN_DOMAIN_SUFFIX="${LAN_DOMAIN_SUFFIX}" LAN_IP="${LAN_IP}" bash "$doctor_script"; then
        warn "LAN diagnostics reported issues"
      fi
    else
      warn "Doctor script missing or not executable at ${doctor_script}"
    fi
  fi

  msg "Installation completed at $(date)"
  show_summary
}

detect_shell_kind() {
  local kind="other"
  local omz=0

  if [ -n "${ZSH_VERSION:-}" ] || printf '%s' "${SHELL:-}" | grep -q 'zsh'; then
    kind="zsh"
    if [ -n "${ZSH:-}" ] && [ -d "$ZSH" ] && [ -f "$ZSH/oh-my-zsh.sh" ]; then
      omz=1
    elif [ -d "$HOME/.oh-my-zsh" ] && [ -f "$HOME/.oh-my-zsh/oh-my-zsh.sh" ]; then
      omz=1
    fi
  elif [ -n "${BASH_VERSION:-}" ] || printf '%s' "${SHELL:-}" | grep -q 'bash'; then
    kind="bash"
  fi

  printf '%s %s\n' "$kind" "$omz"
}

reload_shell_rc() {
  local force=0
  if [ "${1:-}" = "--force" ]; then
    force=1
  fi

  local kind=""
  local omz=""
  IFS=' ' read -r kind omz <<<"$(detect_shell_kind)"
  [ -n "$kind" ] || kind="other"
  [ -n "$omz" ] || omz=0

  if [ "$kind" = "zsh" ] && [ "$omz" -eq 1 ] && have_command omz; then
    if omz reload; then
      return 0
    fi
  fi

  local rc=""
  case "$kind" in
    zsh)
      [ -r "$HOME/.zshrc" ] && rc="$HOME/.zshrc"
      ;;
    bash)
      if [ -r "$HOME/.bashrc" ]; then
        rc="$HOME/.bashrc"
      elif [ -r "$HOME/.bash_profile" ]; then
        rc="$HOME/.bash_profile"
      elif [ -r "$HOME/.profile" ]; then
        rc="$HOME/.profile"
      fi
      ;;
    *)
      [ -r "$HOME/.profile" ] && rc="$HOME/.profile"
      ;;
  esac

  if [ -z "$rc" ] && [ "$kind" = "zsh" ] && [ "$omz" -eq 1 ]; then
    [ -r "$HOME/.zshrc" ] && rc="$HOME/.zshrc"
  fi

  if [ -n "$rc" ] && [ -r "$rc" ]; then
    # shellcheck disable=SC1090
    . "$rc" || return 1
    return 0
  fi

  if [ "$force" -eq 1 ]; then
    return 0
  fi

  return 1
}

if [[ "${ARRSTACK_NO_MAIN:-0}" != "1" ]]; then
  main "$@"
fi

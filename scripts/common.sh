# shellcheck shell=bash

: "${CYAN:=}"
: "${YELLOW:=}"
: "${RESET:=}"
: "${SECRET_FILE_MODE:=600}"
: "${NONSECRET_FILE_MODE:=600}"
: "${DATA_DIR_MODE:=700}"
: "${LOCK_FILE_MODE:=600}"

have_command() {
  command -v "$1" >/dev/null 2>&1
}

missing_commands() {
  local -a missing=()
  local cmd

  for cmd in "$@"; do
    if ! have_command "$cmd"; then
      missing+=("$cmd")
    fi
  done

  if ((${#missing[@]} == 0)); then
    return 0
  fi

  printf '%s\n' "${missing[@]}"
}

check_dependencies() {
  local missing
  missing="$(missing_commands "$@" || true)"

  if [[ -z "$missing" ]]; then
    return 0
  fi

  local display
  display="${missing//$'\n'/, }"
  warn "Missing recommended command(s): ${display}"
  return 1
}

require_dependencies() {
  local missing
  missing="$(missing_commands "$@" || true)"

  if [[ -z "$missing" ]]; then
    return 0
  fi

  local display
  display="${missing//$'\n'/, }"
  die "Missing required command(s): ${display}"
}

ensure_dir() {
  local dir="$1"
  mkdir -p "$dir"
}

ensure_dir_mode() {
  local dir="$1"
  local mode="$2"

  ensure_dir "$dir"

  if [[ -z "$mode" ]]; then
    return 0
  fi

  chmod "$mode" "$dir" 2>/dev/null || warn "Could not apply mode ${mode} to ${dir}"
}

ensure_file_mode() {
  local file="$1"
  local mode="$2"

  if [[ ! -e "$file" ]]; then
    return 0
  fi

  chmod "$mode" "$file" 2>/dev/null || warn "Could not apply mode ${mode} to ${file}"
}

ensure_secret_file_mode() {
  ensure_file_mode "$1" "$SECRET_FILE_MODE"
}

ensure_nonsecret_file_mode() {
  ensure_file_mode "$1" "$NONSECRET_FILE_MODE"
}

ensure_data_dir_mode() {
  ensure_dir_mode "$1" "$DATA_DIR_MODE"
}

arrstack_mktemp_file() {
  local template="${1-}"
  local mode="${2:-600}"
  local tmp=""

  if [[ -n "$template" ]]; then
    tmp="$(mktemp "$template" 2>/dev/null)" || return 1
  else
    tmp="$(mktemp 2>/dev/null)" || return 1
  fi

  if [[ -n "$mode" ]]; then
    chmod "$mode" "$tmp" 2>/dev/null || warn "Could not set mode ${mode} on temporary file ${tmp}"
  fi

  printf '%s\n' "$tmp"
}

arrstack_mktemp_dir() {
  local template="${1-}"
  local mode="${2:-700}"
  local tmp=""

  if [[ -n "$template" ]]; then
    tmp="$(mktemp -d "$template" 2>/dev/null)" || return 1
  else
    tmp="$(mktemp -d 2>/dev/null)" || return 1
  fi

  if [[ -n "$mode" ]]; then
    chmod "$mode" "$tmp" 2>/dev/null || warn "Could not set mode ${mode} on temporary directory ${tmp}"
  fi

  printf '%s\n' "$tmp"
}

arrstack_escalate_privileges() {
  # POSIX-safe locals
  _euid="${EUID:-$(id -u)}"
  if [ "${_euid}" -eq 0 ]; then
    # Already root: nothing to do
    return 0
  fi

  # Save original argv for possible su fallback reconstruction
  _script_path="${0:-}"
  # If script was invoked via relative path, attempt to get absolute path
  if [ -n "${_script_path}" ] && [ "${_script_path#./}" = "${_script_path}" ] && [ "${_script_path#/}" = "${_script_path}" ]; then
    # not absolute, try to resolve
    if command -v realpath >/dev/null 2>&1; then
      _script_path="$(realpath "${_script_path}" 2>/dev/null || printf '%s' "${_script_path}")"
    else
      # fallback: prefix cwd
      _script_path="$(pwd)/${_script_path}"
    fi
  fi

  # Prefer sudo (preserve env with -E). First try non-interactive.
  if command -v sudo >/dev/null 2>&1; then
    if sudo -n true >/dev/null 2>&1; then
      # passwordless sudo available: re-exec with preserved env
      exec sudo -E "${_script_path}" "$@"
      # unreachable
      return 0
    else
      # Interactive sudo available — notify user and re-exec (will prompt)
      printf '[%s] escalating privileges with sudo; you may be prompted for your password…\n' "$(basename "${_script_path}")" >&2
      exec sudo -E "${_script_path}" "$@"
      # unreachable
      return 0
    fi
  fi

  # If pkexec exists, attempt to use it (polkit). pkexec may not preserve env;
  # still it's often available on desktop systems where sudo isn't.
  if command -v pkexec >/dev/null 2>&1; then
    printf '[%s] escalating privileges with pkexec; you may be prompted for authentication…\n' "$(basename "${_script_path}")" >&2
    # pkexec requires the binary to be executable; using the interpreter ensures portability
    # Try to preserve PATH and a minimal env for the invocation
    if command -v bash >/dev/null 2>&1; then
      exec pkexec /bin/bash -c "exec \"${_script_path}\" \"\$@\"" -- "$@"
    else
      exec pkexec /bin/sh -c "exec \"${_script_path}\" \"\$@\"" -- "$@"
    fi
    return 0
  fi

  # Last resort: try su -c, reconstruct quoted command line
  if command -v su >/dev/null 2>&1; then
    printf '[%s] escalating privileges with su; you may be prompted for the root password…\n' "$(basename "${_script_path}")" >&2

    # Build a safely quoted command string to pass to su -c
    _cmd=""
    # prefer absolute script path if resolved above; otherwise pass original $0
    if [ -n "${_script_path}" ]; then
      _cmd="$(printf '%s' "${_script_path}")"
    else
      _cmd="$(printf '%s' "$0")"
    fi

    for _arg in "$@"; do
      # escape single quotes by closing, inserting '\'' and re-opening
      _escaped="$(printf '%s' "${_arg}" | sed "s/'/'\\\\''/g")"
      _cmd="${_cmd} '${_escaped}'"
    done

    # Execute via su - root -c 'exec CMD'
    exec su - root -c "exec ${_cmd}"
    # unreachable
    return 0
  fi

  # No escalation mechanism available
  printf '[%s] ERROR: root privileges are required. Install sudo, pkexec (polkit) or su, or run this script as root.\n' "$(basename "${_script_path}")" >&2
  return 2
}

ss_port_bound() {
  local proto="$1"
  local port="$2"

  if ! have_command ss; then
    return 2
  fi

  local flag
  case "$proto" in
    udp)
      flag="u"
      ;;
    tcp)
      flag="t"
      ;;
    *)
      return 2
      ;;
  esac

  if ss -H -ln${flag} "sport = :${port}" 2>/dev/null | awk 'NR>0 {exit 0} END {exit 1}'; then
    return 0
  fi

  return 1
}

lsof_port_bound() {
  local proto="$1"
  local port="$2"

  if ! have_command lsof; then
    return 2
  fi

  local spec
  case "$proto" in
    udp)
      spec=(-iUDP:"${port}")
      ;;
    tcp)
      spec=(-iTCP:"${port}" -sTCP:LISTEN)
      ;;
    *)
      return 2
      ;;
  esac

  if lsof -nP "${spec[@]}" 2>/dev/null | awk 'NR>0 {exit 0} END {exit 1}'; then
    return 0
  fi

  return 1
}

port_bound_any() {
  local proto="$1"
  local port="$2"

  if ss_port_bound "$proto" "$port"; then
    return 0
  fi

  if lsof_port_bound "$proto" "$port"; then
    return 0
  fi

  return 1
}

compose() {
  if ((${#DOCKER_COMPOSE_CMD[@]} == 0)); then
    die "Docker Compose command not detected; run preflight first"
  fi

  "${DOCKER_COMPOSE_CMD[@]}" "$@"
}

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

arrstack_timestamp() {
  date '+%H:%M:%S'
}

log_info() {
  printf '[%s] %s\n' "$(arrstack_timestamp)" "$*"
}

log_warn() {
  printf '[%s] WARNING: %s\n' "$(arrstack_timestamp)" "$*" >&2
}

log_error() {
  printf '[%s] ERROR: %s\n' "$(arrstack_timestamp)" "$*" >&2
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
  log_error "$@"
  exit 1
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
  trap 'rm -f -- "$ARRSTACK_LOCKFILE"' EXIT INT TERM HUP QUIT
}

atomic_write() {
  local target="$1"
  local content="$2"
  local mode="${3:-600}"
  local tmp

  tmp="$(arrstack_mktemp_file "${target}.XXXXXX.tmp" '')" || die "Failed to create temp file for ${target}"

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

escape_env_value_for_compose() {
  local value="${1-}"

  if [[ -z "$value" ]]; then
    printf '%s' ""
    return
  fi

  value="${value//\$/\$\$}"

  printf '%s' "$value"
}

write_env_kv() {
  local key="$1"
  local value="${2-}"

  if [[ -z "$key" ]]; then
    die "write_env_kv requires a key"
  fi

  if [[ "$value" == *$'\n'* ]]; then
    die "Environment value for ${key} contains newline characters"
  fi

  local escaped
  escaped="$(escape_env_value_for_compose "$value")"

  printf '%s=%s\n' "$key" "$escaped"
}

trim_string() {
  local value="${1-}"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

normalize_csv() {
  local csv="${1-}"
  csv="${csv//$'\r'/}"
  csv="${csv//$'\n'/,}"
  csv="${csv//$'\t'/,}"

  local -A seen=()
  local -a ordered=()
  local entry
  local IFS=','
  read -ra entries <<<"$csv"

  for entry in "${entries[@]}"; do
    entry="$(trim_string "$entry")"
    [[ -z "$entry" ]] && continue
    if [[ -z "${seen[$entry]+x}" ]]; then
      seen[$entry]=1
      ordered+=("$entry")
    fi
  done

  local joined=""
  for entry in "${ordered[@]}"; do
    if [[ -z "$joined" ]]; then
      joined="$entry"
    else
      joined+=",$entry"
    fi
  done

  printf '%s' "$joined"
}

collect_upstream_dns_servers() {
  local csv=""

  if [[ -n "${UPSTREAM_DNS_1:-}" ]]; then
    csv+="${UPSTREAM_DNS_1}"
  fi

  if [[ -n "${UPSTREAM_DNS_SERVERS:-}" ]]; then
    csv+="${csv:+,}${UPSTREAM_DNS_SERVERS}"
  fi

  if [[ -n "${UPSTREAM_DNS_2:-}" ]]; then
    csv+="${csv:+,}${UPSTREAM_DNS_2}"
  fi

  if [[ -z "$csv" ]]; then
    if declare -p ARRSTACK_UPSTREAM_DNS_CHAIN >/dev/null 2>&1; then
      local entry
      for entry in "${ARRSTACK_UPSTREAM_DNS_CHAIN[@]}"; do
        csv+="${csv:+,}${entry}"
      done
    fi
  fi

  if [[ -z "$csv" ]]; then
    csv="1.1.1.1,1.0.0.1"
  fi

  csv="$(normalize_csv "$csv")"

  local -a servers=()
  IFS=',' read -r -a servers <<<"$csv"

  local server
  for server in "${servers[@]}"; do
    [[ -z "$server" ]] && continue
    printf '%s\n' "$server"
  done
}

probe_dns_resolver() {
  local server="$1"
  local domain="${2:-cloudflare.com}"
  local timeout="${3:-2}"

  if command -v dig >/dev/null 2>&1; then
    if dig +time="${timeout}" +tries=1 @"${server}" "${domain}" >/dev/null 2>&1; then
      return 0
    fi
    return 1
  fi

  if command -v drill >/dev/null 2>&1; then
    if drill -Q "${domain}" @"${server}" >/dev/null 2>&1; then
      return 0
    fi
    return 1
  fi

  if command -v kdig >/dev/null 2>&1; then
    if kdig @"${server}" "${domain}" >/dev/null 2>&1; then
      return 0
    fi
    return 1
  fi

  if command -v nslookup >/dev/null 2>&1; then
    if nslookup "${domain}" "${server}" >/dev/null 2>&1; then
      return 0
    fi
    return 1
  fi

  return 2
}

verify_single_level_env_placeholders() {
  local file="$1"

  if [[ -z "$file" || ! -f "$file" ]]; then
    die "verify_single_level_env_placeholders requires an existing file"
  fi

  local nested=""

  nested="$(awk '/\$\{[^}]*\$\{/{printf "%d:%s\n", NR, $0}' "$file" || true)"

  if [[ -z "$nested" ]]; then
    return 0
  fi

  warn "Detected unsupported nested environment placeholders while rendering ${file}"
  warn "  Nested variable expansions:"
  printf '%s\n' "$nested" >&2

  return 1
}

portable_sed() {
  local expr="$1"
  local file="$2"
  local tmp

  tmp="$(arrstack_mktemp_file "${file}.XXXXXX.tmp")" || die "Failed to create temp file for sed"

  local perms=""
  if [ -e "$file" ]; then
    perms="$(stat -c '%a' "$file" 2>/dev/null || echo '')"
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

escape_sed_replacement() {
  printf '%s' "$1" | sed -e 's/[&/]/\\&/g'
}

unescape_env_value_from_compose() {
  local value="${1-}"
  local sentinel=$'\001__ARRSTACK_DOLLAR__\002'

  value="${value//$'\r'/}" # Normalize line endings

  if [[ "$value" =~ ^".*"$ ]]; then
    value="${value:1:${#value}-2}"
    value="${value//\$\$/${sentinel}}"
    value="$(printf '%b' "$value")"
    value="${value//${sentinel}/\$}"
    printf '%s' "$value"
    return
  fi

  value="${value//\$\$/${sentinel}}"
  value="${value//${sentinel}/\$}"
  printf '%s' "$value"
}

set_qbt_conf_value() {
  local file="$1"
  local key="$2"
  local value="$3"
  local tmp

  tmp="$(arrstack_mktemp_file)" || die "Failed to create temporary file while updating ${file}"

  if [ -f "$file" ]; then
    local replaced=0
    while IFS= read -r line || [ -n "$line" ]; do
      if [[ "$line" == "$key="* ]]; then
        printf '%s=%s\n' "$key" "$value" >>"$tmp"
        replaced=1
      else
        printf '%s\n' "$line" >>"$tmp"
      fi
    done <"$file"
    if ((replaced == 0)); then
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

  if [ -z "$key" ]; then
    return
  fi

  if [[ "$value" == *$'\n'* ]]; then
    die "Environment value for ${key} contains newline characters"
  fi

  if [ -f "${ARR_ENV_FILE}" ]; then
    local compose_safe
    compose_safe="$(escape_env_value_for_compose "$value")"
    if grep -q "^${key}=" "${ARR_ENV_FILE}"; then
      local escaped
      escaped="$(escape_sed_replacement "$compose_safe")"
      portable_sed "s/^${key}=.*/${key}=${escaped}/" "${ARR_ENV_FILE}"
    else
      write_env_kv "$key" "$value" >>"${ARR_ENV_FILE}"
    fi
  fi
}

obfuscate_sensitive() {
  local value="${1-}"
  local visible_prefix="${2:-2}"
  local visible_suffix="${3:-${visible_prefix}}"

  if [ -z "$value" ]; then
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

gen_safe_password() {
  local len="${1:-20}"

  if ((len <= 0)); then
    len=20
  fi

  if command -v openssl >/dev/null 2>&1; then
    LC_ALL=C openssl rand -base64 $((len * 2)) | tr -dc 'A-Za-z0-9' | head -c "$len" || true
    printf '\n'
    return
  fi

  if [ -r /dev/urandom ]; then
    LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c "$len" || true
    printf '\n'
    return
  fi

  printf '%s' "$(date +%s%N)$$" | sha256sum | tr -dc 'A-Za-z0-9' | head -c "$len" || true
  printf '\n'
}

sanitize_user() {
  local input="${1:-user}"
  local sanitized
  sanitized="$(printf '%s' "$input" | tr -cd 'A-Za-z0-9._-' || true)"
  if [ -z "$sanitized" ]; then
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

is_bcrypt_hash() {
  local candidate="${1-}"

  candidate="$(unescape_env_value_from_compose "$candidate")"

  valid_bcrypt "$candidate"
}

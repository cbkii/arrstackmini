# shellcheck shell=bash

have_command() {
  command -v "$1" >/dev/null 2>&1
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

ensure_dir() {
  local dir="$1"
  mkdir -p "$dir"
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

write_env_kv() {
  local key="$1"
  local value="${2-}"

  if [[ -z "$key" ]]; then
    die "write_env_kv requires a key"
  fi

  if [[ "$value" == *$'\n'* ]]; then
    die "Environment value for ${key} contains newline characters"
  fi

  printf '%s=%s\n' "$key" "$value"
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

  tmp="$(mktemp "${file}.XXXXXX.tmp" 2>/dev/null)" || die "Failed to create temp file for sed"
  chmod 600 "$tmp" 2>/dev/null || true

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

  tmp="$(mktemp)"
  chmod 600 "$tmp" 2>/dev/null || true

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
    if grep -q "^${key}=" "${ARR_ENV_FILE}"; then
      local escaped
      escaped="$(escape_sed_replacement "$value")"
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

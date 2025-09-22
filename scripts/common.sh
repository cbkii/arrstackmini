# shellcheck shell=bash

have_command() {
  command -v "$1" >/dev/null 2>&1
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
  trap 'rm -f -- "$ARRSTACK_LOCKFILE"' EXIT INT TERM
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

  local escaped_value
  escaped_value="$(escape_env_value_for_compose "$value")"

  if [ -f "$ARR_ENV_FILE" ]; then
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

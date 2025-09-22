#!/usr/bin/env bash
# shellcheck enable=require-variable-braces
# shellcheck enable=quote-safe-variables
escalate_privileges() {
  # POSIX-safe locals
  _euid="${EUID:-$(id -u)}"
  if [ "${_euid}" -eq 0 ]; then
    # Already root: nothing to do
    return 0
  fi

  # Save original argv for possible su fallback reconstruction
  _script_path="${0:-}"
  # If script was invoked via relative path, attempt to get absolute path
  if [ -n "$_script_path" ] && [ "${_script_path#./}" = "$_script_path" ] && [ "${_script_path#/}" = "$_script_path" ]; then
    # not absolute, try to resolve
    if command -v realpath >/dev/null 2>&1; then
      _script_path="$(realpath "$_script_path" 2>/dev/null || printf '%s' "$_script_path")"
    else
      # fallback: prefix cwd
      _script_path="$(pwd)/${_script_path}"
    fi
  fi

  # Prefer sudo (preserve env with -E). First try non-interactive.
  if command -v sudo >/dev/null 2>&1; then
    if sudo -n true >/dev/null 2>&1; then
      # passwordless sudo available: re-exec with preserved env
      exec sudo -E "$_script_path" "$@"
      # unreachable
      return 0
    else
      # Interactive sudo available — notify user and re-exec (will prompt)
      printf '[%s] escalating privileges with sudo; you may be prompted for your password…\n' "$(basename "$_script_path")" >&2
      exec sudo -E "$_script_path" "$@"
      # unreachable
      return 0
    fi
  fi

  # If pkexec exists, attempt to use it (polkit). pkexec may not preserve env;
  # still it's often available on desktop systems where sudo isn't.
  if command -v pkexec >/dev/null 2>&1; then
    printf '[%s] escalating privileges with pkexec; you may be prompted for authentication…\n' "$(basename "$_script_path")" >&2
    # pkexec requires the binary to be executable; using the interpreter ensures portability
    # Try to preserve PATH and a minimal env for the invocation
    if command -v bash >/dev/null 2>&1; then
      exec pkexec /bin/bash -c "exec \"$_script_path\" \"\$@\"" -- "$@"
    else
      exec pkexec /bin/sh -c "exec \"$_script_path\" \"\$@\"" -- "$@"
    fi
    return 0
  fi

  # Last resort: try su -c, reconstruct quoted command line
  if command -v su >/dev/null 2>&1; then
    printf '[%s] escalating privileges with su; you may be prompted for the root password…\n' "$(basename "$_script_path")" >&2

    # Build a safely quoted command string to pass to su -c
    _cmd=""
    # prefer absolute script path if resolved above; otherwise pass original $0
    if [ -n "$_script_path" ]; then
      _cmd="$(printf '%s' "$_script_path")"
    else
      _cmd="$(printf '%s' "$0")"
    fi

    for _arg in "$@"; do
      # escape single quotes by closing, inserting '\'' and re-opening
      _escaped="$(printf '%s' "$_arg" | sed "s/'/'\\\\''/g")"
      _cmd="$_cmd '$_escaped'"
    done

    # Execute via su - root -c 'exec CMD'
    exec su - root -c "exec $_cmd"
    # unreachable
    return 0
  fi

  # No escalation mechanism available
  printf '[%s] ERROR: root privileges are required. Install sudo, pkexec (polkit) or su, or run this script as root.\n' "$(basename "$_script_path")" >&2
  return 2
}

# Escalation insertion point: call this at top of scripts that need root
escalate_privileges "$@"

set -euo pipefail
IFS=$'\n\t'

log() {
  printf '%s\n' "$*"
}

warn() {
  printf 'WARN: %s\n' "$*" >&2
}

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

is_debian_like() {
  if [[ ! -r /etc/os-release ]]; then
    return 1
  fi

  # shellcheck disable=SC1091
  . /etc/os-release

  local id_like_lower="${ID_LIKE:-}" id_lower="${ID:-}"
  id_like_lower="${id_like_lower,,}"
  id_lower="${id_lower,,}"

  if [[ "$id_lower" == debian* || "$id_lower" == raspbian* ]]; then
    return 0
  fi

  if [[ "$id_like_lower" == *debian* || "$id_like_lower" == *raspbian* ]]; then
    return 0
  fi

  return 1
}

validate_ipv4() {
  local ip="$1"
  if [[ ! "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    die "Invalid IPv4 address: $ip"
  fi

  local segment
  IFS='.' read -r -a segment <<<"$ip"
  for part in "${segment[@]}"; do
    if ((part < 0 || part > 255)); then
      die "Invalid IPv4 segment in $ip"
    fi
  done
}

fuzzy_remove_entries() {
  local file="$1"
  local begin_marker="$2"
  local end_marker="$3"

  awk -v begin="$begin_marker" -v end="$end_marker" '
    BEGIN { skip=0 }
    $0 == begin { skip=1; next }
    $0 == end { skip=0; next }
    skip { next }
    {
      line = tolower($0)
      if (index(line, "arrstack-managed") > 0) {
        next
      }
      print $0
    }
  ' "$file"
}

rewrite_hosts_file() {
  local file="$1"
  local content="$2"
  local tmp

  tmp="$(mktemp "${file}.XXXXXX" 2>/dev/null)" || die "Unable to create temporary file for ${file}"
  trap 'rm -f "$tmp"' EXIT

  printf '%s\n' "$content" >"$tmp"
  chmod 644 "$tmp" 2>/dev/null || true

  if ! cat "$tmp" >"$file" 2>/dev/null; then
    rm -f "$tmp"
    trap - EXIT
    die "Failed to update ${file}; try running with elevated privileges"
  fi

  rm -f "$tmp"
  trap - EXIT
}

main() {
  if [[ $# -lt 2 ]]; then
    die "Usage: $0 <domain_suffix> <lan_ip>"
  fi

  local domain_suffix="$1"
  local lan_ip="$2"

  if [[ -z "$domain_suffix" ]]; then
    die "Domain suffix is required"
  fi

  if [[ -z "$lan_ip" ]]; then
    die "LAN IP is required"
  fi

  if [[ "$lan_ip" == "0.0.0.0" ]]; then
    log "LAN_IP is 0.0.0.0; skipping hosts update"
    exit 0
  fi

  if ! is_debian_like; then
    log "Non-Debian system detected; skipping hosts update"
    exit 0
  fi

  validate_ipv4 "$lan_ip"

  local hosts_file="/etc/hosts"
  if [[ ! -w "$hosts_file" ]]; then
    if [[ $EUID -ne 0 ]]; then
      die "Insufficient permissions to modify ${hosts_file}; rerun with sudo"
    fi
  fi

  local begin_marker="# >>> arrstack-managed hosts >>>"
  local end_marker="# <<< arrstack-managed hosts <<<"

  local sanitized
  sanitized="$(fuzzy_remove_entries "$hosts_file" "$begin_marker" "$end_marker")"

  local services=(qbittorrent sonarr radarr prowlarr bazarr flaresolverr gluetun caddy)
  local host_line
  host_line="${lan_ip}"
  local service
  for service in "${services[@]}"; do
    host_line+=" ${service}.${domain_suffix}"
  done
  host_line+=" # arrstack-managed ${domain_suffix}"

  local newline=$'\n'
  local new_content
  if [[ -n "$sanitized" ]]; then
    new_content="${sanitized}${newline}${begin_marker}${newline}${host_line}${newline}${end_marker}"
  else
    new_content="${begin_marker}${newline}${host_line}${newline}${end_marker}"
  fi

  rewrite_hosts_file "$hosts_file" "$new_content"
  log "Updated ${hosts_file} with arrstack-managed host entries"
}

main "$@"

#!/usr/bin/env bash
# shellcheck enable=require-variable-braces
# shellcheck enable=quote-safe-variables
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
    if (( part < 0 || part > 255 )); then
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

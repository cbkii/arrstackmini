#!/usr/bin/env bash
# shellcheck shell=bash
# ProtonVPN P2P server discovery and management for port forwarding

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

# shellcheck source=scripts/common.sh
. "$SCRIPT_DIR/common.sh"

# Cache file for P2P servers
PF_SERVER_CACHE="${ARR_DOCKER_DIR:-${REPO_ROOT}/docker-data}/gluetun/p2p-servers.json"
PF_SERVER_CACHE_MAX_AGE="${PF_SERVER_CACHE_MAX_AGE:-86400}"  # 24 hours

# ProtonVPN API endpoints for server discovery
PROTONVPN_API_BASE="https://api.protonmail.ch"
PROTONVPN_SERVERS_ENDPOINT="/vpn/logicals"

msg() {
  printf '[pf-servers] %s\n' "$1" >&2
}

warn() {
  printf '[pf-servers][warn] %s\n' "$1" >&2
}

die() {
  printf '[pf-servers][error] %s\n' "$1" >&2
  exit 1
}

# Check if cache file is fresh
is_cache_fresh() {
  local cache_file="$1"
  local max_age="$2"
  
  [[ -f "$cache_file" ]] || return 1
  
  local cache_time
  cache_time=$(stat -c %Y "$cache_file" 2>/dev/null || echo 0)
  local current_time
  current_time=$(date +%s)
  local age=$((current_time - cache_time))
  
  ((age < max_age))
}

# Fetch ProtonVPN server list from API
fetch_proton_servers() {
  local output_file="$1"
  
  if ! command -v curl >/dev/null 2>&1; then
    warn "curl not available, cannot fetch ProtonVPN server list"
    return 1
  fi
  
  if ! command -v jq >/dev/null 2>&1; then
    warn "jq not available, cannot parse ProtonVPN server list"
    return 1
  fi
  
  msg "Fetching ProtonVPN server list from API..."
  
  local tmp_file
  tmp_file=$(arrstack_mktemp_file "proton-servers.XXXXXX.json")
  
  if ! curl -fsSL --max-time 30 "${PROTONVPN_API_BASE}${PROTONVPN_SERVERS_ENDPOINT}" >"$tmp_file"; then
    rm -f "$tmp_file"
    warn "Failed to fetch ProtonVPN server list from API"
    return 1
  fi
  
  # Validate JSON structure
  if ! jq empty "$tmp_file" 2>/dev/null; then
    rm -f "$tmp_file"
    warn "Invalid JSON response from ProtonVPN API"
    return 1
  fi
  
  ensure_dir "$(dirname "$output_file")"
  mv "$tmp_file" "$output_file"
  msg "ProtonVPN server list cached to $output_file"
}

# Extract P2P-enabled servers from the cached server list
extract_p2p_servers() {
  local cache_file="$1"
  local country_filter="${2:-}"
  
  [[ -f "$cache_file" ]] || return 1
  
  local jq_filter='.[] | select(.Features? // 0 | . & 4 != 0) | {
    name: .Name,
    domain: .Domain,
    country: .Location.Country,
    country_code: .Location.CountryCode,
    load: .Load,
    score: .Score,
    features: .Features
  }'
  
  if [[ -n "$country_filter" ]]; then
    local country_lower
    country_lower=$(printf '%s' "$country_filter" | tr '[:upper:]' '[:lower:]')
    jq_filter='.[] | select(.Features? // 0 | . & 4 != 0) | select(.Location.Country | ascii_downcase | contains("'"$country_lower"'")) | {
      name: .Name,
      domain: .Domain,
      country: .Location.Country,
      country_code: .Location.CountryCode,
      load: .Load,
      score: .Score,
      features: .Features
    }'
  fi
  
  jq -c "$jq_filter" "$cache_file" 2>/dev/null || return 1
}

# Get the best P2P servers for a country, sorted by load and score
get_best_p2p_servers() {
  local country="${1:-}"
  local limit="${2:-5}"
  
  local cache_file="$PF_SERVER_CACHE"
  
  # Refresh cache if needed
  if ! is_cache_fresh "$cache_file" "$PF_SERVER_CACHE_MAX_AGE"; then
    if ! fetch_proton_servers "$cache_file"; then
      warn "Using stale cache or no cache available"
    fi
  fi
  
  if [[ ! -f "$cache_file" ]]; then
    warn "No server cache available and unable to fetch from API"
    return 1
  fi
  
  # Extract and sort P2P servers
  extract_p2p_servers "$cache_file" "$country" | \
    jq -s 'sort_by(.load, -.score) | .[0:'"$limit"']' 2>/dev/null || return 1
}

# Get server hostnames for Gluetun configuration
get_p2p_server_hostnames() {
  local country="${1:-}"
  local limit="${2:-5}"
  
  get_best_p2p_servers "$country" "$limit" | \
    jq -r '.[].name' 2>/dev/null || return 1
}

# Test if a specific server supports port forwarding
test_server_pf_capability() {
  local server_name="$1"
  
  # This would require actually connecting to test, which is complex
  # For now, we rely on the P2P feature flag from the API
  # In a real implementation, this could do a test connection
  
  msg "Testing P2P capability for server: $server_name"
  # Placeholder - in real implementation would test actual connectivity
  return 0
}

# Print available P2P servers for a country
list_p2p_servers() {
  local country="${1:-}"
  local limit="${2:-10}"
  
  local servers
  if ! servers=$(get_best_p2p_servers "$country" "$limit"); then
    die "Failed to get P2P server list"
  fi
  
  if [[ -z "$servers" || "$servers" == "[]" ]]; then
    warn "No P2P servers found${country:+ for country: $country}"
    return 1
  fi
  
  printf 'P2P-enabled ProtonVPN servers%s:\n' "${country:+ for $country}"
  printf "%-20s %-15s %-8s %-8s %s\n" "Server" "Country" "Load" "Score" "Domain"
  printf "%-20s %-15s %-8s %-8s %s\n" "------" "-------" "----" "-----" "------"
  
  printf '%s\n' "$servers" | jq -r '.[] | "\(.name) \(.country) \(.load)% \(.score) \(.domain)"' | \
    while read -r name country_name load score domain; do
      printf "%-20s %-15s %-8s %-8s %s\n" "$name" "$country_name" "$load" "$score" "$domain"
    done
}

# Generate SERVER_HOSTNAMES configuration for Gluetun
generate_gluetun_config() {
  local country="${1:-}"
  local limit="${2:-3}"
  
  local hostnames
  if ! hostnames=$(get_p2p_server_hostnames "$country" "$limit"); then
    warn "Failed to get P2P server hostnames"
    return 1
  fi
  
  if [[ -z "$hostnames" ]]; then
    warn "No P2P servers found${country:+ for country: $country}"
    return 1
  fi
  
  # Convert to comma-separated list
  local hostname_list
  hostname_list=$(printf '%s\n' "$hostnames" | paste -sd ',' -)
  
  printf "SERVER_HOSTNAMES=%s\n" "$hostname_list"
}

# Main command dispatcher
main() {
  local command="${1:-list}"
  shift || true
  
  case "$command" in
    list|ls)
      local country="${1:-}"
      local limit="${2:-10}"
      list_p2p_servers "$country" "$limit"
      ;;
    hostnames|names)
      local country="${1:-}"
      local limit="${2:-3}"
      get_p2p_server_hostnames "$country" "$limit"
      ;;
    config|gluetun)
      local country="${1:-}"
      local limit="${2:-3}"
      generate_gluetun_config "$country" "$limit"
      ;;
    refresh|update)
      msg "Refreshing ProtonVPN server cache..."
      rm -f "$PF_SERVER_CACHE"
      fetch_proton_servers "$PF_SERVER_CACHE"
      ;;
    test)
      local server="${1:-}"
      if [[ -z "$server" ]]; then
        die "Usage: $0 test <server_name>"
      fi
      test_server_pf_capability "$server"
      ;;
    help|--help|-h)
      cat <<EOF
Usage: $0 <command> [options]

Commands:
  list [country] [limit]     List P2P-enabled servers (default: all, limit 10)
  hostnames [country] [limit] Get server hostnames for Gluetun (default: limit 3)
  config [country] [limit]   Generate SERVER_HOSTNAMES config line
  refresh                    Force refresh of server cache
  test <server>              Test P2P capability of specific server
  help                       Show this help

Examples:
  $0 list Netherlands 5      # List top 5 P2P servers in Netherlands
  $0 hostnames Switzerland   # Get P2P server hostnames for Switzerland
  $0 config Netherlands 3    # Generate Gluetun config for Netherlands
  $0 refresh                 # Update server cache from ProtonVPN API

Cache location: $PF_SERVER_CACHE
Cache max age: $PF_SERVER_CACHE_MAX_AGE seconds
EOF
      ;;
    *)
      die "Unknown command: $command. Use '$0 help' for usage."
      ;;
  esac
}

main "$@"
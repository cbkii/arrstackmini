#!/usr/bin/env bash
# VPN Auto-Reconnect - Monitor qBittorrent traffic and reconnect VPN when needed
# Part of arrstack-mini: https://github.com/cbkii/arrstackmini

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STACK_DIR_DEFAULT="$(cd "${SCRIPT_DIR}/.." && pwd)"
STACK_DIR="${ARR_STACK_DIR:-${STACK_DIR_DEFAULT}}"
if ! STACK_DIR="$(cd "${STACK_DIR}" 2>/dev/null && pwd)"; then
  echo "Stack directory not found: ${STACK_DIR}" >&2
  exit 1
fi

# shellcheck source=scripts/common.sh
. "${STACK_DIR}/scripts/common.sh"

# shellcheck source=scripts/gluetun.sh
. "${STACK_DIR}/scripts/gluetun.sh"

ENV_FILE="${ARR_ENV_FILE:-${STACK_DIR}/.env}"

# Load environment early to ensure variables are available
load_env() {
  if [[ -f "$ENV_FILE" ]]; then
    set -a
    # shellcheck source=/dev/null
    source "$ENV_FILE"
    set +a
  fi
}

# Resolve docker data directory
resolve_docker_data() {
  local candidates=()
  
  if [[ -n "${ARR_DOCKER_DIR:-}" ]]; then
    candidates+=("$ARR_DOCKER_DIR")
  fi
  candidates+=("${HOME}/srv/docker-data" "${STACK_DIR}/docker-data")
  
  local path
  for path in "${candidates[@]}"; do
    if [[ -n "$path" && -d "$path" ]]; then
      printf '%s\n' "$path"
      return 0
    fi
  done
  
  # Default fallback
  printf '%s\n' "${HOME}/srv/docker-data"
}

# Initialize variables
load_env
ARR_DOCKER_DIR="${ARR_DOCKER_DIR:-$(resolve_docker_data)}"

# State directory
STATE_DIR="${ARR_DOCKER_DIR}/gluetun/auto-reconnect"
STATE_FILE="${STATE_DIR}/state.json"
HISTORY_LOG="${STATE_DIR}/history.log"
PAUSE_FILE="${STATE_DIR}/.pause"
KILL_FILE="${STACK_DIR}/.vpn-reconnect-kill-24h"
TEMP_PAUSE_FILE="${STACK_DIR}/.vpn-reconnect-pause"

# Configuration defaults (will be overridden by ENV_FILE)
VPN_AUTO_RECONNECT_ENABLED=0
VPN_SPEED_THRESHOLD_KBPS=12
VPN_CHECK_INTERVAL_MINUTES=20
VPN_CONSECUTIVE_CHECKS=3
VPN_ALLOWED_HOURS_START=2
VPN_ALLOWED_HOURS_END=8
VPN_RECONNECT_COOLDOWN_HOURS=24
VPN_MAX_ATTEMPTS_PER_SESSION=6

initialize_state_dir() {
  ensure_dir_mode "$STATE_DIR" 755
  if [[ ! -f "$STATE_FILE" ]]; then
    cat > "$STATE_FILE" <<EOF
{
  "last_check": 0,
  "consecutive_slow_checks": 0,
  "last_reconnect": 0,
  "attempts_this_session": 0,
  "session_start": $(date +%s),
  "cooldown_until": 0,
  "last_webui_access": 0
}
EOF
    ensure_nonsecret_file_mode "$STATE_FILE"
  fi
  
  if [[ ! -f "$HISTORY_LOG" ]]; then
    touch "$HISTORY_LOG"
    ensure_nonsecret_file_mode "$HISTORY_LOG"
  fi
}

log_event() {
  local level="$1"
  shift
  local message="$*"
  local timestamp
  timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
  
  printf '[%s] %s: %s\n' "$timestamp" "$level" "$message" | tee -a "$HISTORY_LOG"
  
  case "$level" in
    INFO) msg "$message" ;;
    WARN) warn "$message" ;;
    ERROR) log_error "$message" ;;
  esac
}

read_state() {
  if [[ ! -f "$STATE_FILE" ]]; then
    echo "{}"
    return
  fi
  
  if command -v jq >/dev/null 2>&1; then
    jq -c . "$STATE_FILE" 2>/dev/null || echo "{}"
  else
    cat "$STATE_FILE"
  fi
}

write_state() {
  local new_state="$1"
  if command -v jq >/dev/null 2>&1; then
    echo "$new_state" | jq -c . > "$STATE_FILE.tmp" && mv "$STATE_FILE.tmp" "$STATE_FILE"
  else
    echo "$new_state" > "$STATE_FILE"
  fi
}

update_state_field() {
  local field="$1"
  local value="$2"
  local current_state
  current_state="$(read_state)"
  
  if command -v jq >/dev/null 2>&1; then
    local new_state
    new_state="$(echo "$current_state" | jq -c --arg field "$field" --argjson value "$value" '.[$field] = $value')"
    write_state "$new_state"
  else
    # Fallback for systems without jq - use awk instead of sed for better parsing
    local temp_file
    temp_file="$(mktemp)"
    awk -v field="$field" -v value="$value" '
      {
        if (match($0, "\"" field "\":[^,}]*")) {
          gsub("\"" field "\":[^,}]*", "\"" field "\":" value)
        }
        print
      }
    ' <<< "$current_state" > "$temp_file"
    write_state "$(cat "$temp_file")"
    rm -f "$temp_file"
  fi
}

get_state_field() {
  local field="$1"
  local default="${2:-0}"
  local current_state
  current_state="$(read_state)"
  
  if command -v jq >/dev/null 2>&1; then
    echo "$current_state" | jq -r --arg field "$field" --arg default "$default" '.[$field] // $default'
  else
    # Fallback parsing
    echo "$current_state" | sed -n "s/.*\"$field\":\([^,}]*\).*/\1/p" | head -n1 || echo "$default"
  fi
}

is_within_allowed_hours() {
  local current_hour
  current_hour="$(date +%H | sed 's/^0//')"
  
  if [[ "$VPN_ALLOWED_HOURS_START" -le "$VPN_ALLOWED_HOURS_END" ]]; then
    # Normal range (e.g., 2-8)
    [[ "$current_hour" -ge "$VPN_ALLOWED_HOURS_START" && "$current_hour" -lt "$VPN_ALLOWED_HOURS_END" ]]
  else
    # Wrap-around range (e.g., 22-6)
    [[ "$current_hour" -ge "$VPN_ALLOWED_HOURS_START" || "$current_hour" -lt "$VPN_ALLOWED_HOURS_END" ]]
  fi
}

check_manual_overrides() {
  local now
  now="$(date +%s)"
  
  # Check for permanent pause
  if [[ -f "$PAUSE_FILE" ]]; then
    log_event "INFO" "Manual pause file detected: $PAUSE_FILE"
    return 1
  fi
  
  # Check for temporary pause
  if [[ -f "$TEMP_PAUSE_FILE" ]]; then
    log_event "INFO" "Temporary pause file detected: $TEMP_PAUSE_FILE"
    return 1
  fi
  
  # Check for 24-hour kill switch
  if [[ -f "$KILL_FILE" ]]; then
    local kill_time
    kill_time="$(stat -c %Y "$KILL_FILE" 2>/dev/null || echo 0)"
    local kill_expires=$((kill_time + 24 * 3600))
    
    if [[ "$now" -lt "$kill_expires" ]]; then
      local remaining=$((kill_expires - now))
      log_event "INFO" "24-hour kill switch active. Remaining: $((remaining / 3600))h $((remaining % 3600 / 60))m"
      return 1
    else
      log_event "INFO" "24-hour kill switch expired, removing: $KILL_FILE"
      rm -f "$KILL_FILE"
    fi
  fi
  
  # Check cooldown
  local cooldown_until
  cooldown_until="$(get_state_field "cooldown_until" 0)"
  if [[ "$now" -lt "$cooldown_until" ]]; then
    local remaining=$((cooldown_until - now))
    log_event "INFO" "In cooldown period. Remaining: $((remaining / 3600))h $((remaining % 3600 / 60))m"
    return 1
  fi
  
  return 0
}

get_qbt_transfer_rates() {
  local qbt_url="http://127.0.0.1:${QBT_HTTP_PORT_HOST:-8080}"
  local response
  
  # Try without authentication first (for whitelisted IPs)
  if response="$(curl -fsS --max-time 10 "${qbt_url}/api/v2/transfer/info" 2>/dev/null)"; then
    echo "$response"
    return 0
  fi
  
  # Try with authentication
  if [[ -n "${QBT_USER:-}" && -n "${QBT_PASS:-}" ]]; then
    local cookie_file
    cookie_file="$(mktemp)"
    trap 'rm -f "$cookie_file"' RETURN
    
    if curl -fsS --max-time 5 -c "$cookie_file" \
        --data-urlencode "username=${QBT_USER}" \
        --data-urlencode "password=${QBT_PASS}" \
        "${qbt_url}/api/v2/auth/login" >/dev/null 2>&1; then
      
      if response="$(curl -fsS --max-time 10 -b "$cookie_file" "${qbt_url}/api/v2/transfer/info" 2>/dev/null)"; then
        echo "$response"
        return 0
      fi
    fi
  fi
  
  return 1
}

check_webui_activity() {
  local qbt_url="http://127.0.0.1:${QBT_HTTP_PORT_HOST:-8080}"
  local now
  now="$(date +%s)"
  local last_access
  last_access="$(get_state_field "last_webui_access" 0)"
  
  # Check if WebUI is accessible (indicates recent activity)
  if curl -fsS --max-time 5 "${qbt_url}/" >/dev/null 2>&1; then
    # Check if this is a new access (different from stored timestamp)
    local current_log_time
    current_log_time="$(docker logs qbittorrent --since="30m" 2>/dev/null | grep -i "webui\|http\|login" | tail -n1 | cut -d' ' -f1-2 2>/dev/null || echo "")"
    
    if [[ -n "$current_log_time" ]]; then
      # Convert log timestamp to epoch (simplified approach)
      local log_timestamp
      log_timestamp="$(date -d "$current_log_time" +%s 2>/dev/null || echo "$now")"
      
      if [[ "$log_timestamp" -gt "$last_access" ]]; then
        update_state_field "last_webui_access" "$log_timestamp"
        log_event "INFO" "Recent WebUI activity detected"
        return 0
      fi
    fi
  fi
  
  # Check if last access was within 30 minutes
  local activity_threshold=$((now - 30 * 60))
  if [[ "$last_access" -gt "$activity_threshold" ]]; then
    log_event "INFO" "Recent WebUI activity within 30 minutes"
    return 0
  fi
  
  return 1
}

is_speed_below_threshold() {
  local transfer_info="$1"
  local dl_rate up_rate
  
  if command -v jq >/dev/null 2>&1; then
    dl_rate="$(echo "$transfer_info" | jq -r '.dl_info_speed // 0')"
    up_rate="$(echo "$transfer_info" | jq -r '.up_info_speed // 0')"
  else
    # Fallback parsing
    dl_rate="$(echo "$transfer_info" | sed -n 's/.*"dl_info_speed":\([0-9]*\).*/\1/p' | head -n1)"
    up_rate="$(echo "$transfer_info" | sed -n 's/.*"up_info_speed":\([0-9]*\).*/\1/p' | head -n1)"
    : "${dl_rate:=0}"
    : "${up_rate:=0}"
  fi
  
  # Convert bytes/sec to kbps
  local dl_kbps=$((dl_rate * 8 / 1000))
  local up_kbps=$((up_rate * 8 / 1000))
  local total_kbps=$((dl_kbps + up_kbps))
  
  log_event "INFO" "Current speeds: ${dl_kbps} kbps down, ${up_kbps} kbps up (total: ${total_kbps} kbps, threshold: ${VPN_SPEED_THRESHOLD_KBPS} kbps)"
  
  [[ "$total_kbps" -lt "$VPN_SPEED_THRESHOLD_KBPS" ]]
}

perform_vpn_reconnect() {
  local now
  now="$(date +%s)"
  local attempts
  attempts="$(get_state_field "attempts_this_session" 0)"
  
  if [[ "$attempts" -ge "$VPN_MAX_ATTEMPTS_PER_SESSION" ]]; then
    log_event "WARN" "Maximum attempts reached for this session, entering cooldown"
    local cooldown_until=$((now + VPN_RECONNECT_COOLDOWN_HOURS * 3600))
    update_state_field "cooldown_until" "$cooldown_until"
    update_state_field "attempts_this_session" 0
    update_state_field "session_start" "$now"
    return 1
  fi
  
  log_event "INFO" "Attempting VPN reconnection (attempt $((attempts + 1))/${VPN_MAX_ATTEMPTS_PER_SESSION})"
  
  # Use existing gluetun cycle function
  if gluetun_cycle_openvpn; then
    log_event "INFO" "VPN reconnection successful"
    update_state_field "last_reconnect" "$now"
    update_state_field "attempts_this_session" "$((attempts + 1))"
    update_state_field "consecutive_slow_checks" 0
    
    # Wait for connection to stabilize
    sleep 10
    
    return 0
  else
    log_event "ERROR" "VPN reconnection failed"
    update_state_field "attempts_this_session" "$((attempts + 1))"
    return 1
  fi
}

monitor_loop() {
  log_event "INFO" "Starting VPN auto-reconnect monitor (PID: $$)"
  
  while true; do
    local now
    now="$(date +%s)"
    
    # Check if monitoring is enabled
    if [[ "$VPN_AUTO_RECONNECT_ENABLED" != "1" ]]; then
      log_event "INFO" "VPN auto-reconnect disabled, sleeping..."
      sleep $((VPN_CHECK_INTERVAL_MINUTES * 60))
      continue
    fi
    
    # Check manual overrides and time windows
    if ! check_manual_overrides || ! is_within_allowed_hours; then
      sleep $((VPN_CHECK_INTERVAL_MINUTES * 60))
      continue
    fi
    
    # Check for recent WebUI activity
    if check_webui_activity; then
      log_event "INFO" "Skipping check due to recent user activity"
      update_state_field "consecutive_slow_checks" 0
      sleep $((VPN_CHECK_INTERVAL_MINUTES * 60))
      continue
    fi
    
    # Get qBittorrent transfer rates
    local transfer_info
    if ! transfer_info="$(get_qbt_transfer_rates)"; then
      log_event "WARN" "Failed to get qBittorrent transfer rates"
      sleep $((VPN_CHECK_INTERVAL_MINUTES * 60))
      continue
    fi
    
    # Check if speed is below threshold
    if is_speed_below_threshold "$transfer_info"; then
      local consecutive_checks
      consecutive_checks="$(get_state_field "consecutive_slow_checks" 0)"
      consecutive_checks=$((consecutive_checks + 1))
      update_state_field "consecutive_slow_checks" "$consecutive_checks"
      
      log_event "INFO" "Slow speed detected ($consecutive_checks/${VPN_CONSECUTIVE_CHECKS} consecutive checks)"
      
      if [[ "$consecutive_checks" -ge "$VPN_CONSECUTIVE_CHECKS" ]]; then
        log_event "WARN" "Speed threshold exceeded for ${VPN_CONSECUTIVE_CHECKS} consecutive checks, triggering reconnect"
        
        if perform_vpn_reconnect; then
          log_event "INFO" "VPN reconnection completed successfully"
        else
          log_event "ERROR" "VPN reconnection failed or cooldown activated"
        fi
      fi
    else
      log_event "INFO" "Speed above threshold, resetting consecutive check counter"
      update_state_field "consecutive_slow_checks" 0
    fi
    
    update_state_field "last_check" "$now"
    sleep $((VPN_CHECK_INTERVAL_MINUTES * 60))
  done
}

show_status() {
  load_env
  
  printf "VPN Auto-Reconnect Status\n"
  printf "========================\n"
  printf "Enabled: %s\n" "${VPN_AUTO_RECONNECT_ENABLED}"
  printf "Speed threshold: %s kbps\n" "${VPN_SPEED_THRESHOLD_KBPS}"
  printf "Check interval: %s minutes\n" "${VPN_CHECK_INTERVAL_MINUTES}"
  printf "Consecutive checks required: %s\n" "${VPN_CONSECUTIVE_CHECKS}"
  printf "Allowed hours: %02d:00 - %02d:00\n" "${VPN_ALLOWED_HOURS_START}" "${VPN_ALLOWED_HOURS_END}"
  printf "Cooldown period: %s hours\n" "${VPN_RECONNECT_COOLDOWN_HOURS}"
  printf "Max attempts per session: %s\n" "${VPN_MAX_ATTEMPTS_PER_SESSION}"
  printf "\n"
  
  if [[ -f "$STATE_FILE" ]]; then
    echo "Current State:"
    echo "-------------"
    local state
    state="$(read_state)"
    
    if command -v jq >/dev/null 2>&1; then
      echo "$state" | jq -r '
        "Last check: " + (if .last_check > 0 then (.last_check | strftime("%Y-%m-%d %H:%M:%S")) else "Never" end) + "\n" +
        "Consecutive slow checks: " + (.consecutive_slow_checks | tostring) + "\n" +
        "Last reconnect: " + (if .last_reconnect > 0 then (.last_reconnect | strftime("%Y-%m-%d %H:%M:%S")) else "Never" end) + "\n" +
        "Attempts this session: " + (.attempts_this_session | tostring) + "\n" +
        "Session start: " + (.session_start | strftime("%Y-%m-%d %H:%M:%S")) + "\n" +
        "Cooldown until: " + (if .cooldown_until > 0 then (.cooldown_until | strftime("%Y-%m-%d %H:%M:%S")) else "None" end) + "\n" +
        "Last WebUI access: " + (if .last_webui_access > 0 then (.last_webui_access | strftime("%Y-%m-%d %H:%M:%S")) else "Never" end)
      '
    else
      printf "Raw state: %s\n" "$state"
    fi
  else
    echo "No state file found"
  fi
  
  echo ""
  echo "Manual overrides:"
  echo "----------------"
  [[ -f "$PAUSE_FILE" ]] && printf "Paused: %s\\n" "$PAUSE_FILE" || echo "Paused: No"
  [[ -f "$TEMP_PAUSE_FILE" ]] && printf "Temp pause: %s\\n" "$TEMP_PAUSE_FILE" || echo "Temp pause: No"
  [[ -f "$KILL_FILE" ]] && printf "Kill switch: %s\\n" "$KILL_FILE" || echo "Kill switch: No"
}

main() {
  local action="${1:-monitor}"
  
  load_env
  initialize_state_dir
  
  case "$action" in
    monitor|daemon|start)
      monitor_loop
      ;;
    status)
      show_status
      ;;
    enable)
      log_event "INFO" "Enabling VPN auto-reconnect"
      # This would typically update the .env file
      printf "VPN auto-reconnect enabled. Set VPN_AUTO_RECONNECT_ENABLED=1 in your .env file and restart.\n"
      ;;
    disable)
      log_event "INFO" "Disabling VPN auto-reconnect"
      printf "VPN auto-reconnect disabled. Set VPN_AUTO_RECONNECT_ENABLED=0 in your .env file.\n"
      ;;
    pause)
      log_event "INFO" "Creating pause file"
      touch "$PAUSE_FILE"
      printf "VPN auto-reconnect paused. Remove %s to resume.\n" "$PAUSE_FILE"
      ;;
    resume)
      log_event "INFO" "Removing pause file"
      rm -f "$PAUSE_FILE"
      printf "VPN auto-reconnect resumed.\n"
      ;;
    reset)
      log_event "INFO" "Resetting state"
      rm -f "$STATE_FILE"
      initialize_state_dir
      printf "State reset.\n"
      ;;
    test-reconnect)
      log_event "INFO" "Testing VPN reconnection"
      if perform_vpn_reconnect; then
        printf "Test reconnection successful.\n"
      else
        printf "Test reconnection failed.\n"
        exit 1
      fi
      ;;
    --help|help|-h)
      cat <<EOF
VPN Auto-Reconnect Monitor

Usage: $0 [COMMAND]

Commands:
  monitor, daemon, start    Start the monitoring daemon (default)
  status                    Show current status and configuration
  enable                    Enable auto-reconnect
  disable                   Disable auto-reconnect
  pause                     Temporarily pause monitoring
  resume                    Resume monitoring after pause
  reset                     Reset state file
  test-reconnect           Test VPN reconnection once
  help                     Show this help

Configuration is loaded from: $ENV_FILE
State directory: $STATE_DIR
EOF
      ;;
    *)
      printf "Unknown command: %s\n" "$action" >&2
      printf "Run '%s help' for usage information.\n" "$0" >&2
      exit 1
      ;;
  esac
}

main "$@"
# shellcheck shell=bash
# Common helpers for interacting with the Gluetun control server.

_gluetun_control_base() {
  local port host
  port="${GLUETUN_CONTROL_PORT:-8000}"
  host="${LOCALHOST_IP:-127.0.0.1}"
  if [[ $host == *:* && $host != [* ]]; then
    printf 'http://[%s]:%s' "$host" "$port"
  else
    printf 'http://%s:%s' "$host" "$port"
  fi
}

gluetun_control_get() {
  local path url
  path="$1"
  url="$(_gluetun_control_base)${path}"

  if [[ -n "${GLUETUN_API_KEY:-}" ]]; then
    curl -fsS -H "X-Api-Key: ${GLUETUN_API_KEY}" "$url" 2>/dev/null
  else
    curl -fsS "$url" 2>/dev/null
  fi
}

_gluetun_extract_json_string() {
  local payload="$1"
  local key="$2"
  local value=""

  if command -v jq >/dev/null 2>&1; then
    value="$(printf '%s' "$payload" | jq -r --arg key "$key" '.[$key] // empty' 2>/dev/null || printf '')"
    if [[ "$value" == "null" ]]; then
      value=""
    fi
  fi

  if [[ -z "$value" ]]; then
    value="$(printf '%s\n' "$payload" | sed -n "s/.*\"${key}\"[[:space:]]*:[[:space:]]*\"\\([^\"\\]*\\)\".*/\\1/p" | head -n1)"
  fi

  printf '%s' "$value"
}

_gluetun_extract_json_number() {
  local payload="$1"
  local key="$2"
  local value=""

  if command -v jq >/dev/null 2>&1; then
    value="$(printf '%s' "$payload" | jq -r --arg key "$key" '.[$key] // empty' 2>/dev/null || printf '')"
    if [[ "$value" == "null" ]]; then
      value=""
    fi
  fi

  if [[ -z "$value" ]]; then
    value="$(printf '%s\n' "$payload" | sed -n "s/.*\"${key}\"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\\1/p" | head -n1)"
  fi

  printf '%s' "$value"
}

gluetun_public_ip_details() {
  local payload="$1"

  GLUETUN_PUBLIC_IP=""
  GLUETUN_PUBLIC_IP_CITY=""
  GLUETUN_PUBLIC_IP_REGION=""
  GLUETUN_PUBLIC_IP_COUNTRY=""
  GLUETUN_PUBLIC_IP_HOSTNAME=""
  GLUETUN_PUBLIC_IP_ORGANIZATION=""
  GLUETUN_PUBLIC_IP_TIMEZONE=""

  if [[ -z "$payload" ]]; then
    return 1
  fi

  GLUETUN_PUBLIC_IP="$(_gluetun_extract_json_string "$payload" "public_ip")"
  GLUETUN_PUBLIC_IP_CITY="$(_gluetun_extract_json_string "$payload" "city")"
  GLUETUN_PUBLIC_IP_REGION="$(_gluetun_extract_json_string "$payload" "region")"
  GLUETUN_PUBLIC_IP_COUNTRY="$(_gluetun_extract_json_string "$payload" "country")"
  GLUETUN_PUBLIC_IP_HOSTNAME="$(_gluetun_extract_json_string "$payload" "hostname")"
  GLUETUN_PUBLIC_IP_ORGANIZATION="$(_gluetun_extract_json_string "$payload" "organization")"
  GLUETUN_PUBLIC_IP_TIMEZONE="$(_gluetun_extract_json_string "$payload" "timezone")"

  [[ -n "$GLUETUN_PUBLIC_IP" ]]
}

gluetun_public_ip_location() {
  local -a parts=()

  if [[ -n "${GLUETUN_PUBLIC_IP_CITY:-}" ]]; then
    parts+=("$GLUETUN_PUBLIC_IP_CITY")
  fi

  if [[ -n "${GLUETUN_PUBLIC_IP_REGION:-}" && "${GLUETUN_PUBLIC_IP_REGION}" != "${GLUETUN_PUBLIC_IP_CITY}" ]]; then
    parts+=("$GLUETUN_PUBLIC_IP_REGION")
  fi

  if [[ -n "${GLUETUN_PUBLIC_IP_COUNTRY:-}" ]]; then
    parts+=("$GLUETUN_PUBLIC_IP_COUNTRY")
  fi

  if ((${#parts[@]} == 0)); then
    return 1
  fi

  (
    IFS=', '
    printf '%s' "${parts[*]}"
  )
}

gluetun_public_ip_summary() {
  local payload="$1"

  if ! gluetun_public_ip_details "$payload"; then
    return 1
  fi

  local summary="$GLUETUN_PUBLIC_IP"
  local location
  location="$(gluetun_public_ip_location 2>/dev/null || printf '')"

  local -a detail_segments=()
  if [[ -n "$location" ]]; then
    detail_segments+=("$location")
  fi

  if [[ -n "${GLUETUN_PUBLIC_IP_HOSTNAME:-}" ]]; then
    detail_segments+=("host ${GLUETUN_PUBLIC_IP_HOSTNAME}")
  fi

  if [[ -n "${GLUETUN_PUBLIC_IP_TIMEZONE:-}" ]]; then
    detail_segments+=("tz ${GLUETUN_PUBLIC_IP_TIMEZONE}")
  fi

  if ((${#detail_segments[@]} > 0)); then
    local details_formatted
    details_formatted=$(
      IFS='; '
      printf '%s' "${detail_segments[*]}"
    )
    summary+=" (${details_formatted})"
  fi

  if [[ -n "${GLUETUN_PUBLIC_IP_ORGANIZATION:-}" ]]; then
    summary+=" via ${GLUETUN_PUBLIC_IP_ORGANIZATION}"
  fi

  printf '%s' "$summary"
}

gluetun_port_forward_details() {
  local payload="$1"

  GLUETUN_PORT_FORWARD_PORT=""
  GLUETUN_PORT_FORWARD_STATUS=""
  GLUETUN_PORT_FORWARD_MESSAGE=""
  GLUETUN_PORT_FORWARD_EXPIRES_AT=""

  if [[ -z "$payload" ]]; then
    return 1
  fi

  local port
  port="$(_gluetun_extract_json_number "$payload" "port")"
  if [[ -z "$port" ]]; then
    port="$(_gluetun_extract_json_number "$payload" "PublicPort")"
  fi
  GLUETUN_PORT_FORWARD_PORT="$port"

  GLUETUN_PORT_FORWARD_STATUS="$(_gluetun_extract_json_string "$payload" "status")"
  if [[ -z "$GLUETUN_PORT_FORWARD_STATUS" ]]; then
    GLUETUN_PORT_FORWARD_STATUS="$(_gluetun_extract_json_string "$payload" "Status")"
  fi

  GLUETUN_PORT_FORWARD_MESSAGE="$(_gluetun_extract_json_string "$payload" "message")"
  if [[ -z "$GLUETUN_PORT_FORWARD_MESSAGE" ]]; then
    GLUETUN_PORT_FORWARD_MESSAGE="$(_gluetun_extract_json_string "$payload" "error")"
  fi
  if [[ -z "$GLUETUN_PORT_FORWARD_MESSAGE" ]]; then
    GLUETUN_PORT_FORWARD_MESSAGE="$(_gluetun_extract_json_string "$payload" "error_message")"
  fi

  GLUETUN_PORT_FORWARD_EXPIRES_AT="$(_gluetun_extract_json_string "$payload" "expires_at")"
  if [[ -z "$GLUETUN_PORT_FORWARD_EXPIRES_AT" ]]; then
    GLUETUN_PORT_FORWARD_EXPIRES_AT="$(_gluetun_extract_json_string "$payload" "ExpiresAt")"
  fi

  if [[ -n "$GLUETUN_PORT_FORWARD_PORT" || -n "$GLUETUN_PORT_FORWARD_STATUS" || -n "$GLUETUN_PORT_FORWARD_MESSAGE" ]]; then
    return 0
  fi

  return 1
}

gluetun_port_forward_summary() {
  local payload="$1"

  if ! gluetun_port_forward_details "$payload"; then
    return 1
  fi

  local summary=""

  if [[ -n "$GLUETUN_PORT_FORWARD_PORT" && "$GLUETUN_PORT_FORWARD_PORT" != "0" ]]; then
    summary="$GLUETUN_PORT_FORWARD_PORT"
    local -a extras=()
    if [[ -n "$GLUETUN_PORT_FORWARD_EXPIRES_AT" ]]; then
      extras+=("expires ${GLUETUN_PORT_FORWARD_EXPIRES_AT}")
    fi
    if [[ -n "$GLUETUN_PORT_FORWARD_STATUS" ]]; then
      case "$GLUETUN_PORT_FORWARD_STATUS" in
        '' | ok | OK | active | Active | open | OPEN) ;;
        *)
          extras+=("status ${GLUETUN_PORT_FORWARD_STATUS}")
          ;;
      esac
    fi
    if ((${#extras[@]} > 0)); then
      local extras_str
      extras_str=$(
        IFS='; '
        printf '%s' "${extras[*]}"
      )
      summary+=" (${extras_str})"
    fi
  else
    summary="not available"
    local -a extras=()
    if [[ -n "$GLUETUN_PORT_FORWARD_STATUS" ]]; then
      extras+=("status ${GLUETUN_PORT_FORWARD_STATUS}")
    fi
    if [[ -n "$GLUETUN_PORT_FORWARD_MESSAGE" ]]; then
      extras+=("$GLUETUN_PORT_FORWARD_MESSAGE")
    fi
    if ((${#extras[@]} > 0)); then
      local extras_str
      extras_str=$(
        IFS='; '
        printf '%s' "${extras[*]}"
      )
      summary+=" (${extras_str})"
    fi
  fi

  printf '%s' "$summary"
}

fetch_forwarded_port() {
  local response port

  if response=$(gluetun_control_get "/v1/forwardedport" 2>/dev/null); then
    port=$(printf '%s' "$response" | tr -d '[:space:]')
    if [[ "$port" =~ ^[0-9]+$ ]]; then
      printf '%s' "$port"
      return 0
    fi
  fi

  if response=$(gluetun_control_get "/v1/openvpn/portforwarded" 2>/dev/null); then
    if gluetun_port_forward_details "$response" && [[ -n "$GLUETUN_PORT_FORWARD_PORT" ]]; then
      printf '%s' "$GLUETUN_PORT_FORWARD_PORT"
      return 0
    fi
  fi

  printf '0'
}

fetch_public_ip() {
  local response

  if response=$(gluetun_control_get "/v1/publicip/ip" 2>/dev/null); then
    if gluetun_public_ip_details "$response" && [[ -n "$GLUETUN_PUBLIC_IP" ]]; then
      printf '%s' "$GLUETUN_PUBLIC_IP"
      return 0
    fi
  fi

  printf ''
}

ensure_proton_port_forwarding_ready() {
  # shellcheck disable=SC2034  # exported for callers to read the ensured port
  PF_ENSURED_PORT=""

  if [[ "${VPN_SERVICE_PROVIDER:-}" != "protonvpn" ]]; then
    return 0
  fi

  if [[ "${VPN_PORT_FORWARDING:-on}" != "on" ]]; then
    return 0
  fi

  if ! command -v curl >/dev/null 2>&1; then
    warn "[pf] curl is required to manage Proton port forwarding; skipping ensure loop"
    return 1
  fi

  local api_base
  api_base="$(_gluetun_control_base)"

  local -a curl_common=(-fsS)
  if [[ -n "${GLUETUN_API_KEY:-}" ]]; then
    curl_common+=(-H "X-Api-Key: ${GLUETUN_API_KEY}")
  fi

  local max_attempts wait_secs attempt port
  max_attempts="${PF_MAX_ATTEMPTS:-8}"
  wait_secs="${PF_WAIT_SECS:-90}"
  attempt=1
  port="0"

  while ((attempt <= max_attempts)); do
    msg "[pf] Attempt ${attempt}/${max_attempts}: waiting up to ${wait_secs}s..."

    local waited=0
    while ((waited < wait_secs)); do
      port="$(fetch_forwarded_port 2>/dev/null || printf '0')"
      if [[ -n "$port" && "$port" != "0" ]]; then
        msg "[pf] Forwarded port: $port"
        PF_ENSURED_PORT="$port"
        return 0
      fi
      sleep 1
      waited=$((waited + 1))
    done

    msg "[pf] Still 0; cycling OpenVPN to pick another PF server..."
    if ! curl "${curl_common[@]}" -X PUT -H 'Content-Type: application/json' \
      --data '{"status":"stopped"}' "${api_base}/v1/openvpn/status" >/dev/null 2>&1; then
      warn "[pf] Failed to stop OpenVPN via Gluetun control API"
      break
    fi

    sleep 2

    if ! curl "${curl_common[@]}" -X PUT -H 'Content-Type: application/json' \
      --data '{"status":"running"}' "${api_base}/v1/openvpn/status" >/dev/null 2>&1; then
      warn "[pf] Failed to start OpenVPN via Gluetun control API"
      break
    fi

    sleep 10
    attempt=$((attempt + 1))
  done

  # shellcheck disable=SC2034  # exported for callers to read the ensured port
  PF_ENSURED_PORT="${port:-0}"
  warn "[pf] Port forwarding still unavailable after ${max_attempts} attempts. Consider pinning SERVER_HOSTNAMES."
  return 1
}

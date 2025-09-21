# shellcheck shell=bash
# Common helpers for interacting with the Gluetun control server.

_gluetun_control_base() {
  local port
  port="${GLUETUN_CONTROL_PORT:-8000}"
  printf 'http://localhost:%s' "$port"
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

fetch_forwarded_port() {
  local response port status_file

  if response=$(gluetun_control_get "/v1/forwardedport" 2>/dev/null); then
    port=$(printf '%s' "$response" | tr -d '[:space:]')
    if [[ "$port" =~ ^[0-9]+$ ]]; then
      printf '%s' "$port"
      return 0
    fi
  fi

  if response=$(gluetun_control_get "/v1/openvpn/portforwarded" 2>/dev/null); then
    port=$(printf '%s' "$response" | jq -r '.port // empty' 2>/dev/null || printf '')
    if [[ "$port" =~ ^[0-9]+$ ]]; then
      printf '%s' "$port"
      return 0
    fi
  fi

  status_file="${VPN_PORT_FORWARDING_STATUS_FILE:-/tmp/gluetun/forwarded_port}"
  if [[ -f "$status_file" ]]; then
    port=$(tr -d '[:space:]' <"$status_file" 2>/dev/null || printf '')
    if [[ "$port" =~ ^[0-9]+$ ]]; then
      printf '%s' "$port"
      return 0
    fi
  fi

  printf '0'
}

fetch_public_ip() {
  local response ip

  if response=$(gluetun_control_get "/v1/publicip/ip" 2>/dev/null); then
    ip=$(printf '%s' "$response" | jq -r '.public_ip // empty' 2>/dev/null || printf '')
    if [[ -n "$ip" && "$ip" != "null" ]]; then
      printf '%s' "$ip"
      return 0
    fi
  fi

  printf ''
}

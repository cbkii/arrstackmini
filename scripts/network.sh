# shellcheck shell=bash

validate_ipv4() {
  local ip="$1"
  local regex='^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'
  [[ "$ip" =~ $regex ]]
}

validate_port() {
  local port="$1"
  [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]
}

detect_lan_ip() {
  if ! have_command ip; then
    return 1
  fi
  local candidates=()

  local default_iface
  default_iface="$(ip route show default | awk '/default/ {print $5}' | head -n1)"

  if [[ -n "$default_iface" ]]; then
    local ip
    ip="$(ip -4 addr show dev "$default_iface" | awk '/inet / {print $2}' | cut -d/ -f1 | head -n1)"
    [[ -n "$ip" ]] && candidates+=("$ip")
  fi

  while IFS= read -r ip; do
    [[ "$ip" =~ ^127\. ]] && continue
    candidates+=("$ip")
  done < <(ip -4 addr show | awk '/inet / {print $2}' | cut -d/ -f1)

  local candidate
  for candidate in "${candidates[@]}"; do
    if validate_ipv4 "$candidate"; then
      printf '%s' "$candidate"
      return 0
    fi
  done

  return 1
}

ip_assigned() {
  local target_ip="$1"
  if ! have_command ip; then
    return 1
  fi
  ip -4 addr show | grep -q "inet ${target_ip}/"
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

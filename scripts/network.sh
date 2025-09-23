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

is_private_ipv4() {
  local ip="$1"

  case "$ip" in
    10.* | 192.168.* | 172.1[6-9].* | 172.2[0-9].* | 172.3[0-1].*)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

ip_assigned() {
  local ip="$1"

  if [[ -z "$ip" || "$ip" == "0.0.0.0" ]]; then
    return 1
  fi

  if ! command -v ip >/dev/null 2>&1; then
    return 0
  fi

  if ip -o -4 addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | grep -Fxq "$ip"; then
    return 0
  fi

  return 1
}

assert_ip_assigned() {
  local ip="$1"

  if [[ -z "$ip" || "$ip" == "0.0.0.0" ]]; then
    die "LAN_IP ${ip:-<unset>} is not a usable address; set LAN_IP to a specific interface IP."
  fi

  if ! command -v ip >/dev/null 2>&1; then
    warn "Cannot verify LAN_IP ownership for ${ip}: 'ip' command not found"
    return 0
  fi

  if ip_assigned "$ip"; then
    return 0
  fi

  die "LAN_IP ${ip} is not assigned to this host. Run 'ip -4 addr show' to find valid addresses or remove LAN_IP from arrconf/userconf.sh to auto-detect."
}

detect_lan_ip() {
  local addr=""

  if command -v hostname >/dev/null 2>&1; then
    for addr in $(hostname -I 2>/dev/null || true); do
      if is_private_ipv4 "$addr"; then
        echo "$addr"
        return 0
      fi
    done
  fi

  if command -v ip >/dev/null 2>&1; then
    while IFS= read -r addr; do
      addr="${addr%/*}"
      if is_private_ipv4 "$addr"; then
        echo "$addr"
        return 0
      fi
    done < <(ip -o -4 addr show scope global 2>/dev/null || true)
  fi

  warn "Unable to detect a LAN address automatically; defaulting to 0.0.0.0"
  echo "0.0.0.0"
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

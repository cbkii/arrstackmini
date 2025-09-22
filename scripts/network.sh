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

is_virtual_interface_name() {
  local name="$1"

  case "$name" in
    lo | lo0 | docker* | br-* | veth* | virbr* | vbox* | vmnet* | vti* | cni* | flannel* | kube* | tailscale* | tun* | tap* | wg* | zt* | podman* | dummy*)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

interface_for_ip() {
  local ip="$1"

  if ! command -v ip >/dev/null 2>&1; then
    return 1
  fi

  ip -o -4 addr show scope global 2>/dev/null | awk -v target="$ip" '$4 ~ ("^" target "/") {print $2; exit}'
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
  local candidate=""
  local candidate_iface=""
  local method=""

  LAN_IP_AUTODETECTED_IFACE=""
  LAN_IP_AUTODETECTED_METHOD=""

  if command -v ip >/dev/null 2>&1; then
    local route_line=""
    route_line="$(ip -o route get 1.1.1.1 2>/dev/null | head -n1 || true)"
    if [[ -n "$route_line" ]]; then
      local route_iface=""
      local route_src=""
      route_iface="$(awk '{for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}' <<<"$route_line")"
      route_src="$(awk '{for (i=1;i<=NF;i++) if ($i=="src") {print $(i+1); exit}}' <<<"$route_line")"
      if [[ -n "$route_iface" && -n "$route_src" ]] && is_private_ipv4 "$route_src" && ! is_virtual_interface_name "$route_iface"; then
        if ip_assigned "$route_src"; then
          candidate="$route_src"
          candidate_iface="$route_iface"
          method="default route"
        fi
      fi
    fi

    if [[ -z "$candidate" ]]; then
      local line=""
      while IFS= read -r line; do
        local ifname=""
        local ip_cidr=""
        local ip_addr=""
        ifname="$(awk '{print $2}' <<<"$line")"
        ip_cidr="$(awk '{print $4}' <<<"$line")"
        ip_addr="${ip_cidr%/*}"
        if [[ -z "$ip_addr" ]]; then
          continue
        fi
        if ! is_private_ipv4 "$ip_addr"; then
          continue
        fi
        if is_virtual_interface_name "$ifname"; then
          continue
        fi
        candidate="$ip_addr"
        candidate_iface="$ifname"
        method="interface scan"
        break
      done < <(ip -o -4 addr show scope global 2>/dev/null || true)
    fi
  fi

  if [[ -z "$candidate" ]]; then
    local addresses=""
    addresses="$(hostname -I 2>/dev/null || true)"
    if [[ -n "$addresses" ]]; then
      local addr=""
      for addr in $addresses; do
        if ! is_private_ipv4 "$addr"; then
          continue
        fi
        candidate="$addr"
        method="hostname -I"
        if command -v ip >/dev/null 2>&1; then
          candidate_iface="$(interface_for_ip "$candidate")"
        fi
        break
      done
    fi
  fi

  if [[ -n "$candidate" && -z "$candidate_iface" ]]; then
    if command -v ip >/dev/null 2>&1; then
      candidate_iface="$(interface_for_ip "$candidate")"
    fi
  fi

  LAN_IP_AUTODETECTED_IFACE="$candidate_iface"
  LAN_IP_AUTODETECTED_METHOD="$method"

  if [[ -z "$candidate" ]]; then
    warn "================================================"
    warn "WARNING: Unable to detect a private LAN IP automatically"
    warn "Services will bind to 0.0.0.0 (all interfaces) until LAN_IP is set"
    warn "Edit arrconf/userconf.sh and set LAN_IP to a specific address"
    warn "================================================"
    echo "0.0.0.0"
  else
    echo "$candidate"
  fi
}

normalize_bind_address() {
  local address="$1"

  address="${address%%%*}"
  address="${address#[}"
  address="${address%]}"

  if [[ "$address" == ::ffff:* ]]; then
    address="${address##::ffff:}"
  fi

  if [[ -z "$address" ]]; then
    address="*"
  fi

  printf '%s\n' "$address"
}

address_conflicts() {
  local desired_raw="$1"
  local actual_raw="$2"

  local desired
  local actual
  desired="$(normalize_bind_address "$desired_raw")"
  actual="$(normalize_bind_address "$actual_raw")"

  if [[ "$desired" == "0.0.0.0" || "$desired" == "*" ]]; then
    return 0
  fi

  case "$actual" in
    "0.0.0.0" | "::" | "*")
      return 0
      ;;
  esac

  if [[ "$desired" == "$actual" ]]; then
    return 0
  fi

  return 1
}

port_in_use_with_ss() {
  local proto="$1"
  local bind_ip="$2"
  local port="$3"

  local flag="t"
  if [[ "$proto" == "udp" ]]; then
    flag="u"
  fi

  local output
  output="$(ss -H -ln${flag} 2>/dev/null || true)"
  if [[ -z "$output" ]]; then
    return 1
  fi

  local line
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    local addr_field=""
    addr_field="$(awk '{print $5}' <<<"$line")"
    if [[ -z "$addr_field" ]]; then
      addr_field="$(awk '{print $4}' <<<"$line")"
    fi
    [[ -z "$addr_field" ]] && continue
    local host="${addr_field%:*}"
    local port_field="${addr_field##*:}"
    host="${host%%%*}"
    if [[ "$port_field" != "$port" ]]; then
      continue
    fi
    if address_conflicts "$bind_ip" "$host"; then
      return 0
    fi
  done <<<"$output"

  return 1
}

port_in_use_with_netstat() {
  local proto="$1"
  local bind_ip="$2"
  local port="$3"

  local -a cmd
  if [[ "$proto" == "udp" ]]; then
    cmd=(netstat -lnu)
  else
    cmd=(netstat -lnt)
  fi

  local output
  output="$(${cmd[@]} 2>/dev/null || true)"
  if [[ -z "$output" ]]; then
    return 1
  fi

  local line
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    [[ "$line" =~ ^(Active|Proto) ]] && continue
    local local_field
    local_field="$(awk '{print $4}' <<<"$line")"
    [[ -z "$local_field" ]] && continue
    local_field="${local_field//\[/}"
    local_field="${local_field//\]/}"
    local host="${local_field%:*}"
    local port_field="${local_field##*:}"
    if [[ "$port_field" != "$port" ]]; then
      continue
    fi
    if address_conflicts "$bind_ip" "$host"; then
      return 0
    fi
  done <<<"$output"

  return 1
}

check_required_ports() {
  local lan_ip_for_check=""
  local lan_ip_source="configured"

  if [[ -n "${LAN_IP:-}" && "${LAN_IP}" != "0.0.0.0" ]]; then
    lan_ip_for_check="$LAN_IP"
  else
    lan_ip_for_check="$(detect_lan_ip)"
    lan_ip_source="auto-detected"
  fi

  if [[ -z "$lan_ip_for_check" || "$lan_ip_for_check" == "0.0.0.0" ]]; then
    warn "Skipping LAN port availability check: LAN_IP is not set. Services will bind to 0.0.0.0."
    return 0
  fi

  if ! validate_ipv4 "$lan_ip_for_check"; then
    warn "Skipping LAN port availability check: ${lan_ip_for_check} is not a valid IPv4 address."
    return 0
  fi

  local port_tool=""
  if command -v ss >/dev/null 2>&1; then
    port_tool="ss"
  elif command -v netstat >/dev/null 2>&1; then
    port_tool="netstat"
  else
    warn "Cannot check host port usage automatically: install 'ss' (iproute2) or 'netstat' (net-tools)."
    return 0
  fi

  msg "🔍 Checking host ports for ${lan_ip_for_check} (${lan_ip_source})"

  local local_dns_requested=0
  if [[ "${ENABLE_LOCAL_DNS:-1}" -eq 1 ]]; then
    local_dns_requested=1
  fi

  local -a port_checks=(
    "tcp:${lan_ip_for_check}:80:Caddy HTTP"
    "tcp:${lan_ip_for_check}:443:Caddy HTTPS"
  )

  if ((local_dns_requested)); then
    port_checks+=("udp:${lan_ip_for_check}:53:Local DNS")
    port_checks+=("tcp:${lan_ip_for_check}:53:Local DNS")
  fi

  port_checks+=("tcp:${LOCALHOST_IP:-127.0.0.1}:${GLUETUN_CONTROL_PORT}:Gluetun control API")

  local -a conflicts=()
  local local_dns_conflicts=0
  local entry=""
  for entry in "${port_checks[@]}"; do
    IFS=: read -r proto bind_ip port label <<<"$entry"
    if [[ "$label" == "Local DNS" && "${ENABLE_LOCAL_DNS:-1}" -ne 1 ]]; then
      continue
    fi

    local in_use=1
    if [[ "$port_tool" == "ss" ]]; then
      port_in_use_with_ss "$proto" "$bind_ip" "$port"
      in_use=$?
    else
      port_in_use_with_netstat "$proto" "$bind_ip" "$port"
      in_use=$?
    fi

    if ((in_use == 0)); then
      if [[ "$label" == "Local DNS" && "${AUTO_DISABLE_LOCAL_DNS:-0}" -eq 1 ]]; then
        warn "  Port ${port}/${proto^^} already in use on ${bind_ip}; disabling local DNS (--auto-disable-local-dns)."
        ENABLE_LOCAL_DNS=0
        LOCAL_DNS_AUTO_DISABLED=1
        LOCAL_DNS_AUTO_DISABLED_REASON="port ${port}/${proto^^}"
        LOCAL_DNS_SERVICE_REASON="auto-disabled-port-conflict"
        continue
      fi
      if [[ "$label" == "Local DNS" ]]; then
        local_dns_conflicts=$((local_dns_conflicts + 1))
      fi
      conflicts+=("${label} requires ${bind_ip}:${port}/${proto}")
    fi
  done

  if ((${#conflicts[@]} > 0)); then
    warn "Host port conflicts detected:"
    local conflict=""
    for conflict in "${conflicts[@]}"; do
      warn "  - ${conflict}"
    done
    warn "Free these ports or adjust arrconf/userconf.sh (LAN_IP, ENABLE_LOCAL_DNS, or ports) before retrying."
    warn "Tip: run 'sudo ss -tulpn' or 'sudo netstat -tulpn' to identify the conflicting services."
    if ((local_dns_conflicts > 0)); then
      if ((local_dns_conflicts == ${#conflicts[@]})); then
        warn "Tip: rerun with --auto-disable-local-dns (or set AUTO_DISABLE_LOCAL_DNS=1) to skip launching dnsmasq when port 53 is already in use."
      else
        warn "Tip: consider --auto-disable-local-dns if you prefer to disable the bundled dnsmasq when port 53 conflicts persist."
      fi
    fi
    die "Resolve host port conflicts before continuing."
  fi

  msg "  Required host ports are available ✓"
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

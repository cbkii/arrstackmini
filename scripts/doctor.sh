#!/usr/bin/env bash
set -euo pipefail

have_command() {
  command -v "$1" >/dev/null 2>&1
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
    local addr_field
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
  output="$("${cmd[@]}" 2>/dev/null || true)"
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

PORT_TOOL=""
if have_command ss; then
  PORT_TOOL="ss"
elif have_command netstat; then
  PORT_TOOL="netstat"
fi

port_in_use() {
  local proto="$1"
  local bind_ip="$2"
  local port="$3"

  case "$PORT_TOOL" in
    ss)
      port_in_use_with_ss "$proto" "$bind_ip" "$port"
      return $?
      ;;
    netstat)
      port_in_use_with_netstat "$proto" "$bind_ip" "$port"
      return $?
      ;;
    *)
      return 2
      ;;
  esac
}

report_port() {
  local label="$1"
  local proto="$2"
  local bind_ip="$3"
  local port="$4"

  if [[ -z "$PORT_TOOL" ]]; then
    printf '[doctor][warn] Cannot check %s (%s %s:%s): missing \"ss\"/\"netstat\".\n' "$label" "${proto^^}" "$bind_ip" "$port"
    return
  fi

  if port_in_use "$proto" "$bind_ip" "$port"; then
    printf '[doctor][warn] %s port %s/%s is already in use on %s.\n' "$label" "$port" "${proto^^}" "$bind_ip"
  else
    printf '[doctor][ok] %s port %s/%s is free on %s.\n' "$label" "$port" "${proto^^}" "$bind_ip"
  fi
}

test_lan_connectivity() {
  echo "[doctor] Testing LAN accessibility..."

  if [[ -z "$LAN_IP" || "$LAN_IP" == "0.0.0.0" ]]; then
    echo "[doctor][warn] LAN_IP unset or 0.0.0.0; skipping LAN connectivity checks."
    return
  fi

  if ! have_command curl; then
    echo "[doctor][warn] 'curl' not available; cannot probe LAN HTTP endpoints."
    return
  fi

  if curl -fsS -m 5 "http://${LAN_IP}/healthz" >/dev/null 2>&1; then
    echo "[doctor][ok] Caddy responds on http://${LAN_IP}/healthz"
  else
    echo "[doctor][error] Caddy not accessible on http://${LAN_IP}/healthz"
  fi

  local service
  for service in qbittorrent sonarr radarr prowlarr bazarr; do
    if curl -fsS -m 5 -H "Host: ${service}.${SUFFIX}" "http://${LAN_IP}/" >/dev/null 2>&1; then
      echo "[doctor][ok] ${service} accessible via Caddy on ${LAN_IP}"
    else
      echo "[doctor][warn] ${service} not accessible via Caddy on ${LAN_IP}"
    fi
  done
}

SUFFIX="${LAN_DOMAIN_SUFFIX:-}"
LAN_IP="${LAN_IP:-}"
DNS_IP="${LAN_IP:-127.0.0.1}"
ENABLE_LOCAL_DNS="${ENABLE_LOCAL_DNS:-1}"
LOCAL_DNS_SERVICE_ENABLED="${LOCAL_DNS_SERVICE_ENABLED:-1}"
LOCALHOST_IP="${LOCALHOST_IP:-127.0.0.1}"
GLUETUN_CONTROL_PORT="${GLUETUN_CONTROL_PORT:-8000}"

printf '[doctor] LAN domain suffix: %s\n' "${SUFFIX:-<unset>}"
printf '[doctor] LAN IP: %s\n' "${LAN_IP:-<unset>}"
printf '[doctor] Using DNS server at: %s\n' "${DNS_IP}"

if [[ "${ENABLE_LOCAL_DNS}" -eq 1 ]]; then
  if [[ "${LOCAL_DNS_SERVICE_ENABLED}" -eq 1 ]]; then
    echo "[doctor] Local DNS container: enabled"
  else
    echo "[doctor][warn] Local DNS requested but the container is disabled."
  fi
else
  echo "[doctor][info] Local DNS disabled in configuration."
fi

echo "[doctor] Checking host reachability"
if [[ -z "$LAN_IP" || "$LAN_IP" == "0.0.0.0" ]]; then
  echo "[doctor][warn] LAN_IP is unset or 0.0.0.0; skipping ping check."
elif have_command ping; then
  if ping -c 1 -W 1 "$LAN_IP" >/dev/null 2>&1; then
    echo "[doctor][ok] Host responded to ping at $LAN_IP"
  else
    echo "[doctor][warn] Host did not respond to ping at $LAN_IP"
  fi
else
  echo "[doctor][warn] 'ping' command not found; skipping reachability test."
fi

if [[ -z "$LAN_IP" || "$LAN_IP" == "0.0.0.0" ]]; then
  echo "[doctor][warn] Skipping LAN port checks because LAN_IP is not set to a specific address."
else
  report_port "Caddy HTTP" tcp "$LAN_IP" 80
  report_port "Caddy HTTPS" tcp "$LAN_IP" 443

  if [[ "${ENABLE_LOCAL_DNS}" -eq 1 && "${LOCAL_DNS_SERVICE_ENABLED}" -eq 1 ]]; then
    report_port "Local DNS" udp "$LAN_IP" 53
    report_port "Local DNS" tcp "$LAN_IP" 53
  else
    echo "[doctor][info] Skipping port 53 checks because local DNS is disabled."
  fi
fi

if [[ -n "$LOCALHOST_IP" ]]; then
  report_port "Gluetun control" tcp "$LOCALHOST_IP" "$GLUETUN_CONTROL_PORT"
fi

if [[ "${ENABLE_LOCAL_DNS}" -eq 1 && "${LOCAL_DNS_SERVICE_ENABLED}" -eq 1 ]]; then
  echo "[doctor] Testing DNS resolution of qbittorrent.${SUFFIX} via local resolver"
  if ! have_command dig; then
    echo "[doctor][warn] 'dig' command not found; skipping DNS lookup."
  else
    res="$(dig +short @"${DNS_IP}" qbittorrent."${SUFFIX}" 2>/dev/null || true)"
    if [[ -z "$res" ]]; then
      echo "[doctor][error] qbittorrent.${SUFFIX} did NOT resolve via ${DNS_IP}"
    else
      echo "[doctor][ok] qbittorrent.${SUFFIX} resolves to ${res}"
    fi
  fi
else
  echo "[doctor][info] DNS checks skipped: local DNS is disabled."
fi

echo "[doctor] Testing HTTPS endpoint"
if ! have_command curl; then
  echo "[doctor][warn] 'curl' command not found; skipping HTTPS probe."
else
  curl_args=(-k --silent --max-time 5)
  if [[ -n "$LAN_IP" && "$LAN_IP" != "0.0.0.0" ]]; then
    curl_args+=(--resolve "qbittorrent.${SUFFIX}:443:${LAN_IP}" --resolve "qbittorrent.${SUFFIX}:80:${LAN_IP}")
  fi
  if curl "${curl_args[@]}" "https://qbittorrent.${SUFFIX}/" -o /dev/null; then
    echo "[doctor][ok] HTTPS endpoint reachable"
  else
    echo "[doctor][warn] HTTPS endpoint not reachable. Could be DNS, Caddy, or firewall issue."
  fi
fi

test_lan_connectivity

exit 0

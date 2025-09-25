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
  output="$(ss -H -ln${flag} "sport = :${port}" 2>/dev/null || true)"
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

port_in_use_with_lsof() {
  local proto="$1"
  local bind_ip="$2"
  local port="$3"

  local -a cmd=(lsof -nP)
  if [[ "$proto" == "udp" ]]; then
    cmd+=(-iUDP:"${port}")
  else
    cmd+=(-iTCP:"${port}" -sTCP:LISTEN)
  fi

  local output
  output="$("${cmd[@]}" 2>/dev/null || true)"
  if [[ -z "$output" ]]; then
    return 1
  fi

  local line
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    [[ "$line" =~ ^COMMAND ]] && continue
    local name
    name="$(awk '{print $9}' <<<"$line" 2>/dev/null || true)"
    [[ -z "$name" ]] && continue
    name="${name%%->*}"
    name="${name% (LISTEN)}"
    local host="${name%:*}"
    local port_field="${name##*:}"
    port_field="${port_field%%[^0-9]*}"
    host="${host##*@}"
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
elif have_command lsof; then
  PORT_TOOL="lsof"
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
    lsof)
      port_in_use_with_lsof "$proto" "$bind_ip" "$port"
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
    printf '[doctor][warn] Cannot check %s (%s %s:%s): missing \"ss\"/\"lsof\".\n' "$label" "${proto^^}" "$bind_ip" "$port"
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

  if [[ "${ENABLE_CADDY}" -ne 1 ]]; then
    echo "[doctor][info] Skipping Caddy HTTP checks (ENABLE_CADDY=0)."
    return
  fi

  if [[ -z "${LAN_IP}" || "${LAN_IP}" == "0.0.0.0" ]]; then
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
ENABLE_LOCAL_DNS="${ENABLE_LOCAL_DNS:-0}"
LOCAL_DNS_SERVICE_ENABLED="${LOCAL_DNS_SERVICE_ENABLED:-1}"
ENABLE_CADDY="${ENABLE_CADDY:-0}"
EXPOSE_DIRECT_PORTS="${EXPOSE_DIRECT_PORTS:-1}"
LOCALHOST_IP="${LOCALHOST_IP:-127.0.0.1}"
GLUETUN_CONTROL_PORT="${GLUETUN_CONTROL_PORT:-8000}"
DNS_DISTRIBUTION_MODE="${DNS_DISTRIBUTION_MODE:-router}"
QBT_HTTP_PORT_HOST="${QBT_HTTP_PORT_HOST:-8080}"
SONARR_PORT="${SONARR_PORT:-8989}"
RADARR_PORT="${RADARR_PORT:-7878}"
PROWLARR_PORT="${PROWLARR_PORT:-9696}"
BAZARR_PORT="${BAZARR_PORT:-6767}"
FLARESOLVERR_PORT="${FLARESOLVERR_PORT:-8191}"

if [[ "${ENABLE_LOCAL_DNS}" -eq 1 ]]; then
  echo "[doctor] Checking if port 53 is free (or already bound):"
  if have_command ss; then
    if [[ -n "$(ss -H -lnu 'sport = :53' 2>/dev/null)" ]] || [[ -n "$(ss -H -lnt 'sport = :53' 2>/dev/null)" ]]; then
      echo "[doctor][warn] Something is listening on port 53. Could conflict with local_dns service."
      if have_command systemctl && systemctl is-active --quiet systemd-resolved; then
        echo "[doctor][hint] systemd-resolved is active and commonly owns :53 on Bookworm."
        echo "[doctor][hint] Run: ./scripts/host-dns-setup.sh (safe takeover with backup & rollback)."
      fi
    else
      echo "[doctor][ok] Port 53 appears free."
    fi
  elif have_command lsof; then
    if [[ -n "$(lsof -nP -iUDP:53 2>/dev/null)" ]] || [[ -n "$(lsof -nP -iTCP:53 -sTCP:LISTEN 2>/dev/null)" ]]; then
      echo "[doctor][warn] Something is listening on port 53. Could conflict with local_dns service."
    else
      echo "[doctor][ok] Port 53 appears free."
    fi
  else
    echo "[doctor][warn] Cannot test port 53 status (missing 'ss' and 'lsof')."
  fi
else
  echo "[doctor][info] Skipping port 53 availability check (local DNS disabled)."
fi

printf '[doctor] LAN domain suffix: %s\n' "${SUFFIX:-<unset>}"
printf '[doctor] LAN IP: %s\n' "${LAN_IP:-<unset>}"
printf '[doctor] Using DNS server at: %s\n' "${DNS_IP}"
printf '[doctor] DNS distribution mode: %s\n' "${DNS_DISTRIBUTION_MODE}"

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
if [[ -z "${LAN_IP}" || "${LAN_IP}" == "0.0.0.0" ]]; then
  echo "[doctor][warn] LAN_IP is unset or 0.0.0.0; skipping ping check."
elif have_command ping; then
  if ping -c 1 -W 1 "${LAN_IP}" >/dev/null 2>&1; then
    echo "[doctor][ok] Host responded to ping at ${LAN_IP}"
  else
    echo "[doctor][warn] Host did not respond to ping at ${LAN_IP}"
  fi
else
  echo "[doctor][warn] 'ping' command not found; skipping reachability test."
fi

if [[ -z "${LAN_IP}" || "${LAN_IP}" == "0.0.0.0" ]]; then
  echo "[doctor][warn] Skipping LAN port checks because LAN_IP is not set to a specific address."
else
  if [[ "${EXPOSE_DIRECT_PORTS}" -eq 1 ]]; then
    report_port "qBittorrent UI" tcp "${LAN_IP}" "${QBT_HTTP_PORT_HOST}"
    report_port "Sonarr UI" tcp "${LAN_IP}" "${SONARR_PORT}"
    report_port "Radarr UI" tcp "${LAN_IP}" "${RADARR_PORT}"
    report_port "Prowlarr UI" tcp "${LAN_IP}" "${PROWLARR_PORT}"
    report_port "Bazarr UI" tcp "${LAN_IP}" "${BAZARR_PORT}"
    report_port "FlareSolverr" tcp "${LAN_IP}" "${FLARESOLVERR_PORT}"
  else
    echo "[doctor][info] Direct LAN ports are disabled (EXPOSE_DIRECT_PORTS=0)."
  fi

  if [[ "${ENABLE_CADDY}" -eq 1 ]]; then
    report_port "Caddy HTTP" tcp "${LAN_IP}" 80
    report_port "Caddy HTTPS" tcp "${LAN_IP}" 443
  else
    echo "[doctor][info] Skipping Caddy port checks (ENABLE_CADDY=0)."
  fi

  if [[ "${ENABLE_LOCAL_DNS}" -eq 1 && "${LOCAL_DNS_SERVICE_ENABLED}" -eq 1 ]]; then
    report_port "Local DNS" udp "${LAN_IP}" 53
    report_port "Local DNS" tcp "${LAN_IP}" 53
  else
    echo "[doctor][info] Skipping port 53 checks because local DNS is disabled."
  fi
fi

if [[ -n "${LOCALHOST_IP}" ]]; then
  report_port "Gluetun control" tcp "${LOCALHOST_IP}" "${GLUETUN_CONTROL_PORT}"
fi

if [[ "${ENABLE_LOCAL_DNS}" -eq 1 && "${LOCAL_DNS_SERVICE_ENABLED}" -eq 1 ]]; then
  echo "[doctor] Testing DNS resolution of qbittorrent.${SUFFIX} via local resolver"
  if ! have_command dig; then
    echo "[doctor][warn] 'dig' command not found; skipping DNS lookup."
  else
    res_udp="$(dig +short @"${DNS_IP}" qbittorrent."${SUFFIX}" 2>/dev/null || true)"
    if [[ -z "$res_udp" ]]; then
      echo "[doctor][error] qbittorrent.${SUFFIX} did NOT resolve via ${DNS_IP} (UDP)"
    else
      echo "[doctor][ok] qbittorrent.${SUFFIX} resolves to ${res_udp} (UDP)"
    fi

    res_tcp="$(dig +tcp +short @"${DNS_IP}" qbittorrent."${SUFFIX}" 2>/dev/null || true)"
    if [[ -z "$res_tcp" ]]; then
      echo "[doctor][error] qbittorrent.${SUFFIX} did NOT resolve via ${DNS_IP} (TCP)"
    else
      echo "[doctor][ok] qbittorrent.${SUFFIX} resolves to ${res_tcp} (TCP)"
    fi
  fi
else
  echo "[doctor][info] DNS checks skipped: local DNS is disabled."
fi

if [[ "${ENABLE_CADDY}" -eq 1 ]]; then
  echo "[doctor] Testing CA fetch over HTTP (bootstrap)"
  if have_command curl && have_command openssl; then
    if cert_output="$(curl -fsS "http://ca.${SUFFIX}/root.crt" 2>/dev/null | openssl x509 -noout -subject -issuer 2>/dev/null)"; then
      printf '[doctor][ok] CA download succeeded:%s%s\n' "${cert_output:+\n}" "${cert_output}"
    else
      echo "[doctor][warn] Could not fetch CA over HTTP"
    fi
  else
    echo "[doctor][warn] Skipping CA fetch test: missing 'curl' or 'openssl'."
  fi

  echo "[doctor] Testing HTTPS endpoint"
  if ! have_command curl; then
    echo "[doctor][warn] 'curl' command not found; skipping HTTPS probe."
  else
    curl_args=(-k --silent --max-time 5)
    if [[ -n "${LAN_IP}" && "${LAN_IP}" != "0.0.0.0" ]]; then
      curl_args+=(--resolve "qbittorrent.${SUFFIX}:443:${LAN_IP}" --resolve "qbittorrent.${SUFFIX}:80:${LAN_IP}")
    fi
    if curl "${curl_args[@]}" "https://qbittorrent.${SUFFIX}/" -o /dev/null; then
      echo "[doctor][ok] HTTPS endpoint reachable"
    else
      echo "[doctor][warn] HTTPS endpoint not reachable. Could be DNS, Caddy, or firewall issue."
    fi
  fi
else
  echo "[doctor][info] Skipping Caddy CA and HTTPS checks (ENABLE_CADDY=0)."
fi

test_lan_connectivity

if [[ "${ENABLE_LOCAL_DNS}" -eq 1 ]]; then
  case "${DNS_DISTRIBUTION_MODE}" in
    router)
      echo "[doctor][info] DNS distribution mode 'router': set DHCP Option 6 (DNS server) on your router to ${LAN_IP}."
      ;;
    per-device)
      echo "[doctor][info] DNS distribution mode 'per-device': point important clients at ${LAN_IP} and keep Android Private DNS Off/Automatic."
      ;;
    *)
      echo "[doctor][warn] Unknown DNS_DISTRIBUTION_MODE='${DNS_DISTRIBUTION_MODE}'. Expected 'router' or 'per-device'."
      ;;
  esac
else
  echo "[doctor][info] DNS distribution mode ignored (local DNS disabled)."
fi

lan_target="${LAN_IP:-<unset>}"
echo "[doctor] From another LAN device you can try:"
if [[ "${EXPOSE_DIRECT_PORTS}" -eq 1 ]]; then
  echo "  curl -I http://${lan_target}:${QBT_HTTP_PORT_HOST}"
  echo "  curl -I http://${lan_target}:${SONARR_PORT}"
else
  echo "  (Direct ports disabled; set EXPOSE_DIRECT_PORTS=1 to enable IP:PORT access.)"
fi

if [[ "${ENABLE_LOCAL_DNS}" -eq 1 ]]; then
  echo "  nslookup qbittorrent.${SUFFIX} ${lan_target}"
  echo "[doctor][note] If DNS queries fail:"
  echo "  - Ensure the client and ${lan_target} are on the same VLAN/subnet;"
  echo "  - Some routers block DNS to LAN hosts; allow UDP/TCP 53 to ${lan_target};"
  echo "  - Temporarily set the client DNS to ${lan_target} and retry."
fi

if [[ "${ENABLE_CADDY}" -eq 1 ]]; then
  echo "  curl -k https://qbittorrent.${SUFFIX}/ --resolve qbittorrent.${SUFFIX}:443:${lan_target}"
fi

exit 0

# shellcheck shell=bash
show_summary() {

  msg "🎉 Setup complete!!"
  warn "Check these details and revisit the README for any manual steps you may need to perform from here"

  msg "LAN binding target: ${LAN_IP:-<unset>}"

  # Always show qBittorrent access information prominently
  local qbt_pass_msg=""
  if [[ -f "$ARR_ENV_FILE" ]]; then
    local configured_pass
    configured_pass="$(grep "^QBT_PASS=" "$ARR_ENV_FILE" | cut -d= -f2- || true)"
    if [[ -n "$configured_pass" && "$configured_pass" != "adminadmin" ]]; then
      qbt_pass_msg="Password: ${configured_pass} (from .env)"
    else
      qbt_pass_msg="Password: Check docker logs qbittorrent"
    fi
  fi

  local ip_hint="${LAN_IP:-}"
  if [[ -z "$ip_hint" || "$ip_hint" == "0.0.0.0" ]]; then
    ip_hint="<LAN_IP>"
  fi

  cat <<QBT_INFO
================================================
qBittorrent Access Information:
================================================
WebUI:    http://${ip_hint}:${QBT_HTTP_PORT_HOST}
Username: ${QBT_USER}
${qbt_pass_msg}
================================================

QBT_INFO

  cat <<'DIRECT'
Direct LAN URLs (ipdirect profile enabled):
DIRECT
  cat <<DIRECT_URLS
  qBittorrent:  http://${ip_hint}:${QBT_HTTP_PORT_HOST}
  Sonarr:       http://${ip_hint}:${SONARR_PORT}
  Radarr:       http://${ip_hint}:${RADARR_PORT}
  Prowlarr:     http://${ip_hint}:${PROWLARR_PORT}
  Bazarr:       http://${ip_hint}:${BAZARR_PORT}
  FlareSolverr: http://${ip_hint}:${FLARESOLVERR_PORT}
DIRECT_URLS

  if [[ "${ENABLE_CADDY:-0}" -eq 1 ]]; then
    local domain_suffix="${ARR_DOMAIN_SUFFIX_CLEAN}"
    cat <<CADDY_INFO

Proxy profile enabled (Caddy reverse proxy):
  http://qbittorrent.${domain_suffix}
  https://qbittorrent.${domain_suffix} (trust the internal CA)
  Health endpoint: http://${ip_hint}/healthz
Remote clients must authenticate with '${CADDY_BASIC_AUTH_USER}' using the password stored in ${ARR_DOCKER_DIR}/caddy/credentials.
CADDY_INFO
  fi

  if [[ "${ENABLE_LOCAL_DNS:-0}" -eq 1 ]]; then
    if [[ ${LOCAL_DNS_SERVICE_ENABLED:-0} -eq 1 ]]; then
      msg "Local DNS is enabled. Point DHCP Option 6 (or per-device DNS) at ${LAN_IP:-<unset>} so hostnames resolve."
    else
      warn "Local DNS requested but the container is disabled (port 53 conflict). Resolve the conflict and rerun."
    fi
  fi

  if [[ "${LAN_IP}" == "0.0.0.0" || -z "${LAN_IP:-}" ]]; then
    cat <<'WARNING'
⚠️  SECURITY WARNING
   LAN_IP is unset or 0.0.0.0 so services listen on all interfaces.
   Update arrconf/userconf.sh with a specific LAN_IP to limit exposure.

WARNING
  fi

  if [[ "${QBT_USER}" == "admin" && "${QBT_PASS}" == "adminadmin" ]]; then
    cat <<'WARNING'
⚠️  DEFAULT CREDENTIALS
   qBittorrent is using admin/adminadmin.
   Change this in the WebUI and update QBT_USER/QBT_PASS in .env.

WARNING
  fi

  local pf_current=""
  if declare -f fetch_forwarded_port >/dev/null 2>&1; then
    pf_current="$(fetch_forwarded_port 2>/dev/null || printf '0')"
  elif [[ -f "${ARR_DOCKER_DIR}/gluetun/forwarded_port" ]]; then
    pf_current="$(tr -d '[:space:]' <"${ARR_DOCKER_DIR}/gluetun/forwarded_port" 2>/dev/null || printf '0')"
  fi

  if [[ "${PF_PENDING_DURING_INSTALL:-0}" -eq 1 && ( -z "$pf_current" || "$pf_current" == "0" ) ]]; then
    cat <<'PF_WARNING'
⚠️  PORT FORWARDING PENDING
   Proton VPN did not return a forwarded port during setup.
   Run `arr.vpn.port.sync` (or `arr.vpn.port`) after a minute to retry.
   If the issue persists, consider pinning SERVER_COUNTRIES or SERVER_NAMES.

PF_WARNING
  fi

  cat <<SUMMARY
Gluetun control server (local only): http://${LOCALHOST_IP}:${GLUETUN_CONTROL_PORT}

Helper commands:
  source ${ARR_STACK_DIR}/.arraliases
  arr.help       # Show all available aliases
  arr.vpn.status # Check VPN status and forwarded port
  arr.logs       # Follow container logs via docker compose

SUMMARY
}

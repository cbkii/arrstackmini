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

  local vt_summary_message="${VUETORRENT_STATUS_MESSAGE:-}"
  if [[ -z "$vt_summary_message" ]]; then
    if [[ "${VUETORRENT_MODE}" == "manual" ]]; then
      vt_summary_message="VueTorrent manual mode active at ${VUETORRENT_ROOT}."
    else
      vt_summary_message="VueTorrent via LSIO Docker mod (WebUI root ${VUETORRENT_ROOT})."
    fi
  fi

  if [[ "${VUETORRENT_STATUS_LEVEL:-msg}" == "warn" ]]; then
    warn "$vt_summary_message"
  else
    msg "$vt_summary_message"
  fi

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
  else
    cat <<NO_CADDY

Reverse proxy disabled (ENABLE_CADDY=0).
Access the services via the direct LAN URLs above.
Set ENABLE_CADDY=1 in ${ARR_USERCONF_PATH} and rerun ./arrstack.sh to publish HTTPS hostnames signed by the internal CA.
NO_CADDY
    if [[ "${ENABLE_LOCAL_DNS:-0}" -eq 1 ]]; then
      cat <<'DNS_HTTP'
Local DNS is enabled. Hostnames will resolve but continue serving plain HTTP until Caddy is enabled.
DNS_HTTP
    fi
  fi

  if [[ "${ENABLE_LOCAL_DNS:-0}" -eq 1 ]]; then
    if [[ ${LOCAL_DNS_SERVICE_ENABLED:-0} -eq 1 ]]; then
      msg "Local DNS is enabled. Point DHCP Option 6 (or per-device DNS) at ${LAN_IP:-<unset>} so hostnames resolve."
    else
      warn "Local DNS requested but the container is disabled (port 53 conflict). Resolve the conflict and rerun."
    fi
  fi

  if [[ "${LAN_IP}" == "0.0.0.0" || -z "${LAN_IP:-}" ]]; then
    cat <<WARNING
⚠️  SECURITY WARNING
   LAN_IP is unset or 0.0.0.0 so services listen on all interfaces.
   Update ${ARR_USERCONF_PATH} with a specific LAN_IP to limit exposure.

WARNING
  fi

  if [[ "${QBT_USER}" == "admin" && "${QBT_PASS}" == "adminadmin" ]]; then
    cat <<'WARNING'
⚠️  DEFAULT CREDENTIALS
   qBittorrent is using admin/adminadmin.
   Change this in the WebUI and update QBT_USER/QBT_PASS in .env.

WARNING
  fi

  if [[ "${VPN_SERVICE_PROVIDER:-}" == "protonvpn" && "${VPN_PORT_FORWARDING:-on}" == "on" ]]; then
    local pf_summary_port="${PF_ENSURED_PORT:-0}"
    if [[ ! "$pf_summary_port" =~ ^[0-9]+$ || "$pf_summary_port" == "0" ]]; then
      local pf_status="${PF_ENSURE_STATUS_MESSAGE:-pending}"
      warn "⚠️  ProtonVPN port forwarding is still pending (${pf_status})."
      warn "   Run 'arr.vpn.port' or 'arr.vpn.port.sync' once Gluetun assigns a port."
      warn "   Persistent zeros? Pin SERVER_COUNTRIES or SERVER_NAMES in ${ARR_USERCONF_PATH}."
      if [[ -n "${PF_ASYNC_RETRY_LOG:-}" ]]; then
        msg "  Background retry log: ${PF_ASYNC_RETRY_LOG}"
      fi
    fi
  fi

  if [[ "${ARR_PERMISSION_PROFILE}" == "collab" && -n "${COLLAB_PERMISSION_WARNINGS:-}" ]]; then
    warn "Collaborative profile notes:"
    while IFS= read -r collab_warning; do
      [[ -z "$collab_warning" ]] && continue
      warn "  - ${collab_warning}"
    done < <(printf '%s\n' "${COLLAB_PERMISSION_WARNINGS}")
  fi

  cat <<SUMMARY
Gluetun control server (local only): http://${LOCALHOST_IP}:${GLUETUN_CONTROL_PORT}

Helper commands:
  source ${ARR_STACK_DIR}/.aliasarr
  arr.help       # Show all available aliases
  arr.vpn.status # Check VPN status and forwarded port
  arr.logs       # Follow container logs via docker compose

SUMMARY
}

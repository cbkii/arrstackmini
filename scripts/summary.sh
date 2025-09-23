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

  local domain_suffix="${ARR_DOMAIN_SUFFIX_CLEAN}"

  local lan_ip_display="${LAN_IP:-<unset>}"
  local lan_dns_hint
  if [[ "${ENABLE_LOCAL_DNS:-1}" -eq 1 && ${LOCAL_DNS_SERVICE_ENABLED:-0} -eq 1 ]]; then
    lan_dns_hint="LAN DNS hint: ensure clients use ${lan_ip_display} as their DNS server so *.${domain_suffix} resolves via local dnsmasq."
  elif [[ "${ENABLE_LOCAL_DNS:-1}" -eq 1 ]]; then
    lan_dns_hint="LAN DNS hint: local_dns container is not active; clients must use another resolver until LAN_IP/port conflicts are resolved."
  else
    lan_dns_hint="LAN DNS hint: point qbittorrent.${domain_suffix} to ${lan_ip_display} (via DNS or /etc/hosts)."
  fi

  cat <<QBT_INFO
================================================
qBittorrent Access Information:
================================================
LAN URL:  http://qbittorrent.${domain_suffix}/
HTTPS:    https://qbittorrent.${domain_suffix}/  (trust the Caddy internal CA)
Username: ${QBT_USER}
${qbt_pass_msg}

${lan_dns_hint}
Remote clients must supply the Caddy Basic Auth user '${CADDY_BASIC_AUTH_USER}' with the password saved in ${ARR_DOCKER_DIR}/caddy/credentials.
================================================

QBT_INFO

  if [[ "${LAN_IP}" == "0.0.0.0" ]]; then
    cat <<'WARNING'
⚠️  SECURITY WARNING
   LAN_IP is 0.0.0.0 so services listen on all interfaces.
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

  cat <<SUMMARY
Access your services via Caddy:
  qBittorrent:   http://qbittorrent.${domain_suffix}
  Sonarr:        http://sonarr.${domain_suffix}
  Radarr:        http://radarr.${domain_suffix}
  Prowlarr:      http://prowlarr.${domain_suffix}
  Bazarr:        http://bazarr.${domain_suffix}
  FlareSolverr:  http://flaresolverr.${domain_suffix}

HTTPS is also available on the same hostnames (Caddy issues an internal certificate).

Gluetun control server (local only): http://${LOCALHOST_IP}:${GLUETUN_CONTROL_PORT}

Helper commands:
  source ${ARR_STACK_DIR}/.arraliases
  arr.help       # Show all available aliases
  arr.vpn.status # Check VPN status and forwarded port
  arr.logs       # Follow container logs via docker compose

SUMMARY
}

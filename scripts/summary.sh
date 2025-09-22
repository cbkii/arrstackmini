# shellcheck shell=bash
show_summary() {

  msg "🎉 Setup complete!!"
  warn "Check these details and revisit the README for any manual steps you may need to perform from here"

  local lan_binding_summary="LAN binding target: ${LAN_IP:-<unset>}"
  if [[ -n "${LAN_IP_EFFECTIVE_IFACE:-}" ]]; then
    lan_binding_summary+=" on ${LAN_IP_EFFECTIVE_IFACE}"
  fi
  if [[ -n "${LAN_IP_EFFECTIVE_METHOD:-}" ]]; then
    lan_binding_summary+=" (${LAN_IP_EFFECTIVE_METHOD})"
  fi
  msg "$lan_binding_summary"

  case "${LOCAL_DNS_SERVICE_REASON}" in
    auto-disabled-port-conflict)
      warn "Local DNS container disabled automatically because ${LOCAL_DNS_AUTO_DISABLED_REASON}. Free port 53 and rerun without --auto-disable-local-dns (or set AUTO_DISABLE_LOCAL_DNS=0) to restore it."
      ;;
    invalid-ip)
      warn "Local DNS container skipped because LAN_IP (${LAN_IP:-<unset>}) is not a specific address. Update arrconf/userconf.sh and rerun."
      ;;
  esac

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

  local helper_script_path="${REPO_ROOT}/scripts/setup-lan-dns.sh"
  case "${LOCAL_DNS_HELPER_STATUS}" in
    skipped-missing-ip)
      warn "Local DNS host entries were not updated because LAN_IP was unavailable. Provide a valid LAN_IP and rerun arrstack.sh --setup-host-dns if needed."
      ;;
    skipped-unassigned)
      warn "Local DNS host entries were not updated because LAN_IP ${LAN_IP:-<unset>} is not assigned on this host."
      ;;
    missing-script)
      warn "Local DNS helper script not found at ${helper_script_path}; host entries were not configured."
      ;;
    not-executable)
      warn "Local DNS helper script at ${helper_script_path} is not executable; run chmod +x to allow host entry updates."
      ;;
    failed-invalid-ip)
      warn "Local DNS helper skipped because LAN_IP is 0.0.0.0; update LAN_IP and rerun."
      ;;
    failed)
      warn "Local DNS helper could not update /etc/hosts; rerun arrstack.sh with sudo if host entries are desired."
      ;;
  esac

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


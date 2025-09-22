# shellcheck shell=bash

validate_proton_creds() {
  local user="$1"
  local pass="$2"

  if [ ${#user} -lt 3 ] || [ ${#pass} -lt 6 ]; then
    return 1
  fi

  if [[ "$user" =~ [[:space:]] ]] || [[ "$pass" =~ [[:space:]] ]]; then
    return 1
  fi

  return 0
}

calculate_qbt_auth_whitelist() {
  local auth_whitelist=""

  append_whitelist_entry() {
    local entry="${1-}"
    entry="${entry//[[:space:]]/}"
    if [[ -z "$entry" ]]; then
      return
    fi
    if [[ ",${auth_whitelist}," == *",${entry},"* ]]; then
      return
    fi
    if [[ -z "$auth_whitelist" ]]; then
      auth_whitelist="$entry"
    else
      auth_whitelist="${auth_whitelist},${entry}"
    fi
  }

  if [[ -n "${QBT_AUTH_WHITELIST:-}" ]]; then
    local sanitized="${QBT_AUTH_WHITELIST//[[:space:]]/}"
    if [[ -n "$sanitized" ]]; then
      local -a entries=()
      IFS=',' read -ra entries <<<"$sanitized"
      local entry
      for entry in "${entries[@]}"; do
        append_whitelist_entry "$entry"
      done
    fi
  fi

  if [[ -n "${CADDY_LAN_CIDRS:-}" ]]; then
    local lan_entries
    lan_entries="${CADDY_LAN_CIDRS//,/ }"
    lan_entries="${lan_entries//$'\n'/ }"
    for entry in $lan_entries; do
      append_whitelist_entry "$entry"
    done
  fi

  append_whitelist_entry "127.0.0.1/32"
  append_whitelist_entry "127.0.0.0/8"
  append_whitelist_entry "::1/128"

  if [[ -n "${LAN_IP:-}" && "$LAN_IP" != "0.0.0.0" && "$LAN_IP" == *.*.*.* ]]; then
    append_whitelist_entry "${LAN_IP%.*}.0/24"
  fi

  if [[ -z "$auth_whitelist" ]]; then
    auth_whitelist="127.0.0.1/32,127.0.0.0/8,::1/128"
  fi

  printf '%s' "$auth_whitelist"
  unset -f append_whitelist_entry || true
}

load_proton_credentials() {
  local proton_file="${ARRCONF_DIR}/proton.auth"

  PROTON_USER_VALUE=""
  PROTON_PASS_VALUE=""
  OPENVPN_USER_VALUE=""
  PROTON_USER_PMP_ADDED=0

  if [[ -f "$proton_file" ]]; then
    PROTON_USER_VALUE="$(grep '^PROTON_USER=' "$proton_file" | head -n1 | cut -d= -f2- | tr -d '\r' || true)"
    PROTON_PASS_VALUE="$(grep '^PROTON_PASS=' "$proton_file" | head -n1 | cut -d= -f2- | tr -d '\r' || true)"
  fi

  if [[ -z "$PROTON_USER_VALUE" || -z "$PROTON_PASS_VALUE" ]]; then
    die "Missing or empty PROTON_USER/PROTON_PASS in ${proton_file}"
  fi

  local enforced
  enforced="${PROTON_USER_VALUE%+pmp}+pmp"
  if [[ "$enforced" != "$PROTON_USER_VALUE" ]]; then
    PROTON_USER_PMP_ADDED=1
  fi

  OPENVPN_USER_VALUE="$enforced"
}

show_configuration_preview() {
  msg "🔎 Configuration preview"

  if [[ -z "$PROTON_USER_VALUE" || -z "$PROTON_PASS_VALUE" ]]; then
    load_proton_credentials
  fi

  local proton_user="${PROTON_USER_VALUE}"
  local proton_pass="${PROTON_PASS_VALUE}"
  local openvpn_user="${OPENVPN_USER_VALUE}"

  local proton_user_display="${proton_user:-'(not set)'}"
  local proton_pass_display
  proton_pass_display="$(obfuscate_sensitive "$proton_pass")"

  local qbt_pass_display
  qbt_pass_display="$(obfuscate_sensitive "${QBT_PASS:-}")"

  local openvpn_user_display
  if [[ -n "$openvpn_user" ]]; then
    openvpn_user_display="$(obfuscate_sensitive "$openvpn_user" 2 4)"
  else
    openvpn_user_display="(not set)"
  fi

  local gluetun_api_key_display
  if [[ -n "${GLUETUN_API_KEY:-}" ]]; then
    gluetun_api_key_display="$(obfuscate_sensitive "$GLUETUN_API_KEY")"
  else
    gluetun_api_key_display="(will be generated during setup)"
  fi

  local qbt_auth_whitelist_preview
  qbt_auth_whitelist_preview="$(calculate_qbt_auth_whitelist)"
  local lan_ip_display
  if [[ -n "${LAN_IP:-}" ]]; then
    lan_ip_display="$LAN_IP"
  else
    lan_ip_display="(auto-detect during setup)"
  fi

  cat <<CONFIG
------------------------------------------------------------
ARR Stack configuration preview
------------------------------------------------------------
Paths
  • Stack directory: ${ARR_STACK_DIR}
  • Docker data root: ${ARR_DOCKER_DIR}
  • Downloads: ${DOWNLOADS_DIR}
  • Completed downloads: ${COMPLETED_DIR}
  • TV library: ${TV_DIR}
  • Movies library: ${MOVIES_DIR}
$([[ -n "${SUBS_DIR:-}" ]] && printf '  • Subtitles directory: %s\n' "${SUBS_DIR}")

Network & system
  • Timezone: ${TIMEZONE}
  • LAN IP: ${lan_ip_display}
  • Localhost IP override: ${LOCALHOST_IP}
  • Server countries: ${SERVER_COUNTRIES}
  • User/Group IDs: ${PUID}/${PGID}

Credentials & secrets
  • Proton username: ${proton_user_display}
  • Proton OpenVPN username (+pmp enforced): ${openvpn_user_display}
  • Proton password: ${proton_pass_display}
  • Gluetun API key: ${gluetun_api_key_display}
  • qBittorrent username: ${QBT_USER}
  • qBittorrent password: ${qbt_pass_display}
  • qBittorrent auth whitelist (final): ${qbt_auth_whitelist_preview}
  • qBittorrent auth whitelist: ${QBT_AUTH_WHITELIST}

Ports
  • Gluetun control: ${GLUETUN_CONTROL_PORT}
  • qBittorrent WebUI (host): ${QBT_HTTP_PORT_HOST}
  • Sonarr: ${SONARR_PORT}
  • Radarr: ${RADARR_PORT}
  • Prowlarr: ${PROWLARR_PORT}
  • Bazarr: ${BAZARR_PORT}
  • FlareSolverr: ${FLARESOLVERR_PORT}

Files that will be created/updated
  • Environment file: ${ARR_ENV_FILE}
  • Compose file: ${ARR_STACK_DIR}/docker-compose.yml

If anything looks incorrect, edit arrconf/userconf.sh before continuing.
------------------------------------------------------------
CONFIG
}

validate_config() {
  if [ -n "${LAN_IP:-}" ] && [ "${LAN_IP}" != "0.0.0.0" ]; then
    validate_ipv4 "$LAN_IP" || die "Invalid LAN_IP: ${LAN_IP}"
    assert_ip_assigned "$LAN_IP"
  fi
  validate_port "$GLUETUN_CONTROL_PORT" || die "Invalid GLUETUN_CONTROL_PORT: ${GLUETUN_CONTROL_PORT}"
  validate_port "$QBT_HTTP_PORT_HOST" || die "Invalid QBT_HTTP_PORT_HOST: ${QBT_HTTP_PORT_HOST}"
  validate_port "$SONARR_PORT" || die "Invalid SONARR_PORT: ${SONARR_PORT}"
  validate_port "$RADARR_PORT" || die "Invalid RADARR_PORT: ${RADARR_PORT}"
  validate_port "$PROWLARR_PORT" || die "Invalid PROWLARR_PORT: ${PROWLARR_PORT}"
  validate_port "$BAZARR_PORT" || die "Invalid BAZARR_PORT: ${BAZARR_PORT}"
  validate_port "$FLARESOLVERR_PORT" || die "Invalid FLARESOLVERR_PORT: ${FLARESOLVERR_PORT}"

  validate_proton_creds "$PU" "$PW" || die "Invalid ProtonVPN credentials format"
}

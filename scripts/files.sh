# shellcheck shell=bash
caddy_bcrypt() {
  local plaintext="${1-}"

  if [[ -z "$plaintext" ]]; then
    return 1
  fi

  local hash_output=""

  if command -v openssl >/dev/null 2>&1; then
    hash_output="$(
      printf '%s\n' "$plaintext" \
        | openssl passwd -bcrypt -stdin 2>/dev/null
    )" || true

    if [[ -n "$hash_output" ]]; then
      printf '%s\n' "$hash_output"
      return 0
    fi
  fi

  docker run --rm "${CADDY_IMAGE}" caddy hash-password --algorithm bcrypt --plaintext "$plaintext" 2>/dev/null
}

arrstack_track_created_media_dir() {
  local dir="$1"

  if [[ -z "$dir" ]]; then
    return 0
  fi

  if [[ -z "${COLLAB_CREATED_MEDIA_DIRS:-}" ]]; then
    COLLAB_CREATED_MEDIA_DIRS="$dir"
  else
    local padded=$'\n'"${COLLAB_CREATED_MEDIA_DIRS}"$'\n'
    local needle=$'\n'"${dir}"$'\n'
    if [[ "$padded" != *"${needle}"* ]]; then
      COLLAB_CREATED_MEDIA_DIRS+=$'\n'"${dir}"
    fi
  fi
}

arrstack_report_collab_skip() {
  if [[ -n "${COLLAB_GROUP_WRITE_DISABLED_REASON:-}" ]]; then
    arrstack_append_collab_warning "${COLLAB_GROUP_WRITE_DISABLED_REASON}"
  fi
}

mkdirs() {
  msg "📁 Creating directories"
  ensure_dir_mode "$ARR_STACK_DIR" 755

  ensure_dir_mode "$ARR_DOCKER_DIR" "$DATA_DIR_MODE"

  local service
  for service in "${ARR_DOCKER_SERVICES[@]}"; do
    if [[ "$service" == "local_dns" && "${ENABLE_LOCAL_DNS:-0}" -ne 1 ]]; then
      continue
    fi
    if [[ "$service" == "caddy" && "${ENABLE_CADDY:-0}" -ne 1 ]]; then
      continue
    fi
    ensure_dir_mode "${ARR_DOCKER_DIR}/${service}" "$DATA_DIR_MODE"
  done

  local collab_enabled=0
  if [[ "${ARR_PERMISSION_PROFILE}" == "collab" && "${COLLAB_GROUP_WRITE_ENABLED:-0}" -eq 1 ]]; then
    collab_enabled=1
  elif [[ "${ARR_PERMISSION_PROFILE}" == "collab" ]]; then
    arrstack_report_collab_skip
  fi

  collab_warn_permission_failure() {
    local message="$1"

    if [[ -z "$message" ]]; then
      return 0
    fi

    local already_listed=0
    if [[ -n "${COLLAB_PERMISSION_WARNINGS:-}" ]]; then
      local padded=$'\n'"${COLLAB_PERMISSION_WARNINGS}"$'\n'
      local needle=$'\n'"${message}"$'\n'
      if [[ "$padded" == *"${needle}"* ]]; then
        already_listed=1
      fi
    fi

    if ((already_listed == 0)); then
      warn "$message"
    fi

    arrstack_append_collab_warning "$message"
  }

  collab_remediate_dir() {
    local dir="$1"
    local label="$2"

    if [[ -z "$dir" || -z "$label" || ! -d "$dir" ]]; then
      return 0
    fi

    chmod "$DATA_DIR_MODE" "$dir" 2>/dev/null || true

    if arrstack_is_group_writable "$dir"; then
      return 0
    fi

    local message
    message="${label} directory not group-writable and could not apply ${DATA_DIR_MODE} (collab) — fix manually: ${dir}"
    collab_warn_permission_failure "$message"
  }

  ensure_dir "$DOWNLOADS_DIR"
  if ((collab_enabled)); then
    collab_remediate_dir "$DOWNLOADS_DIR" "Downloads"
  fi

  ensure_dir "$COMPLETED_DIR"
  if ((collab_enabled)); then
    collab_remediate_dir "$COMPLETED_DIR" "Completed"
  fi

  ensure_dir_mode "$ARR_STACK_DIR/scripts" 755

  if [[ -d "$ARRCONF_DIR" ]]; then
    ensure_dir_mode "$ARRCONF_DIR" 700
    if [[ -f "${ARRCONF_DIR}/proton.auth" ]]; then
      ensure_secret_file_mode "${ARRCONF_DIR}/proton.auth"
    fi
  fi

  manage_media_dir() {
    local dir="$1"
    local label="$2"
    if [[ -z "$dir" ]]; then
      return 0
    fi

    if [[ ! -d "$dir" ]]; then
      warn "${label} directory does not exist: ${dir}"
      warn "Creating it now (may fail if parent directory is missing)"
      if mkdir -p "$dir" 2>/dev/null; then
        arrstack_track_created_media_dir "$dir"
      else
        warn "Could not create ${label} directory"
        return 0
      fi
    fi

    if ((collab_enabled)); then
      # Attempt remediation before warning so existing libraries are auto-fixed when possible.
      collab_remediate_dir "$dir" "$label"
    fi
  }

  manage_media_dir "$TV_DIR" "TV"
  manage_media_dir "$MOVIES_DIR" "Movies"

  if [[ -n "${SUBS_DIR:-}" ]]; then
    manage_media_dir "$SUBS_DIR" "Subtitles"
  fi

  if [[ -n "${PUID:-}" && -n "${PGID:-}" ]]; then
    local ownership_marker="${ARR_DOCKER_DIR}/.arrstack-owner"
    local desired_owner="${PUID}:${PGID}"
    local current_owner=""

    if [[ -f "$ownership_marker" ]]; then
      current_owner="$(<"$ownership_marker")"
    fi

    if [[ "$current_owner" != "$desired_owner" ]]; then
      if chown -R "${desired_owner}" "$ARR_DOCKER_DIR" 2>/dev/null; then
        printf '%s\n' "$desired_owner" >"$ownership_marker" 2>/dev/null || true
      else
        warn "Could not update ownership on $ARR_DOCKER_DIR"
      fi
    fi
  fi
}

generate_api_key() {
  msg "🔐 Generating API key"

  if [[ -f "$ARR_ENV_FILE" ]] && [[ "$FORCE_ROTATE_API_KEY" != 1 ]]; then
    local existing
    existing="$(grep '^GLUETUN_API_KEY=' "$ARR_ENV_FILE" 2>/dev/null | cut -d= -f2- || true)"
    if [[ -n "$existing" ]]; then
      existing="$(unescape_env_value_from_compose "$existing")"
      GLUETUN_API_KEY="$existing"
      msg "Using existing API key"
      return
    fi
  fi

  GLUETUN_API_KEY="$(openssl rand -base64 48 | tr -d '\n/')"
  msg "Generated new API key"
}

hydrate_caddy_auth_from_env_file() {
  if [[ -z "${ARR_ENV_FILE:-}" || ! -f "$ARR_ENV_FILE" ]]; then
    return 0
  fi

  if [[ -z "${CADDY_BASIC_AUTH_USER:-}" || "${CADDY_BASIC_AUTH_USER}" == "user" ]]; then
    local hydrated_user=""
    if hydrated_user="$(get_env_kv "CADDY_BASIC_AUTH_USER" "$ARR_ENV_FILE" 2>/dev/null)"; then
      if [[ -n "$hydrated_user" ]]; then
        CADDY_BASIC_AUTH_USER="$hydrated_user"
      fi
    fi
  fi

  if [[ -z "${CADDY_BASIC_AUTH_HASH:-}" ]]; then
    local hydrated_hash=""
    if hydrated_hash="$(get_env_kv "CADDY_BASIC_AUTH_HASH" "$ARR_ENV_FILE" 2>/dev/null)"; then
      if [[ -n "$hydrated_hash" ]]; then
        CADDY_BASIC_AUTH_HASH="$hydrated_hash"
      fi
    fi
  fi
}

write_env() {
  msg "📝 Writing .env file"

  hydrate_caddy_auth_from_env_file

  CADDY_BASIC_AUTH_USER="$(sanitize_user "$CADDY_BASIC_AUTH_USER")"

  local direct_ports_requested="${EXPOSE_DIRECT_PORTS:-0}"
  local userconf_path="${ARR_USERCONF_PATH:-${ARR_BASE:-${HOME}/srv}/userr.conf}"

  if [[ -z "${LAN_IP:-}" || "$LAN_IP" == "0.0.0.0" ]]; then
    if detected_ip="$(detect_lan_ip 2>/dev/null)"; then
      LAN_IP="$detected_ip"
      msg "Auto-detected LAN_IP: $LAN_IP"
    else
      LAN_IP="0.0.0.0"
      warn "LAN_IP could not be detected automatically; set it in ${userconf_path} so services bind to the correct interface."
    fi
  else
    msg "Using configured LAN_IP: $LAN_IP"
  fi

  if (( direct_ports_requested == 1 )); then
    if [[ -z "${LAN_IP:-}" || "$LAN_IP" == "0.0.0.0" ]]; then
      die "EXPOSE_DIRECT_PORTS=1 requires LAN_IP to be set to your host's private IPv4 address in ${userconf_path}."
    fi
    if ! is_private_ipv4 "$LAN_IP"; then
      die "LAN_IP='${LAN_IP}' is not a private IPv4 address. Set LAN_IP to your LAN host IP before exposing ports."
    fi
  fi

  load_proton_credentials

  PU="$OPENVPN_USER_VALUE"
  PW="$PROTON_PASS_VALUE"

  validate_config "$PU" "$PW"

  if [[ -z "${COMPOSE_PROJECT_NAME:-}" ]]; then
    local existing_project_name=""
    if existing_project_name="$(get_env_kv "COMPOSE_PROJECT_NAME" "$ARR_ENV_FILE" 2>/dev/null)"; then
      COMPOSE_PROJECT_NAME="$existing_project_name"
    else
      COMPOSE_PROJECT_NAME="arrstack"
    fi
  fi
  local dns_host_entry="${LAN_IP:-0.0.0.0}"
  if [[ -z "$dns_host_entry" || "$dns_host_entry" == "0.0.0.0" ]]; then
    dns_host_entry="HOST_IP"
  fi
  local -a outbound_candidates=("192.168.0.0/16" "10.0.0.0/8" "172.16.0.0/12")
  local lan_private_subnet=""
  if lan_private_subnet="$(lan_ipv4_subnet_cidr "$LAN_IP" 2>/dev/null)"; then
    outbound_candidates=("$lan_private_subnet" "${outbound_candidates[@]}")
  fi
  local gluetun_firewall_outbound
  gluetun_firewall_outbound="$(printf '%s\n' "${outbound_candidates[@]}" | sort -u | paste -sd, -)"

  local -a firewall_ports=()
  if [[ "${ENABLE_CADDY:-0}" -eq 1 ]]; then
    firewall_ports+=(80 443)
  fi
  if [[ "${EXPOSE_DIRECT_PORTS:-0}" -eq 1 ]]; then
    firewall_ports+=("${QBT_HTTP_PORT_HOST}" "${SONARR_PORT}" "${RADARR_PORT}" "${PROWLARR_PORT}" "${BAZARR_PORT}" "${FLARESOLVERR_PORT}")
  fi

  local -a upstream_dns_servers=()
  mapfile -t upstream_dns_servers < <(collect_upstream_dns_servers)

  if ((${#upstream_dns_servers[@]} > 0)); then
    UPSTREAM_DNS_SERVERS="$(IFS=','; printf '%s' "${upstream_dns_servers[*]}")"
    UPSTREAM_DNS_1="${upstream_dns_servers[0]}"
    UPSTREAM_DNS_2="${upstream_dns_servers[1]:-}"
  else
    UPSTREAM_DNS_SERVERS=""
    UPSTREAM_DNS_1=""
    UPSTREAM_DNS_2=""
  fi

  local firewall_ports_csv=""
  if ((${#firewall_ports[@]})); then
    local -A seen_firewall_ports=()
    local firewall_port
    for firewall_port in "${firewall_ports[@]}"; do
      if [[ -n "$firewall_port" && -z "${seen_firewall_ports[$firewall_port]:-}" ]]; then
        seen_firewall_ports["$firewall_port"]=1
        firewall_ports_csv+="${firewall_ports_csv:+,}${firewall_port}"
      fi
    done
  fi

  local -a compose_profiles=(ipdirect)
  if [[ "${ENABLE_CADDY:-0}" -eq 1 ]]; then
    compose_profiles+=(proxy)
  fi
  if [[ "${ENABLE_LOCAL_DNS:-0}" -eq 1 ]]; then
    compose_profiles+=(localdns)
  fi

  local compose_profiles_csv=""
  if ((${#compose_profiles[@]})); then
    local -A seen_profiles=()
    local profile
    for profile in "${compose_profiles[@]}"; do
      if [[ -n "$profile" && -z "${seen_profiles[$profile]:-}" ]]; then
        seen_profiles["$profile"]=1
        compose_profiles_csv+="${compose_profiles_csv:+,}${profile}"
      fi
    done
  fi

  local qbt_whitelist_raw
  qbt_whitelist_raw="${QBT_AUTH_WHITELIST:-}"
  if [[ -z "$qbt_whitelist_raw" ]]; then
    qbt_whitelist_raw="127.0.0.1/32,::1/128"
  fi
  if [[ -n "$lan_private_subnet" ]]; then
    qbt_whitelist_raw+="${qbt_whitelist_raw:+,}${lan_private_subnet}"
  fi
  QBT_AUTH_WHITELIST="$(normalize_csv "$qbt_whitelist_raw")"
  local tmp
  tmp="$(arrstack_mktemp_file "${ARR_ENV_FILE}.XXXXXX.tmp")" || die "Failed to create temp file for ${ARR_ENV_FILE}"

  {
    printf '# Core settings\n'
    write_env_kv "VPN_TYPE" "openvpn"
    write_env_kv "PUID" "$PUID"
    write_env_kv "PGID" "$PGID"
    write_env_kv "TIMEZONE" "$TIMEZONE"
    write_env_kv "LAN_IP" "$LAN_IP"
    write_env_kv "LOCALHOST_IP" "$LOCALHOST_IP"
    write_env_kv "EXPOSE_DIRECT_PORTS" "$EXPOSE_DIRECT_PORTS"
    write_env_kv "ENABLE_CADDY" "$ENABLE_CADDY"
    printf '\n'

    printf '# Optional tooling\\n'
    write_env_kv "ENABLE_CONFIGARR" "$ENABLE_CONFIGARR"
    printf '\n'

    printf '# Local DNS (disabled by default)\n'
    printf '# Preferred comma-separated chain (legacy UPSTREAM_DNS_1/UPSTREAM_DNS_2 remain supported).\n'
    write_env_kv "LAN_DOMAIN_SUFFIX" "$LAN_DOMAIN_SUFFIX"
    write_env_kv "ENABLE_LOCAL_DNS" "$ENABLE_LOCAL_DNS"
    write_env_kv "DNS_DISTRIBUTION_MODE" "$DNS_DISTRIBUTION_MODE"
    write_env_kv "UPSTREAM_DNS_SERVERS" "$UPSTREAM_DNS_SERVERS"
    write_env_kv "UPSTREAM_DNS_1" "$UPSTREAM_DNS_1"
    write_env_kv "UPSTREAM_DNS_2" "$UPSTREAM_DNS_2"
    write_env_kv "DNS_HOST_ENTRY" "$dns_host_entry"
    printf '\n'

    printf '# ProtonVPN OpenVPN credentials\n'
    write_env_kv "OPENVPN_USER" "$PU"
    write_env_kv "OPENVPN_PASSWORD" "$PW"
    printf '\n'

    printf '# Derived values\n'
    write_env_kv "OPENVPN_USER_ENFORCED" "$PU"
    write_env_kv "COMPOSE_PROJECT_NAME" "$COMPOSE_PROJECT_NAME"
    write_env_kv "COMPOSE_PROFILES" "$compose_profiles_csv"
    printf '\n'

    printf '# Gluetun settings\n'
    write_env_kv "VPN_SERVICE_PROVIDER" "protonvpn"
    write_env_kv "GLUETUN_API_KEY" "$GLUETUN_API_KEY"
    write_env_kv "GLUETUN_CONTROL_PORT" "$GLUETUN_CONTROL_PORT"
    write_env_kv "SERVER_COUNTRIES" "$SERVER_COUNTRIES"
    write_env_kv "GLUETUN_FIREWALL_INPUT_PORTS" "$firewall_ports_csv"
    write_env_kv "GLUETUN_FIREWALL_OUTBOUND_SUBNETS" "$gluetun_firewall_outbound"
    printf '\n'

    printf '# Service ports\n'
    write_env_kv "QBT_HTTP_PORT_HOST" "$QBT_HTTP_PORT_HOST"
    write_env_kv "SONARR_PORT" "$SONARR_PORT"
    write_env_kv "RADARR_PORT" "$RADARR_PORT"
    write_env_kv "PROWLARR_PORT" "$PROWLARR_PORT"
    write_env_kv "BAZARR_PORT" "$BAZARR_PORT"
    write_env_kv "FLARESOLVERR_PORT" "$FLARESOLVERR_PORT"
    printf '\n'

    printf '# qBittorrent credentials (change in WebUI after install, then update here)\n'
    write_env_kv "QBT_USER" "$QBT_USER"
    write_env_kv "QBT_PASS" "$QBT_PASS"
    write_env_kv "QBT_DOCKER_MODS" "$QBT_DOCKER_MODS"
    write_env_kv "QBT_AUTH_WHITELIST" "$QBT_AUTH_WHITELIST"
    printf '\n'

    printf '# Reverse proxy defaults\n'
    write_env_kv "CADDY_DOMAIN_SUFFIX" "$ARR_DOMAIN_SUFFIX_CLEAN"
    write_env_kv "CADDY_LAN_CIDRS" "$CADDY_LAN_CIDRS"
    write_env_kv "CADDY_BASIC_AUTH_USER" "$CADDY_BASIC_AUTH_USER"
    write_env_kv "CADDY_BASIC_AUTH_HASH" "$(unescape_env_value_from_compose "$CADDY_BASIC_AUTH_HASH")"
    printf '\n'

    printf '# Paths\n'
    write_env_kv "ARR_DOCKER_DIR" "$ARR_DOCKER_DIR"
    write_env_kv "DOWNLOADS_DIR" "$DOWNLOADS_DIR"
    write_env_kv "COMPLETED_DIR" "$COMPLETED_DIR"
    write_env_kv "TV_DIR" "$TV_DIR"
    write_env_kv "MOVIES_DIR" "$MOVIES_DIR"
    if [[ -n "${SUBS_DIR:-}" ]]; then
      write_env_kv "SUBS_DIR" "$SUBS_DIR"
    fi
    printf '\n'

    printf '# Images\n'
    write_env_kv "GLUETUN_IMAGE" "$GLUETUN_IMAGE"
    write_env_kv "QBITTORRENT_IMAGE" "$QBITTORRENT_IMAGE"
    write_env_kv "SONARR_IMAGE" "$SONARR_IMAGE"
    write_env_kv "RADARR_IMAGE" "$RADARR_IMAGE"
    write_env_kv "PROWLARR_IMAGE" "$PROWLARR_IMAGE"
    write_env_kv "BAZARR_IMAGE" "$BAZARR_IMAGE"
    write_env_kv "FLARESOLVERR_IMAGE" "$FLARESOLVERR_IMAGE"
    write_env_kv "CONFIGARR_IMAGE" "$CONFIGARR_IMAGE"
    write_env_kv "CADDY_IMAGE" "$CADDY_IMAGE"
  } >"$tmp"

  mv "$tmp" "$ARR_ENV_FILE"

}

write_compose() {
    msg "🐳 Writing docker-compose.yml"

    local compose_path="${ARR_STACK_DIR}/docker-compose.yml"
    local tmp

    LOCAL_DNS_SERVICE_ENABLED=0
    local include_caddy=0
    local include_local_dns=0
    local local_dns_state_message="Local DNS container disabled (ENABLE_LOCAL_DNS=0)"
    local -a upstream_dns_servers=()
    local userconf_path="${ARR_USERCONF_PATH:-${ARR_BASE:-${HOME}/srv}/userr.conf}"

    mapfile -t upstream_dns_servers < <(collect_upstream_dns_servers)

    if [[ "${ENABLE_CADDY:-0}" -eq 1 ]]; then
      include_caddy=1
    fi

    if [[ "${ENABLE_LOCAL_DNS:-0}" -eq 1 ]]; then
      include_local_dns=1
      local_dns_state_message="Local DNS container requested"
    fi

    if ((include_local_dns)); then
      if port_bound_any udp 53 || port_bound_any tcp 53; then
        include_local_dns=0
        local_dns_state_message="Local DNS disabled automatically (port 53 already in use)"
        warn "Port 53 is already in use (likely systemd-resolved). Local DNS will be disabled (LOCAL_DNS_SERVICE_ENABLED=0)."
      fi
    fi

    if ((include_local_dns)); then
      LOCAL_DNS_SERVICE_ENABLED=1
      local_dns_state_message="Local DNS container enabled"
      if [[ -z "${LAN_IP:-}" || "${LAN_IP}" == "0.0.0.0" ]]; then
        warn "Local DNS will bind to all interfaces (0.0.0.0:53)"
      fi
    fi

    tmp="$(arrstack_mktemp_file "${compose_path}.XXXXXX.tmp" "$NONSECRET_FILE_MODE")" || die "Failed to create temp file for ${compose_path}"
    ensure_nonsecret_file_mode "$tmp"

    {
      if ((include_caddy == 0)); then
        printf '# Caddy reverse proxy disabled (ENABLE_CADDY=0).\n'
        printf '# Set ENABLE_CADDY=1 in %s and rerun ./arrstack.sh to add HTTPS hostnames via Caddy.\n' "$userconf_path"
      fi

      cat <<'YAML'
services:
  gluetun:
    image: ${GLUETUN_IMAGE}
    container_name: gluetun
    profiles:
      - ipdirect
    cap_add:
      - NET_ADMIN
    devices:
      - /dev/net/tun
    environment:
      VPN_SERVICE_PROVIDER: ${VPN_SERVICE_PROVIDER}
      VPN_TYPE: openvpn
      OPENVPN_USER: ${OPENVPN_USER}
      OPENVPN_PASSWORD: ${OPENVPN_PASSWORD}
      OPENVPN_CUSTOM_CONFIG: ""
      FREE_ONLY: "off"
      SERVER_COUNTRIES: ${SERVER_COUNTRIES}
      VPN_PORT_FORWARDING: "on"
      VPN_PORT_FORWARDING_PROVIDER: protonvpn
      HTTP_CONTROL_SERVER_ADDRESS: 0.0.0.0:${GLUETUN_CONTROL_PORT}
      HTTP_CONTROL_SERVER_AUTH: "apikey"
      HTTP_CONTROL_SERVER_APIKEY: "${GLUETUN_API_KEY}"
      VPN_PORT_FORWARDING_UP_COMMAND: "/gluetun/hooks/update-qbt-port.sh {{PORTS}}"
      QBT_USER: ${QBT_USER}
      QBT_PASS: ${QBT_PASS}
      QBITTORRENT_ADDR: "http://127.0.0.1:8080"
      PORT_FORWARD_ONLY: "on"
      HEALTH_TARGET_ADDRESS: "1.1.1.1:443"
      HEALTH_VPN_DURATION_INITIAL: "30s"
      HEALTH_VPN_DURATION_ADDITION: "10s"
      HEALTH_SUCCESS_WAIT_DURATION: "10s"
      DNS_KEEP_NAMESERVER: "off"
      FIREWALL_OUTBOUND_SUBNETS: ${GLUETUN_FIREWALL_OUTBOUND_SUBNETS}
      FIREWALL_INPUT_PORTS: ${GLUETUN_FIREWALL_INPUT_PORTS}
      UPDATER_PERIOD: "24h"
      PUID: ${PUID}
      PGID: ${PGID}
      TZ: ${TIMEZONE}
    volumes:
      - ${ARR_DOCKER_DIR}/gluetun:/gluetun
    ports:
      - "${LOCALHOST_IP}:${GLUETUN_CONTROL_PORT}:${GLUETUN_CONTROL_PORT}"
YAML
    } >"$tmp"

    if ((include_caddy)); then
      cat <<'YAML' >>"$tmp"
      - "${LAN_IP}:80:80"
      - "${LAN_IP}:443:443"
YAML
    fi

    if [[ "${EXPOSE_DIRECT_PORTS:-0}" -eq 1 ]]; then
      cat <<'YAML' >>"$tmp"
      - "${LAN_IP}:${QBT_HTTP_PORT_HOST}:8080"
      - "${LAN_IP}:${SONARR_PORT}:${SONARR_PORT}"
      - "${LAN_IP}:${RADARR_PORT}:${RADARR_PORT}"
      - "${LAN_IP}:${PROWLARR_PORT}:${PROWLARR_PORT}"
      - "${LAN_IP}:${BAZARR_PORT}:${BAZARR_PORT}"
      - "${LAN_IP}:${FLARESOLVERR_PORT}:${FLARESOLVERR_PORT}"
YAML
    fi

    cat <<'YAML' >>"$tmp"
    healthcheck:
      test: /gluetun-entrypoint healthcheck
      interval: 30s
      timeout: 30s
      retries: 10
      start_period: 120s
    restart: unless-stopped
    logging:
      driver: json-file
      options:
        max-size: "1m"
        max-file: "3"
YAML

    if ((include_local_dns)); then
      cat <<'YAML' >>"$tmp"
  local_dns:
    image: 4km3/dnsmasq:2.90-r3
    container_name: arr_local_dns
    profiles:
      - localdns
    cap_add:
      - NET_ADMIN
    ports:
      - "${LAN_IP}:53:53/udp"
      - "${LAN_IP}:53:53/tcp"
    command:
      - --log-facility=-
      - --log-async=5
      - --log-queries
      - --no-resolv
YAML
      local server
      for server in "${upstream_dns_servers[@]}"; do
        printf '      - --server=%s\n' "$server"
      done >>"$tmp"
      cat <<'YAML' >>"$tmp"
      - --domain-needed
      - --bogus-priv
      - --local-service
      - --domain=${LAN_DOMAIN_SUFFIX}
      - --local=/${LAN_DOMAIN_SUFFIX}/
      - --address=/${LAN_DOMAIN_SUFFIX}/${DNS_HOST_ENTRY}
    restart: unless-stopped
    logging:
      driver: json-file
      options:
        max-size: "1m"
        max-file: "2"
    healthcheck:
      test:
        - "CMD-SHELL"
        - >
          if command -v drill >/dev/null 2>&1; then
            drill -Q example.com @127.0.0.1 >/dev/null 2>&1;
          elif command -v nslookup >/dev/null 2>&1; then
            nslookup example.com 127.0.0.1 >/dev/null 2>&1;
          elif command -v dig >/dev/null 2>&1; then
            dig +time=2 +tries=1 @127.0.0.1 example.com >/dev/null 2>&1;
          else
            exit 1;
          fi
      interval: 10s
      timeout: 3s
      retries: 6
      start_period: 10s

YAML
    fi

    cat <<'YAML' >>"$tmp"
  qbittorrent:
    image: ${QBITTORRENT_IMAGE}
    container_name: qbittorrent
    profiles:
      - ipdirect
    network_mode: "service:gluetun"
    environment:
      PUID: ${PUID}
      PGID: ${PGID}
      TZ: ${TIMEZONE}
      LANG: en_US.UTF-8
YAML
    if [[ -n "${QBT_DOCKER_MODS}" ]]; then
      printf "      DOCKER_MODS: \${QBT_DOCKER_MODS}\n" >>"$tmp"
    fi
    cat <<'YAML' >>"$tmp"
    volumes:
      - ${ARR_DOCKER_DIR}/qbittorrent:/config
      - ${DOWNLOADS_DIR}:/downloads
      - ${COMPLETED_DIR}:/completed
    depends_on:
      gluetun:
        condition: service_healthy
        restart: true
    healthcheck:
      test: ["CMD", "curl", "-f", "http://127.0.0.1:8080/api/v2/app/version"]
      interval: 30s
      timeout: 10s
      retries: 3
    restart: unless-stopped
    logging:
      driver: json-file
      options:
        max-size: "1m"
        max-file: "2"

  sonarr:
    image: ${SONARR_IMAGE}
    container_name: sonarr
    profiles:
      - ipdirect
    network_mode: "service:gluetun"
    environment:
      PUID: ${PUID}
      PGID: ${PGID}
      TZ: ${TIMEZONE}
      LANG: en_US.UTF-8
    volumes:
      - ${ARR_DOCKER_DIR}/sonarr:/config
      - ${DOWNLOADS_DIR}:/downloads
      - ${COMPLETED_DIR}:/completed
      - ${TV_DIR}:/tv
    depends_on:
      gluetun:
        condition: service_healthy
        restart: true
    restart: unless-stopped
    logging:
      driver: json-file
      options:
        max-size: "1m"
        max-file: "2"

  radarr:
    image: ${RADARR_IMAGE}
    container_name: radarr
    profiles:
      - ipdirect
    network_mode: "service:gluetun"
    environment:
      PUID: ${PUID}
      PGID: ${PGID}
      TZ: ${TIMEZONE}
      LANG: en_US.UTF-8
    volumes:
      - ${ARR_DOCKER_DIR}/radarr:/config
      - ${DOWNLOADS_DIR}:/downloads
      - ${COMPLETED_DIR}:/completed
      - ${MOVIES_DIR}:/movies
    depends_on:
      gluetun:
        condition: service_healthy
        restart: true
    restart: unless-stopped
    logging:
      driver: json-file
      options:
        max-size: "1m"
        max-file: "2"

  prowlarr:
    image: ${PROWLARR_IMAGE}
    container_name: prowlarr
    profiles:
      - ipdirect
    network_mode: "service:gluetun"
    environment:
      PUID: ${PUID}
      PGID: ${PGID}
      TZ: ${TIMEZONE}
      LANG: en_US.UTF-8
    volumes:
      - ${ARR_DOCKER_DIR}/prowlarr:/config
    depends_on:
      gluetun:
        condition: service_healthy
        restart: true
    restart: unless-stopped
    logging:
      driver: json-file
      options:
        max-size: "1m"
        max-file: "2"

  bazarr:
    image: ${BAZARR_IMAGE}
    container_name: bazarr
    profiles:
      - ipdirect
    network_mode: "service:gluetun"
    environment:
      PUID: ${PUID}
      PGID: ${PGID}
      TZ: ${TIMEZONE}
      LANG: en_US.UTF-8
    volumes:
      - ${ARR_DOCKER_DIR}/bazarr:/config
      - ${TV_DIR}:/tv
      - ${MOVIES_DIR}:/movies
YAML

    if [[ -n "${SUBS_DIR:-}" ]]; then
      cat <<'YAML' >>"$tmp"
      - ${SUBS_DIR}:/subs
YAML
    fi

    cat <<'YAML' >>"$tmp"
    depends_on:
      gluetun:
        condition: service_healthy
        restart: true
    restart: unless-stopped
    logging:
      driver: json-file
      options:
        max-size: "1m"
        max-file: "2"

  flaresolverr:
    image: ${FLARESOLVERR_IMAGE}
    container_name: flaresolverr
    profiles:
      - ipdirect
    network_mode: "service:gluetun"
    environment:
      LOG_LEVEL: info
    depends_on:
      gluetun:
        condition: service_healthy
        restart: true
    healthcheck:
      test:
        - "CMD-SHELL"
        - >
          if command -v curl >/dev/null 2>&1; then
            curl -fsS --max-time 10 http://127.0.0.1:${FLARESOLVERR_PORT}/health >/dev/null 2>&1;
          elif command -v wget >/dev/null 2>&1; then
            wget -qO- http://127.0.0.1:${FLARESOLVERR_PORT}/health >/dev/null 2>&1;
          else
            exit 1;
          fi
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    restart: unless-stopped
    logging:
      driver: json-file
      options:
        max-size: "1m"
        max-file: "2"
YAML

    if [[ "${ENABLE_CONFIGARR:-0}" -eq 1 ]]; then
      cat <<'YAML' >>"$tmp"
  configarr:
    image: ${CONFIGARR_IMAGE}
    container_name: configarr
    profiles:
      - ipdirect
    network_mode: "service:gluetun"
    depends_on:
      gluetun:
        condition: service_healthy
        restart: true
      sonarr:
        condition: service_started
      radarr:
        condition: service_started
    volumes:
      - ${ARR_DOCKER_DIR}/configarr/config.yml:/app/config.yml:ro
      - ${ARR_DOCKER_DIR}/configarr/secrets.yml:/app/secrets.yml:ro
      - ${ARR_DOCKER_DIR}/configarr/cfs:/app/cfs:ro
    working_dir: /app
    entrypoint: ["/bin/sh","-lc","node dist/index.js || exit 1"]
    environment:
      TZ: ${TIMEZONE}
    restart: "no"
    logging:
      driver: json-file
      options:
        max-size: "512k"
        max-file: "2"
YAML
    fi

    if ((include_caddy)); then
      cat <<'YAML' >>"$tmp"
  caddy:
    image: ${CADDY_IMAGE}
    container_name: caddy
    profiles:
      - proxy
    network_mode: "service:gluetun"
    volumes:
      - ${ARR_DOCKER_DIR}/caddy/Caddyfile:/etc/caddy/Caddyfile:ro
      - ${ARR_DOCKER_DIR}/caddy/data:/data
      - ${ARR_DOCKER_DIR}/caddy/config:/config
      - ${ARR_DOCKER_DIR}/caddy/ca-pub:/ca-pub:ro
    depends_on:
      gluetun:
        condition: service_healthy
        restart: true
YAML
      if ((include_local_dns)); then
        cat <<'YAML' >>"$tmp"
      local_dns:
        condition: service_healthy
YAML
      fi
      cat <<'YAML' >>"$tmp"
    healthcheck:
      test:
        - "CMD-SHELL"
        - >-
          curl -fsS --max-time 3 http://127.0.0.1/healthz >/dev/null 2>&1 || wget -qO- --timeout=3 http://127.0.0.1/healthz >/dev/null 2>&1
      interval: 10s
      timeout: 5s
      retries: 6
      start_period: 20s
    restart: unless-stopped
    logging:
      driver: json-file
      options:
        max-size: "1m"
        max-file: "2"
YAML
    fi

    if ! verify_single_level_env_placeholders "$tmp"; then
      rm -f "$tmp"
      die "Generated docker-compose.yml contains nested environment placeholders"
    fi

    mv "$tmp" "$compose_path"
    ensure_nonsecret_file_mode "$compose_path"

    msg "  Local DNS status: ${local_dns_state_message} (LOCAL_DNS_SERVICE_ENABLED=${LOCAL_DNS_SERVICE_ENABLED})"
}

write_gluetun_control_assets() {
  msg "🛡️ Preparing Gluetun control assets"

  local gluetun_root="${ARR_DOCKER_DIR}/gluetun"
  local hooks_dir="${gluetun_root}/hooks"

  ensure_dir "$gluetun_root"
  ensure_dir_mode "$hooks_dir" 700

  cat >"${hooks_dir}/update-qbt-port.sh" <<'HOOK'
#!/bin/sh
set -eu

log() {
    printf '[%s] [update-qbt-port] %s\n' "$(date '+%Y-%m-%dT%H:%M:%S')" "$1" >&2
}

if ! command -v curl >/dev/null 2>&1; then
    log "curl not available inside Gluetun; skipping port update"
    exit 0
fi

PORT_SPEC="${1:-}"
PORT_VALUE="${PORT_SPEC%%,*}"
PORT_VALUE="${PORT_VALUE%%:*}"

case "$PORT_VALUE" in
    ''|*[!0-9]*)
        log "Ignoring non-numeric port payload: ${PORT_SPEC}"
        exit 0
        ;;
esac

QBITTORRENT_ADDR="${QBITTORRENT_ADDR:-http://127.0.0.1:8080}"
PAYLOAD=$(printf 'json={\"listen_port\":%s,\"random_port\":false}' "$PORT_VALUE")

if curl -fsS --max-time 8 \
    --data "$PAYLOAD" \
    "${QBITTORRENT_ADDR%/}/api/v2/app/setPreferences" >/dev/null 2>&1; then
    log "Updated qBittorrent listen port to ${PORT_VALUE}"
    exit 0
fi

if [ -n "${QBT_USER:-}" ] && [ -n "${QBT_PASS:-}" ]; then
    COOKIE="$(mktemp)"
    trap 'rm -f "$COOKIE"' INT TERM EXIT
    if curl -fsS --max-time 5 -c "$COOKIE" \
        --data-urlencode "username=${QBT_USER}" \
        --data-urlencode "password=${QBT_PASS}" \
        "${QBITTORRENT_ADDR%/}/api/v2/auth/login" >/dev/null 2>&1; then
        if curl -fsS --max-time 8 -b "$COOKIE" \
            --data "$PAYLOAD" \
            "${QBITTORRENT_ADDR%/}/api/v2/app/setPreferences" >/dev/null 2>&1; then
            log "Updated qBittorrent listen port to ${PORT_VALUE} after authentication"
        else
            log "Authenticated but failed to apply port update"
        fi
    else
        log "qBittorrent authentication failed"
    fi
    rm -f "$COOKIE"
else
    log "Skipping authenticated update: QBT_USER/QBT_PASS not provided"
fi
HOOK

  ensure_file_mode "${hooks_dir}/update-qbt-port.sh" 700
}

ensure_caddy_auth() {
  if [[ "${ENABLE_CADDY:-0}" -ne 1 ]]; then
    msg "🔐 Skipping Caddy Basic Auth setup (ENABLE_CADDY=0)"
    return 0
  fi

  msg "🔐 Ensuring Caddy Basic Auth"

  hydrate_caddy_auth_from_env_file

  local sanitized_user
  sanitized_user="$(sanitize_user "${CADDY_BASIC_AUTH_USER}")"
  if [[ "$sanitized_user" != "$CADDY_BASIC_AUTH_USER" ]]; then
    CADDY_BASIC_AUTH_USER="$sanitized_user"
    persist_env_var "CADDY_BASIC_AUTH_USER" "$CADDY_BASIC_AUTH_USER"
    msg "  Caddy user sanitized → ${CADDY_BASIC_AUTH_USER}"
  fi

  local current_hash
  current_hash="$(unescape_env_value_from_compose "${CADDY_BASIC_AUTH_HASH:-}")"
  CADDY_BASIC_AUTH_HASH="$current_hash"

  local need_regen=0
  if [[ "${FORCE_REGEN_CADDY_AUTH:-0}" == "1" ]]; then
    need_regen=1
  elif [[ -z "$current_hash" ]] || ! valid_bcrypt "$current_hash"; then
    need_regen=1
  fi

  local cred_dir="${ARR_DOCKER_DIR}/caddy"
  local cred_file="${cred_dir}/credentials"

  if [[ "$need_regen" == "1" ]]; then
    local plaintext
    plaintext="$(gen_safe_password 20)"

    local hash_output
    hash_output="$(caddy_bcrypt "$plaintext" || true)"
    local new_hash
    new_hash="$(printf '%s\n' "$hash_output" | awk '/^\$2[aby]\$/{hash=$0} END {if (hash) print hash}')"

    if [[ -z "$new_hash" ]] || ! valid_bcrypt "$new_hash"; then
      die "Failed to generate Caddy bcrypt hash (docker or ${CADDY_IMAGE} unavailable?)"
    fi

    CADDY_BASIC_AUTH_HASH="$new_hash"
    persist_env_var "CADDY_BASIC_AUTH_HASH" "$CADDY_BASIC_AUTH_HASH"

    ensure_dir "$cred_dir"
    chmod 700 "$cred_dir" 2>/dev/null || true
    (
      umask 0077
      {
        printf 'username=%s\n' "$CADDY_BASIC_AUTH_USER"
        printf 'password=%s\n' "$plaintext"
      } >"$cred_file"
    )
    chmod 600 "$cred_file" 2>/dev/null || true

    local passmask
    passmask="$(obfuscate_sensitive "$plaintext" 2 2)"
    msg "  Generated new Caddy credentials → user: ${CADDY_BASIC_AUTH_USER}, pass: ${passmask}"
    msg "  Full credentials saved to: ${cred_file}"
  else
    ensure_dir "$cred_dir"
    chmod 700 "$cred_dir" 2>/dev/null || true
    local existing_plain=""
    if [[ -f "$cred_file" ]]; then
      existing_plain="$(grep '^password=' "$cred_file" | head -n1 | cut -d= -f2- || true)"
    fi
    if [[ -n "$existing_plain" ]]; then
      (
        umask 0077
        {
          printf 'username=%s\n' "$CADDY_BASIC_AUTH_USER"
          printf 'password=%s\n' "$existing_plain"
        } >"$cred_file"
      )
      chmod 600 "$cred_file" 2>/dev/null || true
    else
      warn "Caddy credentials file missing plaintext password; use --rotate-caddy-auth to recreate it."
    fi
    msg "  Existing Caddy bcrypt hash is valid ✓"
  fi
}

sync_caddy_ca_public_copy() {
  local wait_attempts=1
  local quiet=0

  while (($#)); do
    case "$1" in
      --wait)
        wait_attempts=10
        ;;
      --quiet)
        quiet=1
        ;;
    esac
    shift
  done

  local caddy_root="${ARR_DOCKER_DIR}/caddy"
  local ca_source="${caddy_root}/data/pki/authorities/local/root.crt"
  local ca_pub_dir="${caddy_root}/ca-pub"
  local ca_dest="${ca_pub_dir}/root.crt"

  ensure_dir "$ca_pub_dir"
  chmod "$DATA_DIR_MODE" "$ca_pub_dir" 2>/dev/null || true

  local attempt
  for ((attempt = 1; attempt <= wait_attempts; attempt++)); do
    if [[ -f "$ca_source" ]]; then
      if [[ -f "$ca_dest" ]] && cmp -s "$ca_source" "$ca_dest" 2>/dev/null; then
        chmod 644 "$ca_dest" 2>/dev/null || true
        return 0
      fi

      if cp -f "$ca_source" "$ca_dest" 2>/dev/null; then
        chmod 644 "$ca_dest" 2>/dev/null || true
        msg "  Published Caddy root certificate to ${ca_dest}"
        return 0
      fi

      warn "Failed to copy Caddy root certificate to ${ca_dest}"
      return 1
    fi

    if ((attempt < wait_attempts)); then
      sleep 2
    fi
  done

  if ((quiet == 0)); then
    warn "Caddy root certificate not found at ${ca_source}; it will be copied after Caddy issues it."
  fi

  return 1
}

write_caddy_assets() {
  if [[ "${ENABLE_CADDY:-0}" -ne 1 ]]; then
    msg "🌐 Skipping Caddy configuration (ENABLE_CADDY=0)"
    return 0
  fi

  msg "🌐 Writing Caddy reverse proxy config"

  local caddy_root="${ARR_DOCKER_DIR}/caddy"
  local data_dir="${caddy_root}/data"
  local config_dir="${caddy_root}/config"
  local caddyfile="${caddy_root}/Caddyfile"
  local userconf_path="${ARR_USERCONF_PATH:-${ARR_BASE:-${HOME}/srv}/userr.conf}"

  ensure_dir "$caddy_root"
  ensure_dir "$data_dir"
  ensure_dir "$config_dir"
  chmod "$DATA_DIR_MODE" "$caddy_root" 2>/dev/null || true
  chmod "$DATA_DIR_MODE" "$data_dir" 2>/dev/null || true
  chmod "$DATA_DIR_MODE" "$config_dir" 2>/dev/null || true

  # Normalize LAN CIDRs (commas, tabs, multiple spaces, and newlines → single spaces)
  local lan_cidrs
  lan_cidrs="$(printf '%s' "${CADDY_LAN_CIDRS}" | tr ',\t\r\n' '    ')"
  lan_cidrs="$(printf '%s\n' "$lan_cidrs" | xargs 2>/dev/null || printf '')"
  if [[ -z "$lan_cidrs" ]]; then
    lan_cidrs="127.0.0.1/32"
  fi

  local caddy_auth_hash
  caddy_auth_hash="$(unescape_env_value_from_compose "${CADDY_BASIC_AUTH_HASH}")"

  if ! is_bcrypt_hash "$caddy_auth_hash"; then
    warn "CADDY_BASIC_AUTH_HASH does not appear to be a valid bcrypt string; use --rotate-caddy-auth to regenerate."
  fi

  # Prefer normalized suffix if set via .env; fall back to computed value
  local domain_suffix="${ARR_DOMAIN_SUFFIX_CLEAN}"

  local -a services=(
    "qbittorrent 8080"
    "sonarr ${SONARR_PORT}"
    "radarr ${RADARR_PORT}"
    "prowlarr ${PROWLARR_PORT}"
    "bazarr ${BAZARR_PORT}"
    "flaresolverr ${FLARESOLVERR_PORT}"
  )

  local caddyfile_content
  caddyfile_content="$({
    printf '# Auto-generated by arrstack.sh\n'
    printf '# Adjust LAN CIDRs or add TLS settings via %s overrides.\n\n' "$userconf_path"
    printf '{\n'
    printf '  admin off\n'
    printf '}\n\n'

    # Plain HTTP health endpoint for container healthcheck
    printf 'http://ca.%s {\n' "$domain_suffix"
    printf '    root * /ca-pub\n'
    printf '    file_server\n'
    printf '    # Serve the public root over HTTP to avoid bootstrap loops\n'
    printf '    @ca_cert {\n'
    printf '        path /root.crt\n'
    printf '    }\n'
    printf '    handle @ca_cert {\n'
    printf '        header Content-Type "application/pkix-cert"\n'
    printf '        header Content-Disposition "attachment; filename=\"arrstackmini-root.cer\""\n'
    printf '    }\n'
    printf '}\n\n'

    local entry name port host
    for entry in "${services[@]}"; do
      name="${entry%% *}"
      port="${entry##* }"
      host="${name}.${domain_suffix}"
      printf '%s {\n' "$host"
      printf '    tls internal\n'
      printf '    @lan remote_ip %s\n' "$lan_cidrs"
      printf '    handle @lan {\n'
      printf '        reverse_proxy 127.0.0.1:%s\n' "$port"
      printf '    }\n'
      printf '    handle {\n'
      printf '        basic_auth * {\n'
      printf '            %s %s\n' "$CADDY_BASIC_AUTH_USER" "$caddy_auth_hash"
      printf '        }\n'
      printf '        reverse_proxy 127.0.0.1:%s\n' "$port"
      printf '    }\n'
      printf '}\n\n'
    done

    printf ':80, :443 {\n'
    printf '    encode zstd gzip\n'
    printf '    @lan remote_ip %s\n' "$lan_cidrs"
    printf '    route /healthz {\n'
    printf '        respond "ok" 200\n'
    printf '    }\n'
    printf '\n'
    printf '    handle @lan {\n'
    for entry in "${services[@]}"; do
      name="${entry%% *}"
      port="${entry##* }"
      printf '        handle_path /apps/%s/* {\n' "$name"
      printf '            reverse_proxy http://127.0.0.1:%s\n' "$port"
      printf '        }\n'
    done
    printf '        respond "ARR Stack Running" 200\n'
    printf '    }\n'
    printf '\n'
    printf '    handle {\n'
    printf '        basic_auth * {\n'
    printf '            %s %s\n' "$CADDY_BASIC_AUTH_USER" "$caddy_auth_hash"
    printf '        }\n'
    for entry in "${services[@]}"; do
      name="${entry%% *}"
      port="${entry##* }"
      printf '        handle_path /apps/%s/* {\n' "$name"
      printf '            reverse_proxy http://127.0.0.1:%s\n' "$port"
      printf '        }\n'
    done
    printf '        respond "ARR Stack Running" 200\n'
    printf '    }\n'
    printf '\n'
    printf '    tls internal\n'
    printf '}\n\n'
  })"

  atomic_write "$caddyfile" "$caddyfile_content" "$NONSECRET_FILE_MODE"

  sync_caddy_ca_public_copy --quiet || true

  if ! grep -Fq "${CADDY_BASIC_AUTH_USER}" "$caddyfile"; then
    warn "Caddyfile is missing the configured Basic Auth user; verify CADDY_BASIC_AUTH_USER"
  fi

  # shellcheck disable=SC2016  # intentional literal $ in regex
  if ! grep -qE '\\$2[aby]\\$[0-9]{2}\\$[./A-Za-z0-9]{53}' "$caddyfile"; then
    warn "Caddyfile bcrypt string may be invalid; hash regeneration fixes this (use --rotate-caddy-auth)."
  fi
}

sync_gluetun_library() {
  msg "📚 Syncing Gluetun helper library"

  ensure_dir_mode "$ARR_STACK_DIR/scripts" 755

  cp "${REPO_ROOT}/scripts/gluetun.sh" "$ARR_STACK_DIR/scripts/gluetun.sh"
  ensure_file_mode "$ARR_STACK_DIR/scripts/gluetun.sh" 644
}

write_qbt_helper_script() {
  msg "🧰 Writing qBittorrent helper script"

  ensure_dir_mode "$ARR_STACK_DIR/scripts" 755

  cp "${REPO_ROOT}/scripts/qbt-helper.sh" "$ARR_STACK_DIR/scripts/qbt-helper.sh"
  ensure_file_mode "$ARR_STACK_DIR/scripts/qbt-helper.sh" 755

  msg "  qBittorrent helper: ${ARR_STACK_DIR}/scripts/qbt-helper.sh"
}

write_qbt_config() {
  msg "🧩 Writing qBittorrent config"
  local config_dir="${ARR_DOCKER_DIR}/qbittorrent"
  local runtime_dir="${config_dir}/qBittorrent"
  local conf_file="${config_dir}/qBittorrent.conf"
  local legacy_conf="${runtime_dir}/qBittorrent.conf"

  ensure_dir "$config_dir"
  ensure_dir "$runtime_dir"

  if [[ -f "$legacy_conf" && ! -f "$conf_file" ]]; then
    msg "  Migrating legacy config from ${legacy_conf}"
    mv "$legacy_conf" "$conf_file"
    ensure_secret_file_mode "$conf_file"
  fi

  if [[ -f "$legacy_conf" ]]; then
    msg "  Removing unused legacy config at ${legacy_conf}"
    rm -f "$legacy_conf"
  fi
  local auth_whitelist
  auth_whitelist="$(normalize_csv "${QBT_AUTH_WHITELIST:-127.0.0.1/32,::1/128}")"
  QBT_AUTH_WHITELIST="$auth_whitelist"
  msg "  Stored WebUI auth whitelist entries: ${auth_whitelist}"

  local vt_root="${VUETORRENT_ROOT:-/config/vuetorrent}"
  local vt_alt_value="true"
  if [[ "${VUETORRENT_ALT_ENABLED:-1}" -eq 0 ]]; then
    vt_alt_value="false"
  fi

  local default_conf
  default_conf="$(cat <<EOF
[AutoRun]
enabled=false

[BitTorrent]
Session\AddTorrentStopped=false
Session\DefaultSavePath=/completed/
Session\TempPath=/downloads/incomplete/
Session\TempPathEnabled=true

[Meta]
MigrationVersion=8

[Network]
PortForwardingEnabled=false

[Preferences]
General\UseRandomPort=false
Connection\UPnP=false
Connection\UseNAT-PMP=false
WebUI\UseUPnP=false
Downloads\SavePath=/completed/
Downloads\TempPath=/downloads/incomplete/
Downloads\TempPathEnabled=true
WebUI\Address=0.0.0.0
WebUI\AlternativeUIEnabled=${vt_alt_value}
WebUI\RootFolder=${vt_root}
WebUI\Port=8080
WebUI\Username=${QBT_USER}
WebUI\LocalHostAuth=true
WebUI\AuthSubnetWhitelistEnabled=true
WebUI\AuthSubnetWhitelist=${auth_whitelist}
WebUI\CSRFProtection=true
WebUI\ClickjackingProtection=true
WebUI\HostHeaderValidation=true
WebUI\HTTPS\Enabled=false
WebUI\ServerDomains=*
EOF
)"

  local source_content="$default_conf"
  if [[ -f "$conf_file" ]]; then
    source_content="$(<"$conf_file")"
  fi

  local managed_spec
  local -a managed_lines=(
    "WebUI\\AlternativeUIEnabled=${vt_alt_value}"
    "WebUI\\RootFolder=${vt_root}"
    "WebUI\\ServerDomains=*"
    "WebUI\\LocalHostAuth=true"
    "WebUI\\AuthSubnetWhitelistEnabled=true"
    "WebUI\\CSRFProtection=true"
    "WebUI\\ClickjackingProtection=true"
    "WebUI\\HostHeaderValidation=true"
    "WebUI\\AuthSubnetWhitelist=${auth_whitelist}"
  )
  managed_spec="$(printf '%s\n' "${managed_lines[@]}")"
  managed_spec="${managed_spec%$'\n'}"

  local managed_spec_for_awk
  # Escape backslashes so awk -v does not treat sequences like \A as escapes
  managed_spec_for_awk="${managed_spec//\\/\\\\}"

  local updated_content
  updated_content="$(
    printf '%s' "$source_content" \
      | awk -v managed="$managed_spec_for_awk" '
        BEGIN {
          FS = "=";
          OFS = "=";
          order_count = 0;
          count = split(managed, arr, "\n");
          for (i = 1; i <= count; i++) {
            if (arr[i] == "") {
              continue;
            }
            split(arr[i], kv, "=");
            key = kv[1];
            value = substr(arr[i], length(key) + 2);
            replacements[key] = value;
            order[++order_count] = key;
          }
        }
        {
          line = $0;
          if (index(line, "=") == 0) {
            print line;
            next;
          }
          split(line, kv, "=");
          key = kv[1];
          if (key in replacements) {
            print key, replacements[key];
            seen[key] = 1;
          } else {
            print line;
          }
        }
        END {
          for (i = 1; i <= order_count; i++) {
            key = order[i];
            if (!(key in seen)) {
              print key, replacements[key];
            }
          }
        }
      '
  )"

  atomic_write "$conf_file" "$updated_content" "$SECRET_FILE_MODE"
}

write_configarr_assets() {
  if [[ "${ENABLE_CONFIGARR:-0}" -ne 1 ]]; then
    msg "🧾 Skipping Configarr assets (ENABLE_CONFIGARR=0)"
    return 0
  fi

  msg "🧾 Preparing Configarr assets"

  local configarr_root="${ARR_DOCKER_DIR}/configarr"
  local runtime_config="${configarr_root}/config.yml"
  local runtime_secrets="${configarr_root}/secrets.yml"
  local runtime_cfs="${configarr_root}/cfs"
  local -A configarr_policy=()

  ensure_dir_mode "$configarr_root" "$DATA_DIR_MODE"
  ensure_dir_mode "$runtime_cfs" "$DATA_DIR_MODE"

  local sanitized_video_min_res=""
  local sanitized_video_max_res=""
  local episode_max_mbmin=""
  local episode_min_mbmin=""
  local episode_pref_mbmin=""
  local episode_cap_mb=""
  local sanitized_ep_max_gb=""
  local sanitized_ep_min_mb=""
  local sanitized_runtime_min=""
  local sanitized_season_max_gb=""
  local sanitized_mbmin_decimals=""

  if have_command python3; then
    local py_output=""
    if py_output=$(python3 <<'PY'
import math
import os


def trim_float(value: float, precision: int = 2) -> str:
    if math.isclose(value, round(value)):
        return str(int(round(value)))
    fmt = "{:." + str(precision) + "f}"
    text = fmt.format(value)
    return text.rstrip("0").rstrip(".")


def sanitize_resolution(name: str, default: str, allowed: list[str], warnings: list[str]) -> str:
    raw = (os.environ.get(name, "") or "").strip()
    if not raw:
        return default
    lowered = raw.lower()
    for candidate in allowed:
        if candidate.lower() == lowered:
            return candidate
    warnings.append(f"{name}='{raw}' not supported; using {default}")
    return default


def parse_float(name: str, default: float, warnings: list[str], minimum: float | None = None, maximum: float | None = None) -> float:
    raw = os.environ.get(name, "")
    if raw is None or raw == "":
        return default
    try:
        value = float(raw)
    except ValueError:
        warnings.append(f"{name}='{raw}' is not numeric; using {default}")
        return default
    if minimum is not None and value < minimum:
        warnings.append(f"{name}={raw} below minimum {minimum}; clamping")
        value = minimum
    if maximum is not None and value > maximum:
        warnings.append(f"{name}={raw} above maximum {maximum}; clamping")
        value = maximum
    return value


warnings: list[str] = []
allowed_res = ["480p", "576p", "720p", "1080p", "2160p"]
res_index = {res: idx for idx, res in enumerate(allowed_res)}

min_res = sanitize_resolution("ARR_VIDEO_MIN_RES", "720p", allowed_res, warnings)
max_res = sanitize_resolution("ARR_VIDEO_MAX_RES", "1080p", allowed_res, warnings)

if res_index[min_res] > res_index[max_res]:
    warnings.append(
        f"ARR_VIDEO_MIN_RES='{min_res}' and ARR_VIDEO_MAX_RES='{max_res}' conflict; using 720p–1080p"
    )
    min_res = "720p"
    max_res = "1080p"

max_gb = parse_float("ARR_EP_MAX_GB", 5.0, warnings, minimum=1.0, maximum=20.0)
min_mb = parse_float("ARR_EP_MIN_MB", 250.0, warnings, minimum=1.0)
runtime = parse_float("ARR_TV_RUNTIME_MIN", 45.0, warnings, minimum=1.0)
season_cap = parse_float("ARR_SEASON_MAX_GB", 30.0, warnings, minimum=1.0)

dec_raw = os.environ.get("ARR_MBMIN_DECIMALS", "1") or "1"
try:
    decimals = int(dec_raw)
except ValueError:
    warnings.append(f"ARR_MBMIN_DECIMALS='{dec_raw}' invalid; using 1")
    decimals = 1

if decimals < 0:
    warnings.append("ARR_MBMIN_DECIMALS below 0; clamping to 0")
    decimals = 0
elif decimals > 3:
    warnings.append("ARR_MBMIN_DECIMALS above 3; clamping to 3")
    decimals = 3

max_total_mb = max_gb * 1024.0

if min_mb >= max_total_mb:
    warnings.append(
        f"ARR_EP_MIN_MB={min_mb} must be smaller than ARR_EP_MAX_GB*1024={max_total_mb}; reducing"
    )
    min_mb = min(250.0, max_total_mb * 0.5)
    if min_mb <= 0:
        min_mb = max_total_mb * 0.25

episode_max_mbmin = max_total_mb / runtime
episode_min_mbmin = min_mb / runtime

if episode_max_mbmin < 20.0:
    warnings.append(
        f"Derived episode max {episode_max_mbmin:.2f} MB/min is too small; using 60"
    )
    episode_max_mbmin = 60.0

if episode_min_mbmin >= episode_max_mbmin:
    episode_min_mbmin = max(episode_max_mbmin * 0.5, 1.0)

episode_pref_mbmin = (episode_min_mbmin + episode_max_mbmin) / 2.0

fmt = "{:." + str(decimals) + "f}"

print(f"sanitized_video_min_res={min_res}")
print(f"sanitized_video_max_res={max_res}")
print(f"episode_max_mbmin={fmt.format(episode_max_mbmin)}")
print(f"episode_min_mbmin={fmt.format(episode_min_mbmin)}")
print(f"episode_pref_mbmin={fmt.format(episode_pref_mbmin)}")
print(f"episode_cap_mb={int(round(max_total_mb))}")
print(f"sanitized_ep_max_gb={trim_float(max_gb)}")
print(f"sanitized_ep_min_mb={trim_float(min_mb, 1)}")
print(f"sanitized_runtime_min={trim_float(runtime, 1)}")
print(f"sanitized_season_max_gb={trim_float(season_cap, 1)}")
print(f"sanitized_mbmin_decimals={decimals}")

for warning in warnings:
    print("warn::" + warning)
PY
    ); then
      while IFS= read -r line; do
        case "$line" in
          warn::*)
            warn "Configarr: ${line#warn::}"
            ;;
          sanitized_video_min_res=*)
            sanitized_video_min_res="${line#*=}"
            ;;
          sanitized_video_max_res=*)
            sanitized_video_max_res="${line#*=}"
            ;;
          episode_max_mbmin=*)
            episode_max_mbmin="${line#*=}"
            ;;
          episode_min_mbmin=*)
            episode_min_mbmin="${line#*=}"
            ;;
          episode_pref_mbmin=*)
            episode_pref_mbmin="${line#*=}"
            ;;
          episode_cap_mb=*)
            episode_cap_mb="${line#*=}"
            ;;
          sanitized_ep_max_gb=*)
            sanitized_ep_max_gb="${line#*=}"
            ;;
          sanitized_ep_min_mb=*)
            sanitized_ep_min_mb="${line#*=}"
            ;;
          sanitized_runtime_min=*)
            sanitized_runtime_min="${line#*=}"
            ;;
          sanitized_season_max_gb=*)
            sanitized_season_max_gb="${line#*=}"
            ;;
          sanitized_mbmin_decimals=*)
            sanitized_mbmin_decimals="${line#*=}"
            ;;
        esac
      done <<<"$py_output"
    else
      warn "Configarr: failed to evaluate policy heuristics via python3; using defaults"
    fi
  else
    warn "Configarr: python3 unavailable; using default policy heuristics"
  fi

  : "${sanitized_video_min_res:=720p}"
  : "${sanitized_video_max_res:=1080p}"
  : "${episode_max_mbmin:=113.8}"
  : "${episode_min_mbmin:=5.6}"
  : "${episode_pref_mbmin:=59.7}"
  : "${episode_cap_mb:=5120}"
  : "${sanitized_ep_max_gb:=5}"
  : "${sanitized_ep_min_mb:=250}"
  : "${sanitized_runtime_min:=45}"
  : "${sanitized_season_max_gb:=30}"
  : "${sanitized_mbmin_decimals:=1}"

  declare -A res_index=(
    [480p]=0
    [576p]=1
    [720p]=2
    [1080p]=3
    [2160p]=4
  )

  local min_idx="${res_index[$sanitized_video_min_res]:-${res_index[720p]}}"
  local max_idx="${res_index[$sanitized_video_max_res]:-${res_index[1080p]}}"

  local include_720=0
  local include_1080=0

  if (( min_idx <= res_index[720p] && max_idx >= res_index[720p] )); then
    include_720=1
  fi
  if (( min_idx <= res_index[1080p] && max_idx >= res_index[1080p] )); then
    include_1080=1
  fi

  if (( include_720 == 0 && include_1080 == 0 )); then
    include_1080=1
    sanitized_video_min_res="1080p"
    sanitized_video_max_res="1080p"
    min_idx="${res_index[1080p]}"
    max_idx="${res_index[1080p]}"
  fi

  local -a sonarr_qualities=()
  local -a radarr_qualities=()

  if (( include_720 )); then
    sonarr_qualities+=("HDTV-720p" "WEBRip-720p" "WEBDL-720p" "Bluray-720p")
    radarr_qualities+=("HDTV-720p" "WEBRip-720p" "WEBDL-720p" "Bluray-720p")
  fi
  if (( include_1080 )); then
    sonarr_qualities+=("HDTV-1080p" "WEBRip-1080p" "WEBDL-1080p" "Bluray-1080p" "Bluray-1080p Remux")
    radarr_qualities+=("HDTV-1080p" "WEBRip-1080p" "WEBDL-1080p" "Bluray-1080p" "Remux-1080p")
  fi

  if ((${#sonarr_qualities[@]} == 0)); then
    sonarr_qualities=("WEBRip-1080p" "WEBDL-1080p")
  fi
  if ((${#radarr_qualities[@]} == 0)); then
    radarr_qualities=("WEBRip-1080p" "WEBDL-1080p")
  fi

  local sonarr_quality_yaml=""
  local radarr_quality_yaml=""
  local quality

  for quality in "${sonarr_qualities[@]}"; do
    sonarr_quality_yaml+="    - quality: \"${quality}\"\n"
    sonarr_quality_yaml+="      min: ${episode_min_mbmin}\n"
    sonarr_quality_yaml+="      preferred: ${episode_pref_mbmin}\n"
    sonarr_quality_yaml+="      max: ${episode_max_mbmin}\n"
  done

  for quality in "${radarr_qualities[@]}"; do
    radarr_quality_yaml+="    - quality: \"${quality}\"\n"
    radarr_quality_yaml+="      min: ${episode_min_mbmin}\n"
    radarr_quality_yaml+="      preferred: ${episode_pref_mbmin}\n"
    radarr_quality_yaml+="      max: ${episode_max_mbmin}\n"
  done

  local sonarr_override_path="${runtime_cfs}/sonarr-quality-definition-override.yml"
  local radarr_override_path="${runtime_cfs}/radarr-quality-definition-override.yml"
  local common_cf_path="${runtime_cfs}/common-negative-formats.yml"

  if [[ ! -f "$sonarr_override_path" ]]; then
    local sonarr_content
    sonarr_content="# Auto-generated by arrstack.sh for Configarr size guardrails\n"
    sonarr_content+="# Derived from ARR_EP_MAX_GB=${sanitized_ep_max_gb} (~${episode_cap_mb} MB) and ARR_TV_RUNTIME_MIN=${sanitized_runtime_min} minutes.\n"
    sonarr_content+="quality_definition:\n"
    sonarr_content+="  qualities:\n"
    sonarr_content+="${sonarr_quality_yaml}"
    atomic_write "$sonarr_override_path" "$sonarr_content" "$NONSECRET_FILE_MODE"
    msg "  Created Sonarr quality override: ${sonarr_override_path}"
  else
    ensure_nonsecret_file_mode "$sonarr_override_path"
  fi

  if [[ ! -f "$radarr_override_path" ]]; then
    local radarr_content
    radarr_content="# Auto-generated by arrstack.sh for Configarr size guardrails\n"
    radarr_content+="# Derived from ARR_EP_MAX_GB=${sanitized_ep_max_gb} (~${episode_cap_mb} MB) and ARR_TV_RUNTIME_MIN=${sanitized_runtime_min} minutes.\n"
    radarr_content+="quality_definition:\n"
    radarr_content+="  qualities:\n"
    radarr_content+="${radarr_quality_yaml}"
    atomic_write "$radarr_override_path" "$radarr_content" "$NONSECRET_FILE_MODE"
    msg "  Created Radarr quality override: ${radarr_override_path}"
  else
    ensure_nonsecret_file_mode "$radarr_override_path"
  fi

  normalize_toggle() {
    local value="${1:-0}"
    case "$value" in
      1|true|TRUE|yes|YES|on|ON)
        printf '1'
        ;;
      *)
        printf '0'
        ;;
    esac
  }

  sanitize_score() {
    local value="${1:-0}"
    local default="${2:-0}"
    if [[ "$value" =~ ^-?[0-9]+$ ]]; then
      printf '%s' "$value"
    else
      warn "Configarr: invalid score '${value}', using ${default}"
      printf '%s' "$default"
    fi
  }

  local english_only
  english_only="$(normalize_toggle "${ARR_ENGLISH_ONLY:-1}")"
  local discourage_multi
  discourage_multi="$(normalize_toggle "${ARR_DISCOURAGE_MULTI:-1}")"
  local penalize_hd_x265
  penalize_hd_x265="$(normalize_toggle "${ARR_PENALIZE_HD_X265:-1}")"
  local strict_junk_block
  strict_junk_block="$(normalize_toggle "${ARR_STRICT_JUNK_BLOCK:-1}")"

  local junk_score
  junk_score="$(sanitize_score "${ARR_JUNK_NEGATIVE_SCORE:- -1000}" "-1000")"
  local x265_score
  x265_score="$(sanitize_score "${ARR_X265_HD_NEGATIVE_SCORE:- -200}" "-200")"
  local multi_score
  multi_score="$(sanitize_score "${ARR_MULTI_NEGATIVE_SCORE:- -50}" "-50")"
  local english_bias_raw
  english_bias_raw="$(sanitize_score "${ARR_ENGLISH_POSITIVE_SCORE:-50}" "50")"

  local english_penalty_score="-${english_bias_raw#-}"

  local -a policy_profile_targets=("WEB-1080p" "HD Bluray + WEB")
  append_cf_block() {
    local -n ids_ref=$1
    local score="$2"
    local label="$3"
    if [[ -z "$score" || "$score" == "0" ]]; then
      return 0
    fi
    if ((${#ids_ref[@]} == 0)); then
      return 0
    fi
    local block="  # ${label}\n  - trash_ids:\n"
    local id
    for id in "${ids_ref[@]}"; do
      block+="      - ${id}\n"
    done
    block+="    assign_scores_to:\n"
    local target
    for target in "${policy_profile_targets[@]}"; do
      block+="      - name: ${target}\n"
      block+="        score: ${score}\n"
    done
    printf '%s' "$block"
  }

  # shellcheck disable=SC2034
  local -a cf_ids_lq=("9c11cd3f07101cdba90a2d81cf0e56b4" "90a6f9a284dff5103f6346090e6280c8")
  # shellcheck disable=SC2034
  local -a cf_ids_lq_title=("e2315f990da2e2cbfc9fa5b7a6fcfe48" "e204b80c87be9497a8a6eaff48f72905")
  # shellcheck disable=SC2034
  local -a cf_ids_upscaled=("23297a736ca77c0fc8e70f8edd7ee56c" "bfd8eb01832d646a0a89c4deb46f8564")
  # shellcheck disable=SC2034
  local -a cf_ids_language=("69aa1e159f97d860440b04cd6d590c4f" "0dc8aec3bd1c47cd6c40c46ecd27e846")
  # shellcheck disable=SC2034
  local -a cf_ids_multi=("7ba05c6e0e14e793538174c679126996" "4b900e171accbfb172729b63323ea8ca")
  # shellcheck disable=SC2034
  local -a cf_ids_x265=("47435ece6b99a0b477caf360e79ba0bb" "dc98083864ea246d05a42df0d05f81cc")

  local common_cf_body=""
  local block=""

  if (( strict_junk_block )); then
    block="$(append_cf_block cf_ids_lq "$junk_score" "LQ releases")"
    if [[ -n "$block" ]]; then
      common_cf_body+="$block\n"
    fi
    block="$(append_cf_block cf_ids_lq_title "$junk_score" "LQ (Release Title)")"
    if [[ -n "$block" ]]; then
      common_cf_body+="$block\n"
    fi
    block="$(append_cf_block cf_ids_upscaled "$junk_score" "Upscaled flags")"
    if [[ -n "$block" ]]; then
      common_cf_body+="$block\n"
    fi
  fi

  if (( english_only )); then
    block="$(append_cf_block cf_ids_language "$english_penalty_score" "Language: Not English")"
    if [[ -n "$block" ]]; then
      common_cf_body+="$block\n"
    fi
  fi

  if (( discourage_multi )); then
    block="$(append_cf_block cf_ids_multi "$multi_score" "MULTi releases")"
    if [[ -n "$block" ]]; then
      common_cf_body+="$block\n"
    fi
  fi

  if (( penalize_hd_x265 )); then
    block="$(append_cf_block cf_ids_x265 "$x265_score" "x265 (HD)")"
    if [[ -n "$block" ]]; then
      common_cf_body+="$block\n"
    fi
  fi

  local common_cf_exists=0
  if [[ -n "$common_cf_body" ]]; then
    local cf_payload="# Auto-generated by arrstack.sh to reinforce Configarr scoring\n"
    cf_payload+="# Adjust ARR_* environment variables to regenerate; delete this file to rebuild.\n"
    cf_payload+="custom_formats:\n"
    cf_payload+="$common_cf_body"
    if [[ ! -f "$common_cf_path" ]]; then
      atomic_write "$common_cf_path" "$cf_payload" "$NONSECRET_FILE_MODE"
      msg "  Created shared custom-format reinforcements: ${common_cf_path}"
    else
      ensure_nonsecret_file_mode "$common_cf_path"
    fi
    common_cf_exists=1
  elif [[ -f "$common_cf_path" ]]; then
    ensure_nonsecret_file_mode "$common_cf_path"
    common_cf_exists=1
  fi

  local -a sonarr_templates=("sonarr-quality-definition-series")
  local sonarr_profile_template="${SONARR_TRASH_TEMPLATE:-sonarr-v4-quality-profile-web-1080p}"
  if [[ -n "$sonarr_profile_template" ]]; then
    sonarr_templates+=("${sonarr_profile_template}")
  fi
  sonarr_templates+=("sonarr-v4-custom-formats-web-1080p")
  if [[ -f "$sonarr_override_path" ]]; then
    sonarr_templates+=("sonarr-quality-definition-override")
  fi
  if (( common_cf_exists )); then
    sonarr_templates+=("common-negative-formats")
  fi

  local -a radarr_templates=("radarr-quality-definition")
  local radarr_profile_template="${RADARR_TRASH_TEMPLATE:-radarr-v5-quality-profile-hd-bluray-web}"
  if [[ -n "$radarr_profile_template" ]]; then
    radarr_templates+=("${radarr_profile_template}")
  fi
  radarr_templates+=("radarr-v5-custom-formats-hd-bluray-web")
  if [[ -f "$radarr_override_path" ]]; then
    radarr_templates+=("radarr-quality-definition-override")
  fi
  if (( common_cf_exists )); then
    radarr_templates+=("common-negative-formats")
  fi

  local sonarr_include_yaml=""
  local template
  for template in "${sonarr_templates[@]}"; do
    sonarr_include_yaml+="      - template: ${template}\n"
  done
  sonarr_include_yaml+="      # - template: sonarr-v4-quality-profile-web-2160p\n"
  sonarr_include_yaml+="      # - template: sonarr-v4-custom-formats-web-2160p\n"

  local radarr_include_yaml=""
  for template in "${radarr_templates[@]}"; do
    radarr_include_yaml+="      - template: ${template}\n"
  done
  radarr_include_yaml+="      # - template: radarr-v5-quality-profile-uhd-bluray-web\n"
  radarr_include_yaml+="      # - template: radarr-v5-custom-formats-uhd-bluray-web\n"

  local default_config
  default_config=$(cat <<EOF_CFG
# Auto-generated by arrstack.sh. Edit cautiously or disable via ENABLE_CONFIGARR=0.
version: 1

localConfigTemplatesPath: /app/cfs
# localCustomFormatsPath: /app/cfs

sonarr:
  main:
    define: true
    host: http://127.0.0.1:8989
    apiKey: !secret SONARR_API_KEY
    include:
${sonarr_include_yaml}    custom_formats: []

radarr:
  main:
    define: true
    host: http://127.0.0.1:7878
    apiKey: !secret RADARR_API_KEY
    include:
${radarr_include_yaml}    custom_formats: []
EOF_CFG
)

  if [[ ! -f "$runtime_config" ]]; then
    atomic_write "$runtime_config" "$default_config" "$NONSECRET_FILE_MODE"
    msg "  Installed default config: ${runtime_config}"
  else
    ensure_nonsecret_file_mode "$runtime_config"
  fi

  if [[ ! -f "$runtime_secrets" ]]; then
    local secrets_stub
    secrets_stub=$'SONARR_API_KEY: "REPLACE_WITH_SONARR_API_KEY"\nRADARR_API_KEY: "REPLACE_WITH_RADARR_API_KEY"\n'
    atomic_write "$runtime_secrets" "$secrets_stub" "$SECRET_FILE_MODE"
    msg "  Stubbed secrets file: ${runtime_secrets}"
  else
    ensure_secret_file_mode "$runtime_secrets"
  fi

  local resolution_display="${sanitized_video_min_res}–${sanitized_video_max_res}"
  local lang_primary="${ARR_LANG_PRIMARY:-en}"
  lang_primary="${lang_primary,,}"

  configarr_policy[resolution]="$resolution_display"
  configarr_policy[episode_cap_gb]="$sanitized_ep_max_gb"
  configarr_policy[episode_mbmin]="$episode_max_mbmin"
  configarr_policy[runtime]="$sanitized_runtime_min"
  configarr_policy[season_cap_gb]="$sanitized_season_max_gb"
  configarr_policy[language_primary]="$lang_primary"

  if (( english_only )); then
    configarr_policy[english_bias]="ON (score ${english_penalty_score})"
  else
    configarr_policy[english_bias]="OFF"
  fi
  if (( discourage_multi )); then
    configarr_policy[multi_penalty]="ON (score ${multi_score})"
  else
    configarr_policy[multi_penalty]="OFF"
  fi
  if (( penalize_hd_x265 )); then
    configarr_policy[x265_penalty]="ON (score ${x265_score})"
  else
    configarr_policy[x265_penalty]="OFF"
  fi
  if (( strict_junk_block )); then
    if (( common_cf_exists )); then
      configarr_policy[junk_reinforce]="ON (score ${junk_score})"
    else
      configarr_policy[junk_reinforce]="ON (template missing)"
    fi
  else
    configarr_policy[junk_reinforce]="OFF"
  fi

  CONFIGARR_POLICY_RESOLUTION="${configarr_policy[resolution]}"
  CONFIGARR_POLICY_EP_GB="${configarr_policy[episode_cap_gb]}"
  CONFIGARR_POLICY_EP_MBMIN="${configarr_policy[episode_mbmin]}"
  CONFIGARR_POLICY_RUNTIME="${configarr_policy[runtime]}"
  CONFIGARR_POLICY_SEASON_GB="${configarr_policy[season_cap_gb]}"
  CONFIGARR_POLICY_LANG="${configarr_policy[language_primary]}"
  CONFIGARR_POLICY_ENGLISH="${configarr_policy[english_bias]}"
  CONFIGARR_POLICY_MULTI="${configarr_policy[multi_penalty]}"
  CONFIGARR_POLICY_X265="${configarr_policy[x265_penalty]}"
  CONFIGARR_POLICY_JUNK="${configarr_policy[junk_reinforce]}"
  export CONFIGARR_POLICY_RESOLUTION CONFIGARR_POLICY_EP_GB CONFIGARR_POLICY_EP_MBMIN \
    CONFIGARR_POLICY_RUNTIME CONFIGARR_POLICY_SEASON_GB CONFIGARR_POLICY_LANG \
    CONFIGARR_POLICY_ENGLISH CONFIGARR_POLICY_MULTI CONFIGARR_POLICY_X265 CONFIGARR_POLICY_JUNK

  msg "  Configarr policy: ${resolution_display}, cap ${sanitized_ep_max_gb} GB (~${episode_max_mbmin} MB/min)"
  msg "  Penalties: English=${configarr_policy[english_bias]}, Multi=${configarr_policy[multi_penalty]}, x265=${configarr_policy[x265_penalty]}, Junk=${configarr_policy[junk_reinforce]}"
}


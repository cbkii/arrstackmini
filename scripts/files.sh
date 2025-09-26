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

  ensure_dir "$DOWNLOADS_DIR"
  ensure_dir "$COMPLETED_DIR"

  ensure_dir_mode "$ARR_STACK_DIR/scripts" 755

  if [[ -d "$ARRCONF_DIR" ]]; then
    ensure_dir_mode "$ARRCONF_DIR" 700
    if [[ -f "${ARRCONF_DIR}/proton.auth" ]]; then
      ensure_secret_file_mode "${ARRCONF_DIR}/proton.auth"
    fi
  fi

  if [[ ! -d "$TV_DIR" ]]; then
    warn "TV directory does not exist: $TV_DIR"
    warn "Creating it now (may fail if parent directory is missing)"
    mkdir -p "$TV_DIR" 2>/dev/null || warn "Could not create TV directory"
  fi

  if [[ ! -d "$MOVIES_DIR" ]]; then
    warn "Movies directory does not exist: $MOVIES_DIR"
    warn "Creating it now (may fail if parent directory is missing)"
    mkdir -p "$MOVIES_DIR" 2>/dev/null || warn "Could not create Movies directory"
  fi

  if [[ -n "${SUBS_DIR:-}" && ! -d "$SUBS_DIR" ]]; then
    warn "Subtitles directory does not exist: ${SUBS_DIR}"
    warn "Creating it now (may fail if parent directory is missing)"
    mkdir -p "$SUBS_DIR" 2>/dev/null || warn "Could not create subtitles directory"
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

write_env() {
  msg "📝 Writing .env file"

  if [[ -f "$ARR_ENV_FILE" ]]; then
    if [[ -z "${CADDY_BASIC_AUTH_USER:-}" || "${CADDY_BASIC_AUTH_USER}" == "user" ]]; then
      local env_user_line env_user_value
      env_user_line="$(grep '^CADDY_BASIC_AUTH_USER=' "$ARR_ENV_FILE" | head -n1 || true)"
      if [[ -n "$env_user_line" ]]; then
        env_user_value="${env_user_line#CADDY_BASIC_AUTH_USER=}"
        env_user_value="$(unescape_env_value_from_compose "$env_user_value")"
        if [[ -n "$env_user_value" ]]; then
          CADDY_BASIC_AUTH_USER="$env_user_value"
        fi
      fi
    fi

    if [[ -z "${CADDY_BASIC_AUTH_HASH:-}" ]]; then
      local env_hash_line env_hash_value
      env_hash_line="$(grep '^CADDY_BASIC_AUTH_HASH=' "$ARR_ENV_FILE" | head -n1 || true)"
      if [[ -n "$env_hash_line" ]]; then
        env_hash_value="${env_hash_line#CADDY_BASIC_AUTH_HASH=}"
        env_hash_value="$(unescape_env_value_from_compose "$env_hash_value")"
        if [[ -n "$env_hash_value" ]]; then
          CADDY_BASIC_AUTH_HASH="$env_hash_value"
        fi
      fi
    fi
  fi

  CADDY_BASIC_AUTH_USER="$(sanitize_user "$CADDY_BASIC_AUTH_USER")"

  local direct_ports_requested="${EXPOSE_DIRECT_PORTS:-0}"

  if [[ -z "${LAN_IP:-}" || "$LAN_IP" == "0.0.0.0" ]]; then
    if detected_ip="$(detect_lan_ip 2>/dev/null)"; then
      LAN_IP="$detected_ip"
      msg "Auto-detected LAN_IP: $LAN_IP"
    else
      LAN_IP="0.0.0.0"
      warn "LAN_IP could not be detected automatically; set it in arrconf/userconf.sh so services bind to the correct interface."
    fi
  else
    msg "Using configured LAN_IP: $LAN_IP"
  fi

  if (( direct_ports_requested == 1 )); then
    if [[ -z "${LAN_IP:-}" || "$LAN_IP" == "0.0.0.0" ]]; then
      die "EXPOSE_DIRECT_PORTS=1 requires LAN_IP to be set to your host's private IPv4 address in arrconf/userconf.sh."
    fi
    if ! is_private_ipv4 "$LAN_IP"; then
      die "LAN_IP='${LAN_IP}' is not a private IPv4 address. Set LAN_IP to your LAN host IP before exposing ports."
    fi
  fi

  load_proton_credentials

  PU="$OPENVPN_USER_VALUE"
  PW="$PROTON_PASS_VALUE"

  validate_config
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

    printf '# Local DNS\n'
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

    cat <<'YAML' >"$tmp"
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

  if [[ -f "$ARR_ENV_FILE" ]]; then
    if [[ -z "${CADDY_BASIC_AUTH_USER:-}" || "${CADDY_BASIC_AUTH_USER}" == "user" ]]; then
      local env_user_line env_user_value
      env_user_line="$(grep '^CADDY_BASIC_AUTH_USER=' "$ARR_ENV_FILE" | head -n1 || true)"
      if [[ -n "$env_user_line" ]]; then
        env_user_value="${env_user_line#CADDY_BASIC_AUTH_USER=}"
        env_user_value="$(unescape_env_value_from_compose "$env_user_value")"
        if [[ -n "$env_user_value" ]]; then
          CADDY_BASIC_AUTH_USER="$env_user_value"
        fi
      fi
    fi

    if [[ -z "${CADDY_BASIC_AUTH_HASH:-}" ]]; then
      local env_hash_line env_hash_value
      env_hash_line="$(grep '^CADDY_BASIC_AUTH_HASH=' "$ARR_ENV_FILE" | head -n1 || true)"
      if [[ -n "$env_hash_line" ]]; then
        env_hash_value="${env_hash_line#CADDY_BASIC_AUTH_HASH=}"
        env_hash_value="$(unescape_env_value_from_compose "$env_hash_value")"
        if [[ -n "$env_hash_value" ]]; then
          CADDY_BASIC_AUTH_HASH="$env_hash_value"
        fi
      fi
    fi
  fi

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
    printf '# Adjust LAN CIDRs or add TLS settings via arrconf/userconf.sh overrides.\n\n'
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

  if [[ ! -f "$conf_file" ]]; then
    cat >"$conf_file" <<EOF
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
WebUI\AlternativeUIEnabled=true
WebUI\RootFolder=/config/vuetorrent
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
    chmod 600 "$conf_file"
  fi
  set_qbt_conf_value "$conf_file" 'WebUI\AlternativeUIEnabled' 'true'
  set_qbt_conf_value "$conf_file" 'WebUI\RootFolder' '/config/vuetorrent'
  set_qbt_conf_value "$conf_file" 'WebUI\ServerDomains' '*'
  set_qbt_conf_value "$conf_file" 'WebUI\LocalHostAuth' 'true'
  set_qbt_conf_value "$conf_file" 'WebUI\AuthSubnetWhitelistEnabled' 'true'
  set_qbt_conf_value "$conf_file" 'WebUI\CSRFProtection' 'true'
  set_qbt_conf_value "$conf_file" 'WebUI\ClickjackingProtection' 'true'
  set_qbt_conf_value "$conf_file" 'WebUI\HostHeaderValidation' 'true'
  set_qbt_conf_value "$conf_file" 'WebUI\AuthSubnetWhitelist' "$auth_whitelist"
}

# shellcheck shell=bash
caddy_bcrypt() {
  local plaintext="${1-}"

  if [[ -z "$plaintext" ]]; then
    return 1
  fi

  docker run --rm "${CADDY_IMAGE}" caddy hash-password --algorithm bcrypt --plaintext "$plaintext" 2>/dev/null
}

mkdirs() {
  msg "📁 Creating directories"
  ensure_dir "$ARR_STACK_DIR"
  chmod 755 "$ARR_STACK_DIR" 2>/dev/null || true

  ensure_dir "$ARR_DOCKER_DIR"
  chmod "$DATA_DIR_MODE" "$ARR_DOCKER_DIR" 2>/dev/null || true

  local service
  for service in "${ARR_DOCKER_SERVICES[@]}"; do
    if [[ "$service" == "local_dns" && "${ENABLE_LOCAL_DNS:-1}" -ne 1 ]]; then
      continue
    fi
    ensure_dir "${ARR_DOCKER_DIR}/${service}"
    chmod "$DATA_DIR_MODE" "${ARR_DOCKER_DIR}/${service}" 2>/dev/null || true
  done

  ensure_dir "$DOWNLOADS_DIR"
  ensure_dir "$COMPLETED_DIR"

  ensure_dir "$ARR_STACK_DIR/scripts"
  chmod 755 "$ARR_STACK_DIR/scripts" 2>/dev/null || true

  if [[ -d "$ARRCONF_DIR" ]]; then
    chmod 700 "$ARRCONF_DIR" 2>/dev/null || true
    if [[ -f "${ARRCONF_DIR}/proton.auth" ]]; then
      chmod 600 "${ARRCONF_DIR}/proton.auth" 2>/dev/null || true
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
}

generate_api_key() {
  msg "🔐 Generating API key"

  if [[ -f "$ARR_ENV_FILE" ]] && [[ "$FORCE_ROTATE_API_KEY" != 1 ]]; then
    local existing
    existing="$(grep '^GLUETUN_API_KEY=' "$ARR_ENV_FILE" 2>/dev/null | cut -d= -f2- || true)"
    if [[ -n "$existing" ]]; then
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

  if (( LOCAL_DNS_AUTO_DISABLED )); then
    warn "Local DNS disabled automatically (${LOCAL_DNS_AUTO_DISABLED_REASON}). Update arrconf/userconf.sh or free the port to re-enable it."
  fi

  LAN_IP_EFFECTIVE_IFACE=""
  LAN_IP_EFFECTIVE_METHOD=""

  if [[ -z "${LAN_IP:-}" ]]; then
    LAN_IP="$(detect_lan_ip)"
    if [[ "$LAN_IP" != "0.0.0.0" ]]; then
      LAN_IP_EFFECTIVE_IFACE="${LAN_IP_AUTODETECTED_IFACE:-$(interface_for_ip "$LAN_IP")}" 
      LAN_IP_EFFECTIVE_METHOD="auto-detected"
      if [[ -n "$LAN_IP_AUTODETECTED_METHOD" ]]; then
        LAN_IP_EFFECTIVE_METHOD+=" via ${LAN_IP_AUTODETECTED_METHOD}"
      fi
      local detection_msg="Detected LAN IP: $LAN_IP"
      if [[ -n "$LAN_IP_EFFECTIVE_IFACE" ]]; then
        detection_msg+=" (interface ${LAN_IP_EFFECTIVE_IFACE}"
        if [[ -n "$LAN_IP_AUTODETECTED_METHOD" ]]; then
          detection_msg+=", ${LAN_IP_AUTODETECTED_METHOD}"
        fi
        detection_msg+=")"
      elif [[ -n "$LAN_IP_AUTODETECTED_METHOD" ]]; then
        detection_msg+=" (${LAN_IP_AUTODETECTED_METHOD})"
      fi
      msg "$detection_msg"
    else
      LAN_IP_EFFECTIVE_METHOD="auto-detected (failed)"
      warn "Using LAN_IP=0.0.0.0; services will listen on all interfaces"
    fi
  elif [[ "$LAN_IP" == "0.0.0.0" ]]; then
    LAN_IP_EFFECTIVE_METHOD="wildcard (0.0.0.0)"
    warn "LAN_IP explicitly set to 0.0.0.0; services will bind to all interfaces"
    warn "Consider using a specific RFC1918 address to limit exposure"
  else
    LAN_IP_EFFECTIVE_IFACE="$(interface_for_ip "$LAN_IP")"
    LAN_IP_EFFECTIVE_METHOD="user-specified"
    local configured_msg="Using configured LAN_IP: $LAN_IP"
    if [[ -n "$LAN_IP_EFFECTIVE_IFACE" ]]; then
      configured_msg+=" (interface ${LAN_IP_EFFECTIVE_IFACE})"
    fi
    msg "$configured_msg"
  fi

  load_proton_credentials

  PU="$OPENVPN_USER_VALUE"
  PW="$PROTON_PASS_VALUE"
  OPENVPN_USER="$PU"

  validate_config

  local env_content
  env_content="$({
    printf '# Core settings\n'
    format_env_line "VPN_TYPE" "openvpn"
    format_env_line "PUID" "$PUID"
    format_env_line "PGID" "$PGID"
    format_env_line "TIMEZONE" "$TIMEZONE"
    format_env_line "LAN_IP" "$LAN_IP"
    format_env_line "LOCALHOST_IP" "$LOCALHOST_IP"
    printf '\n'

    printf '# Local DNS\n'
    format_env_line "LAN_DOMAIN_SUFFIX" "$LAN_DOMAIN_SUFFIX"
    format_env_line "ENABLE_LOCAL_DNS" "$ENABLE_LOCAL_DNS"
    format_env_line "UPSTREAM_DNS_1" "$UPSTREAM_DNS_1"
    format_env_line "UPSTREAM_DNS_2" "$UPSTREAM_DNS_2"
    printf '\n'

    # Derived, so downstream tools (and developers) can reference the normalized suffix directly
    format_env_line "CADDY_DOMAIN_SUFFIX" "$ARR_DOMAIN_SUFFIX_CLEAN"
    printf '\n'

    printf '# ProtonVPN OpenVPN credentials\n'
    format_env_line "OPENVPN_USER" "$PU"
    format_env_line "OPENVPN_PASSWORD" "$PW"
    printf '\n'

    # Also persist for clarity (helps compose templating & external tooling)
    format_env_line "OPENVPN_USER_ENFORCED" "$PU"
    printf '\n'

    printf '# Gluetun settings\n'
    format_env_line "VPN_SERVICE_PROVIDER" "protonvpn"
    format_env_line "GLUETUN_API_KEY" "$GLUETUN_API_KEY"
    format_env_line "GLUETUN_CONTROL_PORT" "$GLUETUN_CONTROL_PORT"
    format_env_line "SERVER_COUNTRIES" "$SERVER_COUNTRIES"
    printf '\n'

    printf '# Service ports\n'
    format_env_line "QBT_HTTP_PORT_HOST" "$QBT_HTTP_PORT_HOST"
    format_env_line "SONARR_PORT" "$SONARR_PORT"
    format_env_line "RADARR_PORT" "$RADARR_PORT"
    format_env_line "PROWLARR_PORT" "$PROWLARR_PORT"
    format_env_line "BAZARR_PORT" "$BAZARR_PORT"
    format_env_line "FLARESOLVERR_PORT" "$FLARESOLVERR_PORT"
    printf '\n'

    printf '# qBittorrent credentials (change in WebUI after install, then update here)\n'
    format_env_line "QBT_USER" "$QBT_USER"
    format_env_line "QBT_PASS" "$QBT_PASS"
    format_env_line "QBT_DOCKER_MODS" "$QBT_DOCKER_MODS"
    printf '\n'

    printf '# Reverse proxy defaults\n'
    format_env_line "CADDY_DOMAIN_SUFFIX" "$ARR_DOMAIN_SUFFIX_CLEAN"
    format_env_line "CADDY_LAN_CIDRS" "$CADDY_LAN_CIDRS"
    format_env_line "CADDY_BASIC_AUTH_USER" "$CADDY_BASIC_AUTH_USER"
    # Store the bcrypt hash and escape dollars so Compose does not expand them
    format_env_line "CADDY_BASIC_AUTH_HASH" "$(unescape_env_value_from_compose "$CADDY_BASIC_AUTH_HASH")"
    printf '\n'

    printf '# Paths\n'
    format_env_line "ARR_DOCKER_DIR" "$ARR_DOCKER_DIR"
    format_env_line "DOWNLOADS_DIR" "$DOWNLOADS_DIR"
    format_env_line "COMPLETED_DIR" "$COMPLETED_DIR"
    format_env_line "TV_DIR" "$TV_DIR"
    format_env_line "MOVIES_DIR" "$MOVIES_DIR"
    if [[ -n "${SUBS_DIR:-}" ]]; then
      format_env_line "SUBS_DIR" "$SUBS_DIR"
    fi
    printf '\n'

    printf '# Images\n'
    format_env_line "GLUETUN_IMAGE" "$GLUETUN_IMAGE"
    format_env_line "QBITTORRENT_IMAGE" "$QBITTORRENT_IMAGE"
    format_env_line "SONARR_IMAGE" "$SONARR_IMAGE"
    format_env_line "RADARR_IMAGE" "$RADARR_IMAGE"
    format_env_line "PROWLARR_IMAGE" "$PROWLARR_IMAGE"
    format_env_line "BAZARR_IMAGE" "$BAZARR_IMAGE"
    format_env_line "FLARESOLVERR_IMAGE" "$FLARESOLVERR_IMAGE"
    format_env_line "CADDY_IMAGE" "$CADDY_IMAGE"
    format_env_line "PORT_SYNC_IMAGE" "$PORT_SYNC_IMAGE"
  })"

  atomic_write "$ARR_ENV_FILE" "$env_content" 600

}

write_compose() {
  msg "🐳 Writing docker-compose.yml"

  local compose_path="${ARR_STACK_DIR}/docker-compose.yml"
  local compose_content

  LOCAL_DNS_SERVICE_ENABLED=0
  if (( LOCAL_DNS_AUTO_DISABLED )); then
    LOCAL_DNS_SERVICE_REASON="auto-disabled-port-conflict"
  elif [[ "${ENABLE_LOCAL_DNS:-1}" -ne 1 ]]; then
    LOCAL_DNS_SERVICE_REASON="disabled"
  else
    LOCAL_DNS_SERVICE_REASON="requested"
  fi

  compose_content="$(
    {
      cat <<'YAML'
services:
  gluetun:
    image: ${GLUETUN_IMAGE}
    container_name: gluetun
    cap_add:
      - NET_ADMIN
    devices:
      - /dev/net/tun
    environment:
      VPN_SERVICE_PROVIDER: ${VPN_SERVICE_PROVIDER}
      VPN_TYPE: openvpn
      OPENVPN_USER: ${OPENVPN_USER}
      OPENVPN_PASSWORD: ${OPENVPN_PASSWORD}
      SERVER_COUNTRIES: ${SERVER_COUNTRIES}
      VPN_PORT_FORWARDING: "on"
      VPN_PORT_FORWARDING_PROVIDER: protonvpn
      HTTP_CONTROL_SERVER_ADDRESS: 0.0.0.0:${GLUETUN_CONTROL_PORT}
      HTTP_CONTROL_SERVER_AUTH: "apikey"
      HTTP_CONTROL_SERVER_APIKEY: ${GLUETUN_API_KEY}
      VPN_PORT_FORWARDING_STATUS_FILE: /tmp/gluetun/forwarded_port
      VPN_PORT_FORWARDING_UP_COMMAND: "/gluetun/hooks/update-qbt-port.sh {{PORTS}}"
      QBT_USER: ${QBT_USER}
      QBT_PASS: ${QBT_PASS}
      QBITTORRENT_ADDR: "http://127.0.0.1:8080"
      PORT_FORWARD_ONLY: "yes"
      HEALTH_TARGET_ADDRESS: "1.1.1.1:443"
      HEALTH_VPN_DURATION_INITIAL: "30s"
      HEALTH_VPN_DURATION_ADDITION: "10s"
      HEALTH_SUCCESS_WAIT_DURATION: "10s"
      DNS_KEEP_NAMESERVER: "off"
      PORT_FORWARDING_STATUS_FILE_CLEANUP: "off"
      FIREWALL_OUTBOUND_SUBNETS: "192.168.0.0/16,10.0.0.0/8,172.16.0.0/12"
      FIREWALL_INPUT_PORTS: "80,443"
      UPDATER_PERIOD: "24h"
      PUID: ${PUID}
      PGID: ${PGID}
      TZ: ${TIMEZONE}
    volumes:
      - ${ARR_DOCKER_DIR}/gluetun:/gluetun
    ports:
      - "${LOCALHOST_IP}:${GLUETUN_CONTROL_PORT}:${GLUETUN_CONTROL_PORT}"
      - "${LAN_IP}:80:80"
      - "${LAN_IP}:443:443"
    healthcheck:
      test: /gluetun-entrypoint healthcheck
      interval: 30s
      timeout: 20s
      retries: 5
      start_period: 60s
    restart: unless-stopped
    logging:
      driver: json-file
      options:
        max-size: "1m"
        max-file: "3"
YAML

      local include_local_dns=0
      if [[ "${ENABLE_LOCAL_DNS:-1}" -eq 1 && "${LAN_IP:-}" != "0.0.0.0" && "${LAN_IP:-}" != "" && ${LOCAL_DNS_AUTO_DISABLED:-0} -eq 0 ]]; then
        include_local_dns=1
      fi

      if ((include_local_dns)); then
        LOCAL_DNS_SERVICE_ENABLED=1
        LOCAL_DNS_SERVICE_REASON="enabled"
        cat <<'YAML'
  local_dns:
    image: 4km3/dnsmasq:2.90-r3
    container_name: arr_local_dns
    cap_add:
      - NET_ADMIN
    ports:
      - "${LAN_IP}:53:53/udp"
      - "${LAN_IP}:53:53/tcp"
    command:
      - --log-facility=-
      - --no-resolv
      - --server=${UPSTREAM_DNS_1}
      - --server=${UPSTREAM_DNS_2}
      - --domain-needed
      - --bogus-priv
      - --domain=${LAN_DOMAIN_SUFFIX}
      - --local=/${LAN_DOMAIN_SUFFIX}/
      - --address=/${LAN_DOMAIN_SUFFIX}/${LAN_IP}
    restart: unless-stopped
    logging:
      driver: json-file
      options:
        max-size: "1m"
        max-file: "2"
YAML
      elif [[ "${ENABLE_LOCAL_DNS:-1}" -eq 1 && ${LOCAL_DNS_AUTO_DISABLED:-0} -eq 0 ]]; then
        LOCAL_DNS_SERVICE_ENABLED=0
        LOCAL_DNS_SERVICE_REASON="invalid-ip"
        warn "Skipping local_dns service because LAN_IP is not set to a specific address. Set LAN_IP or disable ENABLE_LOCAL_DNS."
      fi

      cat <<'YAML'
  qbittorrent:
    image: ${QBITTORRENT_IMAGE}
    container_name: qbittorrent
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
    restart: unless-stopped
    logging:
      driver: json-file
      options:
        max-size: "1m"
        max-file: "2"

  radarr:
    image: ${RADARR_IMAGE}
    container_name: radarr
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
    restart: unless-stopped
    logging:
      driver: json-file
      options:
        max-size: "1m"
        max-file: "2"

  prowlarr:
    image: ${PROWLARR_IMAGE}
    container_name: prowlarr
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
    restart: unless-stopped
    logging:
      driver: json-file
      options:
        max-size: "1m"
        max-file: "2"

  bazarr:
    image: ${BAZARR_IMAGE}
    container_name: bazarr
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
__BAZARR_OPTIONAL_SUBS__
    depends_on:
      gluetun:
        condition: service_healthy
    restart: unless-stopped
    logging:
      driver: json-file
      options:
        max-size: "1m"
        max-file: "2"

  flaresolverr:
    image: ${FLARESOLVERR_IMAGE}
    container_name: flaresolverr
    network_mode: "service:gluetun"
    environment:
      LOG_LEVEL: info
    depends_on:
      gluetun:
        condition: service_healthy
    restart: unless-stopped
    logging:
      driver: json-file
      options:
        max-size: "1m"
        max-file: "2"

  port-sync:
    image: ${PORT_SYNC_IMAGE}
    container_name: port-sync
    network_mode: "service:gluetun"
    environment:
      GLUETUN_API_KEY: ${GLUETUN_API_KEY}
      GLUETUN_ADDR: "http://127.0.0.1:${GLUETUN_CONTROL_PORT}"
      QBITTORRENT_ADDR: "http://127.0.0.1:8080"
      UPDATE_INTERVAL: 300
      BACKOFF_MAX: 900
      QBT_USER: ${QBT_USER}
      QBT_PASS: ${QBT_PASS}
      VPN_PORT_FORWARDING_STATUS_FILE: /tmp/gluetun/forwarded_port
    volumes:
      - ./scripts/port-sync.sh:/port-sync.sh:ro
    command: /port-sync.sh
    depends_on:
      gluetun:
        condition: service_healthy
      qbittorrent:
        condition: service_started
    restart: unless-stopped
    init: true
    logging:
      driver: json-file
      options:
        max-size: "1m"
        max-file: "2"

  caddy:
    image: ${CADDY_IMAGE}
    container_name: caddy
    network_mode: "service:gluetun"
    volumes:
      - ${ARR_DOCKER_DIR}/caddy/Caddyfile:/etc/caddy/Caddyfile:ro
      - ${ARR_DOCKER_DIR}/caddy/data:/data
      - ${ARR_DOCKER_DIR}/caddy/config:/config
    depends_on:
      gluetun:
        condition: service_healthy
    healthcheck:
      test:
        - "CMD-SHELL"
        - >
          if command -v curl >/dev/null 2>&1; then
            curl -fsS http://127.0.0.1/healthz;
          elif command -v wget >/dev/null 2>&1; then
            wget -qO- http://127.0.0.1/healthz;
          else
            echo "missing http client" >&2;
            exit 1;
          fi
      interval: 15s
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
    }
  )"

  local bazarr_subs_volume=""
  if [[ -n "${SUBS_DIR:-}" ]]; then
    printf -v bazarr_subs_volume $'      - ${SUBS_DIR}:/subs\n'
  fi
  compose_content="${compose_content/__BAZARR_OPTIONAL_SUBS__/${bazarr_subs_volume}}"

  atomic_write "$compose_path" "$compose_content" "$NONSECRET_FILE_MODE"
}

write_gluetun_control_assets() {
  msg "🛡️ Preparing Gluetun control assets"

  local gluetun_root="${ARR_DOCKER_DIR}/gluetun"
  local hooks_dir="${gluetun_root}/hooks"

  ensure_dir "$gluetun_root"
  ensure_dir "$hooks_dir"
  chmod 700 "$hooks_dir" 2>/dev/null || true

  cat >"${hooks_dir}/update-qbt-port.sh" <<'HOOK'
#!/bin/sh
set -eu

QBITTORRENT_ADDR="${QBITTORRENT_ADDR:-http://127.0.0.1:8080}"
COOKIE_JAR="/tmp/qbt.hook.cookies"

PORT_SPEC="${1:-}"

if [ -z "$PORT_SPEC" ]; then
    exit 0
fi

PORT_VALUE="${PORT_SPEC%%,*}"
PORT_VALUE="${PORT_VALUE%%:*}"

case "$PORT_VALUE" in
    ''|*[!0-9]*)
        exit 0
        ;;
esac

payload=$(printf 'json={"listen_port":%s,"random_port":false}' "$PORT_VALUE")

touch "$COOKIE_JAR" 2>/dev/null || true
chmod 600 "$COOKIE_JAR" 2>/dev/null || true

post_setprefs_unauth() {
    curl --silent --show-error --max-time 8 \
        --data "$payload" \
        --output /dev/null "${QBITTORRENT_ADDR%/}/api/v2/app/setPreferences"
}

post_setprefs_auth() {
    if [ -z "${QBT_USER:-}" ] || [ -z "${QBT_PASS:-}" ]; then
        return 1
    fi

    if ! curl -fsS --max-time 5 -c "$COOKIE_JAR" \
        --data-urlencode "username=${QBT_USER}" \
        --data-urlencode "password=${QBT_PASS}" \
        "${QBITTORRENT_ADDR%/}/api/v2/auth/login" >/dev/null 2>&1; then
        return 1
    fi

    curl --silent --show-error --max-time 8 -b "$COOKIE_JAR" \
        --data "$payload" \
        --output /dev/null "${QBITTORRENT_ADDR%/}/api/v2/app/setPreferences"
}

if command -v curl >/dev/null 2>&1; then
    attempts=0
    while [ $attempts -lt 5 ]; do
        if post_setprefs_unauth; then
            exit 0
        fi
        if post_setprefs_auth; then
            exit 0
        fi
        attempts=$((attempts + 1))
        sleep 2
    done
fi

exit 0
HOOK

  chmod 700 "${hooks_dir}/update-qbt-port.sh" 2>/dev/null || true
}

ensure_caddy_auth() {
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

write_caddy_assets() {
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
    printf ':80 {\n'
    printf '    respond /healthz 200 {\n'
    printf '        body "ok"\n'
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
  })"

  atomic_write "$caddyfile" "$caddyfile_content" "$NONSECRET_FILE_MODE"

  if ! grep -Fq "${CADDY_BASIC_AUTH_USER}" "$caddyfile"; then
    warn "Caddyfile is missing the configured Basic Auth user; verify CADDY_BASIC_AUTH_USER"
  fi

  if ! grep -qE '\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}' "$caddyfile"; then
    warn "Caddyfile bcrypt string may be invalid; hash regeneration fixes this (use --rotate-caddy-auth)."
  fi
}

sync_gluetun_library() {
  msg "📚 Syncing Gluetun helper library"

  ensure_dir "$ARR_STACK_DIR/scripts"
  chmod 755 "$ARR_STACK_DIR/scripts" 2>/dev/null || true

  cp "${REPO_ROOT}/scripts/gluetun.sh" "$ARR_STACK_DIR/scripts/gluetun.sh"
  chmod 644 "$ARR_STACK_DIR/scripts/gluetun.sh"
}

write_port_sync_script() {
  msg "📜 Writing port sync script"

  ensure_dir "$ARR_STACK_DIR/scripts"

  cat >"$ARR_STACK_DIR/scripts/port-sync.sh" <<'SCRIPT'
#!/bin/sh
set -eu

log() {
    printf '[%s] [port-sync] %s\n' "$(date '+%Y-%m-%dT%H:%M:%S')" "$1" >&2
}

ensure_curl() {
    if command -v curl >/dev/null 2>&1; then
        return
    fi

    log "curl not found, attempting to install..."

    if command -v apk >/dev/null 2>&1; then
        if apk update >/dev/null 2>&1 && apk add --no-cache curl ca-certificates >/dev/null 2>&1; then
            log "curl installed successfully"
            return
        fi
        log "warn: apk update/add failed; retrying simple add..."
        if apk add --no-cache curl >/dev/null 2>&1; then
            log "curl installed successfully (without update)"
            return
        fi
    fi

    if command -v wget >/dev/null 2>&1; then
        log "warn: curl unavailable; using wget shim as fallback"
        curl() {
            set -- "$@"
            headers=""
            url=""
            post_data=""
            method="GET"
            load_cookies=""
            save_cookies=""
            output_target="-"
            newline_store="$(printf '\n_')"
            newline="${newline_store%_}"

            while [ $# -gt 0 ]; do
                case "$1" in
                    -H)
                        [ $# -ge 2 ] || break
                        if [ -z "$headers" ]; then
                            headers="$2"
                        else
                            headers="${headers}${newline}$2"
                        fi
                        shift 2
                        ;;
                    -b)
                        [ $# -ge 2 ] || break
                        load_cookies="$2"
                        shift 2
                        ;;
                    -c)
                        [ $# -ge 2 ] || break
                        save_cookies="$2"
                        shift 2
                        ;;
                    --data|-d|--data-raw)
                        [ $# -ge 2 ] || break
                        method="POST"
                        post_data="$2"
                        shift 2
                        ;;
                    --data-urlencode)
                        [ $# -ge 2 ] || break
                        method="POST"
                        if [ -n "$post_data" ]; then
                            post_data="${post_data}&$2"
                        else
                            post_data="$2"
                        fi
                        shift 2
                        ;;
                    --output|-o)
                        [ $# -ge 2 ] || break
                        output_target="$2"
                        shift 2
                        ;;
                    --max-time)
                        shift
                        [ $# -gt 0 ] && shift
                        ;;
                    -fsS|-f|-s|-S|--silent|--show-error)
                        shift
                        ;;
                    -* )
                        shift
                        ;;
                    *)
                        if [ -z "$url" ]; then
                            url="$1"
                        fi
                        shift
                        ;;
                esac
            done

            if [ -z "$url" ]; then
                return 22
            fi

            set -- --quiet
            if [ "$output_target" = "-" ]; then
                set -- "$@" -O -
            else
                set -- "$@" -O "$output_target"
            fi
            if [ "$method" = "POST" ]; then
                set -- "$@" --post-data="$post_data"
            fi
            if [ -n "$load_cookies" ]; then
                set -- "$@" --load-cookies="$load_cookies"
            fi
            if [ -n "$save_cookies" ]; then
                set -- "$@" --save-cookies="$save_cookies"
            fi

            old_ifs=$IFS
            IFS="$newline"
            for header in $headers; do
                [ -n "$header" ] || continue
                set -- "$@" --header="$header"
            done
            IFS=$old_ifs
            unset newline_store newline

            set -- "$@" "$url"
            wget "$@"
        }
        export -f curl 2>/dev/null || true
        return
    fi

    log "ERROR: Neither curl nor wget available, and installation failed"
    exit 1
}

wait_for_gluetun() {
    local attempts=0
    local max_attempts=8
    local sleep_seconds=2
    local status_url="${GLUETUN_ADDR}/v1/openvpn/status"
    local response=""

    log "Waiting for Gluetun OpenVPN status endpoint (max ~$((max_attempts * sleep_seconds))s)..."

    while [ $attempts -lt $max_attempts ]; do
        if [ -n "$GLUETUN_API_KEY" ]; then
            response="$(curl -fsS --max-time 3 -H "X-Api-Key: $GLUETUN_API_KEY" "$status_url" 2>/dev/null || true)"
        else
            response="$(curl -fsS --max-time 3 "$status_url" 2>/dev/null || true)"
        fi

        if [ -n "$response" ]; then
            if printf '%s' "$response" | grep -q '"status"[[:space:]]*:[[:space:]]*"connected"'; then
                log "Gluetun reports OpenVPN status: connected"
                return 0
            fi

            if printf '%s' "$response" | grep -q '"status"[[:space:]]*:[[:space:]]*"completed"'; then
                log "Gluetun OpenVPN status endpoint is responding"
                return 0
            fi
        fi

        attempts=$((attempts + 1))
        if [ $attempts -lt $max_attempts ]; then
            sleep "$sleep_seconds"
        fi
    done

    log "ERROR: Gluetun OpenVPN status endpoint unavailable after ~$((max_attempts * sleep_seconds))s"
    return 1
}

: "${GLUETUN_ADDR:=http://127.0.0.1:8000}"
: "${GLUETUN_API_KEY:=}"
: "${QBITTORRENT_ADDR:=http://127.0.0.1:8080}"
: "${UPDATE_INTERVAL:=300}"
: "${BACKOFF_MAX:=900}"
: "${QBT_USER:=}"
: "${QBT_PASS:=}"
: "${VPN_PORT_FORWARDING_STATUS_FILE:=}"

COOKIE_JAR="/tmp/qbt.cookies"

if [ ! -f "$COOKIE_JAR" ]; then
    if ! touch "$COOKIE_JAR" 2>/dev/null; then
        log 'warn: unable to create cookie jar; continuing without persistence'
    fi
fi
chmod 600 "$COOKIE_JAR" 2>/dev/null || true

ensure_curl

api_get() {
    local path="$1"
    local url="${GLUETUN_ADDR}${path}"

    if [ -n "$GLUETUN_API_KEY" ]; then
        if ! curl -fsS --max-time 5 -H "X-Api-Key: $GLUETUN_API_KEY" "$url"; then
            log "ERROR: API call failed to $url (with API key)"
            return 1
        fi
    else
        log "WARNING: No API key provided, trying without authentication"
        if ! curl -fsS --max-time 5 "$url"; then
            log "ERROR: API call failed to $url (without API key)"
            return 1
        fi
    fi
}

get_pf() {
    local port=""

    if [ -n "$VPN_PORT_FORWARDING_STATUS_FILE" ] && [ -r "$VPN_PORT_FORWARDING_STATUS_FILE" ]; then
        port="$(awk 'NF {print $1; exit}' "$VPN_PORT_FORWARDING_STATUS_FILE" 2>/dev/null || printf '')"
        if printf '%s' "$port" | grep -Eq '^[0-9]+$'; then
            printf '%s' "$port"
            return 0
        fi
    fi

    local response=""
    response="$(api_get '/v1/forwardedport' || true)"
    if [ -n "$response" ]; then
        port="$(printf '%s' "$response" | tr -d '[:space:]')"
        if printf '%s' "$port" | grep -Eq '^[0-9]+$'; then
            printf '%s' "$port"
            return 0
        fi
    fi

    response="$(api_get '/v1/openvpn/portforwarded' || true)"
    if [ -n "$response" ]; then
        port="$(printf '%s
' "$response" | awk -F'"port":' 'NF>1 {sub(/[^0-9].*/, "", $2); if ($2 != "") {print $2; exit}}')"
        if printf '%s' "$port" | grep -Eq '^[0-9]+$'; then
            printf '%s' "$port"
            return 0
        fi
    fi

    return 1
}

login_qbt() {
    if [ -z "$QBT_USER" ] || [ -z "$QBT_PASS" ]; then
        return 0
    fi

    if curl -fsS --max-time 5 -c "$COOKIE_JAR"         --data-urlencode "username=${QBT_USER}"         --data-urlencode "password=${QBT_PASS}"         "${QBITTORRENT_ADDR}/api/v2/auth/login" >/dev/null 2>&1; then
        return 0
    fi

    rm -f "$COOKIE_JAR"
    log 'warn: login failed; relying on localhost bypass (ensure LocalHostAuth=true)'
    return 0
}

ensure_qbt_session() {
    if [ -s "$COOKIE_JAR" ]; then
        return 0
    fi

    login_qbt
}

get_qbt_listen_port() {
    local response=""

    response="$(curl -fsS --max-time 5 -b "$COOKIE_JAR" "${QBITTORRENT_ADDR}/api/v2/app/preferences" 2>/dev/null || true)"
    if [ -z "$response" ]; then
        response="$(curl -fsS --max-time 5 "${QBITTORRENT_ADDR}/api/v2/app/preferences" 2>/dev/null || true)"
    fi

    if [ -z "$response" ]; then
        rm -f "$COOKIE_JAR"
        return 1
    fi

    printf '%s
' "$response" | tr -d ' 

' | awk -F'"listen_port":' 'NF>1 {sub(/[^0-9].*/, "", $2); if ($2 != "") {print $2; exit}}'
    return 0
}

set_qbt_listen_port() {
    local port="$1"
    local payload="json={"listen_port":${port},"random_port":false}"

    if curl -fsS --max-time 5 -b "$COOKIE_JAR"         --data-raw "$payload" "${QBITTORRENT_ADDR}/api/v2/app/setPreferences" >/dev/null 2>&1; then
        return 0
    fi

    if curl -fsS --max-time 5         --data-raw "$payload" "${QBITTORRENT_ADDR}/api/v2/app/setPreferences" >/dev/null 2>&1; then
        return 0
    fi

    rm -f "$COOKIE_JAR"
    return 1
}

cleanup() {
    rm -f "$COOKIE_JAR"
}

trap 'cleanup' EXIT INT TERM

# Wait for Gluetun to be ready
if ! wait_for_gluetun; then
    log "FATAL: Cannot proceed without Gluetun API"
    exit 1
fi

log "starting port-sync against ${GLUETUN_ADDR} -> ${QBITTORRENT_ADDR}"
ensure_qbt_session || true

last_reported=""
backoff=30
consecutive_failures=0
max_consecutive_failures=5
extended_backoff=300  # 5 minutes

while :; do
    pf="$(get_pf || echo 0)"

    if [ -z "$pf" ] || [ "$pf" = "0" ]; then
        consecutive_failures=$((consecutive_failures + 1))

        if [ $consecutive_failures -ge $max_consecutive_failures ]; then
            log "Multiple failures detected, using extended backoff (${extended_backoff}s)"
            sleep "$extended_backoff"
            consecutive_failures=0
            backoff=30
        else
            sleep "$backoff"
            backoff=$((backoff * 2))
            if [ $backoff -gt "$BACKOFF_MAX" ]; then
                backoff="$BACKOFF_MAX"
            fi
        fi

        continue
    fi

    consecutive_failures=0
    if [ "$pf" != "$last_reported" ]; then
        log "Updating qBittorrent listen port to $pf"
        if set_qbt_listen_port "$pf"; then
            last_reported="$pf"
            backoff=30
        else
            log "warn: failed to update qBittorrent port"
        fi
    fi

    sleep "$UPDATE_INTERVAL"
done
SCRIPT

  chmod 755 "$ARR_STACK_DIR/scripts/port-sync.sh"

  msg "🆘 Writing version recovery script"

  cat >"$ARR_STACK_DIR/scripts/fix-versions.sh" <<'FIXVER'
#!/usr/bin/env bash
set -euo pipefail

msg() { printf '[%s] %s\n' "$(date '+%H:%M:%S')" "$*"; }
warn() { printf '[%s] WARNING: %s\n' "$(date '+%H:%M:%S')" "$*" >&2; }
die() { warn "$1"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STACK_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${STACK_DIR}/.env"

update_env_entry() {
  local key="$1"
  local value="$2"
  local tmp

  tmp="$(mktemp "${ENV_FILE}.XXXXXX.tmp")" || die "Failed to create temp file for ${key}"
  chmod 600 "$tmp" 2>/dev/null || true

  if sed "s|^${key}=.*|${key}=${value}|" "$ENV_FILE" >"$tmp" 2>/dev/null; then
    mv "$tmp" "$ENV_FILE"
  else
    rm -f "$tmp"
    die "Failed to update ${key} in ${ENV_FILE}"
  fi
}

if [[ ! -f "$ENV_FILE" ]]; then
  die ".env file not found at ${ENV_FILE}"
fi

if ! command -v docker >/dev/null 2>&1; then
  die "Docker CLI not found on PATH"
fi

msg "🔧 Fixing Docker image versions..."

USE_LATEST=(
  "lscr.io/linuxserver/prowlarr"
  "lscr.io/linuxserver/bazarr"
)

backup="${ENV_FILE}.bak.$(date +%Y%m%d_%H%M%S)"
cp "$ENV_FILE" "$backup"
msg "Backed up .env to $backup"

for base_image in "${USE_LATEST[@]}"; do
  msg "Checking $base_image..."

  case "$base_image" in
    *prowlarr) var_name="PROWLARR_IMAGE" ;;
    *bazarr) var_name="BAZARR_IMAGE" ;;
    *) continue ;;
  esac

  current_image="$(grep "^${var_name}=" "$ENV_FILE" | cut -d= -f2- || true)"

  if [[ -z "$current_image" ]]; then
    warn "  No ${var_name} entry found in .env; skipping"
    continue
  fi

  if ! docker manifest inspect "$current_image" >/dev/null 2>&1; then
    warn "  Current tag doesn't exist: $current_image"
    latest_image="${base_image}:latest"
    msg "  Updating to: $latest_image"
    update_env_entry "$var_name" "$latest_image"
  else
    msg "  ✅ Current tag is valid: $current_image"
  fi
done

msg "✅ Version fixes complete"
msg "Run './arrstack.sh --yes' to apply changes"
FIXVER

  chmod 755 "$ARR_STACK_DIR/scripts/fix-versions.sh"

}

write_qbt_helper_script() {
  msg "🧰 Writing qBittorrent helper script"

  ensure_dir "$ARR_STACK_DIR/scripts"

  cp "${REPO_ROOT}/scripts/qbt-helper.sh" "$ARR_STACK_DIR/scripts/qbt-helper.sh"
  chmod 755 "$ARR_STACK_DIR/scripts/qbt-helper.sh"

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
    chmod 600 "$conf_file"
  fi

  if [[ -f "$legacy_conf" ]]; then
    msg "  Removing unused legacy config at ${legacy_conf}"
    rm -f "$legacy_conf"
  fi
  local auth_whitelist
  auth_whitelist="$(calculate_qbt_auth_whitelist)"
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


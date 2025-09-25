# shellcheck shell=bash

install_missing() {
  msg "🔧 Checking dependencies"

  if ! docker version --format '{{.Server.Version}}' >/dev/null 2>&1; then
    die "Docker daemon is not running or not accessible"
  fi

  local compose_cmd=""
  local compose_version=""

  if docker compose version >/dev/null 2>&1; then
    compose_version="$(docker compose version --short 2>/dev/null | sed 's/^v//')"
    local compose_major="${compose_version%%.*}"
    if [[ -n "$compose_major" ]] && ((compose_major >= 2)); then
      compose_cmd="docker compose"
      DOCKER_COMPOSE_CMD=(docker compose)
    fi
  fi

  if [[ -z "$compose_cmd" ]] && command -v docker-compose >/dev/null 2>&1; then
    compose_version="$(docker-compose version --short 2>/dev/null | sed 's/^v//')"
    local compose_major="${compose_version%%.*}"
    if [[ -n "$compose_major" ]] && ((compose_major >= 2)); then
      compose_cmd="docker-compose"
      DOCKER_COMPOSE_CMD=(docker-compose)
    fi
  fi

  if [[ -z "$compose_cmd" ]]; then
    die "Docker Compose v2+ is required but not found"
  fi

  local required=(curl jq openssl)
  local missing=()

  for cmd in "${required[@]}"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      missing+=("$cmd")
    fi
  done

  if ((${#missing[@]} > 0)); then
    die "Missing required tools: ${missing[*]}. Please install them and re-run."
  fi

  if ! command -v certutil >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
      msg "  Tip: install certutil for smoother Caddy TLS trust: sudo apt-get install -y libnss3-tools"
    elif command -v yum >/dev/null 2>&1; then
      msg "  Tip: install certutil for smoother Caddy TLS trust: sudo yum install -y nss-tools"
    elif command -v dnf >/dev/null 2>&1; then
      msg "  Tip: install certutil for smoother Caddy TLS trust: sudo dnf install -y nss-tools"
    else
      msg "  Tip: certutil not found (optional); Caddy may print a trust-store warning."
    fi
  fi

  msg "  Docker: $(docker version --format '{{.Server.Version}}')"
  local compose_version_display=""
  if ((${#DOCKER_COMPOSE_CMD[@]} > 0)); then
    if ! compose_version_display="$(compose version --short 2>/dev/null)"; then
      compose_version_display="(unknown)"
    fi
  fi
  msg "  Compose: ${compose_cmd} ${compose_version_display}"
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

port_conflict_listeners() {
  local proto="$1"
  local expected_ip="$2"
  local port="$3"

  local found=0

  if have_command ss; then
    local flag="lntp"
    if [[ "$proto" == "udp" ]]; then
      flag="lnup"
    fi

    while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      local addr_field
      addr_field="$(awk '{print $4}' <<<"$line" 2>/dev/null || true)"
      [[ -z "$addr_field" ]] && continue
      local host="${addr_field%:*}"
      if ! address_conflicts "$expected_ip" "$host"; then
        continue
      fi
      local proc_desc=""
      if [[ $line == *'users:(('* ]]; then
        local proc_segment="${line#*users:(()}"
        proc_segment="${proc_segment#\"}"
        local proc="${proc_segment%%\"*}"
        if [[ $line =~ pid=([0-9]+) ]]; then
          proc_desc="${proc} (pid ${BASH_REMATCH[1]})"
        else
          proc_desc="$proc"
        fi
      fi
      printf '%s|%s\n' "$(normalize_bind_address "$host")" "${proc_desc:-unknown process}"
      found=1
    done < <(ss -H -${flag} "sport = :${port}" 2>/dev/null || true)
  fi

  if ((found == 0)) && have_command lsof; then
    local -a spec
    if [[ "$proto" == "udp" ]]; then
      spec=(-iUDP:"${port}")
    else
      spec=(-iTCP:"${port}" -sTCP:LISTEN)
    fi

    while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      [[ "$line" =~ ^COMMAND ]] && continue
      local name
      name="$(awk '{print $9}' <<<"$line" 2>/dev/null || true)"
      [[ -z "$name" ]] && continue
      name="${name%%->*}"
      name="${name% (LISTEN)}"
      local host="${name%:*}"
      if ! address_conflicts "$expected_ip" "$host"; then
        continue
      fi
      local proc=""
      proc="$(awk '{print $1}' <<<"$line" 2>/dev/null || true)"
      local pid=""
      pid="$(awk '{print $2}' <<<"$line" 2>/dev/null || true)"
      local proc_desc="${proc:-unknown process}"
      if [[ -n "$pid" ]]; then
        proc_desc+=" (pid ${pid})"
      fi
      printf '%s|%s\n' "$(normalize_bind_address "$host")" "$proc_desc"
      found=1
    done < <(lsof -nP "${spec[@]}" 2>/dev/null || true)
  fi
}

check_port_conflicts() {
  msg "  Checking host port availability"

  local -A port_labels=()
  local -A port_protos=()
  local -A port_expected=()

  local lan_ip_known=1
  if [[ -z "${LAN_IP:-}" || "${LAN_IP}" == "0.0.0.0" ]]; then
    lan_ip_known=0
  fi

  port_labels["${GLUETUN_CONTROL_PORT}"]="Gluetun control API"
  port_protos["${GLUETUN_CONTROL_PORT}"]="tcp"
  port_expected["${GLUETUN_CONTROL_PORT}"]="${LOCALHOST_IP:-127.0.0.1}"

  if [[ "${EXPOSE_DIRECT_PORTS:-0}" -eq 1 ]]; then
    if ((lan_ip_known == 0)); then
      die "EXPOSE_DIRECT_PORTS=1 requires LAN_IP to be set to your host's private IPv4 address before installation."
    fi
    if ! is_private_ipv4 "${LAN_IP}"; then
      die "LAN_IP='${LAN_IP}' is not a private IPv4 address. Set LAN_IP correctly before exposing ports."
    fi

    port_labels["${QBT_HTTP_PORT_HOST}"]="qBittorrent WebUI"
    port_labels["${SONARR_PORT}"]="Sonarr WebUI"
    port_labels["${RADARR_PORT}"]="Radarr WebUI"
    port_labels["${PROWLARR_PORT}"]="Prowlarr WebUI"
    port_labels["${BAZARR_PORT}"]="Bazarr WebUI"
    port_labels["${FLARESOLVERR_PORT}"]="FlareSolverr API"
    local expected="${LAN_IP}"
    port_expected["${QBT_HTTP_PORT_HOST}"]="$expected"
    port_expected["${SONARR_PORT}"]="$expected"
    port_expected["${RADARR_PORT}"]="$expected"
    port_expected["${PROWLARR_PORT}"]="$expected"
    port_expected["${BAZARR_PORT}"]="$expected"
    port_expected["${FLARESOLVERR_PORT}"]="$expected"
  fi

  if [[ "${ENABLE_CADDY:-0}" -eq 1 ]] && ((lan_ip_known)); then
    port_labels[80]="Caddy HTTP"
    port_labels[443]="Caddy HTTPS"
    port_expected[80]="${LAN_IP}"
    port_expected[443]="${LAN_IP}"
  fi

  if [[ "${ENABLE_LOCAL_DNS:-0}" -eq 1 ]]; then
    port_labels["53/tcp"]="Local DNS (TCP)"
    port_labels["53/udp"]="Local DNS (UDP)"
    port_protos["53/tcp"]="tcp"
    port_protos["53/udp"]="udp"
    port_expected["53/tcp"]="${LAN_IP:-}"
    port_expected["53/udp"]="${LAN_IP:-}"
  fi

  local conflict_found=0
  local key
  for key in "${!port_labels[@]}"; do
    local proto="${port_protos[$key]:-tcp}"
    local port="$key"
    if [[ "$port" == */* ]]; then
      proto="${port##*/}"
      port="${port%%/*}"
    fi

    local expected="${port_expected[$key]:-*}"
    mapfile -t listeners < <(port_conflict_listeners "$proto" "$expected" "$port")

    if ((${#listeners[@]} == 0)); then
      msg "    [ok] ${port_labels[$key]} port ${port}/${proto^^} is free"
      continue
    fi

    conflict_found=1
    local listener
    for listener in "${listeners[@]}"; do
      IFS='|' read -r bind_host proc <<<"$listener"
      warn "    Port ${port}/${proto^^} needed for ${port_labels[$key]} is already bound on ${bind_host}${proc:+ by ${proc}}."
    done
  done

  if ((conflict_found)); then
    die "Resolve the port conflicts above or change the *_PORT values in arrconf/userconf.sh, then rerun the installer."
  fi
}

validate_dns_configuration() {
  if [[ "${ENABLE_LOCAL_DNS:-0}" -ne 1 ]]; then
    return
  fi

  local missing=()
  if [[ -z "${UPSTREAM_DNS_1:-}" ]]; then
    missing+=("UPSTREAM_DNS_1")
  fi
  if [[ -z "${UPSTREAM_DNS_2:-}" ]]; then
    missing+=("UPSTREAM_DNS_2")
  fi

  if [[ -z "${LAN_DOMAIN_SUFFIX:-}" ]]; then
    missing+=("LAN_DOMAIN_SUFFIX")
  fi

  if ((${#missing[@]} > 0)); then
    die "Local DNS requires ${missing[*]} to be set to reachable resolvers. Update arrconf/userconf.sh before continuing."
  fi
}

preflight() {
  msg "🚀 Preflight checks"

  acquire_lock

  msg "  Permission profile: ${ARR_PERMISSION_PROFILE} (umask $(umask))"

  if [[ ! -f "${ARRCONF_DIR}/proton.auth" ]]; then
    die "Missing ${ARRCONF_DIR}/proton.auth - create it with PROTON_USER and PROTON_PASS"
  fi

  load_proton_credentials

  msg "  OpenVPN username (enforced '+pmp'): $(obfuscate_sensitive "$OPENVPN_USER_VALUE" 2 4)"

  if ((PROTON_USER_PMP_ADDED)); then
    warn "Proton username '${PROTON_USER_VALUE}' missing '+pmp'; using '${OPENVPN_USER_VALUE}'"
  fi

  install_missing

  validate_dns_configuration
  check_port_conflicts

  if [[ -f "${ARR_ENV_FILE}" ]]; then
    local existing_openvpn_user=""
    existing_openvpn_user="$(grep '^OPENVPN_USER=' "${ARR_ENV_FILE}" | head -n1 | cut -d= -f2- | tr -d '\r' || true)"
    if [[ -n "$existing_openvpn_user" ]]; then
      local existing_unescaped
      existing_unescaped="$(unescape_env_value_from_compose "$existing_openvpn_user")"
      if [[ "$existing_unescaped" != *"+pmp" ]]; then
        warn "OPENVPN_USER in ${ARR_ENV_FILE} is '${existing_unescaped}' and will be updated to include '+pmp'."
      fi
    fi
  fi

  show_configuration_preview

  if [[ "${ASSUME_YES}" != 1 ]]; then
    local response=""

    warn "Continue with ProtonVPN OpenVPN setup? [y/N]: "
    if ! IFS= read -r response; then
      response=""
    fi

    if ! [[ ${response,,} =~ ^[[:space:]]*(y|yes)[[:space:]]*$ ]]; then
      die "Aborted"
    fi
  fi
}

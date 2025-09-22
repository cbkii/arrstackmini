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
    if ! compose_version_display="$("${DOCKER_COMPOSE_CMD[@]}" version --short 2>/dev/null)"; then
      compose_version_display="(unknown)"
    fi
  fi
  msg "  Compose: ${compose_cmd} ${compose_version_display}"
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

  if [[ -f "$ARR_ENV_FILE" ]]; then
    local existing_openvpn_user=""
    existing_openvpn_user="$(grep '^OPENVPN_USER=' "$ARR_ENV_FILE" | head -n1 | cut -d= -f2- | tr -d '\r' || true)"
    if [[ -n "$existing_openvpn_user" ]]; then
      local existing_unescaped
      existing_unescaped="$(unescape_env_value_from_compose "$existing_openvpn_user")"
      if [[ "$existing_unescaped" != *"+pmp" ]]; then
        warn "OPENVPN_USER in ${ARR_ENV_FILE} is '${existing_unescaped}' and will be updated to include '+pmp'."
      fi
    fi
  fi

  show_configuration_preview

  check_required_ports

  if [[ "$ASSUME_YES" != 1 ]]; then
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

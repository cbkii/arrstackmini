# shellcheck shell=bash
install_vuetorrent() {
  msg "🎨 Installing VueTorrent WebUI..."

  local vuetorrent_dir="${ARR_DOCKER_DIR}/qbittorrent/vuetorrent"
  local releases_url="https://api.github.com/repos/VueTorrent/VueTorrent/releases/latest"

  ensure_dir "$vuetorrent_dir"

  local download_url=""
  download_url=$(curl -sL "$releases_url" | jq -r '.assets[] | select(.name == "vuetorrent.zip") | .browser_download_url' 2>/dev/null || printf '')

  if [[ -z "$download_url" ]]; then
    warn "Could not find VueTorrent download URL, skipping..."
    return 0
  fi

  if ! command -v unzip >/dev/null 2>&1; then
    warn "unzip command not available; skipping VueTorrent installation"
    return 0
  fi

  local temp_zip="/tmp/vuetorrent-$$.zip"
  if ! curl -sL "$download_url" -o "$temp_zip"; then
    rm -f "$temp_zip"
    warn "  Failed to download VueTorrent, continuing without it"
    return 0
  fi

  local temp_extract=""
  temp_extract="$(mktemp -d "/tmp/vuetorrent.XXXX" 2>/dev/null || printf '')"
  if [[ -z "$temp_extract" ]]; then
    rm -f "$temp_zip"
    warn "  Failed to create temporary directory for VueTorrent, continuing without it"
    return 0
  fi

  if ! unzip -qo "$temp_zip" -d "$temp_extract"; then
    rm -f "$temp_zip"
    rm -rf "$temp_extract"
    warn "  Failed to extract VueTorrent archive, continuing without it"
    return 0
  fi

  rm -f "$temp_zip"

  local source_root="$temp_extract"
  if [[ ! -f "$source_root/index.html" ]]; then
    local nested_index=""
    nested_index="$(find "$temp_extract" -type f -name 'index.html' -print -quit 2>/dev/null || printf '')"
    if [[ -n "$nested_index" ]]; then
      source_root="$(dirname "$nested_index")"
    fi
  fi

  if [[ ! -f "$source_root/index.html" ]]; then
    rm -rf "$temp_extract"
    warn "  VueTorrent archive did not contain an index.html, skipping installation"
    return 0
  fi

  find "$vuetorrent_dir" -mindepth 1 -exec rm -rf {} + 2>/dev/null || true

  ensure_dir "$vuetorrent_dir"

  local copy_failed=0
  shopt -s dotglob nullglob
  if ! cp -a "$source_root"/* "$vuetorrent_dir"/ 2>/dev/null; then
    copy_failed=1
  fi
  shopt -u dotglob nullglob

  rm -rf "$temp_extract"

  if ((copy_failed)); then
    warn "  Failed to install VueTorrent files, continuing without it"
    return 0
  fi

  chown -R "${PUID}:${PGID}" "$vuetorrent_dir" 2>/dev/null || true
  # macOS ships BSD xargs which lacks -r (see POSIX spec)
  local -a stale_containers=()
  while IFS= read -r container_id; do
    stale_containers+=("$container_id")
  done < <(docker ps -a --filter "label=com.docker.compose.project=arrstack" --format "{{.ID}}" 2>/dev/null)

  if ((${#stale_containers[@]} > 0)); then
    docker rm -f "${stale_containers[@]}" >/dev/null 2>&1 || true
  fi
  msg "  ✅ VueTorrent installed successfully"
}

safe_cleanup() {
  msg "🧹 Safely stopping existing services..."

  if [[ -f "$ARR_STACK_DIR/docker-compose.yml" ]]; then
    "${DOCKER_COMPOSE_CMD[@]}" stop 2>/dev/null || true
    sleep 5
    "${DOCKER_COMPOSE_CMD[@]}" down --remove-orphans 2>/dev/null || true
  fi

  local temp_files=(
    "$ARR_DOCKER_DIR/gluetun/forwarded_port"
    "$ARR_DOCKER_DIR/gluetun/forwarded_port.json"
    "$ARR_DOCKER_DIR/gluetun/port-forwarding.json"
    "$ARR_DOCKER_DIR/qbittorrent/qBittorrent/BT_backup/.cleaning"
  )

  local file
  for file in "${temp_files[@]}"; do
    rm -f "$file" 2>/dev/null || true
  done

  docker ps -a --filter "label=com.docker.compose.project=arrstack" --format "{{.ID}}" \
    | xargs -r docker rm -f 2>/dev/null || true
}

update_env_image_var() {
  local var_name="$1"
  local new_value="$2"

  if [[ -z "$var_name" || -z "$new_value" ]]; then
    return
  fi

  printf -v "$var_name" '%s' "$new_value"

  if [[ -f "$ARR_ENV_FILE" ]] && grep -q "^${var_name}=" "$ARR_ENV_FILE"; then
    portable_sed "s|^${var_name}=.*|${var_name}=${new_value}|" "$ARR_ENV_FILE"
  fi
}

check_image_exists() {
  local image="$1"

  if docker manifest inspect "$image" >/dev/null 2>&1; then
    return 0
  fi

  if docker image inspect "$image" >/dev/null 2>&1; then
    return 0
  fi

  return 1
}

validate_images() {
  msg "🔍 Validating Docker images..."

  local image_vars=(
    GLUETUN_IMAGE
    QBITTORRENT_IMAGE
    SONARR_IMAGE
    RADARR_IMAGE
    PROWLARR_IMAGE
    BAZARR_IMAGE
    FLARESOLVERR_IMAGE
    CADDY_IMAGE
  )

  local failed_images=()

  for var_name in "${image_vars[@]}"; do
    local image="${!var_name:-}"
    [[ -z "$image" ]] && continue

    msg "  Checking $image..."

    # Check via manifest (remote) or local cache without pulling layers
    if check_image_exists "$image"; then
      msg "  ✅ Valid: $image"
      continue
    fi

    # If failed, try fallback for LinuxServer images only
    local base_image="$image"
    local tag=""
    if [[ "$image" == *:* ]]; then
      base_image="${image%:*}"
      tag="${image##*:}"
    fi

    if [[ "$tag" != "latest" && "$base_image" == lscr.io/linuxserver/* ]]; then
      local latest_image="${base_image}:latest"
      msg "    Trying fallback: $latest_image"

      if check_image_exists "$latest_image"; then
        msg "    ✅ Using fallback: $latest_image"

        case "$base_image" in
          *qbittorrent) update_env_image_var QBITTORRENT_IMAGE "$latest_image" ;;
          *sonarr) update_env_image_var SONARR_IMAGE "$latest_image" ;;
          *radarr) update_env_image_var RADARR_IMAGE "$latest_image" ;;
          *prowlarr) update_env_image_var PROWLARR_IMAGE "$latest_image" ;;
          *bazarr) update_env_image_var BAZARR_IMAGE "$latest_image" ;;
        esac

        continue
      else
        warn "  ⚠️ Could not validate: $image"
        failed_images+=("$image")
      fi
    else
      warn "  ⚠️ Could not validate: $image"
      failed_images+=("$image")
    fi
  done

  if ((${#failed_images[@]} > 0)); then
    warn "================================================"
    warn "Some images could not be validated:"
    for img in "${failed_images[@]}"; do
      warn "  - $img"
    done
    warn "Check the image names and tags in .env or arrconf/userconf.sh"
    warn "================================================"
  fi
}

compose_up_service() {
  local service="$1"
  local output=""

  msg "  Starting $service..."
  if output="$("${DOCKER_COMPOSE_CMD[@]}" up -d "$service" 2>&1)"; then
    if [[ "$output" == *"is up-to-date"* ]]; then
      msg "  $service is up-to-date"
    elif [[ -n "$output" ]]; then
      while IFS= read -r line; do
        printf '    %s\n' "$line"
      done <<<"$output"
    fi
  else
    warn "  Failed to start $service"
    if [[ -n "$output" ]]; then
      while IFS= read -r line; do
        printf '    %s\n' "$line"
      done <<<"$output"
    fi
  fi
  sleep 2
}

sync_qbt_password_from_logs() {
  if [[ "$QBT_PASS" != "adminadmin" ]]; then
    return
  fi

  msg "  Detecting qBittorrent temporary password..."
  local attempts=0
  local detected=""

  while ((attempts < 60)); do
    detected="$(docker logs qbittorrent 2>&1 | grep -i "temporary password" | tail -1 | sed 's/.*temporary password[^:]*: *//' | awk '{print $1}' || true)"
    if [[ -n "$detected" ]]; then
      QBT_PASS="$detected"
      persist_env_var QBT_PASS "$QBT_PASS"
      msg "  Saved qBittorrent temporary password to .env (QBT_PASS)"
      return
    fi
    sleep 2
    ((attempts++))
  done

  warn "  Unable to automatically determine the qBittorrent password. Update QBT_PASS in .env manually."
}

wait_for_vpn_connection() {
  local max_wait="${1:-60}"
  local elapsed=0
  local check_interval=2
  local host="${LOCALHOST_IP:-localhost}"
  local vpn_status_url
  local public_ip_url

  if [[ $host == *:* && $host != [* ]]; then
    vpn_status_url="http://[$host]:${GLUETUN_CONTROL_PORT}/v1/openvpn/status"
    public_ip_url="http://[$host]:${GLUETUN_CONTROL_PORT}/v1/publicip/ip"
  else
    vpn_status_url="http://${host}:${GLUETUN_CONTROL_PORT}/v1/openvpn/status"
    public_ip_url="http://${host}:${GLUETUN_CONTROL_PORT}/v1/publicip/ip"
  fi

  msg "Waiting for VPN connection (max ${max_wait}s)..."

  while ((elapsed < max_wait)); do
    local health
    health="$(docker inspect gluetun --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' 2>/dev/null || true)"

    if [[ "$health" == "healthy" ]]; then
      msg "  ✅ Gluetun is healthy"
      return 0
    fi

    local -a curl_cmd=(curl -fsS --max-time 5)
    if [[ -n "${GLUETUN_API_KEY:-}" ]]; then
      curl_cmd+=(-H "X-Api-Key: ${GLUETUN_API_KEY}")
    fi

    if "${curl_cmd[@]}" "$vpn_status_url" >/dev/null 2>&1; then
      msg "  ✅ VPN API responding"
      local ip_payload=""
      ip_payload="$("${curl_cmd[@]}" "$public_ip_url" 2>/dev/null || true)"
      if [[ -n "$ip_payload" ]]; then
        local ip_summary
        if ip_summary="$(gluetun_public_ip_summary "$ip_payload" 2>/dev/null || true)" && [[ -n "$ip_summary" ]]; then
          msg "  🌐 Public IP: ${ip_summary}"
        else
          msg "  🌐 Public IP response: ${ip_payload}"
        fi
      else
        msg "  🌐 Public IP: (pending)"
      fi
      return 0
    fi

    sleep "$check_interval"
    elapsed=$((elapsed + check_interval))
  done

  warn "VPN connection timeout after ${max_wait}s"
  return 1
}

show_service_status() {
  msg "Service status summary:"
  local service
  local -a services=(gluetun qbittorrent sonarr radarr prowlarr bazarr flaresolverr caddy)
  if [[ "${ENABLE_LOCAL_DNS:-1}" -eq 1 && ${LOCAL_DNS_SERVICE_ENABLED:-0} -eq 1 ]]; then
    services+=(local_dns)
  fi

  local service
  for service in "${services[@]}"; do
    local status
    status="$(docker inspect "$service" --format '{{.State.Status}}' 2>/dev/null || echo "not found")"
    printf '  %-15s: %s\n' "$service" "$status"
  done
}

start_stack() {
  msg "🚀 Starting services"

  cd "$ARR_STACK_DIR" || die "Failed to change to ${ARR_STACK_DIR}"

  safe_cleanup

  validate_images

  install_vuetorrent

  local gluetun_attempts=0
  local gluetun_max_attempts=3
  local gluetun_started=0
  local output=""

  while ((gluetun_attempts < gluetun_max_attempts)); do
    local attempt=$((gluetun_attempts + 1))
    msg "Starting Gluetun VPN container (attempt ${attempt}/${gluetun_max_attempts})..."

    if output="$("${DOCKER_COMPOSE_CMD[@]}" up -d gluetun 2>&1)"; then
      if [[ -n "$output" ]]; then
        while IFS= read -r line; do
          printf '  %s\n' "$line"
        done <<<"$output"
      fi
      gluetun_started=1
      break
    fi

    warn "Failed to start Gluetun${output:+:}"
    if [[ -n "$output" ]]; then
      while IFS= read -r line; do
        printf '  %s\n' "$line"
      done <<<"$output"
    fi

    gluetun_attempts=$((gluetun_attempts + 1))
    if ((gluetun_attempts < gluetun_max_attempts)); then
      warn "Failed to start Gluetun, retrying in 10s..."
      sleep 10
    else
      warn "Failed to start Gluetun after ${gluetun_max_attempts} attempts"
    fi
  done

  if ((gluetun_started == 0)); then
    warn "Gluetun may not have started successfully"
  fi

  msg "Waiting for VPN connection..."
  local vpn_wait_levels=(60 120 180)
  local vpn_ready=0

  local max_wait
  for max_wait in "${vpn_wait_levels[@]}"; do
    if wait_for_vpn_connection "$max_wait"; then
      vpn_ready=1
      break
    fi

    warn "VPN not ready after ${max_wait}s, extending timeout..."
  done

  if ((vpn_ready == 0)); then
    warn "VPN connection not verified after extended wait"
    warn "Services will start anyway with potential connectivity issues"
  fi

  msg "Checking port forwarding status..."
  local pf_port
  pf_port="$(fetch_forwarded_port 2>/dev/null || printf '0')"

  if [[ -z "$pf_port" || "$pf_port" == "0" ]]; then
    warn "================================================"
    warn "Port forwarding is not active yet."
    warn "This is normal - it can take a few minutes."
    warn "================================================"
  else
    msg "✅ Port forwarding active: Port $pf_port"
  fi

  local services=()
  if [[ "${ENABLE_LOCAL_DNS:-1}" -eq 1 && ${LOCAL_DNS_SERVICE_ENABLED:-0} -eq 1 ]]; then
    services+=(local_dns)
  fi
  services+=(caddy qbittorrent sonarr radarr prowlarr bazarr flaresolverr)
  local service
  local qb_started=0
  local domain_suffix="${ARR_DOMAIN_SUFFIX_CLEAN}"

  for service in "${services[@]}"; do
    msg "Starting $service..."
    local service_started=0
    local start_output=""

    if start_output="$("${DOCKER_COMPOSE_CMD[@]}" up -d "$service" 2>&1)"; then
      if [[ -n "$start_output" ]]; then
        while IFS= read -r line; do
          printf '  %s\n' "$line"
        done <<<"$start_output"
      fi
      service_started=1
    else
      warn "Failed to start $service with normal dependencies"
      if [[ -n "$start_output" ]]; then
        while IFS= read -r line; do
          printf '  %s\n' "$line"
        done <<<"$start_output"
      fi

      local fallback_output=""
      if fallback_output="$("${DOCKER_COMPOSE_CMD[@]}" up -d --no-deps "$service" 2>&1)"; then
        msg "  Started $service without dependency checks"
        if [[ -n "$fallback_output" ]]; then
          while IFS= read -r line; do
            printf '    %s\n' "$line"
          done <<<"$fallback_output"
        fi
        service_started=1
      else
        warn "Failed to start $service even without dependencies, skipping..."
        if [[ -n "$fallback_output" ]]; then
          while IFS= read -r line; do
            printf '    %s\n' "$line"
          done <<<"$fallback_output"
        fi
        continue
      fi
    fi

    if [[ "$service" == "qbittorrent" && $service_started -eq 1 ]]; then
      qb_started=1
    fi

    sleep 3
  done

  if ((qb_started)); then
    sync_qbt_password_from_logs
  fi

  msg "Services started - they may take a minute to be fully ready"
  show_service_status
}

# shellcheck shell=bash

# Enhanced port conflict detection environment variables
: "${ARRSTACK_DEBUG_PORTS:=0}"
: "${ARRSTACK_PORT_TRACE:=0}"
: "${ARRSTACK_LEGACY_PORTCHECK:=0}"

# Structured logging for debugging
json_log() {
  local level="$1"
  shift
  
  if [[ "${ARRSTACK_DEBUG_PORTS}" != "1" ]]; then
    return 0
  fi
  
  local timestamp
  timestamp="$(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')"
  
  # Create logs directory if it doesn't exist
  local log_dir="${ARR_STACK_DIR:-/tmp}/logs"
  mkdir -p "$log_dir" 2>/dev/null || log_dir="/tmp"
  
  local log_file
  log_file="${log_dir}/port-scan-$(date +%Y%m%d).jsonl"
  
  # Build JSON message
  local json_msg="{\"timestamp\":\"$timestamp\",\"level\":\"$level\""
  
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --*)
        local key="${1#--}"
        local value="$2"
        # Escape JSON values
        value="${value//\\/\\\\}"
        value="${value//\"/\\\"}"
        json_msg="$json_msg,\"$key\":\"$value\""
        shift 2
        ;;
      *)
        json_msg="$json_msg,\"message\":\"$1\""
        shift
        ;;
    esac
  done
  
  json_msg="$json_msg}"
  
  printf '%s\n' "$json_msg" >> "$log_file"
  
  # Also log to stderr if trace mode is enabled
  if [[ "${ARRSTACK_PORT_TRACE}" == "1" ]]; then
    printf '[PORT-TRACE] %s\n' "$json_msg" >&2
  fi
}

install_missing() {
  msg "🔧 Checking dependencies"

  require_dependencies docker

  if ! docker version --format '{{.Server.Version}}' >/dev/null 2>&1; then
    die "Docker daemon is not running or not accessible"
  fi

  local compose_version_raw=""
  local compose_version_clean=""
  local compose_major=""

  if docker compose version >/dev/null 2>&1; then
    compose_version_raw="$(docker compose version --short 2>/dev/null || true)"
    compose_version_clean="${compose_version_raw#v}"
    compose_major="${compose_version_clean%%.*}"
    if [[ "$compose_major" =~ ^[0-9]+$ ]] && ((compose_major >= 2)); then
      DOCKER_COMPOSE_CMD=(docker compose)
    else
      compose_version_raw=""
      compose_version_clean=""
    fi
  fi

  if ((${#DOCKER_COMPOSE_CMD[@]} == 0)) && command -v docker-compose >/dev/null 2>&1; then
    compose_version_raw="$(docker-compose version --short 2>/dev/null || true)"
    compose_version_clean="${compose_version_raw#v}"
    compose_major="${compose_version_clean%%.*}"
    if [[ "$compose_major" =~ ^[0-9]+$ ]] && ((compose_major >= 2)); then
      DOCKER_COMPOSE_CMD=(docker-compose)
    else
      compose_version_raw=""
      compose_version_clean=""
    fi
  fi

  if ((${#DOCKER_COMPOSE_CMD[@]} == 0)); then
    die "Docker Compose v2+ is required but not found"
  fi

  require_dependencies curl jq openssl

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
  local compose_cmd_display="${DOCKER_COMPOSE_CMD[*]}"
  local compose_version_display="${compose_version_raw:-${compose_version_clean:-unknown}}"
  if [[ -n "$compose_version_display" && "$compose_version_display" != "unknown" ]]; then
    msg "  Compose: ${compose_cmd_display} ${compose_version_display}"
  else
    msg "  Compose: ${compose_cmd_display} (unknown)"
  fi
}


trim_whitespace() {
  local value="$1"

  if declare -f arrstack_trim_whitespace >/dev/null 2>&1; then
    printf '%s\n' "$(arrstack_trim_whitespace "$value")"
    return
  fi

  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"

  printf '%s\n' "$value"
}

declare -Ag DOCKER_PORT_BINDINGS=()
DOCKER_PORT_BINDINGS_LOADED=0

reset_docker_port_bindings_cache() {
  DOCKER_PORT_BINDINGS=()
  DOCKER_PORT_BINDINGS_LOADED=0
}

load_docker_port_bindings() {
  if ((DOCKER_PORT_BINDINGS_LOADED)); then
    return 0
  fi

  DOCKER_PORT_BINDINGS_LOADED=1

  if ! have_command docker; then
    return 0
  fi

  local line
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue

    local container_id=""
    local container_name=""
    local compose_project=""
    local compose_service=""
    local ports=""

    IFS='|' read -r container_id container_name compose_project compose_service ports <<<"$line"

    if [[ -z "$ports" || "$ports" == "<no value>" ]]; then
      continue
    fi

    compose_project="${compose_project//<no value>/}"
    compose_service="${compose_service//<no value>/}"

    local short_id="${container_id:0:12}"

    IFS=',' read -r -a mapped_ports <<<"$ports"

    local mapping
    for mapping in "${mapped_ports[@]}"; do
      mapping="$(trim_whitespace "$mapping")"
      [[ -z "$mapping" ]] && continue
      [[ "$mapping" != *"->"* ]] && continue

      local host_segment="${mapping%%->*}"
      local container_segment="${mapping##*->}"

      host_segment="$(trim_whitespace "$host_segment")"
      container_segment="$(trim_whitespace "$container_segment")"

      local proto="${container_segment##*/}"
      proto="${proto,,}"

      local host_port="${host_segment##*:}"
      local host_ip="${host_segment%:"${host_port}"}"

      if [[ "$host_ip" == "$host_segment" ]]; then
        host_ip="*"
      fi

      host_ip="$(normalize_bind_address "$host_ip")"

      if [[ -z "$proto" || -z "$host_port" ]]; then
        continue
      fi

      local desc="Docker container ${container_name}"

      if [[ -n "$compose_project" ]]; then
        desc+=" (compose project ${compose_project}"
        if [[ -n "$compose_service" ]]; then
          desc+=", service ${compose_service}"
        fi
        desc+=")"
      elif [[ -n "$compose_service" ]]; then
        desc+=" (service ${compose_service})"
      fi

      desc+=" (id ${short_id})"

      local key="${proto}|${host_port}"
      local value="${host_ip}|${desc}"

      if [[ -n "${DOCKER_PORT_BINDINGS[$key]:-}" ]]; then
        DOCKER_PORT_BINDINGS[$key]+=$'\n'
      fi

      DOCKER_PORT_BINDINGS[$key]+="$value"
    done
  done < <(docker ps --format '{{.ID}}|{{.Names}}|{{.Label "com.docker.compose.project"}}|{{.Label "com.docker.compose.service"}}|{{.Ports}}' 2>/dev/null || true)
}

docker_port_conflict_listeners() {
  local proto="$1"
  local expected_ip="$2"
  local port="$3"

  # address_conflicts is provided by scripts/common.sh (sourced via arrstack.sh).
  load_docker_port_bindings || true

  local key="${proto,,}|${port}"
  local data="${DOCKER_PORT_BINDINGS[$key]:-}"

  [[ -z "$data" ]] && return

  while IFS= read -r entry; do
    [[ -z "$entry" ]] && continue
    IFS='|' read -r bind_host docker_desc <<<"$entry"
    bind_host="$(normalize_bind_address "$bind_host")"
    if ! address_conflicts "$expected_ip" "$bind_host"; then
      continue
    fi
    printf '%s|%s\n' "$bind_host" "$docker_desc"
  done <<<"$data"
}

# Enhanced port conflict detection functions

# Gather comprehensive port snapshot from multiple sources
gather_port_snapshot() {
  local proto="$1"
  local port="$2"
  local expected_ip="${3:-*}"
  
  json_log "debug" "Starting port snapshot" --proto "$proto" --port "$port" --expected_ip "$expected_ip"
  
  local -a listeners=()
  local -A seen=()
  
  # Source 1: ss command (preferred)
  if have_command ss; then
    json_log "debug" "Gathering from ss command"
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
      local pid=""
      if [[ $line == *'users:(('* ]]; then
        local proc_segment="${line#*users:(()}"
        proc_segment="${proc_segment#\"}"
        local proc="${proc_segment%%\"*}"
        if [[ $line =~ pid=([0-9]+) ]]; then
          pid="${BASH_REMATCH[1]}"
          proc_desc="${proc} (pid ${pid})"
        else
          proc_desc="$proc"
        fi
      fi
      
      local normalized_host
      normalized_host="$(normalize_bind_address "$host")"
      local entry="${normalized_host}|${proc_desc:-}|${pid:-}|ss"
      
      if [[ -z "${seen[$entry]:-}" ]]; then
        listeners+=("$entry")
        seen["$entry"]=1
        json_log "debug" "Found listener via ss" --host "$normalized_host" --desc "$proc_desc" --pid "$pid"
      fi
    done < <(ss -H -${flag} "sport = :${port}" 2>/dev/null || true)
  fi
  
  # Source 2: lsof command (fallback)
  if have_command lsof; then
    json_log "debug" "Gathering from lsof command"
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
      
      local proc
      proc="$(awk '{print $1}' <<<"$line" 2>/dev/null || true)"
      local pid
      pid="$(awk '{print $2}' <<<"$line" 2>/dev/null || true)"
      local proc_desc="${proc:-}"
      if [[ -n "$pid" ]]; then
        proc_desc+="${proc_desc:+ }(pid ${pid})"
      fi
      
      local normalized_host
      normalized_host="$(normalize_bind_address "$host")"
      local entry="${normalized_host}|${proc_desc}|${pid:-}|lsof"
      
      if [[ -z "${seen[$entry]:-}" ]]; then
        listeners+=("$entry")
        seen["$entry"]=1
        json_log "debug" "Found listener via lsof" --host "$normalized_host" --desc "$proc_desc" --pid "$pid"
      fi
    done < <(lsof -nP "${spec[@]}" 2>/dev/null || true)
  fi
  
  # Source 3: /proc/net fallback (basic)
  if [[ ${#listeners[@]} -eq 0 ]]; then
    json_log "debug" "Gathering from /proc/net fallback"
    local proc_file="/proc/net/tcp"
    if [[ "$proto" == "udp" ]]; then
      proc_file="/proc/net/udp"
    fi
    
    if [[ -r "$proc_file" ]]; then
      local port_hex
      port_hex="$(printf '%04X' "$port")"
      
      while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*sl ]] && continue
        local local_addr
        local_addr="$(awk '{print $2}' <<<"$line" 2>/dev/null || true)"
        [[ -z "$local_addr" ]] && continue
        
        if [[ "$local_addr" == *":${port_hex}" ]]; then
          local host_hex="${local_addr%:*}"
          local host_ip
          # Convert hex IP to dotted decimal (basic IPv4 only)
          if [[ ${#host_hex} -eq 8 ]]; then
            local a=$((0x${host_hex:6:2}))
            local b=$((0x${host_hex:4:2}))
            local c=$((0x${host_hex:2:2}))
            local d=$((0x${host_hex:0:2}))
            host_ip="$a.$b.$c.$d"
          else
            host_ip="unknown"
          fi
          
          if address_conflicts "$expected_ip" "$host_ip"; then
            local normalized_host
            normalized_host="$(normalize_bind_address "$host_ip")"
            local entry="${normalized_host}|unknown process||proc"
            
            if [[ -z "${seen[$entry]:-}" ]]; then
              listeners+=("$entry")
              seen["$entry"]=1
              json_log "debug" "Found listener via /proc/net" --host "$normalized_host"
            fi
          fi
        fi
      done < "$proc_file"
    fi
  fi
  
  # Source 4: Docker containers
  json_log "debug" "Gathering from Docker containers"
  while IFS= read -r docker_entry; do
    [[ -z "$docker_entry" ]] && continue
    local entry="$docker_entry"
    if [[ -z "${seen[$entry]:-}" ]]; then
      listeners+=("$entry")
      seen["$entry"]=1
      json_log "debug" "Found listener via Docker" --entry "$entry"
    fi
  done < <(docker_port_conflict_listeners "$proto" "$expected_ip" "$port")
  
  # Source 5: systemd-resolved detection for port 53
  if [[ "$port" == "53" ]] && have_command systemctl; then
    json_log "debug" "Checking systemd-resolved for port 53"
    local resolved_pid
    resolved_pid="$(systemctl show systemd-resolved --property MainPID --value 2>/dev/null || true)"
    
    if [[ -n "$resolved_pid" && "$resolved_pid" != "0" ]]; then
      # Check if this PID is actually listening on port 53
      local listening=0
      if have_command ss; then
        if ss -ln | grep -q ":53 "; then
          if ss -lnp | grep ":53 " | grep -q "pid=${resolved_pid}"; then
            listening=1
          fi
        fi
      fi
      
      if ((listening)); then
        local entry="*|systemd-resolved (pid ${resolved_pid})|${resolved_pid}|systemd-resolved"
        if [[ -z "${seen[$entry]:-}" ]]; then
          listeners+=("$entry")
          seen["$entry"]=1
          json_log "debug" "Found systemd-resolved on port 53" --pid "$resolved_pid"
        fi
      fi
    fi
  fi
  
  json_log "debug" "Port snapshot complete" --listeners_found "${#listeners[@]}"
  printf '%s\n' "${listeners[@]}"
}

# Debounce conflicts by taking two snapshots and only keeping persistent listeners
debounce_conflicts() {
  local proto="$1"
  local port="$2" 
  local expected_ip="${3:-*}"
  local delay="${4:-1}"
  
  json_log "debug" "Starting conflict debouncing" --proto "$proto" --port "$port" --delay "$delay"
  
  # First snapshot
  local -a snapshot1=()
  mapfile -t snapshot1 < <(gather_port_snapshot "$proto" "$port" "$expected_ip")
  
  json_log "debug" "First snapshot complete" --count "${#snapshot1[@]}"
  
  # Wait between snapshots
  sleep "$delay"
  
  # Second snapshot
  local -a snapshot2=()
  mapfile -t snapshot2 < <(gather_port_snapshot "$proto" "$port" "$expected_ip")
  
  json_log "debug" "Second snapshot complete" --count "${#snapshot2[@]}"
  
  # Find persistent listeners (present in both snapshots)
  local -A persistent=()
  local -A first_snapshot=()
  
  # Index first snapshot
  local entry
  for entry in "${snapshot1[@]}"; do
    first_snapshot["$entry"]=1
  done
  
  # Check second snapshot for persistence
  for entry in "${snapshot2[@]}"; do
    IFS='|' read -r host desc pid _source <<<"$entry"
    
    # Special case: always include arrstack containers even if they appear in only one snapshot
    # (they might be starting up or shutting down)
    local classification
    classification="$(classify_listener_strict "$desc" "$pid" "$host")"
    
    if [[ "$classification" == "arrstack" ]]; then
      persistent["$entry"]=1
      json_log "debug" "Including arrstack container despite single snapshot" --entry "$entry"
      continue
    fi
    
    # Regular persistence check
    if [[ -n "${first_snapshot[$entry]:-}" ]]; then
      persistent["$entry"]=1
      json_log "debug" "Confirmed persistent listener" --entry "$entry"
    else
      json_log "debug" "Transient listener filtered out" --entry "$entry"
    fi
  done
  
  # Output persistent listeners in legacy format (host|desc)
  for entry in "${!persistent[@]}"; do
    IFS='|' read -r host desc _pid _source <<<"$entry"
    printf '%s|%s\n' "$host" "$desc"
  done
  
  json_log "debug" "Debouncing complete" --persistent_count "${#persistent[@]}"
}

# Strict listener classification to replace fuzzy matching
classify_listener_strict() {
  local desc="$1"
  local pid="${2:-}"
  local host="${3:-}"
  local container_name="${4:-}"
  
  json_log "debug" "Classifying listener" --desc "$desc" --pid "$pid" --host "$host" --container_name "$container_name"
  
  # Check if it's an arrstack container based on compose project or service name
  if [[ -n "$container_name" ]]; then
    # Check against current COMPOSE_PROJECT_NAME if set
    if [[ -n "${COMPOSE_PROJECT_NAME:-}" && "$container_name" == *"${COMPOSE_PROJECT_NAME}"* ]]; then
      printf "arrstack\n"
      json_log "debug" "Classified as arrstack via compose project" --project "$COMPOSE_PROJECT_NAME"
      return
    fi
    
    # Check against known arrstack services
    if [[ -n "${ARR_DOCKER_SERVICES:-}" ]]; then
      local service
      while IFS= read -r service; do
        if [[ -n "$service" && "$container_name" == *"$service"* ]]; then
          printf "arrstack\n" 
          json_log "debug" "Classified as arrstack via service match" --service "$service"
          return
        fi
      done <<<"${ARR_DOCKER_SERVICES}"
    fi
  fi
  
  # Check if it's a known arr process by exact executable name
  local desc_lower="${desc,,}"
  if [[ "$desc_lower" == *"qbittorrent-nox"* ]] || \
     [[ "$desc_lower" == *"mono"* && "$desc_lower" == *"sonarr"* ]] || \
     [[ "$desc_lower" == *"mono"* && "$desc_lower" == *"radarr"* ]] || \
     [[ "$desc_lower" == *"mono"* && "$desc_lower" == *"prowlarr"* ]] || \
     [[ "$desc_lower" == *"mono"* && "$desc_lower" == *"bazarr"* ]] || \
     [[ "$desc_lower" == *"jackett"* ]] || \
     [[ "$desc_lower" == *"flaresolverr"* ]] || \
     [[ "$desc_lower" == *"gluetun"* ]]; then
    printf "arrstack\n"
    json_log "debug" "Classified as arrstack via executable match"
    return
  fi
  
  # Check for systemd-resolved
  if [[ "$desc_lower" == *"systemd-resolved"* ]]; then
    printf "systemd-resolved\n"
    json_log "debug" "Classified as systemd-resolved"
    return
  fi
  
  # Verify systemd-resolved by PID if available
  if [[ -n "$pid" ]] && have_command systemctl; then
    local resolved_pid
    resolved_pid="$(systemctl show systemd-resolved --property MainPID --value 2>/dev/null || true)"
    if [[ -n "$resolved_pid" && "$resolved_pid" == "$pid" ]]; then
      printf "systemd-resolved\n"
      json_log "debug" "Classified as systemd-resolved via PID match" --pid "$pid"
      return
    fi
  fi
  
  # Default: other
  printf "other\n"
  json_log "debug" "Classified as other"
}

port_conflict_listeners() {
  local proto="$1"
  local expected_ip="$2"
  local port="$3"
  
  # Use legacy implementation if requested
  if [[ "${ARRSTACK_LEGACY_PORTCHECK}" == "1" ]]; then
    legacy_port_conflict_listeners "$@"
    return
  fi
  
  # Use new debounced approach
  debounce_conflicts "$proto" "$port" "$expected_ip"
}

# Legacy port conflict detection (original implementation)
legacy_port_conflict_listeners() {
  local proto="$1"
  local expected_ip="$2"
  local port="$3"

  local found=0
  local -a results=()
  local -A seen=()

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
      local normalized_host=""
      normalized_host="$(normalize_bind_address "$host")"
      local entry="${normalized_host}|${proc_desc:-}"
      if [[ -z "${seen[$entry]:-}" ]]; then
        results+=("$entry")
        seen["$entry"]=1
      fi
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
      local proc_desc="${proc:-}"
      if [[ -n "$pid" ]]; then
        proc_desc+="${proc_desc:+ }(pid ${pid})"
      fi
      local normalized_host=""
      normalized_host="$(normalize_bind_address "$host")"
      local entry="${normalized_host}|$proc_desc"
      if [[ -z "${seen[$entry]:-}" ]]; then
        results+=("$entry")
        seen["$entry"]=1
      fi
      found=1
    done < <(lsof -nP "${spec[@]}" 2>/dev/null || true)
  fi

  while IFS= read -r docker_entry; do
    [[ -z "$docker_entry" ]] && continue
    local entry="$docker_entry"
    if [[ -n "${seen[$entry]:-}" ]]; then
      continue
    fi
    results+=("$entry")
    seen["$entry"]=1
    found=1
  done < <(docker_port_conflict_listeners "$proto" "$expected_ip" "$port")

  printf '%s\n' "${results[@]}"
}


wait_for_conflicts_to_clear() {
  local -n _targets_ref="$1"
  local timeout="${2:-20}"

  if ((${#_targets_ref[@]} == 0)); then
    return 0
  fi

  local deadline=$((SECONDS + timeout))

  while ((SECONDS < deadline)); do
    local still_conflicted=0

    reset_docker_port_bindings_cache

    local entry=""
    for entry in "${_targets_ref[@]}"; do
      IFS='|' read -r port proto _rest <<<"$entry"
      proto="${proto,,}"

      local -a _listeners=()
      mapfile -t _listeners < <(port_conflict_listeners "$proto" "*" "$port")
      if ((${#_listeners[@]} > 0)); then
        still_conflicted=1
        break
      fi
    done

    if ((still_conflicted == 0)); then
      return 0
    fi

    sleep 1
  done

  return 1
}

listener_is_arrstack() {
  local desc="${1,,}"

  if [[ -z "$desc" ]]; then
    return 1
  fi

  # Use legacy classification if requested
  if [[ "${ARRSTACK_LEGACY_PORTCHECK}" == "1" ]]; then
    local patterns=(
      "arrstack"
      "qbittorrent"
      "sonarr"
      "radarr"
      "prowlarr"
      "jackett"
      "bazarr"
      "flaresolverr"
      "byparr"
      "proton"
      "gluetun"
    )

    local pattern
    for pattern in "${patterns[@]}"; do
      if [[ "$desc" == *"$pattern"* ]]; then
        return 0
      fi
    done

    if [[ "$desc" =~ [[:alpha:]]+arr ]]; then
      return 0
    fi

    return 1
  fi
  
  # Use new strict classification
  local classification
  classification="$(classify_listener_strict "$desc" "" "")"
  
  [[ "$classification" == "arrstack" ]]
}

format_listener_description() {
  local raw_desc="$1"

  if listener_is_arrstack "$raw_desc"; then
    printf '%s\n' "existing arrstack installation"
    return
  fi

  if [[ -z "$raw_desc" ]]; then
    printf '%s\n' "another service"
    return
  fi

  printf '%s\n' "$raw_desc"
}

stop_arrstack_services_and_continue() {
  local _arrstack_conflicts_name="$1"
  local -n _arrstack_conflicts_ref="$_arrstack_conflicts_name"

  msg ""
  msg "Stopping existing arrstack services..."

  if safe_cleanup; then
    msg "Existing arrstack services were stopped."
    if wait_for_conflicts_to_clear "$_arrstack_conflicts_name"; then
      msg "Ports previously held by arrstack were released."
    else
      warn "Ports are still reported in use after stopping arrstack. Re-checking availability."
    fi
    return 0
  fi

  die "Failed to stop the existing arrstack services. Resolve the conflicts manually and rerun the installer."
}

prompt_port_conflict_resolution() {
  local _conflicts_name="$1"
  local _arrstack_conflicts_name="$2"
  local -n _conflicts_ref="$_conflicts_name"
  local -n _arrstack_conflicts_ref="$_arrstack_conflicts_name"

msg ""
  msg "Port Conflict Detected!"
  msg ""
  msg "The following ports are already in use:"
  local entry
  for entry in "${_conflicts_ref[@]}"; do
    IFS='|' read -r port proto label host desc _is_arrstack <<<"$entry"
    local display_host
    display_host="$(trim_whitespace "${host:-}")"
    if [[ -z "$display_host" ]]; then
      display_host="*"
    fi
    msg "- Port ${port} (${label}): In use on ${display_host}${desc:+ by ${desc}}"
  done
  msg ""

  if ((${#_arrstack_conflicts_ref[@]} == ${#_conflicts_ref[@]})) && ((${#_conflicts_ref[@]} > 0)); then
    msg "These ports are likely being used by an existing arrstack installation."
  elif ((${#_arrstack_conflicts_ref[@]} > 0)); then
    msg "Some of these ports are currently in use by an existing arrstack installation."
  else
    msg "These ports are currently in use by other services on this host."
  fi

  msg ""
  if [[ "${ASSUME_YES}" == 1 ]]; then
    if ((${#_arrstack_conflicts_ref[@]} > 0)); then
      msg ""
      msg "--yes supplied: automatically selecting option 2 to stop the existing arrstack installation."
      stop_arrstack_services_and_continue "$_arrstack_conflicts_name"
      return $?
    fi

    die "--yes supplied but conflicting ports are not held by arrstack services. Resolve the conflicts manually or rerun without --yes."
  fi
  
  msg "How would you like to resolve this?"
  msg ""
  msg "1. Edit ports (Keeps existing arrstack running, you'll need to update userconf.sh)"
  msg "2. Stop existing arrstack and continue installation"
  msg "3. Use existing services (Stops this installation)"
  msg ""

  local choice=""
  while true; do
    printf 'Enter 1, 2, or 3: '
    if ! IFS= read -r choice; then
      choice=""
    fi
    case "$choice" in
      1)
        msg ""
        msg "Installation paused."
        msg "1. Edit the ports in userconf.sh"
        msg "2. Run this installer again"
        msg ""
        msg "Installation stopped. No changes were made."
        exit 0
        ;;
      2)
        if ((${#_arrstack_conflicts_ref[@]} == 0)); then
          msg ""
          msg "Option 2 is only available when an existing arrstack installation is detected on the conflicting ports."
          msg "Please choose a different option."
          continue
        fi

        msg ""
        msg "This will:"
        msg "1. Stop your existing arrstack installation"
        msg "2. Continue installing arrstackmini with default ports"
        msg ""
        printf 'Are you sure? (yes/no): '
        local confirm=""
        if ! IFS= read -r confirm; then
          confirm=""
        fi
        if [[ ${confirm,,} == "yes" ]]; then
          if stop_arrstack_services_and_continue "$_arrstack_conflicts_name"; then
            return 0
          fi
        fi
        msg ""
        msg "Installation cancelled."
        msg "Your existing arrstack installation will continue running."
        msg "No changes were made."
        exit 0
        ;;
      3)
        msg ""
        msg "Installation cancelled."
        msg "Your existing arrstack installation will continue running."
        msg "No changes were made."
        exit 0
        ;;
      *)
        msg ""
        msg "Please enter 1, 2, or 3 only."
        ;;
    esac
  done
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

  local cleanup_performed=0

  while true; do
    local conflict_found=0
    declare -A conflict_map=()
    declare -A conflict_arrstack=()
    local -a conflict_order=()

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

      local listener
      for listener in "${listeners[@]}"; do
        IFS='|' read -r bind_host raw_desc <<<"$listener"
        local is_arrstack=0
        if listener_is_arrstack "$raw_desc"; then
          is_arrstack=1
        fi
        local desc
        desc="$(format_listener_description "$raw_desc")"
        local conflict_key="${port}|${proto}|${bind_host}"
        if [[ -z "${conflict_map[$conflict_key]:-}" ]]; then
          conflict_map[$conflict_key]="${port}|${proto}|${port_labels[$key]}|${bind_host}|${desc}|${is_arrstack}"
          conflict_order+=("$conflict_key")
        fi
        if ((is_arrstack)); then
          conflict_map[$conflict_key]="${port}|${proto}|${port_labels[$key]}|${bind_host}|${desc}|1"
          conflict_arrstack[$conflict_key]=1
        fi
        conflict_found=1
      done
    done

    if ((conflict_found)); then
      local -a conflicts=()
      local -a arrstack_conflicts=()
      local conflict_id
      for conflict_id in "${conflict_order[@]}"; do
        local record="${conflict_map[$conflict_id]}"
        conflicts+=("$record")
        if [[ "${conflict_arrstack[$conflict_id]:-0}" -eq 1 ]]; then
          arrstack_conflicts+=("$record")
        fi
      done

      if prompt_port_conflict_resolution conflicts arrstack_conflicts; then
        reset_docker_port_bindings_cache
        DOCKER_PORT_BINDINGS=()
        DOCKER_PORT_BINDINGS_LOADED=0
        cleanup_performed=1
        continue
      fi
    fi

    break
  done

  if ((cleanup_performed)); then
    msg "    Existing arrstack services were stopped to free required ports."
  fi
}

validate_dns_configuration() {
  if [[ "${ENABLE_LOCAL_DNS:-0}" -ne 1 ]]; then
    return
  fi

  if [[ -z "${LAN_DOMAIN_SUFFIX:-}" ]]; then
    die "Local DNS requires LAN_DOMAIN_SUFFIX to be set to a non-empty domain suffix."
  fi

  local -a resolvers=()
  mapfile -t resolvers < <(collect_upstream_dns_servers)

  if ((${#resolvers[@]} == 0)); then
    die "Local DNS requires at least one upstream resolver via UPSTREAM_DNS_SERVERS or the legacy UPSTREAM_DNS_1/2 variables."
  fi

  local -a healthy=()
  local -a unhealthy=()
  local probe_rc=0
  local resolver

  for resolver in "${resolvers[@]}"; do
    local rc=0
    if probe_dns_resolver "$resolver" "cloudflare.com" 2; then
      healthy+=("$resolver")
      continue
    fi

    rc=$?
    if ((rc == 2)); then
      probe_rc=2
      warn "Skipping DNS reachability probe: install dig, drill, kdig, or nslookup to enable upstream validation."
      healthy=("${resolvers[@]}")
      unhealthy=()
      break
    fi

    unhealthy+=("$resolver")
  done

  if ((probe_rc != 2)); then
    if ((${#healthy[@]} == 0)); then
      die "None of the upstream DNS servers responded (${resolvers[*]}). Update UPSTREAM_DNS_SERVERS with reachable resolvers before continuing."
    fi

    if ((${#unhealthy[@]} > 0)); then
      warn "Upstream DNS servers unreachable during preflight probe: ${unhealthy[*]}"
    fi

    local -a ordered=()
    ordered+=("${healthy[@]}")
    ordered+=("${unhealthy[@]}")
    if [[ "${ordered[*]}" != "${resolvers[*]}" ]]; then
      # shellcheck disable=SC2034  # propagated to downstream scripts
      UPSTREAM_DNS_SERVERS="$(IFS=','; printf '%s' "${ordered[*]}")"
      # shellcheck disable=SC2034  # propagated to downstream scripts
      UPSTREAM_DNS_1="${ordered[0]}"
      # shellcheck disable=SC2034  # propagated to downstream scripts
      UPSTREAM_DNS_2="${ordered[1]:-}"
      if declare -p ARRSTACK_UPSTREAM_DNS_CHAIN >/dev/null 2>&1; then
        ARRSTACK_UPSTREAM_DNS_CHAIN=("${ordered[@]}")
      fi
      msg "  Reordered upstream DNS preference: ${ordered[*]}"
    fi
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

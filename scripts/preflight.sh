# shellcheck shell=bash

# Advisory on Port 53:
# Pros of keeping DNS on port 53:
# - Standards-compliant DNS (RFC 1035)
# - Universal client compatibility without configuration
# - Compatible with DHCP Option 6/Option 119 distribution
# - No need for client-side port customization
# Cons:
# - Commonly occupied by systemd-resolved, Pi-hole, AdGuard Home
# - Requires host takeover or alternative architectural approach
# Alternative ports (5053, 1053, 5335):
# - Reduce collision probability but break seamless LAN consumption
# - Clients/DHCP cannot use non-53 without stub forwarders
# Recommendation: retain port 53 by default; only advanced users should remap
# if they run external DNS aggregators.

# Global structures for enhanced port conflict detection
declare -Ag PID_CONTAINER_INDEX=()
declare -ig PID_CONTAINER_INDEX_LOADED=0

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

# Build PID→container mapping for enriched process descriptions
build_pid_container_index() {
  PID_CONTAINER_INDEX=()
  PID_CONTAINER_INDEX_LOADED=1

  if ! have_command docker; then
    return 0
  fi

  local line
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    
    local container_id container_name
    IFS='|' read -r container_id container_name <<<"$line"
    [[ -z "$container_id" || -z "$container_name" ]] && continue
    
    # Get all PIDs for this container
    local pid_line
    while IFS= read -r pid_line; do
      [[ -z "$pid_line" ]] && continue
      PID_CONTAINER_INDEX["$pid_line"]="$container_name"
    done < <(docker exec "$container_id" ps -eo pid --no-headers 2>/dev/null | tr -d ' ' || true)
    
    # Also map docker-proxy PIDs if available
    local proxy_pids
    proxy_pids="$(pgrep -f "docker-proxy.*${container_id:0:12}" 2>/dev/null || true)"
    if [[ -n "$proxy_pids" ]]; then
      local proxy_pid
      while read -r proxy_pid; do
        [[ -n "$proxy_pid" ]] && PID_CONTAINER_INDEX["$proxy_pid"]="$container_name"
      done <<<"$proxy_pids"
    fi
  done < <(docker ps --format '{{.ID}}|{{.Names}}' 2>/dev/null || true)
}

# Collect detailed listener information for a specific port with strict matching
# Returns TSV-like format: addr|pid|cmd|exe|user|container|proto|port|tools
collect_port_listeners_strict() {
  local proto="$1"
  local port="$2"
  
  # Ensure PID→container index is loaded
  if ((PID_CONTAINER_INDEX_LOADED == 0)); then
    build_pid_container_index
  fi
  
  local -A seen_records=()
  local -a results=()
  
  # Primary tool: ss
  if have_command ss; then
    local flag="lntp"
    [[ "$proto" == "udp" ]] && flag="lnup"
    
    local line
    while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      
      # Extract address and port - strict matching only
      local addr_field
      addr_field="$(awk '{print $4}' <<<"$line" 2>/dev/null || true)"
      [[ -z "$addr_field" ]] && continue
      
      local line_port="${addr_field##*:}"
      [[ "$line_port" != "$port" ]] && continue
      
      local bind_addr="${addr_field%:*}"
      bind_addr="$(normalize_bind_address "$bind_addr")"
      
      # Extract process info
      local pid="" cmd="" exe="" user=""
      if [[ $line == *'users:(('* ]]; then
        local proc_segment="${line#*users:((}"
        proc_segment="${proc_segment#\"}"
        cmd="${proc_segment%%\"*}"
        
        if [[ $line =~ pid=([0-9]+) ]]; then
          pid="${BASH_REMATCH[1]}"
        fi
        
        if [[ -n "$pid" ]]; then
          exe="$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo "")"
          user="$(ps -o user= -p "$pid" 2>/dev/null | tr -d ' ' || echo "")"
        fi
      fi
      
      local container="${PID_CONTAINER_INDEX[$pid]:-}"
      local record="${bind_addr}|${pid}|${cmd}|${exe}|${user}|${container}|${proto}|${port}|ss"
      
      if [[ -z "${seen_records[$record]:-}" ]]; then
        results+=("$record")
        seen_records["$record"]=1
      fi
    done < <(ss -H -${flag} "sport = :${port}" 2>/dev/null || true)
  fi
  
  # Secondary tool: lsof
  if have_command lsof; then
    local -a spec
    if [[ "$proto" == "udp" ]]; then
      spec=(-iUDP:"${port}")
    else
      spec=(-iTCP:"${port}" -sTCP:LISTEN)
    fi
    
    local line
    while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      [[ "$line" =~ ^COMMAND ]] && continue
      
      # Extract process info
      local cmd pid user name
      cmd="$(awk '{print $1}' <<<"$line" 2>/dev/null || true)"
      pid="$(awk '{print $2}' <<<"$line" 2>/dev/null || true)"
      user="$(awk '{print $3}' <<<"$line" 2>/dev/null || true)"
      name="$(awk '{print $9}' <<<"$line" 2>/dev/null || true)"
      
      [[ -z "$name" || -z "$pid" ]] && continue
      
      # Strict port matching
      name="${name%%->*}"
      name="${name% (LISTEN)}"
      local line_port="${name##*:}"
      [[ "$line_port" != "$port" ]] && continue
      
      local bind_addr="${name%:*}"
      bind_addr="$(normalize_bind_address "$bind_addr")"
      
      local exe
      exe="$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo "")"
      
      local container="${PID_CONTAINER_INDEX[$pid]:-}"
      local tools="lsof"
      
      # Check if we already have this from ss
      local existing_key="${bind_addr}|${pid}|${cmd}|${exe}|${user}|${container}|${proto}|${port}"
      local updated_record="${existing_key}|ss,lsof"
      local ss_record="${existing_key}|ss"
      
      if [[ -n "${seen_records[$ss_record]:-}" ]]; then
        # Update existing ss record to include lsof
        local idx
        for idx in "${!results[@]}"; do
          if [[ "${results[idx]}" == "$ss_record" ]]; then
            results[idx]="$updated_record"
            seen_records["$updated_record"]=1
            unset "seen_records[$ss_record]"
            break
          fi
        done
      else
        local record="${bind_addr}|${pid}|${cmd}|${exe}|${user}|${container}|${proto}|${port}|lsof"
        if [[ -z "${seen_records[$record]:-}" ]]; then
          results+=("$record")
          seen_records["$record"]=1
        fi
      fi
    done < <(lsof -nP "${spec[@]}" 2>/dev/null || true)
  fi
  
  # Tertiary tool: netstat (if available)
  if have_command netstat; then
    local netstat_flag="-lnpt"
    [[ "$proto" == "udp" ]] && netstat_flag="-lnpu"
    
    local line
    while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      [[ "$line" =~ ^(Active|Proto) ]] && continue
      
      local addr_field
      addr_field="$(awk '{print $4}' <<<"$line" 2>/dev/null || true)"
      [[ -z "$addr_field" ]] && continue
      
      local line_port="${addr_field##*:}"
      [[ "$line_port" != "$port" ]] && continue
      
      local bind_addr="${addr_field%:*}"
      bind_addr="$(normalize_bind_address "$bind_addr")"
      
      local pid_prog
      pid_prog="$(awk '{print $7}' <<<"$line" 2>/dev/null || true)"
      [[ -z "$pid_prog" || "$pid_prog" == "-" ]] && continue
      
      local pid="${pid_prog%%/*}"
      local cmd="${pid_prog##*/}"
      local exe user
      
      if [[ -n "$pid" && "$pid" =~ ^[0-9]+$ ]]; then
        exe="$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo "")"
        user="$(ps -o user= -p "$pid" 2>/dev/null | tr -d ' ' || echo "")"
      fi
      
      local container="${PID_CONTAINER_INDEX[$pid]:-}"
      local record="${bind_addr}|${pid}|${cmd}|${exe}|${user}|${container}|${proto}|${port}|netstat"
      
      # Check for existing records from ss/lsof and merge tools
      local base_key="${bind_addr}|${pid}|${cmd}|${exe}|${user}|${container}|${proto}|${port}"
      local found_existing=0
      local idx
      for idx in "${!results[@]}"; do
        if [[ "${results[idx]}" == "${base_key}|"* ]]; then
          local existing_tools="${results[idx]##*|}"
          results[idx]="${base_key}|${existing_tools},netstat"
          found_existing=1
          break
        fi
      done
      
      if ((!found_existing)) && [[ -z "${seen_records[$record]:-}" ]]; then
        results+=("$record")
        seen_records["$record"]=1
      fi
    done < <(netstat $netstat_flag 2>/dev/null | grep ":${port}[[:space:]]" || true)
  fi
  
  # Optional tool: fuser
  if have_command fuser; then
    local fuser_output
    fuser_output="$(fuser -v "${port}/${proto}" 2>/dev/null || true)"
    
    if [[ -n "$fuser_output" ]]; then
      local line
      while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        [[ "$line" =~ ^[[:space:]]*(USER|root) ]] && continue
        
        local fields
        read -r -a fields <<<"$line"
        
        if ((${#fields[@]} >= 3)); then
          local user="${fields[0]}"
          local pid="${fields[1]}"  
          local access="${fields[2]}"
          local cmd="${fields[3]:-}"
          
          [[ "$access" != *"F"* ]] && continue  # Only listening processes
          [[ ! "$pid" =~ ^[0-9]+$ ]] && continue
          
          local exe
          exe="$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo "")"
          
          local container="${PID_CONTAINER_INDEX[$pid]:-}"
          
          # Try to match with existing records and add fuser to tools
          local found_existing=0
          local idx
          for idx in "${!results[@]}"; do
            if [[ "${results[idx]}" == *"|${pid}|"* ]]; then
              local existing_tools="${results[idx]##*|}"
              results[idx]="${results[idx]%|*}|${existing_tools},fuser"
              found_existing=1
              break
            fi
          done
          
          if ((!found_existing)); then
            local record="*|${pid}|${cmd}|${exe}|${user}||${proto}|${port}|fuser"
            if [[ -z "${seen_records[$record]:-}" ]]; then
              results+=("$record")
              seen_records["$record"]=1
            fi
          fi
        fi
      done <<<"$fuser_output"
    fi
  fi
  
  printf '%s\n' "${results[@]}"
}

# Format listener record for display
describe_listener_record() {
  local record="$1"
  
  IFS='|' read -r addr pid cmd exe user container proto port tools <<<"$record"
  
  local desc=""
  if [[ -n "$container" ]]; then
    desc="PID ${pid} (${cmd}) container:${container}"
  else
    desc="PID ${pid} (${cmd})"
  fi
  
  [[ -n "$exe" ]] && desc+=" exe:${exe}"
  [[ -n "$user" ]] && desc+=" user:${user}"
  [[ -n "$tools" ]] && desc+=" tools:${tools}"
  
  printf '%s\n' "$desc"
}

port_conflict_listeners() {
  local proto="$1"
  local expected_ip="$2"
  local port="$3"

  # Use enhanced version if strict matching tools are available
  if have_command ss || have_command lsof; then
    # For exact port matching, we ignore expected_ip for the initial collection
    # and filter by address conflicts later to maintain existing behavior
    local -a strict_listeners=()
    mapfile -t strict_listeners < <(collect_port_listeners_strict "$proto" "$port")
    
    local -a results=()
    local -A seen=()
    
    local record
    for record in "${strict_listeners[@]}"; do
      [[ -z "$record" ]] && continue
      
      IFS='|' read -r bind_addr pid cmd exe user container record_proto record_port tools <<<"$record"
      
      # Apply address conflict logic for backward compatibility
      if ! address_conflicts "$expected_ip" "$bind_addr"; then
        continue
      fi
      
      local rich_desc
      rich_desc="$(describe_listener_record "$record")"
      
      local entry="${bind_addr}|${rich_desc}"
      if [[ -z "${seen[$entry]:-}" ]]; then
        results+=("$entry")
        seen["$entry"]=1
      fi
    done
    
    printf '%s\n' "${results[@]}"
    return 0
  fi

  # Original implementation as fallback when no enhanced tools available
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
        local proc_segment="${line#*users:((}"
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

# Check if PID is safe to kill (not PID 1 or kernel thread)
is_safe_to_kill() {
  local pid="$1"
  
  # Block PID 1 (init)
  if [[ "$pid" == "1" ]]; then
    return 1
  fi
  
  # Block kernel threads (PIDs with [ ] in comm)
  if [[ -f "/proc/$pid/comm" ]]; then
    local comm
    comm="$(cat "/proc/$pid/comm" 2>/dev/null || echo "")"
    if [[ "$comm" == \[*\] ]]; then
      return 1
    fi
  fi
  
  return 0
}

# Force stop conflicting processes/containers
force_stop_conflicts() {
  local _conflicts_name="$1"
  local -n _conflicts_ref="$_conflicts_name"
  
  msg ""
  msg "Force stopping conflicting processes/containers..."
  
  local -a strict_records=()
  local entry
  for entry in "${_conflicts_ref[@]}"; do
    IFS='|' read -r port proto label host desc is_arrstack <<<"$entry"
    
    # Get detailed info for this port
    local -a port_listeners=()
    mapfile -t port_listeners < <(collect_port_listeners_strict "$proto" "$port")
    
    local record
    for record in "${port_listeners[@]}"; do
      [[ -z "$record" ]] && continue
      
      IFS='|' read -r bind_addr pid cmd exe user container record_proto record_port tools <<<"$record"
      
      # Apply address conflict logic
      if ! address_conflicts "$host" "$bind_addr"; then
        continue
      fi
      
      strict_records+=("$record")
    done
  done
  
  local -A processed_pids=()
  local -A processed_containers=()
  local stopped_any=0
  
  local record
  for record in "${strict_records[@]}"; do
    [[ -z "$record" ]] && continue
    
    IFS='|' read -r bind_addr pid cmd exe user container record_proto record_port tools <<<"$record"
    
    # Handle containers first
    if [[ -n "$container" && -z "${processed_containers[$container]:-}" ]]; then
      processed_containers["$container"]=1
      msg "  Stopping container: $container"
      
      if have_command docker; then
        if docker stop "$container" >/dev/null 2>&1; then
          msg "    Container $container stopped successfully"
          stopped_any=1
          sleep 2
          
          # Check if still running, if so try kill
          if docker ps --format '{{.Names}}' | grep -q "^${container}$"; then
            warn "    Container $container still running, trying docker kill..."
            if docker kill "$container" >/dev/null 2>&1; then
              msg "    Container $container killed successfully"
              sleep 1
            else
              warn "    Failed to kill container $container"
            fi
          fi
        else
          warn "    Failed to stop container $container"
        fi
      fi
    fi
    
    # Handle individual processes
    if [[ -n "$pid" && "$pid" =~ ^[0-9]+$ && -z "${processed_pids[$pid]:-}" ]]; then
      processed_pids["$pid"]=1
      
      if ! is_safe_to_kill "$pid"; then
        warn "  Skipping unsafe PID $pid ($cmd)"
        continue
      fi
      
      # Special handling for systemd-resolved
      if [[ "$cmd" == "systemd-resolved" ]]; then
        if [[ "${ENABLE_LOCAL_DNS:-0}" -eq 1 ]]; then
          msg "  systemd-resolved detected with ENABLE_LOCAL_DNS=1"
          msg "  Recommendation: Run 'scripts/host-dns-setup.sh' after installation"
          msg "  For now, stopping systemd-resolved (not disabling)"
        else
          msg "  Stopping systemd-resolved (PID $pid)"
        fi
        
        if have_command systemctl; then
          if systemctl stop systemd-resolved >/dev/null 2>&1; then
            msg "    systemd-resolved stopped successfully"
            stopped_any=1
            sleep 2
          else
            warn "    Failed to stop systemd-resolved"
          fi
        fi
        continue
      fi
      
      # Generic process handling
      msg "  Stopping process: PID $pid ($cmd)"
      
      # Send SIGTERM first
      if kill -TERM "$pid" 2>/dev/null; then
        msg "    Sent SIGTERM to PID $pid"
        stopped_any=1
        
        # Wait up to 5 seconds for graceful shutdown
        local waited=0
        while ((waited < 5)) && kill -0 "$pid" 2>/dev/null; do
          sleep 1
          ((waited++))
        done
        
        # If still running, send SIGKILL
        if kill -0 "$pid" 2>/dev/null; then
          warn "    Process $pid still running after SIGTERM, sending SIGKILL"
          if kill -KILL "$pid" 2>/dev/null; then
            msg "    Sent SIGKILL to PID $pid"
            sleep 1
          else
            warn "    Failed to kill PID $pid"
          fi
        else
          msg "    Process PID $pid terminated gracefully"
        fi
      else
        warn "    Failed to send signal to PID $pid (may have already exited)"
      fi
    fi
  done
  
  if ((stopped_any)); then
    msg "  Waiting for ports to be released..."
    sleep 3
    
    # Reset caches
    reset_docker_port_bindings_cache
    PID_CONTAINER_INDEX=()
    PID_CONTAINER_INDEX_LOADED=0
    
    msg "  Force stop completed"
    return 0
  else
    warn "  No processes were stopped"
    return 1
  fi
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
  msg "4. Force stop conflicting processes/containers and continue"
  msg ""

  local choice=""
  while true; do
    printf 'Enter 1, 2, 3, or 4: '
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
      4)
        msg ""
        warn "This will forcibly terminate conflicting processes/containers!"
        warn "This may cause data loss or service interruption."
        msg ""
        printf 'Are you sure you want to force stop conflicts? (yes/no): '
        local confirm=""
        if ! IFS= read -r confirm; then
          confirm=""
        fi
        if [[ ${confirm,,} == "yes" ]]; then
          if force_stop_conflicts "$_conflicts_name"; then
            msg "Force stop completed. Continuing installation..."
            return 0
          else
            warn "Force stop failed or no processes were stopped."
            msg "Please resolve conflicts manually and try again."
            exit 1
          fi
        fi
        msg ""
        msg "Force stop cancelled."
        ;;
      *)
        msg ""
        msg "Please enter 1, 2, 3, or 4 only."
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

      # Handle automatic force-stop if --force-stop-conflicts was supplied
      if [[ "${FORCE_STOP_CONFLICTS:-0}" -eq 1 ]]; then
        msg ""
        msg "--force-stop-conflicts supplied: automatically force stopping conflicting processes/containers."
        
        if force_stop_conflicts conflicts; then
          msg "Force stop completed. Continuing installation..."
          reset_docker_port_bindings_cache
          DOCKER_PORT_BINDINGS=()
          DOCKER_PORT_BINDINGS_LOADED=0
          cleanup_performed=1
          continue
        else
          die "Force stop failed. Unable to free required ports automatically."
        fi
      fi

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

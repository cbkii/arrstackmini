# shellcheck shell=bash

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

PORT_SNAPSHOT_DEBUG_FILE=""
PORT_SNAPSHOT_SEQUENCE=0
PORT_MENU_REQUEST_RESCAN=0

port_snapshot_debug_enabled() {
  if [[ "${ARRSTACK_DEBUG_PORTS:-0}" -eq 1 ]]; then
    return 0
  fi
  if [[ "${ARRSTACK_PORT_TRACE:-0}" -eq 1 ]]; then
    return 0
  fi
  return 1
}

ensure_port_snapshot_debug_file() {
  if [[ -n "$PORT_SNAPSHOT_DEBUG_FILE" ]]; then
    return 0
  fi

  if ! port_snapshot_debug_enabled; then
    return 1
  fi

  local log_dir="${ARR_LOG_DIR:-${ARR_STACK_DIR:-}/logs}"
  if [[ -z "$log_dir" ]]; then
    log_dir="${ARR_STACK_DIR:-.}/logs"
  fi

  ensure_dir "$log_dir"
  PORT_SNAPSHOT_DEBUG_FILE="${log_dir}/port-scan-$(date +%Y%m%d-%H%M%S).jsonl"
  return 0
}

write_port_snapshot_debug() {
  local json="$1"
  local label="$2"

  if ! port_snapshot_debug_enabled; then
    return
  fi

  if ! ensure_port_snapshot_debug_file; then
    return
  fi

  local seq="$PORT_SNAPSHOT_SEQUENCE"
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    local with_seq=""
    with_seq="$(jq -c --argjson seq "$seq" '. + {sequence: $seq}' <<<"$line" 2>/dev/null || true)"
    if [[ -z "$with_seq" ]]; then
      continue
    fi
    printf '%s\n' "$with_seq" >>"$PORT_SNAPSHOT_DEBUG_FILE" 2>/dev/null || true
    seq=$((seq + 1))
  done < <(jq -c --arg label "$label" '.[] | {label:$label,proto:.proto,port:.port,bind:.bind,classification:.classification,sources:.sources,pids:.pids,containers:.containers,compose_project:.compose_project,compose_service:.compose_service,exe:.exe,cmd:.cmd,first_seen:.first_seen}' <<<"$json" 2>/dev/null || true)

  PORT_SNAPSHOT_SEQUENCE="$seq"
}

_generate_port_snapshot_json() {
  python3 - <<'PY'
import json
import os
import re
import subprocess
import time
from collections import defaultdict

PROJECT = os.environ.get("COMPOSE_PROJECT_NAME", "arrstack").lower()
ARR_SERVICES = {
    "gluetun",
    "qbittorrent",
    "sonarr",
    "radarr",
    "prowlarr",
    "bazarr",
    "flaresolverr",
    "caddy",
    "arr_local_dns",
    "arrstack_dns",
}
ARR_EXECUTABLES = {
    "gluetun",
    "qbittorrent-nox",
    "sonarr",
    "radarr",
    "prowlarr",
    "bazarr",
    "flaresolverr",
    "caddy",
    "dnsmasq",
}


def normalize_bind(address):
    if not address:
        return "*"
    address = address.split("%", 1)[0]
    address = address.strip()
    if address.startswith("[") and "]" in address:
        address = address[1:].split("]", 1)[0]
    if address.startswith("::ffff:"):
        address = address[7:]
    if not address or address == "0.0.0.0":
        return "*"
    return address


def read_text(path):
    try:
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError:
        return ""
    return data.decode(errors="ignore")


def read_cmdline(pid):
    data = read_text(f"/proc/{pid}/cmdline")
    if not data:
        return ""
    return data.replace("\x00", " ").strip()


def read_comm(pid):
    return read_text(f"/proc/{pid}/comm").strip()


def systemd_resolved_pid():
    try:
        out = subprocess.check_output(
            ["systemctl", "show", "-p", "MainPID", "systemd-resolved"],
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return ""
    if out.startswith("MainPID="):
        return out.strip().split("=", 1)[1]
    return ""


def name_tokens(value):
    value = value.lower()
    return {token for token in re.split(r"[-_.]", value) if token}


def container_matches_service(name):
    tokens = name_tokens(name)
    return any(service in tokens for service in ARR_SERVICES)


def executable_matches(value):
    value = value.lower()
    base = value.split("/")[-1]
    return base in ARR_EXECUTABLES


class SnapshotEntry:
    __slots__ = (
        "proto",
        "port",
        "bind",
        "pids",
        "executables",
        "cmdlines",
        "containers",
        "compose_projects",
        "compose_services",
        "sources",
        "first_seen",
    )

    def __init__(self, proto, port, bind, timestamp):
        self.proto = proto
        self.port = port
        self.bind = bind
        self.pids = set()
        self.executables = set()
        self.cmdlines = set()
        self.containers = {}
        self.compose_projects = set()
        self.compose_services = set()
        self.sources = set()
        self.first_seen = timestamp

    def merge_container(self, name, cid, project, service):
        ident = cid or name
        if not ident:
            return
        existing = self.containers.get(ident, {"id": cid or "", "name": name or ""})
        if name and not existing.get("name"):
            existing["name"] = name
        if cid and not existing.get("id"):
            existing["id"] = cid
        if project:
            existing["project"] = project
            self.compose_projects.add(project)
        if service:
            existing["service"] = service
            self.compose_services.add(service)
        self.containers[ident] = existing

    def to_dict(self, systemd_pid):
        pids_sorted = sorted(self.pids)
        executables_sorted = sorted(self.executables)
        cmdlines_sorted = sorted(self.cmdlines)
        containers_sorted = sorted(
            self.containers.values(),
            key=lambda item: (item.get("name") or "", item.get("id") or ""),
        )
        compose_projects_sorted = sorted({p for p in self.compose_projects if p})
        compose_services_sorted = sorted({s for s in self.compose_services if s})
        classification = "other"
        if any(project.lower() == PROJECT for project in compose_projects_sorted):
            classification = "arrstack"
        elif any(container_matches_service(meta.get("name", "")) for meta in containers_sorted):
            classification = "arrstack"
        elif any(service.lower() in ARR_SERVICES for service in compose_services_sorted):
            classification = "arrstack"
        elif any(executable_matches(exe) for exe in executables_sorted):
            classification = "arrstack"
        elif systemd_pid and systemd_pid in pids_sorted:
            classification = "systemd-resolved"

        primary_container = containers_sorted[0]["name"] if containers_sorted else None
        primary_container_id = containers_sorted[0]["id"] if containers_sorted else None

        primary_exe = executables_sorted[0] if executables_sorted else ""
        primary_cmd = cmdlines_sorted[0] if cmdlines_sorted else ""

        return {
            "proto": self.proto,
            "port": self.port,
            "bind": self.bind,
            "pids": pids_sorted,
            "primary_pid": pids_sorted[0] if pids_sorted else None,
            "executables": executables_sorted,
            "exe": primary_exe,
            "cmd": primary_cmd,
            "cmdlines": cmdlines_sorted,
            "containers": containers_sorted,
            "primary_container": primary_container,
            "primary_container_id": primary_container_id,
            "compose_project": compose_projects_sorted[0] if compose_projects_sorted else None,
            "compose_service": compose_services_sorted[0] if compose_services_sorted else None,
            "classification": classification,
            "sources": sorted(self.sources),
            "first_seen": self.first_seen,
        }


def docker_metadata():
    try:
        out = subprocess.check_output(
            [
                "docker",
                "ps",
                "--format",
                "{{.ID}}|{{.Names}}|{{.Label \"com.docker.compose.project\"}}|{{.Label \"com.docker.compose.service\"}}|{{.Ports}}",
            ],
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return {}, {}

    containers = {}
    port_records = defaultdict(list)

    for line in out.splitlines():
        if not line:
            continue
        parts = line.split("|", 4)
        if len(parts) != 5:
            continue
        cid, name, project, service, ports = parts
        project = "" if project == "<no value>" else project
        service = "" if service == "<no value>" else service
        name = "" if name == "<no value>" else name
        containers[cid] = {
            "id": cid,
            "name": name,
            "project": project,
            "service": service,
        }
        for mapping in ports.split(","):
            mapping = mapping.strip()
            if "->" not in mapping:
                continue
            host_segment, container_segment = mapping.split("->", 1)
            container_segment = container_segment.strip()
            proto = container_segment.split("/")[-1].lower()
            host_segment = host_segment.strip()
            if not proto:
                continue
            host_ip = "*"
            host_port = ""
            if host_segment:
                if host_segment.startswith("[") and "]" in host_segment:
                    host_ip, _, host_port = host_segment[1:].partition("]:")
                else:
                    host_ip, _, host_port = host_segment.rpartition(":")
                if not host_port:
                    host_port = host_ip
                    host_ip = "*"
            if not host_port:
                continue
            host_ip = normalize_bind(host_ip)
            host_port_digits = re.sub(r"[^0-9]", "", host_port)
            if not host_port_digits:
                continue
            port_records[(proto, int(host_port_digits), host_ip)].append(
                {
                    "container_id": cid,
                    "container_name": name,
                    "project": project,
                    "service": service,
                }
            )
    return containers, port_records


def docker_pid_metadata(container_meta):
    if not container_meta:
        return {}
    try:
        cmd = ["docker", "inspect", "-f", "{{.Id}}|{{.State.Pid}}", *container_meta.keys()]
        out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return {}
    mapping = {}
    for line in out.splitlines():
        if not line or "|" not in line:
            continue
        cid, pid = line.split("|", 1)
        pid = pid.strip()
        if pid and cid in container_meta:
            meta = container_meta[cid]
            mapping[pid] = {
                "id": cid,
                "name": meta.get("name", ""),
                "project": meta.get("project", ""),
                "service": meta.get("service", ""),
            }
    return mapping


def add_record(entry_map, proto, port, bind, timestamp, pid=None, exe=None, cmd=None, container=None, project=None, service=None, source=None):
    key = (proto, port, bind)
    if key not in entry_map:
        entry_map[key] = SnapshotEntry(proto, port, bind, timestamp)
    entry = entry_map[key]
    if pid:
        entry.pids.add(pid)
    if exe:
        entry.executables.add(exe)
    if cmd:
        entry.cmdlines.add(cmd)
    container_meta = container or {}
    entry.merge_container(container_meta.get("name"), container_meta.get("id"), project or container_meta.get("project"), service or container_meta.get("service"))
    if project:
        entry.compose_projects.add(project)
    if service:
        entry.compose_services.add(service)
    if source:
        entry.sources.add(source)


def collect_ss(entry_map, pid_meta, timestamp):
    for proto, flag in ("tcp", "t"), ("udp", "u"):
        try:
            out = subprocess.check_output(
                ["ss", "-H", f"-lnp{flag}"],
                text=True,
                stderr=subprocess.DEVNULL,
            )
        except (subprocess.CalledProcessError, FileNotFoundError):
            continue
        for line in out.splitlines():
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) < 4:
                continue
            local_field = parts[3]
            host = ""
            port_value = ""
            if local_field.startswith("[") and "]" in local_field:
                host, _, port_value = local_field[1:].partition("]:")
            else:
                host, _, port_value = local_field.rpartition(":")
            if not port_value:
                continue
            host = normalize_bind(host)
            if not port_value.isdigit():
                continue
            pid_match = re.search(r"pid=([0-9]+)", line)
            pid = pid_match.group(1) if pid_match else ""
            exe_match = re.search(r'users:\(\("([^\"]+)"', line)
            exe = exe_match.group(1) if exe_match else ""
            cmd = ""
            container_meta = None
            project = None
            service = None
            if pid:
                cmd = read_cmdline(pid) or read_comm(pid)
                container_meta = pid_meta.get(pid)
                if container_meta:
                    project = container_meta.get("project")
                    service = container_meta.get("service")
            add_record(entry_map, proto, int(port_value), host, timestamp, pid=pid or None, exe=exe or None, cmd=cmd or None, container=container_meta, project=project, service=service, source="ss")


def collect_lsof(entry_map, pid_meta, timestamp):
    specs = [(["-iTCP", "-sTCP:LISTEN"], "tcp"), (["-iUDP"], "udp")]
    for args, proto in specs:
        try:
            out = subprocess.check_output(
                ["lsof", "-nP", *args],
                text=True,
                stderr=subprocess.DEVNULL,
            )
        except (subprocess.CalledProcessError, FileNotFoundError):
            continue
        for line in out.splitlines():
            if not line or line.startswith("COMMAND"):
                continue
            parts = line.split()
            if len(parts) < 9:
                continue
            command = parts[0]
            pid = parts[1]
            name_field = parts[8]
            name_field = name_field.split("->", 1)[0]
            name_field = name_field.replace(" (LISTEN)", "")
            host, _, port_value = name_field.rpartition(":")
            if not port_value.isdigit():
                continue
            host = normalize_bind(host)
            cmd = read_cmdline(pid) or read_comm(pid)
            container_meta = pid_meta.get(pid)
            project = container_meta.get("project") if container_meta else None
            service = container_meta.get("service") if container_meta else None
            add_record(entry_map, proto, int(port_value), host, timestamp, pid=pid, exe=command, cmd=cmd or None, container=container_meta, project=project, service=service, source="lsof")


def collect_docker_ports(entry_map, port_records, container_meta, timestamp):
    for (proto, port, bind), records in port_records.items():
        for record in records:
            cid = record.get("container_id")
            meta = container_meta.get(cid, {}) if cid else {}
            add_record(entry_map, proto, port, bind, timestamp, container=meta, project=record.get("project"), service=record.get("service"), source="docker")


def main():
    timestamp = int(time.time())
    entry_map = {}
    container_meta, port_records = docker_metadata()
    pid_meta = docker_pid_metadata(container_meta)
    collect_ss(entry_map, pid_meta, timestamp)
    collect_lsof(entry_map, pid_meta, timestamp)
    collect_docker_ports(entry_map, port_records, container_meta, timestamp)
    systemd_pid = systemd_resolved_pid()
    results = [
        entry_map[key].to_dict(systemd_pid)
        for key in sorted(entry_map.keys())
    ]
    print(json.dumps(results))


if __name__ == "__main__":
    main()
PY
}

gather_port_snapshot() {
  local _output_name="$1"
  local label="${2:-snapshot}"
  local json="[]"

  json="$(_generate_port_snapshot_json 2>/dev/null || printf '[]')"

  write_port_snapshot_debug "$json" "$label"

  printf -v "$_output_name" '%s' "$json"
}

build_port_requirements() {
  local _requirements_name="$1"
  # shellcheck disable=SC2178
  local -n _requirements_ref="$_requirements_name"

  _requirements_ref=()

  local lan_ip_known=1
  if [[ -z "${LAN_IP:-}" || "${LAN_IP}" == "0.0.0.0" ]]; then
    lan_ip_known=0
  fi

  _requirements_ref+=("tcp|${GLUETUN_CONTROL_PORT}|Gluetun control API|${LOCALHOST_IP:-127.0.0.1}|gluetun-control")

  if [[ "${EXPOSE_DIRECT_PORTS:-0}" -eq 1 ]]; then
    if ((lan_ip_known == 0)); then
      die "EXPOSE_DIRECT_PORTS=1 requires LAN_IP to be set to your host's private IPv4 address before installation."
    fi
    if ! is_private_ipv4 "${LAN_IP}"; then
      die "LAN_IP='${LAN_IP}' is not a private IPv4 address. Set LAN_IP correctly before exposing ports."
    fi

    local expected="${LAN_IP}"
    _requirements_ref+=("tcp|${QBT_HTTP_PORT_HOST}|qBittorrent WebUI|${expected}|direct-qbt")
    _requirements_ref+=("tcp|${SONARR_PORT}|Sonarr WebUI|${expected}|direct-sonarr")
    _requirements_ref+=("tcp|${RADARR_PORT}|Radarr WebUI|${expected}|direct-radarr")
    _requirements_ref+=("tcp|${PROWLARR_PORT}|Prowlarr WebUI|${expected}|direct-prowlarr")
    _requirements_ref+=("tcp|${BAZARR_PORT}|Bazarr WebUI|${expected}|direct-bazarr")
    _requirements_ref+=("tcp|${FLARESOLVERR_PORT}|FlareSolverr API|${expected}|direct-flaresolverr")
  fi

  if [[ "${ENABLE_CADDY:-0}" -eq 1 ]] && ((lan_ip_known)); then
    _requirements_ref+=("tcp|80|Caddy HTTP|${LAN_IP}|caddy-http")
    _requirements_ref+=("tcp|443|Caddy HTTPS|${LAN_IP}|caddy-https")
  fi

  if [[ "${ENABLE_LOCAL_DNS:-0}" -eq 1 ]]; then
    local dns_expected="*"
    if ((lan_ip_known)); then
      dns_expected="$LAN_IP"
    fi
    _requirements_ref+=("tcp|53|Local DNS (TCP)|${dns_expected}|local-dns")
    _requirements_ref+=("udp|53|Local DNS (UDP)|${dns_expected}|local-dns")
  fi
}

find_requirement_conflicts() {
  local requirement="$1"
  local snapshot_json="$2"
  local _results_name="$3"
  # shellcheck disable=SC2178
  local -n _results_ref="$_results_name"

  _results_ref=()

  IFS='|' read -r req_proto req_port req_label req_expected req_feature <<<"$requirement"
  local port_int="$req_port"

  while IFS= read -r record; do
    [[ -z "$record" ]] && continue
    local bind
    bind="$(jq -r '.bind' <<<"$record" 2>/dev/null || printf '*')"
    if ! address_conflicts "$req_expected" "$bind"; then
      continue
    fi
    local conflict
    conflict="$(jq -c --arg label "$req_label" --arg expected "$req_expected" --arg feature "$req_feature" '
      {requirement:{proto:.proto,port:.port,label:$label,expected:$expected,feature:$feature},listener:.}
    ' <<<"$record" 2>/dev/null || true)"
    if [[ -n "$conflict" ]]; then
      _results_ref+=("$conflict")
    fi
  done < <(jq -c --arg proto "$req_proto" --argjson port "$port_int" '.[] | select(.proto == $proto and .port == $port)' <<<"$snapshot_json" 2>/dev/null || true)
}

evaluate_port_conflicts() {
  local _requirements_name="$1"
  local snapshot_json="$2"
  local _conflicts_name="$3"
  local _summary_name="$4"
  # shellcheck disable=SC2178
  local -n _requirements_ref="$_requirements_name"
  # shellcheck disable=SC2178
  local -n _conflicts_ref="$_conflicts_name"
  # shellcheck disable=SC2178
  local -n _summary_ref="$_summary_name"

  _conflicts_ref=()
  _summary_ref=()

  local requirement
  for requirement in "${_requirements_ref[@]}"; do
    local -a matches=()
    find_requirement_conflicts "$requirement" "$snapshot_json" matches
    _summary_ref["$requirement"]="${#matches[@]}"
    if ((${#matches[@]} > 0)); then
      _conflicts_ref+=("${matches[@]}")
    fi
  done
}

conflict_key() {
  local conflict_json="$1"
  jq -r '(.requirement.proto)+"|"+(.requirement.port|tostring)+"|"+(.listener.bind)+"|"+((.listener.primary_pid // "" )|tostring)+"|"+((.listener.primary_container_id // "")|tostring)' <<<"$conflict_json" 2>/dev/null || printf ''
}

debounce_conflicts() {
  local _requirements_name="$1"
  local _initial_conflicts_name="$2"
  local _final_conflicts_name="$3"
  local _final_summary_name="$4"
  # shellcheck disable=SC2178
  local -n _requirements_ref="$_requirements_name"
  # shellcheck disable=SC2178
  local -n _initial_conflicts_ref="$_initial_conflicts_name"
  # shellcheck disable=SC2178
  local -n _final_conflicts_ref="$_final_conflicts_name"
  # shellcheck disable=SC2178
  local -n _final_summary_ref="$_final_summary_name"

  local snapshot_again="[]"
  gather_port_snapshot snapshot_again "recheck"

  local -a res_conflicts=()
  declare -A res_summary=()
  evaluate_port_conflicts "$_requirements_name" "$snapshot_again" res_conflicts res_summary

  declare -A res_map=()
  local entry
  for entry in "${res_conflicts[@]}"; do
    local key
    key="$(conflict_key "$entry")"
    [[ -z "$key" ]] && continue
    res_map["$key"]="$entry"
  done

  _final_conflicts_ref=()
  for entry in "${_initial_conflicts_ref[@]}"; do
    local key
    key="$(conflict_key "$entry")"
    if [[ -n "${res_map[$key]:-}" ]]; then
      _final_conflicts_ref+=("${res_map[$key]}")
    fi
  done

  _final_summary_ref=()
  for entry in "${!res_summary[@]}"; do
    _final_summary_ref["$entry"]="${res_summary[$entry]}"
  done
}

print_port_statuses() {
  local _requirements_name="$1"
  local _summary_name="$2"
  # shellcheck disable=SC2178
  local -n _requirements_ref="$_requirements_name"
  # shellcheck disable=SC2178
  local -n _summary_ref="$_summary_name"

  local requirement
  for requirement in "${_requirements_ref[@]}"; do
    IFS='|' read -r proto port label _expected _feature <<<"$requirement"
    local count="${_summary_ref[$requirement]:-0}"
    if ((count > 0)); then
      msg "    [busy] ${label} port ${port}/${proto^^} in use"
    else
      msg "    [ok] ${label} port ${port}/${proto^^} is free"
    fi
  done
}

conflict_listener_description() {
  local conflict_json="$1"
  local container
  container="$(jq -r '.listener.primary_container // ""' <<<"$conflict_json" 2>/dev/null || printf '')"
  local pid
  pid="$(jq -r '.listener.primary_pid // ""' <<<"$conflict_json" 2>/dev/null || printf '')"
  local exe
  exe="$(jq -r '.listener.exe // ""' <<<"$conflict_json" 2>/dev/null || printf '')"
  local cmd
  cmd="$(jq -r '.listener.cmd // ""' <<<"$conflict_json" 2>/dev/null || printf '')"

  if [[ -n "$container" ]]; then
    printf '%s' "$container"
    return
  fi

  if [[ -n "$exe" ]]; then
    if [[ -n "$pid" ]]; then
      printf '%s (pid %s)' "$exe" "$pid"
    else
      printf '%s' "$exe"
    fi
    return
  fi

  if [[ -n "$pid" ]]; then
    printf 'pid %s' "$pid"
    return
  fi

  if [[ -n "$cmd" ]]; then
    printf '%s' "$cmd"
    return
  fi

  printf 'another service'
}

render_conflict_summary() {
  local _conflicts_name="$1"
  # shellcheck disable=SC2178
  local -n _conflicts_ref="$_conflicts_name"

  msg ""
  msg "Port Conflict Detected!"
  msg ""
  msg "The following ports are already in use:"
  local conflict
  for conflict in "${_conflicts_ref[@]}"; do
    local label
    local port
    local proto
    local bind
    local desc
    local classification
    label="$(jq -r '.requirement.label' <<<"$conflict" 2>/dev/null || printf '')"
    port="$(jq -r '.requirement.port' <<<"$conflict" 2>/dev/null || printf '')"
    proto="$(jq -r '.requirement.proto' <<<"$conflict" 2>/dev/null || printf '')"
    bind="$(jq -r '.listener.bind' <<<"$conflict" 2>/dev/null || printf '*')"
    desc="$(conflict_listener_description "$conflict")"
    classification="$(jq -r '.listener.classification' <<<"$conflict" 2>/dev/null || printf 'other')"
    msg "- Port ${port}/${proto^^} (${label}) on ${bind}: ${desc} [${classification}]"
  done
  msg ""
}

split_conflicts_by_class() {
  local _conflicts_name="$1"
  local _arr_name="$2"
  local _systemd_name="$3"
  local _other_name="$4"
  # shellcheck disable=SC2178
  local -n _conflicts_ref="$_conflicts_name"
  # shellcheck disable=SC2178
  local -n _arr_ref="$_arr_name"
  # shellcheck disable=SC2178
  local -n _systemd_ref="$_systemd_name"
  # shellcheck disable=SC2178
  local -n _other_ref="$_other_name"

  _arr_ref=()
  _systemd_ref=()
  _other_ref=()

  local conflict
  for conflict in "${_conflicts_ref[@]}"; do
    local classification
    classification="$(jq -r '.listener.classification' <<<"$conflict" 2>/dev/null || printf 'other')"
    case "$classification" in
      arrstack)
        _arr_ref+=("$conflict")
        ;;
      systemd-resolved)
        _systemd_ref+=("$conflict")
        ;;
      *)
        _other_ref+=("$conflict")
        ;;
    esac
  done
}

build_contextual_resolutions() {
  local _conflicts_name="$1"
  local _suggestions_name="$2"
  # shellcheck disable=SC2178
  local -n _conflicts_ref="$_conflicts_name"
  # shellcheck disable=SC2178
  local -n _suggestions_ref="$_suggestions_name"

  _suggestions_ref=()
  if ((${#_conflicts_ref[@]} == 0)); then
    return
  fi

  local conflicts_json="[]"
  conflicts_json="$(printf '%s\n' "${_conflicts_ref[@]}" | jq -s '.' 2>/dev/null || printf '[]')"

  if jq -e 'map(.requirement.feature) | index("local-dns")' <<<"$conflicts_json" >/dev/null 2>&1; then
    _suggestions_ref+=("disable-local-dns|Disable local DNS for this run")
  fi
}

apply_contextual_resolution() {
  local suggestion_id="$1"

  case "$suggestion_id" in
    disable-local-dns)
      if [[ "${ENABLE_LOCAL_DNS:-0}" -eq 1 ]]; then
        ENABLE_LOCAL_DNS=0
        export ENABLE_LOCAL_DNS
        msg "  Local DNS disabled for this run."
      else
        msg "  Local DNS already disabled."
      fi
      ;;
    *)
      warn "Unknown contextual action '${suggestion_id}'."
      return 1
      ;;
  esac

  return 0
}

stop_arrstack_services_and_continue() {
  msg ""
  msg "Stopping existing arrstack services..."

  if safe_cleanup; then
    msg "Existing arrstack services were stopped."
    return 0
  fi

  die "Failed to stop the existing arrstack services. Resolve the conflicts manually and rerun the installer."
}

force_kill_conflicts() {
  local _conflicts_name="$1"
  # shellcheck disable=SC2178
  local -n _conflicts_ref="$_conflicts_name"

  if ((${#_conflicts_ref[@]} == 0)); then
    return 0
  fi

  msg ""
  msg "Force-stopping the following listeners:" 

  declare -A seen_pids=()
  declare -A seen_containers=()
  local conflict
  for conflict in "${_conflicts_ref[@]}"; do
    local label
    local port
    local proto
    local bind
    local classification
    local desc
    label="$(jq -r '.requirement.label' <<<"$conflict" 2>/dev/null || printf '')"
    port="$(jq -r '.requirement.port' <<<"$conflict" 2>/dev/null || printf '')"
    proto="$(jq -r '.requirement.proto' <<<"$conflict" 2>/dev/null || printf '')"
    bind="$(jq -r '.listener.bind' <<<"$conflict" 2>/dev/null || printf '*')"
    classification="$(jq -r '.listener.classification' <<<"$conflict" 2>/dev/null || printf 'other')"
    desc="$(conflict_listener_description "$conflict")"
    msg "- ${label} port ${port}/${proto^^} on ${bind}: ${desc} (${classification})"
  done

  msg ""
  msg "Type FORCE to terminate these processes/containers (or anything else to cancel):"
  local response=""
  if ! IFS= read -r response; then
    return 1
  fi
  if [[ "${response^^}" != "FORCE" ]]; then
    msg "Force stop cancelled."
    return 1
  fi

  local conflict_json
  local action_failed=0
  for conflict_json in "${_conflicts_ref[@]}"; do
    local classification
    classification="$(jq -r '.listener.classification' <<<"$conflict_json" 2>/dev/null || printf 'other')"
    if [[ "$classification" == "systemd-resolved" ]]; then
      msg "  Skipping systemd-resolved (requires manual intervention)."
      continue
    fi

    local pid
    while IFS= read -r pid; do
      [[ -z "$pid" ]] && continue
      if [[ -n "${seen_pids[$pid]:-}" ]]; then
        continue
      fi
      seen_pids[$pid]=1
      if safe_kill "$pid" "listener on port"; then
        arrstack_json_log "{\"action\":\"kill\",\"pid\":${pid},\"result\":\"success\"}"
      else
        arrstack_json_log "{\"action\":\"kill\",\"pid\":${pid},\"result\":\"failed\"}"
        action_failed=1
      fi
    done < <(jq -r '.listener.pids[]? // empty' <<<"$conflict_json" 2>/dev/null || true)

    local container_json
    while IFS= read -r container_json; do
      [[ -z "$container_json" ]] && continue
      local cid
      local name
      cid="$(jq -r '.id // ""' <<<"$container_json" 2>/dev/null || printf '')"
      name="$(jq -r '.name // ""' <<<"$container_json" 2>/dev/null || printf '')"
      local ident="$cid"
      [[ -z "$ident" ]] && ident="$name"
      [[ -z "$ident" ]] && continue
      if [[ -n "${seen_containers[$ident]:-}" ]]; then
        continue
      fi
      seen_containers[$ident]=1
      if docker stop "$ident" >/dev/null 2>&1; then
        arrstack_json_log "{\"action\":\"docker-stop\",\"id\":\"${ident}\",\"result\":\"success\"}"
      else
        arrstack_json_log "{\"action\":\"docker-stop\",\"id\":\"${ident}\",\"result\":\"failed\"}"
        action_failed=1
      fi
    done < <(jq -c '.listener.containers[]?' <<<"$conflict_json" 2>/dev/null || true)
  done

  if ((action_failed)); then
    warn "One or more force-stop actions failed."
    return 1
  fi

  msg "Force-stop actions completed."
  PORT_MENU_REQUEST_RESCAN=1
  return 0
}

render_conflict_details() {
  local _conflicts_name="$1"
  # shellcheck disable=SC2178
  local -n _conflicts_ref="$_conflicts_name"

  msg ""
  msg "Detailed listener information:"
  if ((${#_conflicts_ref[@]} == 0)); then
    msg "  (no conflicts)"
    return
  fi

  local conflict
  for conflict in "${_conflicts_ref[@]}"; do
    local label
    local port
    local proto
    local bind
    local desc
    local classification
    local sources
    local pids
    label="$(jq -r '.requirement.label' <<<"$conflict" 2>/dev/null || printf '')"
    port="$(jq -r '.requirement.port' <<<"$conflict" 2>/dev/null || printf '')"
    proto="$(jq -r '.requirement.proto' <<<"$conflict" 2>/dev/null || printf '')"
    bind="$(jq -r '.listener.bind' <<<"$conflict" 2>/dev/null || printf '*')"
    desc="$(conflict_listener_description "$conflict")"
    classification="$(jq -r '.listener.classification' <<<"$conflict" 2>/dev/null || printf 'other')"
    sources="$(jq -r '.listener.sources | join(", ")' <<<"$conflict" 2>/dev/null || printf '')"
    pids="$(jq -r '.listener.pids | map(tostring) | join(", ")' <<<"$conflict" 2>/dev/null || printf '')"
    msg "- ${label} port ${port}/${proto^^}"
    msg "    Bind: ${bind}"
    msg "    Holder: ${desc}"
    msg "    Classification: ${classification}" 
    if [[ -n "$pids" ]]; then
      msg "    PIDs: ${pids}"
    fi
    if [[ -n "$sources" ]]; then
      msg "    Sources: ${sources}"
    fi
  done
}

select_contextual_resolution() {
  local _suggestions_name="$1"
  # shellcheck disable=SC2178
  local -n _suggestions_ref="$_suggestions_name"

  if ((${#_suggestions_ref[@]} == 0)); then
    warn "No contextual actions available."
    return 1
  fi

  msg ""
  msg "Contextual actions:" 
  local idx=1
  local suggestion
  for suggestion in "${_suggestions_ref[@]}"; do
    IFS='|' read -r ident description <<<"$suggestion"
    msg "  ${idx}. ${description}"
    idx=$((idx + 1))
  done

  printf 'Choose an action number (or press Enter to cancel): '
  local choice=""
  if ! IFS= read -r choice; then
    return 1
  fi
  [[ -z "$choice" ]] && return 1

  if ! [[ "$choice" =~ ^[0-9]+$ ]]; then
    warn "Invalid selection."
    return 1
  fi
  local index=$((choice))
  if ((index < 1 || index > ${#_suggestions_ref[@]})); then
    warn "Invalid selection."
    return 1
  fi

  local selected="${_suggestions_ref[index-1]}"
  IFS='|' read -r ident _description <<<"$selected"
  if apply_contextual_resolution "$ident"; then
    PORT_MENU_REQUEST_RESCAN=1
    return 0
  fi

  return 1
}

prompt_port_conflict_resolution() {
  local _conflicts_name="$1"
  local _arr_name="$2"
  local _systemd_name="$3"
  local _other_name="$4"
  local _suggestions_name="$5"
  # shellcheck disable=SC2178
  local -n _conflicts_ref="$_conflicts_name"
  # shellcheck disable=SC2178
  local -n _arr_ref="$_arr_name"
  # shellcheck disable=SC2178
  local -n _systemd_ref="$_systemd_name"
  # shellcheck disable=SC2178
  local -n _other_ref="$_other_name"
  # shellcheck disable=SC2178
  local -n _suggestions_ref="$_suggestions_name"

  render_conflict_summary "$_conflicts_name"

  if ((${#_arr_ref[@]} == ${#_conflicts_ref[@]})) && ((${#_conflicts_ref[@]} > 0)); then
    msg "These ports are held by an existing arrstack installation."
  elif ((${#_arr_ref[@]} > 0)); then
    msg "Some ports are held by an existing arrstack installation; others are held by external services."
  else
    msg "These ports are currently in use by other services on this host."
  fi
  msg ""

  msg "Available actions:"
  msg " 1. Edit ports and abort installation"
  if ((${#_arr_ref[@]} == ${#_conflicts_ref[@]})) && ((${#_conflicts_ref[@]} > 0)); then
    msg " 2. Stop existing arrstack containers"
  fi
  msg " 3. Abort (use existing services)"
  if ((${#_other_ref[@]} + ${#_systemd_ref[@]} > 0)); then
    msg " 4. Force stop/kill non-arrstack processes"
  fi
  if ((${#_suggestions_ref[@]} > 0)); then
    msg " 5. Apply contextual action"
  fi
  msg " D. Show detailed diagnostics"
  msg " R. Re-scan ports"
  msg ""

  while true; do
    printf 'Select an option: '
    local choice=""
    if ! IFS= read -r choice; then
      choice=""
    fi
    case "${choice^^}" in
      1)
        msg ""
        msg "Installation paused. Update your port configuration and rerun the installer."
        exit 0
        ;;
      2)
        if ! ((${#_arr_ref[@]} == ${#_conflicts_ref[@]} && ${#_conflicts_ref[@]} > 0)); then
          warn "Option 2 is only available when all conflicts are arrstack services."
          continue
        fi
        if stop_arrstack_services_and_continue; then
          PORT_MENU_REQUEST_RESCAN=1
          return 0
        fi
        return 1
        ;;
      3)
        die "Aborted due to existing services occupying required ports."
        ;;
      4)
        if (( ${#_other_ref[@]} + ${#_systemd_ref[@]} == 0 )); then
          warn "Option 4 is unavailable because no external services were detected."
          continue
        fi
        # shellcheck disable=SC2034
        local -a kill_targets=()
        # shellcheck disable=SC2034
        kill_targets=("${_other_ref[@]}" "${_systemd_ref[@]}")
        if force_kill_conflicts kill_targets; then
          return 0
        fi
        ;;
      5)
        if ((${#_suggestions_ref[@]} == 0)); then
          warn "No contextual actions available."
          continue
        fi
        if select_contextual_resolution "$_suggestions_name"; then
          return 0
        fi
        ;;
      D)
        render_conflict_details "$_conflicts_name"
        ;;
      R)
        PORT_MENU_REQUEST_RESCAN=1
        return 0
        ;;
      *)
        warn "Invalid selection."
        ;;
    esac
  done
}

check_port_conflicts() {
  msg "  Checking host port availability"

  local -a requirements=()
  build_port_requirements requirements

  if ((${#requirements[@]} == 0)); then
    msg "    No host port reservations required for the selected configuration."
    return
  fi

  local cleanup_performed=0

  while true; do
    local snapshot_json="[]"
    gather_port_snapshot snapshot_json "initial"

    local -a conflicts=()
    # shellcheck disable=SC2034
    declare -A summary=()
    evaluate_port_conflicts requirements "$snapshot_json" conflicts summary

    if ((${#conflicts[@]} == 0)); then
      print_port_statuses requirements summary
      break
    fi

    local -a confirmed_conflicts=()
    # shellcheck disable=SC2034
    declare -A confirmed_summary=()
    debounce_conflicts requirements conflicts confirmed_conflicts confirmed_summary

    if ((${#confirmed_conflicts[@]} == 0)); then
      print_port_statuses requirements confirmed_summary
      msg "    Detected listeners cleared during validation. Continuing."
      break
    fi

    local -a arr_conflicts=()
    # shellcheck disable=SC2034
    local -a systemd_conflicts=()
    # shellcheck disable=SC2034
    local -a other_conflicts=()
    split_conflicts_by_class confirmed_conflicts arr_conflicts systemd_conflicts other_conflicts

    # shellcheck disable=SC2034
    local -a suggestions=()
    build_contextual_resolutions confirmed_conflicts suggestions

    if [[ "${ASSUME_YES}" == 1 ]]; then
      if ((${#confirmed_conflicts[@]} == ${#arr_conflicts[@]})) && ((${#arr_conflicts[@]} > 0)); then
        if stop_arrstack_services_and_continue; then
          cleanup_performed=1
          continue
        fi
      fi
      die "--yes supplied but conflicting ports are not held by arrstack services. Resolve the conflicts manually or rerun without --yes."
    fi

    PORT_MENU_REQUEST_RESCAN=0
    prompt_port_conflict_resolution confirmed_conflicts arr_conflicts systemd_conflicts other_conflicts suggestions
    if ((PORT_MENU_REQUEST_RESCAN)); then
      cleanup_performed=1
      continue
    fi
  done

  if ((cleanup_performed)); then
    msg "    Existing arrstack services were stopped or adjusted to free required ports."
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
      # shellcheck disable=SC2034
      UPSTREAM_DNS_SERVERS="$(IFS=','; printf '%s' "${ordered[*]}")"
      # shellcheck disable=SC2034
      UPSTREAM_DNS_1="${ordered[0]}"
      # shellcheck disable=SC2034
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

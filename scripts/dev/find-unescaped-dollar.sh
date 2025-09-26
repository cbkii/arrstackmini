#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/dev/find-unescaped-dollar.sh [COMPOSE_FILE]

Scan a docker-compose.yml for environment interpolation tokens (e.g. ${VAR})
and report any that do not have a matching definition in the generated .env file
or the repository defaults.
USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

compose_file="${1:-}";
if [[ -z "$compose_file" ]]; then
  if [[ -n "${ARR_STACK_DIR:-}" ]]; then
    compose_file="${ARR_STACK_DIR}/docker-compose.yml"
  else
    compose_file="docker-compose.yml"
  fi
fi

if [[ ! -f "$compose_file" ]]; then
  echo "compose file not found: $compose_file" >&2
  exit 1
fi

compose_dir="$(cd "$(dirname "$compose_file")" && pwd)"

collect_keys() {
  local file="$1"
  if [[ ! -f "$file" ]]; then
    return
  fi
  awk -F= '/^[A-Za-z_][A-Za-z0-9_]*=/ {print $1}' "$file"
}

declare -A allow_map=()

while IFS= read -r key; do
  [[ -z "$key" ]] && continue
  allow_map["$key"]=1
done < <(collect_keys "${compose_dir}/.env" 2>/dev/null || true)

while IFS= read -r key; do
  [[ -z "$key" ]] && continue
  allow_map["$key"]=1
done < <(collect_keys "${REPO_ROOT}/.env.example" 2>/dev/null || true)

while IFS= read -r key; do
  [[ -z "$key" ]] && continue
  allow_map["$key"]=1
done < <(collect_keys "${REPO_ROOT}/arrconf/userr.conf.defaults.sh" 2>/dev/null || true)

while IFS= read -r key; do
  [[ -z "$key" ]] && continue
  allow_map["$key"]=1
done < <(collect_keys "${REPO_ROOT}/arrconf/userr.conf.example" 2>/dev/null || true)

# Common compose internals we intentionally reference
for key in COMPOSE_PROJECT_NAME DOCKER_CLIENT_TIMEOUT DOCKER_HOST; do
  allow_map["$key"]=1
done

mapfile -t tokens < <(grep -oE '\$\{[^}]+\}' "$compose_file" | sed 's/^\${//' | sed 's/}$//' | sort -u)

if ((${#tokens[@]} == 0)); then
  echo "No interpolation tokens detected in ${compose_file}."
  exit 0
fi

declare -a suspects=()
for token in "${tokens[@]}"; do
  if [[ -z "${allow_map[$token]+x}" ]]; then
    suspects+=("$token")
  fi
done

if ((${#suspects[@]} == 0)); then
  echo "All interpolation tokens are accounted for."
  exit 0
fi

echo "== Tokens without matching definitions =="
printf '%s\n' "${suspects[@]}"

echo
for token in "${suspects[@]}"; do
  echo "-- \${${token}} --"
  while IFS=: read -r line _; do
    start=$((line > 2 ? line - 2 : 1))
    end=$((line + 2))
    nl -ba "$compose_file" | sed -n "${start},${end}p"
    echo
  done < <(grep -nF "\${${token}}" "$compose_file" || true)
done

# shellcheck shell=bash

check_and_fix_mode() {
  local target="$1"
  local desired="$2"
  local issue_label="$3"

  [[ -e "$target" ]] || return 0

  local perms
  perms="$(stat -c '%a' "$target" 2>/dev/null || echo 'unknown')"

  if [[ "$perms" != "$desired" ]]; then
    warn "  ${issue_label} on $target: $perms (should be $desired)"
    chmod "$desired" "$target" 2>/dev/null || warn "  Could not fix permissions on $target"
    return 1
  fi

  return 0
}

verify_permissions() {
  local issues=0

  msg "🔒 Verifying file permissions"

  local -a secret_files=(
    "${ARR_ENV_FILE}"
    "${ARRCONF_DIR}/proton.auth"
    "${ARR_DOCKER_DIR}/qbittorrent/qBittorrent.conf"
    "${ARR_STACK_DIR}/.arraliases"
  )

  local file
  for file in "${secret_files[@]}"; do
    if [[ -f "$file" ]]; then
      if ! check_and_fix_mode "$file" "$SECRET_FILE_MODE" "Insecure permissions"; then
        ((issues++))
      fi
    fi
  done

  local -a nonsecret_files=(
    "${ARR_STACK_DIR}/docker-compose.yml"
    "${REPO_ROOT}/.arraliases.configured"
  )

  for file in "${nonsecret_files[@]}"; do
    if [[ -f "$file" ]]; then
      if ! check_and_fix_mode "$file" "$NONSECRET_FILE_MODE" "Unexpected permissions"; then
        ((issues++))
      fi
    fi
  done

  local -a data_dirs=("${ARR_DOCKER_DIR}")
  local service
  for service in "${ARR_DOCKER_SERVICES[@]}"; do
    if [[ "$service" == "local_dns" ]]; then
      if [[ "${ENABLE_LOCAL_DNS:-1}" -ne 1 || ${LOCAL_DNS_SERVICE_ENABLED:-0} -ne 1 ]]; then
        continue
      fi
    fi
    data_dirs+=("${ARR_DOCKER_DIR}/${service}")
  done

  local dir
  for dir in "${data_dirs[@]}"; do
    if [[ -d "$dir" ]]; then
      if ! check_and_fix_mode "$dir" "$DATA_DIR_MODE" "Loose permissions"; then
        ((issues++))
      fi
    fi
  done

  if [[ -d "${ARRCONF_DIR}" ]]; then
    if ! check_and_fix_mode "${ARRCONF_DIR}" 700 "Loose permissions"; then
      ((issues++))
    fi
  fi

  if ((issues > 0)); then
    warn "$issues permission issues detected (corrected where possible)"
  else
    msg "  All permissions verified ✓"
  fi
}

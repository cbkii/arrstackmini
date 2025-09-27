# shellcheck shell=bash

check_and_fix_mode() {
  local target="$1"
  local desired="$2"
  local issue_label="$3"
  local silent_on_fix="${4:-0}"

  [[ -e "$target" ]] || return 0

  local perms
  perms="$(stat -c '%a' "$target" 2>/dev/null || echo 'unknown')"

  if [[ "$perms" != "$desired" ]]; then
    local mismatch_logged=0
    local mismatch_message
    mismatch_message="  ${issue_label} on $target: $perms (should be $desired)"

    if ((silent_on_fix == 0)); then
      warn "$mismatch_message"
      mismatch_logged=1
    fi

    if chmod "$desired" "$target" 2>/dev/null; then
      perms="$(stat -c '%a' "$target" 2>/dev/null || echo 'unknown')"
      if [[ "$perms" != "$desired" ]]; then
        if ((mismatch_logged == 0)); then
          warn "$mismatch_message"
          mismatch_logged=1
        fi
        warn "  Permissions remain ${perms}; manual fix required for $target"
        return 1
      fi
      return 0
    fi

    if ((mismatch_logged == 0)); then
      warn "$mismatch_message"
    fi
    warn "  Could not fix permissions on $target"
    return 1
  fi

  return 0
}

verify_permissions() {
  local issues=0
  local collab_enabled=0

  if [[ "${ARR_PERMISSION_PROFILE}" == "collab" && "${COLLAB_GROUP_WRITE_ENABLED:-0}" -eq 1 ]]; then
    collab_enabled=1
  fi

  msg "🔒 Verifying file permissions"

  collab_warn_permission_failure() {
    local message="$1"

    if [[ -z "$message" ]]; then
      return 0
    fi

    local already_listed=0
    if [[ -n "${COLLAB_PERMISSION_WARNINGS:-}" ]]; then
      local padded=$'\n'"${COLLAB_PERMISSION_WARNINGS}"$'\n'
      local needle=$'\n'"${message}"$'\n'
      if [[ "$padded" == *"${needle}"* ]]; then
        already_listed=1
      fi
    fi

    if ((already_listed == 0)); then
      warn "$message"
    fi

    arrstack_append_collab_warning "$message"
  }

  collab_try_fix_dir() {
    local dir="$1"

    if [[ -z "$dir" || ! -d "$dir" ]]; then
      return 0
    fi

    chmod "$DATA_DIR_MODE" "$dir" 2>/dev/null || true

    if arrstack_is_group_writable "$dir"; then
      return 0
    fi

    return 1
  }

  collab_warn_label_failure() {
    local dir="$1"
    local label="$2"

    if [[ -z "$dir" || -z "$label" ]]; then
      return 0
    fi

    local message
    message="${label} directory not group-writable and could not apply ${DATA_DIR_MODE} (collab) — fix manually: ${dir}"
    collab_warn_permission_failure "$message"
  }

  local -a secret_files=(
    "${ARR_ENV_FILE}"
    "${ARR_USERCONF_PATH}"
    "${ARRCONF_DIR}/proton.auth"
    "${ARR_DOCKER_DIR}/qbittorrent/qBittorrent.conf"
    "${ARR_STACK_DIR}/.aliasarr"
    "${ARR_DOCKER_DIR}/configarr/secrets.yml"
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
    "${REPO_ROOT}/.aliasarr.configured"
    "${ARR_DOCKER_DIR}/configarr/config.yml"
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
      if [[ "${ENABLE_LOCAL_DNS:-0}" -ne 1 || ${LOCAL_DNS_SERVICE_ENABLED:-0} -ne 1 ]]; then
        continue
      fi
    fi
    data_dirs+=("${ARR_DOCKER_DIR}/${service}")
  done

  local dir
  for dir in "${data_dirs[@]}"; do
    if [[ -d "$dir" ]]; then
      if ! check_and_fix_mode "$dir" "$DATA_DIR_MODE" "Loose permissions" 1; then
        if ((collab_enabled)) && ! collab_try_fix_dir "$dir"; then
          collab_warn_permission_failure "${dir} is not group-writable; adjust manually to let the media group manage container data"
        fi
        ((issues++))
      fi
    fi
  done

  if ((collab_enabled)); then
    if [[ -d "${DOWNLOADS_DIR}" ]]; then
      if ! check_and_fix_mode "${DOWNLOADS_DIR}" "$DATA_DIR_MODE" "Loose permissions" 1; then
        if ! collab_try_fix_dir "${DOWNLOADS_DIR}"; then
          collab_warn_label_failure "${DOWNLOADS_DIR}" "Downloads"
        fi
        ((issues++))
      fi
    fi

    if [[ -d "${COMPLETED_DIR}" ]]; then
      if ! check_and_fix_mode "${COMPLETED_DIR}" "$DATA_DIR_MODE" "Loose permissions" 1; then
        if ! collab_try_fix_dir "${COMPLETED_DIR}"; then
          collab_warn_label_failure "${COMPLETED_DIR}" "Completed"
        fi
        ((issues++))
      fi
    fi
  fi

  if ((collab_enabled)); then
    local collab_created_dir
    if [[ -n "${COLLAB_CREATED_MEDIA_DIRS:-}" ]]; then
      while IFS= read -r collab_created_dir; do
        [[ -z "$collab_created_dir" ]] && continue
        if [[ -d "$collab_created_dir" ]]; then
          if ! check_and_fix_mode "$collab_created_dir" "$DATA_DIR_MODE" "Loose permissions" 1; then
            if ! collab_try_fix_dir "$collab_created_dir"; then
              collab_warn_permission_failure "${collab_created_dir} is not group-writable; adjust manually so the media apps can manage it"
            fi
            ((issues++))
          fi
        fi
      done < <(printf '%s\n' "${COLLAB_CREATED_MEDIA_DIRS}")
    fi

    local -a collab_existing_media=("${TV_DIR}" "${MOVIES_DIR}")
    if [[ -n "${SUBS_DIR:-}" ]]; then
      collab_existing_media+=("${SUBS_DIR}")
    fi

    local media_dir
    for media_dir in "${collab_existing_media[@]}"; do
      [[ -z "$media_dir" ]] && continue
      if [[ -d "$media_dir" ]]; then
        local already_tracked=0
        if [[ -n "${COLLAB_CREATED_MEDIA_DIRS:-}" ]]; then
          local padded=$'\n'"${COLLAB_CREATED_MEDIA_DIRS}"$'\n'
          local needle=$'\n'"${media_dir}"$'\n'
          if [[ "$padded" == *"${needle}"* ]]; then
            already_tracked=1
          fi
        fi
        if ((already_tracked)); then
          continue
        fi
        if ! collab_try_fix_dir "$media_dir"; then
          local label=""
          if [[ -n "${TV_DIR:-}" && "$media_dir" == "$TV_DIR" ]]; then
            label="TV"
          elif [[ -n "${MOVIES_DIR:-}" && "$media_dir" == "$MOVIES_DIR" ]]; then
            label="Movies"
          elif [[ -n "${SUBS_DIR:-}" && "$media_dir" == "$SUBS_DIR" ]]; then
            label="Subtitles"
          fi

          if [[ -n "$label" ]]; then
            collab_warn_label_failure "$media_dir" "$label"
          else
            collab_warn_permission_failure "${media_dir} stays non-group-writable (existing library); update manually if the media group should write here"
          fi
        fi
      fi
    done
  fi

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

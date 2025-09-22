# shellcheck shell=bash
run_one_time_migrations() {
  local legacy_auth="${ARR_DOCKER_DIR}/gluetun/auth/config.toml"

  if [[ -f "$legacy_auth" ]]; then
    local legacy_backup
    legacy_backup="${legacy_auth}.bak.$(date +%s)"
    if mv "$legacy_auth" "$legacy_backup" 2>/dev/null; then
      warn "Removed legacy Gluetun auth config; backup saved to ${legacy_backup}"
    else
      rm -f "$legacy_auth" 2>/dev/null || true
      warn "Removed legacy Gluetun auth config"
    fi
  fi

  if [[ -f "$ARR_ENV_FILE" ]]; then
    local env_backup_created=0
    local env_backup_path=""

    ensure_env_backup() {
      if ((env_backup_created == 0)); then
        env_backup_path="${ARR_ENV_FILE}.bak.$(date +%s)"
        if cp "$ARR_ENV_FILE" "$env_backup_path" 2>/dev/null; then
          chmod 600 "$env_backup_path" 2>/dev/null || true
          warn "Backed up existing .env to ${env_backup_path} before applying migrations"
          env_backup_created=1
        else
          warn "Unable to create backup of ${ARR_ENV_FILE} before migrations"
        fi
      fi
    }

    local existing_line existing_value existing_unescaped fixed_value escaped_fixed sed_value

    existing_line="$(grep '^OPENVPN_USER=' "$ARR_ENV_FILE" | head -n1 || true)"
    if [[ -n "$existing_line" ]]; then
      existing_value="${existing_line#OPENVPN_USER=}"
      existing_unescaped="$(unescape_env_value_from_compose "$existing_value")"
      fixed_value="${existing_unescaped%+pmp}+pmp"
      if [[ "$fixed_value" != "$existing_unescaped" ]]; then
        ensure_env_backup
        escaped_fixed="$(escape_env_value_for_compose "$fixed_value")"
        sed_value="$(escape_sed_replacement "$escaped_fixed")"
        portable_sed "s|^OPENVPN_USER=.*$|OPENVPN_USER=${sed_value}|" "$ARR_ENV_FILE"
        warn "OPENVPN_USER was missing '+pmp'; updated automatically in ${ARR_ENV_FILE}"
      fi
    fi

    existing_line="$(grep '^CADDY_BASIC_AUTH_HASH=' "$ARR_ENV_FILE" | head -n1 || true)"
    if [[ -n "$existing_line" ]]; then
      existing_value="${existing_line#CADDY_BASIC_AUTH_HASH=}"
      existing_unescaped="$(unescape_env_value_from_compose "$existing_value")"
      escaped_fixed="$(escape_env_value_for_compose "$existing_unescaped")"
      if [[ "$existing_value" != "$escaped_fixed" ]]; then
        ensure_env_backup
        sed_value="$(escape_sed_replacement "$escaped_fixed")"
        portable_sed "s|^CADDY_BASIC_AUTH_HASH=.*$|CADDY_BASIC_AUTH_HASH=${sed_value}|" "$ARR_ENV_FILE"
        warn "Escaped dollar signs in CADDY_BASIC_AUTH_HASH for Docker Compose compatibility"
      fi
    fi

    unset -f ensure_env_backup || true
  fi
}


#!/usr/bin/env bash
# shellcheck enable=require-variable-braces
# shellcheck enable=quote-safe-variables
set -Eeuo pipefail

arrstack_err_trap() {
  local rc=$?
  trap - ERR
  local src="${BASH_SOURCE[1]:-${BASH_SOURCE[0]}}"
  local line="${BASH_LINENO[0]:-${LINENO}}"
  printf '[arrstack] error at %s:%s (status=%s)\n' "${src}" "${line}" "${rc}" >&2
  exit "${rc}"
}

REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
[ -f "${REPO_ROOT}/arrconf/userconf.defaults.sh" ] && . "${REPO_ROOT}/arrconf/userconf.defaults.sh"
[ -f "${REPO_ROOT}/arrconf/userconf.sh" ] && . "${REPO_ROOT}/arrconf/userconf.sh"

trap 'arrstack_err_trap' ERR

SCRIPT_LIB_DIR="${REPO_ROOT}/scripts"
modules=(
  "common.sh"
  "defaults.sh"
  "network.sh"
  "config.sh"
  "permissions.sh"
  "preflight.sh"
  "files.sh"
  "migrations.sh"
  "services.sh"
  "aliases.sh"
  "dns.sh"
  "summary.sh"
  "shell.sh"
)
for module in "${modules[@]}"; do
  # shellcheck source=/dev/null
  . "${SCRIPT_LIB_DIR}/${module}"
done

arrstack_setup_defaults

help() {
  cat <<'USAGE'
Usage: ./arrstack.sh [options]

Options:
  --yes                 Run non-interactively and assume yes to prompts
  --enable-caddy        Enable the optional Caddy reverse proxy (sets ENABLE_CADDY=1)
  --rotate-api-key      Force regeneration of the Gluetun API key
  --rotate-caddy-auth   Force regeneration of the Caddy basic auth credentials
  --setup-host-dns      Run the host DNS takeover helper during installation
  --refresh-aliases     Regenerate helper aliases and reload your shell
  --help                Show this help message
USAGE
}

GLUETUN_LIB="${REPO_ROOT}/scripts/gluetun.sh"
if [[ -f "${GLUETUN_LIB}" ]]; then
  # shellcheck source=scripts/gluetun.sh
  . "${GLUETUN_LIB}"
else
  warn "Gluetun helper library not found at ${GLUETUN_LIB}"
fi

main() {
  local IFS=$'\n\t'
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --yes)
        ASSUME_YES=1
        shift
        ;;
      --enable-caddy)
        ENABLE_CADDY=1
        shift
        ;;
      --rotate-api-key)
        FORCE_ROTATE_API_KEY=1
        shift
        ;;
      --rotate-caddy-auth)
        FORCE_REGEN_CADDY_AUTH=1
        shift
        ;;
      --setup-host-dns)
        SETUP_HOST_DNS=1
        shift
        ;;
      --refresh-aliases)
        REFRESH_ALIASES=1
        shift
        ;;
      --help | -h)
        help
        exit 0
        ;;
      *)
        die "Unknown option: $1"
        ;;
    esac
  done

  if [[ "${REFRESH_ALIASES:-0}" -eq 1 ]]; then
    refresh_aliases
    return 0
  fi

  # Initialize logging first
  init_logging

  preflight
  # Check network requirements without blocking
  check_network_requirements
  mkdirs
  run_one_time_migrations
  safe_cleanup
  generate_api_key
  write_env
  write_compose
  preflight_compose_interpolation
  validate_compose_or_die
  write_gluetun_control_assets
  if [[ "${ENABLE_CADDY:-0}" -eq 1 ]]; then
    ensure_caddy_auth
    write_caddy_assets
    validate_caddy_config
  else
    msg "Skipping Caddy assets (ENABLE_CADDY=0)"
  fi
  sync_gluetun_library
  write_qbt_helper_script
  write_qbt_config
  if ! write_aliases_file; then
    warn "Helper aliases file could not be generated"
  fi
  if [[ "${ENABLE_LOCAL_DNS:-0}" -eq 1 ]]; then
    configure_local_dns_entries
  fi
  if [[ "${SETUP_HOST_DNS:-0}" -eq 1 ]]; then
    run_host_dns_setup
  fi
  verify_permissions
  install_aliases
  start_stack

  if [[ "${ENABLE_LOCAL_DNS:-0}" -eq 1 ]]; then
    local doctor_script="${REPO_ROOT}/scripts/doctor.sh"
    if [[ -x "${doctor_script}" ]]; then
      msg "🩺 Running LAN diagnostics"
      if ! LAN_DOMAIN_SUFFIX="${LAN_DOMAIN_SUFFIX}" \
        LAN_IP="${LAN_IP}" \
        ENABLE_LOCAL_DNS="${ENABLE_LOCAL_DNS}" \
        LOCAL_DNS_SERVICE_ENABLED="${LOCAL_DNS_SERVICE_ENABLED}" \
        LOCALHOST_IP="${LOCALHOST_IP}" \
        DNS_DISTRIBUTION_MODE="${DNS_DISTRIBUTION_MODE}" \
        GLUETUN_CONTROL_PORT="${GLUETUN_CONTROL_PORT}" \
        EXPOSE_DIRECT_PORTS="${EXPOSE_DIRECT_PORTS}" \
        bash "${doctor_script}"; then
        warn "LAN diagnostics reported issues"
      fi
    else
      warn "Doctor script missing or not executable at ${doctor_script}"
    fi
  fi

  msg "Installation completed at $(date)"
  show_summary
}

if [[ "${ARRSTACK_NO_MAIN:-0}" != "1" ]]; then
  main "$@"
fi

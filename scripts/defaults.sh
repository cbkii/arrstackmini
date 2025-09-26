# shellcheck shell=bash

if ! declare -f arrstack_var_is_readonly >/dev/null 2>&1; then
  arrstack_var_is_readonly() {
    local var="$1"
    local declaration=""

    if ! declaration=$(declare -p "$var" 2>/dev/null); then
      return 1
    fi

    case $declaration in
      declare\ -r*)
        return 0
        ;;
    esac

    return 1
  }
fi

arrstack_setup_defaults() {
  ARRCONF_DIR="${ARRCONF_DIR:-${REPO_ROOT}/arrconf}"

  if [[ -z "${ARR_DOCKER_DIR}" && -d "${HOME}/srv/docker-data" ]]; then
    ARR_DOCKER_DIR="${HOME}/srv/docker-data"
    ARR_STACK_DIR="${ARR_STACK_DIR:-${PWD}/arrstack}"
  fi

  ARR_ENV_FILE="${ARR_ENV_FILE:-${ARR_STACK_DIR}/.env}"
  ASSUME_YES="${ASSUME_YES:-0}"
  FORCE_ROTATE_API_KEY="${FORCE_ROTATE_API_KEY:-0}"
  LOCALHOST_IP="${LOCALHOST_IP:-127.0.0.1}"
  SERVER_COUNTRIES="${SERVER_COUNTRIES:-Netherlands}"

  : "${PUID:=$(id -u)}"
  : "${PGID:=$(id -g)}"
  : "${TIMEZONE:=Australia/Sydney}"
  : "${SUBS_DIR:=}"

  if [[ -n "${LAN_DOMAIN_SUFFIX:-}" ]]; then
    LAN_DOMAIN_SUFFIX="${LAN_DOMAIN_SUFFIX#.}"
  fi

  : "${ENABLE_LOCAL_DNS:=0}"
  : "${ENABLE_CADDY:=0}"
  : "${DNS_DISTRIBUTION_MODE:=router}"
  : "${SETUP_HOST_DNS:=0}"
  : "${REFRESH_ALIASES:=0}"
  : "${ARR_COLOR_OUTPUT:=1}"

  LOCAL_DNS_SERVICE_ENABLED=0
  : "$LOCAL_DNS_SERVICE_ENABLED" # referenced by other modules after defaults load

  : "${FORCE_REGEN_CADDY_AUTH:=0}"
  : "${CADDY_IMAGE:=caddy:2.8.4}"
  : "${CADDY_LAN_CIDRS:=127.0.0.1/32,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16}"
  : "${CADDY_BASIC_AUTH_USER:=user}"
  : "${CADDY_BASIC_AUTH_HASH:=}"

  : "${QBT_USER:=admin}"
  : "${QBT_PASS:=adminadmin}"
  : "${QBT_DOCKER_MODS:=ghcr.io/vuetorrent/vuetorrent-lsio-mod:latest}"
  : "${QBT_AUTH_WHITELIST:=127.0.0.1/32,::1/128}"

  : "${GLUETUN_IMAGE:=qmcgaw/gluetun:v3.39.1}"
  : "${QBITTORRENT_IMAGE:=lscr.io/linuxserver/qbittorrent:5.1.2-r2-ls415}"
  : "${SONARR_IMAGE:=lscr.io/linuxserver/sonarr:4.0.15.2941-ls291}"
  : "${RADARR_IMAGE:=lscr.io/linuxserver/radarr:5.27.5.10198-ls283}"
  : "${PROWLARR_IMAGE:=lscr.io/linuxserver/prowlarr:latest}"
  : "${BAZARR_IMAGE:=lscr.io/linuxserver/bazarr:latest}"
  : "${FLARESOLVERR_IMAGE:=ghcr.io/flaresolverr/flaresolverr:v3.3.21}"

  if [[ -n "${CADDY_DOMAIN_SUFFIX:-}" ]]; then
    CADDY_DOMAIN_SUFFIX="${CADDY_DOMAIN_SUFFIX#.}"
  fi

  if [[ -z "${CADDY_DOMAIN_SUFFIX:-}" && -n "${LAN_DOMAIN_SUFFIX:-}" ]]; then
    CADDY_DOMAIN_SUFFIX="${LAN_DOMAIN_SUFFIX}"
  fi

  ARR_DOMAIN_SUFFIX_CLEAN="${CADDY_DOMAIN_SUFFIX#.}"
  export ARR_DOMAIN_SUFFIX_CLEAN

  export CADDY_DOMAIN_SUFFIX
  export LAN_DOMAIN_SUFFIX

  PROTON_USER_VALUE=""
  PROTON_PASS_VALUE=""
  OPENVPN_USER_VALUE=""
  PROTON_USER_PMP_ADDED=0
  : "$PROTON_USER_VALUE" "$PROTON_PASS_VALUE" "$OPENVPN_USER_VALUE" "$PROTON_USER_PMP_ADDED"

  DOCKER_COMPOSE_CMD=()
  ARRSTACK_LOCKFILE=""
  LOG_FILE=""
  : "${DOCKER_COMPOSE_CMD[*]}" "$ARRSTACK_LOCKFILE" "$LOG_FILE"

  local requested_permission_profile="${ARR_PERMISSION_PROFILE:-}"
  local permission_profile="${requested_permission_profile:-strict}"
  SECRET_FILE_MODE=600
  LOCK_FILE_MODE=644
  NONSECRET_FILE_MODE=600
  DATA_DIR_MODE=700

  case "${permission_profile}" in
    collaborative)
      umask 0027
      NONSECRET_FILE_MODE=640
      DATA_DIR_MODE=750
      ;;
    strict)
      umask 0077
      ;;
    *)
      warn "Unknown ARR_PERMISSION_PROFILE='${requested_permission_profile}' - defaulting to strict"
      permission_profile="strict"
      umask 0077
      ;;
  esac

  if arrstack_var_is_readonly ARR_PERMISSION_PROFILE; then
    if [[ "${ARR_PERMISSION_PROFILE:-}" != "${permission_profile}" ]]; then
      die "ARR_PERMISSION_PROFILE is read-only with value '${ARR_PERMISSION_PROFILE:-}', expected '${permission_profile}'"
    fi
  else
    ARR_PERMISSION_PROFILE="${permission_profile}"
  fi

  : "$SECRET_FILE_MODE" "$LOCK_FILE_MODE" "$NONSECRET_FILE_MODE" "$DATA_DIR_MODE"
  readonly ARR_PERMISSION_PROFILE SECRET_FILE_MODE LOCK_FILE_MODE NONSECRET_FILE_MODE DATA_DIR_MODE

  ARR_DOCKER_SERVICES=(gluetun qbittorrent sonarr radarr prowlarr bazarr flaresolverr caddy local_dns)
  : "${ARR_DOCKER_SERVICES[*]}"
  readonly -a ARR_DOCKER_SERVICES

  CYAN='\033[0;36m'
  YELLOW='\033[0;33m'
  RESET='\033[0m'
  : "$CYAN" "$YELLOW" "$RESET"
}

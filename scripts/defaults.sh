# shellcheck shell=bash

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
  SERVER_COUNTRIES="${SERVER_COUNTRIES:-Switzerland,Iceland,Romania,Czech Republic,Netherlands}"

  : "${PUID:=$(id -u)}"
  : "${PGID:=$(id -g)}"
  : "${TIMEZONE:=Australia/Sydney}"
  : "${GLUETUN_CONTROL_PORT:=8000}"
  : "${QBT_HTTP_PORT_HOST:=8080}"
  : "${SONARR_PORT:=8989}"
  : "${RADARR_PORT:=7878}"
  : "${PROWLARR_PORT:=9696}"
  : "${BAZARR_PORT:=6767}"
  : "${FLARESOLVERR_PORT:=8191}"
  : "${SUBS_DIR:=}"

  : "${LAN_DOMAIN_SUFFIX:=home.arpa}"
  LAN_DOMAIN_SUFFIX="${LAN_DOMAIN_SUFFIX#.}"
  if [[ -z "${LAN_DOMAIN_SUFFIX}" ]]; then
    LAN_DOMAIN_SUFFIX="lan"
  fi

  : "${UPSTREAM_DNS_1:=1.1.1.1}"
  : "${UPSTREAM_DNS_2:=1.0.0.1}"
  : "${ENABLE_LOCAL_DNS:=1}"
  : "${SETUP_HOST_DNS:=0}"
  : "${AUTO_DISABLE_LOCAL_DNS:=0}"
  : "${REFRESH_ALIASES:=0}"

  LAN_IP_AUTODETECTED_IFACE=""
  LAN_IP_AUTODETECTED_METHOD=""
  LAN_IP_EFFECTIVE_IFACE=""
  LAN_IP_EFFECTIVE_METHOD=""
  LOCAL_DNS_SERVICE_ENABLED=0
  LOCAL_DNS_SERVICE_REASON="pending"
  LOCAL_DNS_HELPER_STATUS="not-run"
  LOCAL_DNS_AUTO_DISABLED=0
  LOCAL_DNS_AUTO_DISABLED_REASON=""

  : "${FORCE_REGEN_CADDY_AUTH:=0}"
  : "${CADDY_IMAGE:=caddy:2.8.4}"
  : "${CADDY_LAN_CIDRS:=192.168.0.0/16 10.0.0.0/8 172.16.0.0/12}"
  : "${CADDY_BASIC_AUTH_USER:=user}"
  : "${CADDY_BASIC_AUTH_HASH:=}"

  : "${QBT_USER:=admin}"
  : "${QBT_PASS:=adminadmin}"
  : "${QBT_DOCKER_MODS:=ghcr.io/vuetorrent/vuetorrent-lsio-mod:latest}"
  : "${QBT_AUTH_WHITELIST:=127.0.0.1/32,127.0.0.0/8,::1/128}"

  : "${GLUETUN_IMAGE:=qmcgaw/gluetun:v3.39.1}"
  : "${QBITTORRENT_IMAGE:=lscr.io/linuxserver/qbittorrent:5.1.2-r2-ls415}"
  : "${SONARR_IMAGE:=lscr.io/linuxserver/sonarr:4.0.15.2941-ls291}"
  : "${RADARR_IMAGE:=lscr.io/linuxserver/radarr:5.27.5.10198-ls283}"
  : "${PROWLARR_IMAGE:=lscr.io/linuxserver/prowlarr:latest}"
  : "${BAZARR_IMAGE:=lscr.io/linuxserver/bazarr:latest}"
  : "${FLARESOLVERR_IMAGE:=ghcr.io/flaresolverr/flaresolverr:v3.3.21}"
  : "${PORT_SYNC_IMAGE:=alpine:3.20.3}"
  : "${PORT_UPDATE_MIN_INTERVAL:=30}"
  : "${PORT_STATUS_MAX_AGE:=300}"
  : "${PORT_SYNC_STARTUP_DELAY:=30}"

  if [[ -n "${CADDY_DOMAIN_SUFFIX:-}" ]]; then
    CADDY_DOMAIN_SUFFIX="${CADDY_DOMAIN_SUFFIX#.}"
  fi

  if [[ -z "${CADDY_DOMAIN_SUFFIX:-}" ]]; then
    CADDY_DOMAIN_SUFFIX="${LAN_DOMAIN_SUFFIX}"
  fi

  if [[ -z "${CADDY_DOMAIN_SUFFIX:-}" ]]; then
    CADDY_DOMAIN_SUFFIX="lan"
  fi

  ARR_DOMAIN_SUFFIX_CLEAN="${CADDY_DOMAIN_SUFFIX#.}"
  ARR_DOMAIN_SUFFIX_CLEAN="${ARR_DOMAIN_SUFFIX_CLEAN:-lan}"

  export CADDY_DOMAIN_SUFFIX
  export LAN_DOMAIN_SUFFIX

  PROTON_USER_VALUE=""
  PROTON_PASS_VALUE=""
  OPENVPN_USER_VALUE=""
  PROTON_USER_PMP_ADDED=0

  DOCKER_COMPOSE_CMD=()
  ARRSTACK_LOCKFILE=""
  LOG_FILE=""

  ARR_PERMISSION_PROFILE="${ARR_PERMISSION_PROFILE:-strict}"
  SECRET_FILE_MODE=600
  LOCK_FILE_MODE=644
  NONSECRET_FILE_MODE=600
  DATA_DIR_MODE=700

  case "${ARR_PERMISSION_PROFILE}" in
    collaborative)
      umask 0027
      NONSECRET_FILE_MODE=640
      DATA_DIR_MODE=750
      ;;
    strict | "")
      umask 0077
      ARR_PERMISSION_PROFILE="strict"
      ;;
    *)
      warn "Unknown ARR_PERMISSION_PROFILE='${ARR_PERMISSION_PROFILE}' - defaulting to strict"
      ARR_PERMISSION_PROFILE="strict"
      umask 0077
      ;;
  esac

  readonly ARR_PERMISSION_PROFILE SECRET_FILE_MODE LOCK_FILE_MODE NONSECRET_FILE_MODE DATA_DIR_MODE

  ARR_DOCKER_SERVICES=(gluetun qbittorrent sonarr radarr prowlarr bazarr flaresolverr caddy local_dns)
  readonly -a ARR_DOCKER_SERVICES

  CYAN='\033[0;36m'
  YELLOW='\033[0;33m'
  RESET='\033[0m'
}

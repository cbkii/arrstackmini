#!/usr/bin/env bash
# Default configuration for ARR Stack
# Override these in arrconf/userconf.sh (git-ignored)

# Base paths
ARR_BASE="${ARR_BASE:-$PWD}"
ARR_STACK_DIR="${ARR_STACK_DIR:-${ARR_BASE}/arrstack}"
ARR_ENV_FILE="${ARR_ENV_FILE:-${ARR_STACK_DIR}/.env}"
ARR_DOCKER_DIR="${ARR_DOCKER_DIR:-${ARR_BASE}/docker-data}"
ARRCONF_DIR="${ARRCONF_DIR:-${PWD}/arrconf}"

# File/dir permissions (strict keeps secrets 600/700, collaborative loosens group access)
ARR_PERMISSION_PROFILE="${ARR_PERMISSION_PROFILE:-strict}"

# Download paths
DOWNLOADS_DIR="${DOWNLOADS_DIR:-${HOME}/Downloads}"
COMPLETED_DIR="${COMPLETED_DIR:-${DOWNLOADS_DIR}/completed}"

# Media library
MEDIA_DIR="${MEDIA_DIR:-/media/mediasmb}"
TV_DIR="${TV_DIR:-${MEDIA_DIR}/Shows}"
MOVIES_DIR="${MOVIES_DIR:-${MEDIA_DIR}/Movies}"
# SUBS_DIR="${SUBS_DIR:-${MEDIA_DIR}/subs}"

# Container identity (current user by default)
PUID="${PUID:-$(id -u)}"
PGID="${PGID:-$(id -g)}"

# Location
TIMEZONE="${TIMEZONE:-Australia/Sydney}"
LAN_IP="${LAN_IP:-}"
LOCALHOST_IP="${LOCALHOST_IP:-127.0.0.1}"
SERVER_COUNTRIES="${SERVER_COUNTRIES:-Switzerland,Iceland,Romania,Czech Republic,Netherlands}"

# Gluetun control server
GLUETUN_CONTROL_PORT="${GLUETUN_CONTROL_PORT:-8000}"
GLUETUN_API_KEY="${GLUETUN_API_KEY:-}"

# Service ports
QBT_HTTP_PORT_HOST="${QBT_HTTP_PORT_HOST:-8080}"
SONARR_PORT="${SONARR_PORT:-8989}"
RADARR_PORT="${RADARR_PORT:-7878}"
PROWLARR_PORT="${PROWLARR_PORT:-9696}"
BAZARR_PORT="${BAZARR_PORT:-6767}"
FLARESOLVERR_PORT="${FLARESOLVERR_PORT:-8191}"

# qBittorrent credentials (override after first login)
QBT_USER="${QBT_USER:-admin}"
QBT_PASS="${QBT_PASS:-adminadmin}"
QBT_DOCKER_MODS="${QBT_DOCKER_MODS:-ghcr.io/vuetorrent/vuetorrent-lsio-mod:latest}"

# Comma-separated CIDR list that can bypass the qBittorrent WebUI login
QBT_AUTH_WHITELIST="${QBT_AUTH_WHITELIST:-127.0.0.1/8,::1/128}"

# Images
GLUETUN_IMAGE="${GLUETUN_IMAGE:-qmcgaw/gluetun:v3.39.1}"
QBITTORRENT_IMAGE="${QBITTORRENT_IMAGE:-lscr.io/linuxserver/qbittorrent:5.1.2-r2-ls415}"
SONARR_IMAGE="${SONARR_IMAGE:-lscr.io/linuxserver/sonarr:4.0.15.2941-ls291}"
RADARR_IMAGE="${RADARR_IMAGE:-lscr.io/linuxserver/radarr:5.27.5.10198-ls283}"
PROWLARR_IMAGE="${PROWLARR_IMAGE:-lscr.io/linuxserver/prowlarr:latest}"
BAZARR_IMAGE="${BAZARR_IMAGE:-lscr.io/linuxserver/bazarr:latest}"
FLARESOLVERR_IMAGE="${FLARESOLVERR_IMAGE:-ghcr.io/flaresolverr/flaresolverr:v3.3.21}"

# Behaviour flags
ASSUME_YES="${ASSUME_YES:-0}"
FORCE_ROTATE_API_KEY="${FORCE_ROTATE_API_KEY:-0}"

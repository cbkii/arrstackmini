#!/usr/bin/env bash
# Default configuration for ARR Stack
# Override these in arrconf/userconf.sh (git-ignored)

# Base paths
ARR_BASE="${ARR_BASE:-${HOME}/srv}"
ARR_STACK_DIR="${ARR_STACK_DIR:-${ARR_BASE}/arrstack}"
ARR_DOCKER_DIR="${ARR_DOCKER_DIR:-${ARR_BASE}/docker-data}"
ARRCONF_DIR="${ARRCONF_DIR:-${PWD}/arrconf}"

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
SERVER_COUNTRIES="${SERVER_COUNTRIES:-Netherlands,Switzerland}"

# Gluetun control server
GLUETUN_CONTROL_PORT="${GLUETUN_CONTROL_PORT:-8000}"
GLUETUN_API_KEY="${GLUETUN_API_KEY:-}"

# Service ports
QBT_HTTP_PORT_HOST="${QBT_HTTP_PORT_HOST:-8081}"
SONARR_PORT="${SONARR_PORT:-8989}"
RADARR_PORT="${RADARR_PORT:-7878}"
PROWLARR_PORT="${PROWLARR_PORT:-9696}"
BAZARR_PORT="${BAZARR_PORT:-6767}"
FLARESOLVERR_PORT="${FLARESOLVERR_PORT:-8191}"

# Images
GLUETUN_IMAGE="${GLUETUN_IMAGE:-qmcgaw/gluetun:v3.39.1}"
QBITTORRENT_IMAGE="${QBITTORRENT_IMAGE:-lscr.io/linuxserver/qbittorrent:latest}"
SONARR_IMAGE="${SONARR_IMAGE:-lscr.io/linuxserver/sonarr:latest}"
RADARR_IMAGE="${RADARR_IMAGE:-lscr.io/linuxserver/radarr:latest}"
PROWLARR_IMAGE="${PROWLARR_IMAGE:-lscr.io/linuxserver/prowlarr:latest}"
BAZARR_IMAGE="${BAZARR_IMAGE:-lscr.io/linuxserver/bazarr:latest}"
FLARESOLVERR_IMAGE="${FLARESOLVERR_IMAGE:-ghcr.io/flaresolverr/flaresolverr:latest}"

# Behaviour flags
ASSUME_YES="${ASSUME_YES:-0}"
FORCE_ROTATE_API_KEY="${FORCE_ROTATE_API_KEY:-0}"

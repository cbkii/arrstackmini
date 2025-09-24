#!/usr/bin/env bash
# shellcheck disable=SC2034
# Copy to arrconf/userconf.sh and edit as needed. Values here override the
# defaults from arrconf/userconf.defaults.sh, which loads first.

# --- Stack paths ---
ARR_BASE="/home/pipi/srv"    # Root directory for generated stack files
ARR_STACK_DIR="${ARR_BASE}/arrstack"    # Location for docker-compose.yml, scripts, and aliases
#ARR_ENV_FILE="${ARR_STACK_DIR}/.env"  # Path to the generated .env secrets file
ARR_DOCKER_DIR="${ARR_BASE}/docker-data"    # Docker volumes and persistent data storage
# ARRCONF_DIR="${HOME}/.config/arrstack"  # Optional: relocate Proton creds outside the repo

# --- Permissions ---
ARR_PERMISSION_PROFILE="collaborative"    # strict keeps secrets 600/700, collaborative loosens group access

# --- Downloads and media ---
DOWNLOADS_DIR="/home/pipi/Downloads"    # Active qBittorrent download folder
COMPLETED_DIR="${DOWNLOADS_DIR}/completed"    # Destination for completed downloads
MEDIA_DIR="/media/mediasmb"    # Root of the media library share
TV_DIR="${MEDIA_DIR}/Shows"    # Sonarr TV library path
MOVIES_DIR="${MEDIA_DIR}/Movies"    # Radarr movie library path
SUBS_DIR="${MEDIA_DIR}/subs"         # Optional Bazarr subtitles directory

# --- User identity ---
#PUID="$(id -u)"                        # Numeric user ID containers should run as
#PGID="$(id -g)"                        # Numeric group ID with write access to media folders
TIMEZONE="Australia/Sydney"    # Timezone for container logs and schedules

# --- Networking ---
LAN_IP="192.168.1.50"    # Bind services to one LAN IP (leave blank to listen on all)
LOCALHOST_IP="127.0.0.1"    # Loopback used by the Gluetun control API
#LAN_DOMAIN_SUFFIX="home.arpa"          # Suffix appended to service hostnames (RFC 8375 default)
#CADDY_DOMAIN_SUFFIX="${LAN_DOMAIN_SUFFIX}"  # Override Caddy hostname suffix independently of LAN DNS
SERVER_COUNTRIES="Netherlands,Iceland,Switzerland"    # ProtonVPN exit country list
PVPN_ROTATE_COUNTRIES="${SERVER_COUNTRIES},Spain,Australia,Malaysia,Germany,Ireland,Singapore,Romania"  # Optional rotation order for arr.vpn switch (always includes SERVER_COUNTRIES)
#GLUETUN_CONTROL_PORT="8000"            # Host port that exposes the Gluetun control API
#ENABLE_LOCAL_DNS="1"                   # Enable the bundled dnsmasq container on LAN_IP
DNS_DISTRIBUTION_MODE="router"    # router (DHCP Option 6) or per-device DNS settings
#UPSTREAM_DNS_1="1.1.1.1"               # First upstream resolver when local DNS is enabled
#UPSTREAM_DNS_2="1.0.0.1" #8.8.8.8"  # Second upstream resolver when local DNS is enabled
#CADDY_LAN_CIDRS="127.0.0.1/32,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"  # Clients allowed to skip Caddy auth
#EXPOSE_DIRECT_PORTS="0"                # Publish raw app ports on the LAN alongside Caddy (troubleshooting aid)

# --- Credentials ---
#QBT_USER="admin"                       # Initial qBittorrent username (change after first login)
#QBT_PASS="adminadmin"                  # Initial qBittorrent password (update immediately after install)
#GLUETUN_API_KEY=""                     # Pre-seed a Gluetun API key or leave empty to auto-generate
QBT_DOCKER_MODS="ghcr.io/vuetorrent/vuetorrent-lsio-mod:latest"    # Vuetorrent WebUI mod (set empty to disable)
#QBT_AUTH_WHITELIST="127.0.0.1/8,::1/128"  # CIDRs allowed to bypass the qBittorrent login prompt
#CADDY_BASIC_AUTH_USER="user"           # Username clients outside CADDY_LAN_CIDRS must use
#CADDY_BASIC_AUTH_HASH=""               # Bcrypt hash for the Basic Auth password (regen when empty)

# --- Service ports ---
QBT_HTTP_PORT_HOST="8080"              # qBittorrent WebUI port exposed on the LAN
SONARR_PORT="8989"                     # Sonarr WebUI port exposed on the LAN
RADARR_PORT="7878"                     # Radarr WebUI port exposed on the LAN
PROWLARR_PORT="9696"                   # Prowlarr WebUI port exposed on the LAN
BAZARR_PORT="6767"                     # Bazarr WebUI port exposed on the LAN
FLARESOLVERR_PORT="8191"               # FlareSolverr service port exposed on the LAN

# --- Container images (advanced) ---
# GLUETUN_IMAGE="qmcgaw/gluetun:v3.39.1"                     # Override the Gluetun container tag
# QBITTORRENT_IMAGE="lscr.io/linuxserver/qbittorrent:5.1.2-r2-ls415"  # Override the qBittorrent container tag
# SONARR_IMAGE="lscr.io/linuxserver/sonarr:4.0.15.2941-ls291"         # Override the Sonarr container tag
# RADARR_IMAGE="lscr.io/linuxserver/radarr:5.27.5.10198-ls283"        # Override the Radarr container tag
# PROWLARR_IMAGE="lscr.io/linuxserver/prowlarr:latest"                # Override the Prowlarr container tag
# BAZARR_IMAGE="lscr.io/linuxserver/bazarr:latest"                    # Override the Bazarr container tag
# FLARESOLVERR_IMAGE="ghcr.io/flaresolverr/flaresolverr:v3.3.21"      # Override the FlareSolverr container tag

# --- Behaviour toggles ---
# ASSUME_YES="0"                         # Skip confirmation prompts when scripting installs
# FORCE_ROTATE_API_KEY="0"               # Force regeneration of the Gluetun API key on next run
# FORCE_REGEN_CADDY_AUTH="0"             # Rotate the Caddy username/password on next run
# SETUP_HOST_DNS="0"                      # Automate host DNS takeover helper (or call with --setup-host-dns)
# REFRESH_ALIASES="0"                     # Regenerate helper aliases without running the installer

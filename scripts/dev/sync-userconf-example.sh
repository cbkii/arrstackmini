#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
OUTPUT="${REPO_ROOT}/arrconf/userconf.sh.example"
MODE="write"

if [[ ${1:-} == "--check" ]]; then
  MODE="check"
fi

# shellcheck disable=SC1091
# shellcheck source=../../arrconf/userconf.defaults.sh
. "${REPO_ROOT}/arrconf/userconf.defaults.sh"

# shellcheck disable=SC2016  # layout strings deliberately keep literal ${...} placeholders
layout=(
  'literal|#!/usr/bin/env bash'
  'literal|# shellcheck disable=SC2034'
  'literal|# Copy to arrconf/userconf.sh and edit as needed. Values here override the'
  'literal|# defaults from arrconf/userconf.defaults.sh, which loads first.'
  'blank'
  'section|Stack paths'
  'var|ARR_BASE|${HOME}/srv|Root directory for generated stack files'
  'var|ARR_STACK_DIR|${ARR_BASE}/arrstack|Location for docker-compose.yml, scripts, and aliases'
  'var|ARR_ENV_FILE|${ARR_STACK_DIR}/.env|Path to the generated .env secrets file'
  'var|ARR_DOCKER_DIR|${ARR_BASE}/docker-data|Docker volumes and persistent data storage'
  'comment|ARRCONF_DIR|${HOME}/.config/arrstack|Optional: relocate Proton creds outside the repo'
  'blank'
  'section|Permissions'
  'var|ARR_PERMISSION_PROFILE|{{default}}|strict keeps secrets 600/700, collaborative loosens group access'
  'blank'
  'section|Downloads and media'
  'var|DOWNLOADS_DIR|${HOME}/Downloads|Active qBittorrent download folder'
  'var|COMPLETED_DIR|${DOWNLOADS_DIR}/completed|Destination for completed downloads'
  'var|MEDIA_DIR|{{default}}|Root of the media library share'
  'var|TV_DIR|{{default}}|Sonarr TV library path'
  'var|MOVIES_DIR|{{default}}|Radarr movie library path'
  'comment|SUBS_DIR|${MEDIA_DIR}/subs|Optional Bazarr subtitles directory'
  'blank'
  'section|User identity'
  'var|PUID|$(id -u)|Numeric user ID containers should run as'
  'var|PGID|$(id -g)|Numeric group ID with write access to media folders'
  'var|TIMEZONE|{{default}}|Timezone for container logs and schedules (default: {{default}})'
  'blank'
  'section|Networking'
  'var|LAN_IP|{{default}}|Bind services to one LAN IP (set a DHCP reservation or static IP before install)'
  'var|LOCALHOST_IP|{{default}}|Loopback used by the Gluetun control API'
  'var|LAN_DOMAIN_SUFFIX|{{default}}|Suffix appended to service hostnames (default: {{default}})'
  'var|CADDY_DOMAIN_SUFFIX|{{default}}|Override Caddy hostname suffix independently of LAN DNS (default: {{default}})'
  'var|SERVER_COUNTRIES|{{default}}|ProtonVPN exit country list (default: {{default}})'
  'comment|SERVER_NAMES|{{default}}|Optionally pin Proton server hostnames (comma-separated) if PF stays at 0'
  'var|PVPN_ROTATE_COUNTRIES|{{default}}|Optional rotation order for arr.vpn switch (default mirrors SERVER_COUNTRIES)'
  'var|GLUETUN_CONTROL_PORT|{{default}}|Host port that exposes the Gluetun control API (default: {{default}})'
  'var|ENABLE_LOCAL_DNS|{{default}}|Advanced: enable the optional dnsmasq container (0/1, default: {{default}})'
  'var|ENABLE_CADDY|{{default}}|Advanced: enable the optional Caddy reverse proxy (0/1, default: {{default}})'
  'var|DNS_DISTRIBUTION_MODE|{{default}}|router (DHCP Option 6) or per-device DNS settings (default: {{default}})'
  'var|UPSTREAM_DNS_SERVERS|{{default}}|Comma-separated resolver list used by dnsmasq (default chain shown)'
  'var|UPSTREAM_DNS_1|{{default}}|Legacy primary resolver override (default derived: {{default}})'
  'var|UPSTREAM_DNS_2|{{default}}|Legacy secondary resolver override (default derived: {{default}})'
  'var|CADDY_LAN_CIDRS|{{default}}|Clients allowed to skip Caddy auth (default: {{default}})'
  'var|EXPOSE_DIRECT_PORTS|{{default}}|Keep 1 so WebUIs publish on http://${LAN_IP}:PORT (requires LAN_IP set to your private IPv4)'
  'blank'
  'section|Credentials'
  'var|QBT_USER|{{default}}|Initial qBittorrent username (change after first login)'
  'var|QBT_PASS|{{default}}|Initial qBittorrent password (update immediately after install)'
  'var|GLUETUN_API_KEY|{{default}}|Pre-seed a Gluetun API key or leave empty to auto-generate'
  'var|QBT_DOCKER_MODS|{{default}}|Vuetorrent WebUI mod (set empty to disable)'
  'var|QBT_AUTH_WHITELIST|{{default}}|CIDRs allowed to bypass the qBittorrent login prompt (default: {{default}})'
  'var|CADDY_BASIC_AUTH_USER|{{default}}|Username clients outside CADDY_LAN_CIDRS must use (default: {{default}})'
  'var|CADDY_BASIC_AUTH_HASH|{{default}}|Bcrypt hash for the Basic Auth password (regen when empty)'
  'blank'
  'section|Service ports'
  'var|QBT_HTTP_PORT_HOST|{{default}}|qBittorrent WebUI port exposed on the LAN (default: {{default}})'
  'var|SONARR_PORT|{{default}}|Sonarr WebUI port exposed on the LAN (default: {{default}})'
  'var|RADARR_PORT|{{default}}|Radarr WebUI port exposed on the LAN (default: {{default}})'
  'var|PROWLARR_PORT|{{default}}|Prowlarr WebUI port exposed on the LAN (default: {{default}})'
  'var|BAZARR_PORT|{{default}}|Bazarr WebUI port exposed on the LAN (default: {{default}})'
  'var|FLARESOLVERR_PORT|{{default}}|FlareSolverr service port exposed on the LAN (default: {{default}})'
  'blank'
  'section|Container images (advanced)'
  'comment|GLUETUN_IMAGE|{{default}}|Override the Gluetun container tag'
  'comment|QBITTORRENT_IMAGE|{{default}}|Override the qBittorrent container tag'
  'comment|SONARR_IMAGE|{{default}}|Override the Sonarr container tag'
  'comment|RADARR_IMAGE|{{default}}|Override the Radarr container tag'
  'comment|PROWLARR_IMAGE|{{default}}|Override the Prowlarr container tag'
  'comment|BAZARR_IMAGE|{{default}}|Override the Bazarr container tag'
  'comment|FLARESOLVERR_IMAGE|{{default}}|Override the FlareSolverr container tag'
  'blank'
  'section|Behaviour toggles'
  'comment|ASSUME_YES|{{default}}|Skip confirmation prompts when scripting installs'
  'comment|FORCE_ROTATE_API_KEY|{{default}}|Force regeneration of the Gluetun API key on next run'
  'comment|FORCE_REGEN_CADDY_AUTH|{{default}}|Rotate the Caddy username/password on next run'
  'comment|SETUP_HOST_DNS|{{default}}|Automate host DNS takeover helper (or call with --setup-host-dns)'
  'comment|REFRESH_ALIASES|{{default}}|Regenerate helper aliases without running the installer'
)

expand_template() {
  local template="$1"
  local default_value="$2"
  if [[ -z "$template" ]]; then
    template='{{default}}'
  fi
  printf '%s' "${template//\{\{default\}\}/$default_value}"
}

render_assignment() {
  local var="$1"
  local value_template="$2"
  local comment_template="$3"
  local prefix="$4"
  local default_value="${!var-}"
  local value comment assignment

  value="$(expand_template "$value_template" "$default_value")"
  comment="$(expand_template "$comment_template" "$default_value")"
  assignment="${var}=\"${value}\""

  if [[ "$prefix" == "#" ]]; then
    printf '# %-44s' "$assignment"
  else
    printf '%-45s' "$assignment"
  fi

  if [[ -n "$comment" ]]; then
    printf ' # %s' "$comment"
  fi

  printf '\n'
}

render() {
  local entry type name value_template comment_template

  for entry in "${layout[@]}"; do
    IFS='|' read -r type name value_template comment_template <<<"$entry"
    case "$type" in
      literal)
        printf '%s\n' "$name"
        ;;
      blank)
        printf '\n'
        ;;
      section)
        printf '# --- %s ---\n' "$name"
        ;;
      var)
        render_assignment "$name" "$value_template" "$comment_template" ""
        ;;
      comment)
        render_assignment "$name" "$value_template" "$comment_template" "#"
        ;;
      *)
        printf 'Unknown layout entry: %s\n' "$entry" >&2
        exit 1
        ;;
    esac
  done
}

if [[ "$MODE" == "check" ]]; then
  tmp="$(mktemp "userconf.sh.example.XXXXXX")"
  trap 'rm -f "$tmp"' EXIT
  render >"$tmp"
  if ! cmp -s "$tmp" "$OUTPUT"; then
    echo "${OUTPUT#"${REPO_ROOT}"/} is out of sync. Run scripts/dev/sync-userconf-example.sh." >&2
    diff -u "$OUTPUT" "$tmp" || true
    exit 3
  fi
  rm -f "$tmp"
  trap - EXIT
else
  render >"$OUTPUT"
  chmod 644 "$OUTPUT" 2>/dev/null || true
fi

#!/usr/bin/env bash
set -Euo pipefail
IFS=$'\n\t'

REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
[ -f "${REPO_ROOT}/arrconf/userconf.defaults.sh" ] && . "${REPO_ROOT}/arrconf/userconf.defaults.sh"
[ -f "${REPO_ROOT}/arrconf/userconf.sh" ] && . "${REPO_ROOT}/arrconf/userconf.sh"

umask 077
export HISTFILE=/dev/null

: "${DEBUG:=0}" : "${ARR_NONINTERACTIVE:=0}" : "${FORCE_ROTATE_API_KEY:=0}"
: "${PURGE_NATIVE:=0}" : "${CHOWN_TREE:=0}" : "${PRUNE_VOLUMES:=0}" : "${BACKUP_EXISTING:=0}"
LOG_FILE=/dev/null

is_tty() { [[ -t 1 && "${NO_COLOR:-0}" -eq 0 ]]; }
color() { is_tty && printf '\033[%sm' "$1" || true; }
msg() { printf '%b%s%b\n' "$(color 36; color 1)" "$1" "$(color 0)"; }
warn(){ printf '%b%s%b\n' "$(color 33)" "$1" "$(color 0)" >&2; }
die(){ printf '%b%s%b\n' "$(color 31)" "$1" "$(color 0)" >&2; exit 1; }

redact() { sed -E 's/(GLUETUN_API_KEY|OPENVPN_PASSWORD|OPENVPN_USER|QBT_PASS|PROTON_PASS|PROTON_USER)=[^[:space:]]+/\1=<REDACTED>/g'; }
run(){ local -a c=("$@"); [[ "$DEBUG" == 1 ]] && printf '+ %s\n' "$(printf '%q ' "${c[@]}")" | redact >>"$LOG_FILE"; "${c[@]}"; }

setup_logging(){ if [[ "$DEBUG" == 1 ]]; then mkdir -p "$ARR_STACK_DIR"; LOG_FILE="$ARR_STACK_DIR/arrstack-$(date +%Y%m%d-%H%M%S).log"; : >"$LOG_FILE"; chmod 600 "$LOG_FILE"; ln -sfn "$(basename "$LOG_FILE")" "$ARR_STACK_DIR/arrstack-install.log"; fi; }

help(){ cat <<'H'
Usage: ./arrstack.sh [--openvpn|--wireguard] [-y|--yes] [--debug] [--rotate-apikey]
       [--purge-native] [--chown-tree] [--prune-volumes] [--backup-existing]
H
}

VPN_TYPE="${VPN_TYPE:-openvpn}"; ASSUME_YES=0
while [ $# -gt 0 ]; do case "$1" in
  --openvpn) VPN_TYPE=openvpn;; --wireguard) VPN_TYPE=wireguard;; --debug) DEBUG=1;;
  -y|--yes) ASSUME_YES=1; ARR_NONINTERACTIVE=1;; --rotate-apikey) FORCE_ROTATE_API_KEY=1;;
  --purge-native) PURGE_NATIVE=1;; --chown-tree) CHOWN_TREE=1;; --prune-volumes) PRUNE_VOLUMES=1;; --backup-existing) BACKUP_EXISTING=1;;
  -h|--help) help; exit 0;; *) warn "Unknown option: $1";; esac; shift; done

setup_logging
export ARR_ENV_FILE="${ARR_ENV_FILE:-${ARR_STACK_DIR}/.env}"

need(){ command -v "$1" >/dev/null 2>&1 || die "Missing dependency: $1"; }
install_missing(){ local pkgs=(); command -v docker >/dev/null || pkgs+=(docker.io); docker compose version >/dev/null 2>&1 || pkgs+=(docker-compose-plugin); command -v curl >/dev/null || pkgs+=(curl); command -v openssl >/dev/null || pkgs+=(openssl); (( ${#pkgs[@]} )) && { run sudo apt-get update -y; run sudo apt-get install -y "${pkgs[@]}"; }; }

ensure_dir(){ [[ -d "$1" ]] || { mkdir -p "$1" || { sudo mkdir -p "$1" && sudo chown "${USER}:${USER}" "$1"; }; }; }

preflight(){ msg "Preflight"; install_missing
  if [[ "$VPN_TYPE" == openvpn ]]; then [[ -f "${ARRCONF_DIR}/proton.auth" ]] || die "arrconf/proton.auth missing"; fi
  if [[ "$VPN_TYPE" == wireguard ]]; then [[ -f "${ARRCONF_DIR}/proton.conf" ]] || die "arrconf/proton.conf missing"; fi
  [[ "$ASSUME_YES" == 1 ]] || { printf 'Continue with VPN_TYPE=%s? [y/N]: ' "$VPN_TYPE"; read -r a; [[ "$a" =~ ^[Yy]$ ]] || die Aborted; }
}

mkdirs(){ msg "Create dirs"; for d in "$ARR_STACK_DIR" "$ARR_DOCKER_DIR"/gluetun "$ARR_DOCKER_DIR"/{qbittorrent,sonarr,radarr,prowlarr,bazarr} "$DOWNLOADS_DIR" "$COMPLETED_DIR" "$MEDIA_DIR" "$TV_DIR" "$MOVIES_DIR" "$ARRCONF_DIR" "$ARR_DOCKER_DIR"/gluetun/auth; do ensure_dir "$d"; done; chmod 700 "$ARRCONF_DIR"; }

api_key(){ msg "API key"; local exist=""; [[ -f "$ARR_ENV_FILE" ]] && exist="$(grep '^GLUETUN_API_KEY=' "$ARR_ENV_FILE" 2>/dev/null | cut -d= -f2-)" || true
  if [[ -n "$exist" && "$FORCE_ROTATE_API_KEY" != 1 ]]; then GLUETUN_API_KEY="$exist"; else GLUETUN_API_KEY="$(openssl rand -base64 48 | tr -d '\n')"; fi
  cat > "$ARR_DOCKER_DIR/gluetun/auth/config.toml" <<EOF
[[roles]]
name="readonly"
auth="basic"
username="gluetun"
password="${GLUETUN_API_KEY}"
routes=[
  "GET /v1/openvpn/status",
  "GET /v1/wireguard/status",
  "GET /v1/publicip/ip",
  "GET /v1/openvpn/portforwarded"
]
EOF
  chmod 600 "$ARR_DOCKER_DIR/gluetun/auth/config.toml"
}

write_env(){ msg ".env"; local PU PW; if [[ "$VPN_TYPE" == openvpn ]]; then PU=$(grep '^PROTON_USER=' "$ARRCONF_DIR/proton.auth" | cut -d= -f2-); PW=$(grep '^PROTON_PASS=' "$ARRCONF_DIR/proton.auth" | cut -d= -f2-); [[ "$PU" == *"+pmp" ]] || PU="${PU}+pmp"; cat > "$ARRCONF_DIR/proton.env" <<E
OPENVPN_USER=${PU}
OPENVPN_PASSWORD=${PW}
E
chmod 600 "$ARRCONF_DIR/proton.env"; fi
  : "${TIMEZONE:=Australia/Sydney}"; : "${LAN_IP:=0.0.0.0}"; : "${SERVER_COUNTRIES:=Netherlands,Germany,Switzerland}"
  cat > "$ARR_ENV_FILE" <<E
VPN_TYPE=${VPN_TYPE}
PUID=$(id -u)
PGID=$(id -g)
TIMEZONE=${TIMEZONE}
LAN_IP=${LAN_IP}
GLUETUN_API_KEY=${GLUETUN_API_KEY}
GLUETUN_IMAGE=${GLUETUN_IMAGE:-qmcgaw/gluetun:v3.39.1}
QBITTORRENT_IMAGE=${QBITTORRENT_IMAGE:-lscr.io/linuxserver/qbittorrent:latest}
SONARR_IMAGE=${SONARR_IMAGE:-lscr.io/linuxserver/sonarr:latest}
RADARR_IMAGE=${RADARR_IMAGE:-lscr.io/linuxserver/radarr:latest}
PROWLARR_IMAGE=${PROWLARR_IMAGE:-lscr.io/linuxserver/prowlarr:latest}
BAZARR_IMAGE=${BAZARR_IMAGE:-lscr.io/linuxserver/bazarr:latest}
FLARESOLVERR_IMAGE=${FLARESOLVERR_IMAGE:-ghcr.io/flaresolverr/flaresolverr:latest}
SERVER_COUNTRIES=${SERVER_COUNTRIES}
QBT_HTTP_PORT_HOST=${QBT_HTTP_PORT_HOST:-8081}
SONARR_PORT=${SONARR_PORT:-8989}
RADARR_PORT=${RADARR_PORT:-7878}
PROWLARR_PORT=${PROWLARR_PORT:-9696}
BAZARR_PORT=${BAZARR_PORT:-6767}
FLARESOLVERR_PORT=${FLARESOLVERR_PORT:-8191}
GLUETUN_CONTROL_PORT=${GLUETUN_CONTROL_PORT:-8000}
ARR_DOCKER_DIR=${ARR_DOCKER_DIR}
DOWNLOADS_DIR=${DOWNLOADS_DIR}
COMPLETED_DIR=${COMPLETED_DIR}
TV_DIR=${TV_DIR}
MOVIES_DIR=${MOVIES_DIR}
E
  chmod 600 "$ARR_ENV_FILE"
}

compose_write(){ msg "docker-compose.yml"; [[ -f "$REPO_ROOT/docker-compose.yml" ]] || die "compose missing"; }

start_stack(){ msg "Start Gluetun"; cd "$ARR_STACK_DIR"; run docker compose up -d gluetun; msg "Wait for health (≤5m)"; local tries=0; while ! docker inspect gluetun --format '{{.State.Health.Status}}' 2>/dev/null | grep -q healthy; do sleep 10; ((tries++)); ((tries>30)) && die "Gluetun not healthy"; done; local ip; ip=$(curl -fsS -u "gluetun:${GLUETUN_API_KEY}" "http://127.0.0.1:${GLUETUN_CONTROL_PORT}/v1/publicip/ip" || true); [[ -n "$ip" ]] && msg "Public IP: $ip" || warn "IP unknown"; msg "Start services"; run docker compose up -d; if [[ "$VPN_TYPE" == openvpn ]]; then sleep 8; local pf; pf=$(curl -fsS -u "gluetun:${GLUETUN_API_KEY}" "http://127.0.0.1:${GLUETUN_CONTROL_PORT}/v1/openvpn/portforwarded" || true); msg "Forwarded port: ${pf:-N/A}"; fi; }

validate(){ msg "Validate LAN"; local host="$LAN_IP"; [[ "$host" == 0.0.0.0 ]] && host=127.0.0.1; for s in "qBittorrent:$QBT_HTTP_PORT_HOST" "Sonarr:$SONARR_PORT" "Radarr:$RADARR_PORT" "Prowlarr:$PROWLARR_PORT" "Bazarr:$BAZARR_PORT" "FlareSolverr:$FLARESOLVERR_PORT"; do n=${s%:*}; p=${s#*:}; if curl -fsS "http://$host:$p" >/dev/null 2>&1; then msg "OK $n@$p"; else warn "$n@$p not reachable"; fi; done; }

aliases(){ cat > "$ARR_STACK_DIR/.aliasarr" <<'A'
export ARR_STACK_DIR="${ARR_STACK_DIR}"
export ARR_ENV_FILE="${ARR_STACK_DIR}/.env"
alias arr.up='cd ${ARR_STACK_DIR} && docker compose up -d'
alias arr.down='cd ${ARR_STACK_DIR} && docker compose down'
alias arr.logs='cd ${ARR_STACK_DIR} && docker compose logs -f'
alias arr.ps='cd ${ARR_STACK_DIR} && docker compose ps'
alias pvpn.status='curl -fsS -u "gluetun:$(grep GLUETUN_API_KEY ${ARR_ENV_FILE} | cut -d= -f2-)" http://127.0.0.1:8000/v1/publicip/ip && echo && curl -fsS -u "gluetun:$(grep GLUETUN_API_KEY ${ARR_ENV_FILE} | cut -d= -f2-)" http://127.0.0.1:8000/v1/openvpn/portforwarded && echo'
alias qbt.port.sync='port=$(curl -fsS -u "gluetun:$(grep GLUETUN_API_KEY ${ARR_ENV_FILE} | cut -d= -f2-)" http://127.0.0.1:8000/v1/openvpn/portforwarded | grep -oE "[0-9]+") && curl -fsS -X POST http://127.0.0.1:8081/api/v2/app/setPreferences --data "json={\"listen_port\":$port}" && echo "Set port: $port"'
A
  local rc="$HOME/.bashrc"; [[ -f "$HOME/.zshrc" ]] && rc="$HOME/.zshrc"; grep -q "\.aliasarr" "$rc" 2>/dev/null || { echo "[ -f '$ARR_STACK_DIR/.aliasarr' ] && source '$ARR_STACK_DIR/.aliasarr'" >> "$rc"; }
}

backup(){ [[ "$BACKUP_EXISTING" == 1 ]] || return 0; msg "Backup"; local bdir="${ARR_BASE}/backups/$(date +%Y%m%d-%H%M%S)"; mkdir -p "$bdir"; for a in gluetun qbittorrent sonarr radarr prowlarr bazarr; do [[ -d "$ARR_DOCKER_DIR/$a" ]] && tar -czf "$bdir/$a.tgz" -C "$ARR_DOCKER_DIR" "$a"; done; }

purge(){ [[ "$PURGE_NATIVE" == 1 ]] || return 0; msg "Purge native"; for p in sonarr radarr prowlarr bazarr qbittorrent transmission-daemon; do dpkg -l | grep -q "^ii.*$p" && run sudo apt-get purge -y "$p"; done; run sudo apt-get autoremove -y; }

fixperms(){ [[ "$CHOWN_TREE" == 1 ]] || return 0; msg "Permissions"; run sudo chown -R "${USER}:${USER}" "$ARR_BASE"; find "$ARR_BASE" -type d -exec chmod 755 {} +; find "$ARR_BASE" -type f -exec chmod 644 {} +; }

prunev(){ [[ "$PRUNE_VOLUMES" == 1 ]] || return 0; msg "Prune volumes"; docker volume prune -f; }

main(){ preflight; mkdirs; api_key; write_env; compose_write; backup; purge; fixperms; prunev; start_stack; validate; aliases; msg "Done."; }
main "$@"

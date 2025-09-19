# arrstack-mini (Raspberry Pi 5 / Debian Bookworm)

Minimal, reproducible ARR stack routed through Gluetun with ProtonVPN port forwarding. A single script bootstraps Docker, applies hardening defaults, and launches the *arr ecosystem end-to-end on a Raspberry Pi 5 running Debian Bookworm.

## Table of contents
- [Overview](#overview)
- [Stack highlights](#stack-highlights)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Configuration](#configuration)
  - [Directory layout](#directory-layout)
  - [Environment variables](#environment-variables)
  - [Service ports](#service-ports)
- [Daily operations](#daily-operations)
- [Security posture](#security-posture)
  - [Gluetun control API](#gluetun-control-api)
  - [Firewall and namespace](#firewall-and-namespace)
- [Logging and diagnostics](#logging-and-diagnostics)
- [Troubleshooting](#troubleshooting)

## Overview
`arrstack.sh` assembles the following containers inside a Gluetun VPN namespace:

- Gluetun (Proton OpenVPN with native port forwarding)
- qBittorrent (Vuetorrent-compatible WebUI)
- Sonarr, Radarr, Prowlarr, Bazarr
- FlareSolverr

By default only LAN listeners are published; *arr apps and qBittorrent egress the tunnel while auxiliary services (health probes, port-sync) stay inside the namespace.

## Stack highlights
- **Reproducible bootstrap** – `arrstack.sh` verifies Docker Compose prerequisites, creates the directory tree, generates secrets, writes `.env`, and starts the stack non-interactively when `--yes` is supplied.
- **Opinionated defaults** – all configuration inputs inherit from `arrconf/userconf.defaults.sh`, allowing simple overrides in `arrconf/userconf.sh` (ignored by Git) without editing the script.
- **Alias-driven operations** – `.arraliases` exposes helper commands (`arr.up`, `arr.logs`, `pvpn.status`, etc.) for routine management.
- **Native port forwarding** – OpenVPN Proton credentials are massaged into the `+pmp` form and synced into qBittorrent once Gluetun reports the forwarded port.

## Requirements
- Raspberry Pi 5 running Debian Bookworm (64-bit).
- Docker Engine and Compose v2. The installer will `apt-get install docker.io docker-compose-plugin` if they are missing.
- ProtonVPN Plus or Unlimited subscription for port forwarding support.
- Proton VPN OpenVPN credentials stored in `arrconf/proton.auth` (`PROTON_USER`, `PROTON_PASS`).

## Quick start
1. **Clone and enter the repository.**
   ```bash
   git clone https://github.com/<you>/arrstackmini.git
   cd arrstackmini
   ```
2. **Prepare configuration directories and Proton credentials.**
   ```bash
   mkdir -p arrconf docker-data
   cat > arrconf/proton.auth <<'EOF_AUTH'
   PROTON_USER=your_proton_username
   PROTON_PASS=your_proton_password
   EOF_AUTH
   chmod 600 arrconf/proton.auth
   ```
3. **(Optional) Pre-set overrides.** Copy `arrconf/userconf.sh.example` to `arrconf/userconf.sh` and adjust values such as `LAN_IP`, `SERVER_COUNTRIES`, or host port overrides before installation.
4. **(Optional) Seed a `.env`.** `arrstack.sh` will generate `.env`, but you can copy `.env.example` for reference or to pin VPN countries in advance.
5. **Run the installer.**
   ```bash
   ./arrstack.sh --yes
   ```
   - Add `--debug` for verbose tracing under `logs/`.
   - Other flags: `--rotate-apikey`, `--purge-native`, `--chown-tree`, `--prune-volumes`, `--backup-existing`.

The script provisions dependencies (Docker, Compose, curl, openssl, python3), builds the directory structure under `${ARR_STACK_DIR}`, generates a Gluetun API key, writes `.env`, waits for Gluetun health/port forwarding, then launches the remaining containers.

## Configuration
### Directory layout
Defaults are defined in `arrconf/userconf.defaults.sh` and can be overridden in `arrconf/userconf.sh`.

| Purpose              | Default path (relative to repo) |
| -------------------- | -------------------------------- |
| Stack root           | `${ARR_BASE}` (defaults to repo) |
| Docker volumes       | `${ARR_DOCKER_DIR}` (`docker-data/`)
| Proton auth/env      | `${ARRCONF_DIR}` (`arrconf/`)
| Downloads (incomplete)| `${DOWNLOADS_DIR}/incomplete`
| Completed downloads  | `${COMPLETED_DIR}`
| Media library        | `${MEDIA_DIR}` → `${TV_DIR}`, `${MOVIES_DIR}`

All secrets and config directories are created with restrictive permissions (`0600`/`0700`).

### Environment variables
`arrstack.sh` writes `.env` during installation with values sourced from your overrides. You can edit `.env` or `arrconf/userconf.sh` and rerun the installer to regenerate settings. Key variables include:

- `LAN_IP` – bind services to a specific RFC1918 address (auto-detected when empty).
- `SERVER_COUNTRIES` – comma-separated Proton country list handed to Gluetun (defaults to `Netherlands,Switzerland` so ProtonVPN stays on port-forwardable regions).
- `GLUETUN_CONTROL_HOST`, `GLUETUN_CONTROL_PORT` – host exposure for the Gluetun control API.
- `QBT_HTTP_PORT_HOST`, `SONARR_PORT`, etc. – LAN-facing ports; mirrored into firewall allow-lists.

### Service ports
The defaults below are published on your LAN IP and configurable via `.env`/`arrconf/userconf.sh`:

| Service       | LAN URL                                         | Container port |
| ------------- | ------------------------------------------------ | -------------- |
| qBittorrent   | `http://${LAN_IP:-0.0.0.0}:${QBT_HTTP_PORT_HOST:-8081}` | `${QBT_HTTP_PORT_CONTAINER:-8080}` |
| Sonarr        | `http://${LAN_IP:-0.0.0.0}:${SONARR_PORT:-8989}`        | `8989` |
| Radarr        | `http://${LAN_IP:-0.0.0.0}:${RADARR_PORT:-7878}`        | `7878` |
| Prowlarr      | `http://${LAN_IP:-0.0.0.0}:${PROWLARR_PORT:-9696}`      | `9696` |
| Bazarr        | `http://${LAN_IP:-0.0.0.0}:${BAZARR_PORT:-6767}`        | `6767` |
| FlareSolverr  | `http://${LAN_IP:-0.0.0.0}:${FLARESOLVERR_PORT:-8191}`  | `8191` |

Set `LAN_IP` in `arrconf/userconf.sh` to bind to a single interface when desired.

## Daily operations
After installation, `~/.bashrc`/`~/.zshrc` sources `.arraliases` so helper functions are available in new shells:

```bash
arr.up         # docker compose up -d
arr.down       # docker compose down
arr.logs       # follow stack logs
arr.restart    # restart all services
pvpn.status    # Gluetun public IP + forwarded port (OpenVPN)
qbt.port.sync  # re-apply forwarded port to qBittorrent
```

Additional helpers include `arr.health`, `arr.backup`, `arr.open`, and `arr.shell <service>` for targeted exec access.

## Security posture
### Gluetun control API
The control server listens inside the VPN namespace at `${GLUETUN_CONTROL_LISTEN_IP:-0.0.0.0}:${GLUETUN_CONTROL_PORT:-8000}` and is published to the host at `${GLUETUN_CONTROL_HOST:-127.0.0.1}`. API-key-only authentication is enforced:

```env
HTTP_CONTROL_SERVER="on"
HTTP_CONTROL_SERVER_AUTH_TYPE="apikey"
HTTP_CONTROL_SERVER_APIKEY="${GLUETUN_API_KEY}"
```

All requests must supply the `X-API-Key` header:

```bash
curl -fsS -H "X-API-Key: $GLUETUN_API_KEY" \
  "http://${GLUETUN_CONTROL_HOST}:${GLUETUN_CONTROL_PORT}/v1/publicip/ip"

curl -fsS -H "X-API-Key: $GLUETUN_API_KEY" \
  "http://${GLUETUN_CONTROL_HOST}:${GLUETUN_CONTROL_PORT}/v1/openvpn/status"
```

### Firewall and namespace
- `GLUETUN_LAN_INPUT_PORTS` populates Gluetun's `FIREWALL_INPUT_PORTS`, limiting host/LAN ingress.
- `GLUETUN_VPN_INPUT_PORTS` feeds `FIREWALL_VPN_INPUT_PORTS` for VPN provider port forwarding only.
- Scope exposure by adjusting `${GLUETUN_CONTROL_HOST}` (`127.0.0.1` keeps the API loopback-only; `0.0.0.0` opens all interfaces).
- Health probes and forwarded port sync execute over `${GLUETUN_LOOPBACK_HOST:-127.0.0.1}` inside the namespace.
- Secrets are never echoed to stdout; files land with `0600` and directories with `0700` permissions.

## Logging and diagnostics
- Pass `--debug` to `arrstack.sh` for full tracing. Logs live under `${ARRSTACK_LOG_ARCHIVE_DIR:=$ARR_STACK_DIR/logs/archive}` with the latest run symlinked at `${ARRSTACK_LOG_FILE:=$ARR_STACK_DIR/logs/arrstack-install.log}`.
- Override `ARRSTACK_LOG_DIR`, `ARRSTACK_LOG_ARCHIVE_DIR`, or `ARRSTACK_LOG_FILE` in `arrconf/userconf.sh` to relocate installer output.
- `arr.logs` streams container logs; `arr.health` inspects Docker health checks.

## Troubleshooting
Refer to [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) for Proton port-forward validation, health check tips, and common fixes.

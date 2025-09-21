# arrstack-mini (Raspberry Pi 5 / Debian Bookworm)

Minimal, reproducible ARR stack routed through Gluetun with ProtonVPN port forwarding. A single script bootstraps Docker, applies hardening defaults, and launches the *arr ecosystem end-to-end on a Raspberry Pi 5 running Debian Bookworm.

## Table of contents
- [Overview](#overview)
- [Stack highlights](#stack-highlights)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Important notes](#important-notes)
  - [First-time checklist](#first-time-checklist)
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
- port-sync (Alpine helper that keeps qBittorrent aligned with the forwarded port)
- Sonarr, Radarr, Prowlarr, Bazarr
- FlareSolverr

By default only LAN listeners are published; *arr apps and qBittorrent egress the tunnel while auxiliary services (health probes, port-sync) stay inside the namespace.

## Stack highlights
- **Reproducible bootstrap** – `arrstack.sh` verifies Docker Compose prerequisites, creates the directory tree, generates secrets, writes `.env`, and starts the stack non-interactively when `--yes` is supplied.
- **Opinionated defaults** – all configuration inputs inherit from `arrconf/userconf.defaults.sh`, allowing simple overrides in `arrconf/userconf.sh` (ignored by Git) without editing the script.
- **Alias-driven operations** – `.arraliases` exposes helper commands (`arr.up`, `arr.logs`, `pvpn.status`, etc.) for routine management.
- **Native port forwarding** – OpenVPN Proton credentials are massaged into the `+pmp` form and a companion `port-sync` container polls Gluetun and updates qBittorrent whenever the forwarded port changes.

## Requirements
- 64-bit Debian Bookworm host with at least 4 CPU cores, 4 GB RAM, and fast storage for downloads.
- Example device: Raspberry Pi 5 (8 GB) running Debian Bookworm (64-bit) has been validated end-to-end.
- Docker Engine and Compose v2. The installer will `apt-get install docker.io docker-compose-plugin` if they are missing.
- Command-line dependencies available on the host: `curl`, `jq`, and `openssl`. Install them on Debian with `sudo apt-get install curl jq openssl`.
- ProtonVPN Plus or Unlimited subscription for port forwarding support.
- Proton VPN OpenVPN credentials stored in `arrconf/proton.auth` (`PROTON_USER`, `PROTON_PASS`).

## Quick start
1. **Clone and enter the repository.**
   ```bash
   git clone https://github.com/cbkii/arrstackmini.git
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
3. **(Optional) Pre-set overrides.** Copy `arrconf/userconf.sh.example` to `arrconf/userconf.sh` and adjust values such as `LAN_IP`, `SERVER_COUNTRIES`, media directories or host port overrides before installation.
4. **(Optional) Seed a `.env`.** `arrstack.sh` will generate `.env`, but you can copy `.env.example` for reference or to pin VPN countries in advance.
5. **Run the installer.**
   ```bash
   ./arrstack.sh --yes
   ```
   - Use `--yes` to skip the interactive confirmation prompt.
   - Run `./arrstack.sh --help` for available flags such as `--rotate-api-key`.

    The script checks for Docker, Compose, curl, jq, and openssl, builds the directory structure under `${ARR_STACK_DIR}`, generates a Gluetun API key, writes `.env`, waits for Gluetun health/port forwarding, then launches the remaining containers. Any blockers surface as warnings where safe fallbacks exist (e.g. unknown LAN IP, default credentials) so first-time installs should always complete.

## Important notes

- ✅ **Pinned container versions with validation** – every service ships with a known-good tag. During startup the installer now validates each image and automatically falls back to LinuxServer's `:latest` tag when a pinned build disappears (the default for Prowlarr and Bazarr). Override tags in `.env`/`arrconf/userconf.sh` and review the [version management guide](docs/VERSION_MANAGEMENT.md) before upgrading.
- 🆘 **Recovery helper** – `${ARR_STACK_DIR}/scripts/fix-versions.sh` repairs `.env` if an old LinuxServer tag is removed. It creates a timestamped backup and replaces missing images with the safe fallback before rerunning the installer.
- ⚠️ **Warnings over failures** – the installer continues when it cannot detect a LAN IP or when default credentials remain. Read the summary at the end of the run and remediate highlighted risks.
- 🪪 **Helper aliases** – a rendered `.arraliases` file lands in `${ARR_STACK_DIR}` and can be sourced for `pvpn.*`, `arr.health`, and other shortcuts.
- ⚠️🔐 **Credentials** – the installer captures the temporary qBittorrent password from container logs and stores it as `QBT_PASS` in `.env`. Port-sync will use those credentials when available but otherwise relies on the localhost/LAN auth bypass. Log in with the recorded value, update it in the WebUI, then mirror the new password in `.env` for continued convenience.

### First-time checklist
After `./arrstack.sh --yes` finishes:

1. **Change the qBittorrent password.** Log in with the credentials stored in `.env` (`QBT_USER`/`QBT_PASS`), update them in Settings → WebUI, then mirror the new values in `.env`.
2. **Set a fixed `LAN_IP`.** Edit `arrconf/userconf.sh` if the summary warned about `0.0.0.0` exposure.
3. **Reload aliases.** `source ${ARR_STACK_DIR}/.arraliases` to gain `pvpn.status`, `arr.logs`, and other useful aliased quick commands.
4. **Verify VPN status.** `docker logs gluetun --tail 100` should show a healthy tunnel and forwarded port.
5. **Review version guidance when upgrading.** Refer to [docs/VERSION_MANAGEMENT.md](docs/VERSION_MANAGEMENT.md) for image pinning strategy and manual upgrade steps.

## Configuration
### Directory layout
Defaults are defined in `arrconf/userconf.defaults.sh` and can be overridden in `arrconf/userconf.sh`.

| Purpose             | Default path |
| ------------------- | ------------ |
| Stack root          | `${PWD}/arrstack` (`${ARR_BASE}/arrstack`)
| Docker volumes      | `${ARR_DOCKER_DIR}` (`${ARR_BASE}/docker-data`)
| Proton auth/env     | `${ARRCONF_DIR}` (`<repo>/arrconf`)
| Downloads           | `${DOWNLOADS_DIR}` (`${HOME}/Downloads`)
| Completed downloads | `${COMPLETED_DIR}` (`${HOME}/Downloads/completed`)
| Media library       | `${MEDIA_DIR}` (`/media/mediasmb`)
| TV library          | `${TV_DIR}` (`/media/mediasmb/Shows`)
| Movies library      | `${MOVIES_DIR}` (`/media/mediasmb/Movies`)

Ensure to edit media and download directories before running, using paths with sufficient free storage space.

All secrets and config directories are created with restrictive permissions (`0600`/`0700`).

### Environment variables
`arrstack.sh` writes `.env` during installation with values sourced from your overrides. You can edit `.env` or `arrconf/userconf.sh` and rerun the installer to regenerate settings. Key variables include:

- `LAN_IP` – bind services to a specific RFC1918 address (auto-detected when empty).
- `SERVER_COUNTRIES` – comma-separated Proton country list handed to Gluetun (defaults to `Switzerland,Iceland,Romania,Czech Republic,Netherlands` so ProtonVPN stays on port-forwardable regions).
- `LOCALHOST_IP`, `GLUETUN_CONTROL_PORT` – host exposure for the Gluetun control API.
- `QBT_HTTP_PORT_HOST`, `SONARR_PORT`, etc. – LAN-facing ports; mirrored into firewall allow-lists.

### Service ports
The defaults below are published on your LAN IP and configurable via `.env`/`arrconf/userconf.sh`:

| Service      | LAN URL                                         |
| ------------ | ----------------------------------------------- |
| qBittorrent  | `http://${LAN_IP:-0.0.0.0}:${QBT_HTTP_PORT_HOST:-8080}` |
| Sonarr       | `http://${LAN_IP:-0.0.0.0}:${SONARR_PORT:-8989}`        |
| Radarr       | `http://${LAN_IP:-0.0.0.0}:${RADARR_PORT:-7878}`        |
| Prowlarr     | `http://${LAN_IP:-0.0.0.0}:${PROWLARR_PORT:-9696}`      |
| Bazarr       | `http://${LAN_IP:-0.0.0.0}:${BAZARR_PORT:-6767}`        |
| FlareSolverr | `http://${LAN_IP:-0.0.0.0}:${FLARESOLVERR_PORT:-8191}`  |

Set `LAN_IP` in `arrconf/userconf.sh` to bind to a single interface when desired.

## Daily operations
The installer adds two aliases to `~/.bashrc` when possible:

```bash
arrstack       # rerun the installer from the repo
arrstack-logs  # follow Gluetun logs
source ${ARR_STACK_DIR:-/path/to/arrstack}/.arraliases  # load helper functions
```

The generated `.arraliases` file enables:

```bash
pvpn.status    # Inspect VPN status and forwarded port
arr.health     # Summarise container health checks
arr.open       # Print (or open) service URLs in your browser
```

The stack also maintains `port-sync`, a lightweight helper container that watches the Gluetun control API and applies the latest forwarded port to qBittorrent without manual input.

Manage the stack directly with Docker Compose commands from `${ARR_STACK_DIR}` if you prefer finer-grained control.

## Security posture
### Gluetun control API
The control server listens inside the VPN namespace and is published to the host at `${LOCALHOST_IP:-127.0.0.1}:${GLUETUN_CONTROL_PORT:-8000}`. API-key authentication is required; requests must include `X-API-Key: ${GLUETUN_API_KEY}`:

```bash
curl -fsS -H "X-API-Key: $GLUETUN_API_KEY" \
  "http://${LOCALHOST_IP:-127.0.0.1}:${GLUETUN_CONTROL_PORT:-8000}/v1/publicip/ip"

curl -fsS -H "X-API-Key: $GLUETUN_API_KEY" \
  "http://${LOCALHOST_IP:-127.0.0.1}:${GLUETUN_CONTROL_PORT:-8000}/v1/forwardedport"

# Fallback for older Gluetun releases that expose JSON only:
curl -fsS -H "X-API-Key: $GLUETUN_API_KEY" \
  "http://${LOCALHOST_IP:-127.0.0.1}:${GLUETUN_CONTROL_PORT:-8000}/v1/openvpn/portforwarded" | jq '.port'
```

### Firewall and namespace
- Gluetun exposes only the configured LAN service ports plus the control API on `${LOCALHOST_IP}`.
- Health probes and forwarded port sync execute over the control API using the generated key.
- Secrets are never echoed to stdout; files land with `0600` and directories with `0700` permissions.

## Logging and diagnostics
- Re-run the installer with `--rotate-api-key` to regenerate credentials if needed.
- Use `docker logs gluetun` (or the `arrstack-logs` alias) to monitor VPN connectivity.
- `docker compose ps` from `${ARR_STACK_DIR}` surfaces container state and health checks.
- `docker logs port-sync --tail 50` shows the helper container polling Gluetun and pushing the forwarded port into qBittorrent.
- Run `${ARR_STACK_DIR}/diagnose-vpn.sh` from the stack root to execute the autogenerated diagnostics (checks Gluetun health, validates the forwarded port, and restarts the VPN container when required).

## Troubleshooting
Refer to [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) for Proton port-forward validation, health check tips, and common fixes. If Docker reports `manifest unknown` for a LinuxServer image, run `${ARR_STACK_DIR}/scripts/fix-versions.sh` to back up `.env`, swap in safe fallbacks, and then re-run the installer.

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
1. **Create the default stack root (`~/srv`) and clone arrstack-mini.**
   ```bash
   mkdir -p ~/srv
   cd ~/srv
   git clone https://github.com/cbkii/arrstackmini.git
   cd arrstackmini
   ```
2. **Add your ProtonVPN credentials.**
   ```bash
   cp arrconf/proton.auth.example arrconf/proton.auth
   nano arrconf/proton.auth
   ```
   Replace the placeholders with your Proton VPN username and password (the installer tightens the file permissions automatically).
3. **(Optional) Adjust defaults before installation.** Copy `arrconf/userconf.sh.example` to `arrconf/userconf.sh` and tweak values such as `LAN_IP`, `SERVER_COUNTRIES`, media directories, or host port overrides. Skip this if the defaults suit you—the installer can be rerun whenever you want to apply changes.
4. **Run the installer.**
   ```bash
   ./arrstack.sh
   ```
   - Review the summary shown before containers launch and confirm to proceed.
   - `--yes` skips the confirmation prompt but is meant for scripted or repeat runs—leave it off on your first install.
   - Run `./arrstack.sh --help` for flags such as `--rotate-api-key`.

    The script installs Docker Compose prerequisites when needed, creates the required directory tree under `${ARR_STACK_DIR}`, generates secrets (including `.env`), waits for Gluetun health/port forwarding, then launches the remaining containers. Any blockers surface as warnings when safe fallbacks exist, so first-time installs should still complete.

## Important notes

- ✅ **Pinned container versions with validation** – every service ships with a known-good tag. During startup the installer now validates each image and automatically falls back to LinuxServer's `:latest` tag when a pinned build disappears (the default for Prowlarr and Bazarr). Override tags in `.env`/`arrconf/userconf.sh` and review the [version management guide](docs/VERSION_MANAGEMENT.md) before upgrading.
- 🆘 **Recovery helper** – `${ARR_STACK_DIR}/scripts/fix-versions.sh` repairs `.env` if an old LinuxServer tag is removed. It creates a timestamped backup and replaces missing images with the safe fallback before rerunning the installer.
- ⚠️ **Warnings over failures** – the installer continues when it cannot detect a LAN IP or when default credentials remain. Read the summary at the end of the run and remediate highlighted risks.
- 🪪 **Helper aliases** – a rendered `.arraliases` file lands in `${ARR_STACK_DIR}` and can be sourced for `pvpn.*`, `arr.health`, and other shortcuts.
- ⚠️🔐 **Credentials** – the installer captures the temporary qBittorrent password from container logs and stores it as `QBT_PASS` in `.env`. Port-sync will use those credentials when available but otherwise relies on the localhost/LAN auth bypass. Log in with the recorded value, update it in the WebUI, then mirror the new password in `.env` for continued convenience.

### First-time checklist
After `./arrstack.sh` (or `./arrstack.sh --yes` when automating) finishes:

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
| Stack root          | `~/srv/arrstack` (`${ARR_BASE}/arrstack`)
| Docker volumes      | `${ARR_DOCKER_DIR}` (`${ARR_BASE}/docker-data` → `~/srv/docker-data` by default)
| Proton auth/env     | `${ARRCONF_DIR}` (`<repo>/arrconf`)
| Downloads           | `${DOWNLOADS_DIR}` (`${HOME}/Downloads`)
| Completed downloads | `${COMPLETED_DIR}` (`${HOME}/Downloads/completed`)
| Media library       | `${MEDIA_DIR}` (`/media/mediasmb`)
| TV library          | `${TV_DIR}` (`/media/mediasmb/Shows`)
| Movies library      | `${MOVIES_DIR}` (`/media/mediasmb/Movies`)

Ensure to edit media and download directories before running, using paths with sufficient free storage space.

All secrets and config directories are created with restrictive permissions (`0600`/`0700`) when using the default permission profile.
To allow read-only collaboration, set `ARR_PERMISSION_PROFILE=collaborative` in `arrconf/userconf.sh`. This relaxes non-secret files to group-readable (`0640`) and data directories to `0750` while keeping secrets locked to `0600`.

### Environment variables
`arrstack.sh` writes `.env` during installation by reading `arrconf/userconf.defaults.sh` and applying any overrides from `arrconf/userconf.sh`. Beginners can copy `arrconf/userconf.sh.example`, adjust values, and rerun `./arrstack.sh` whenever they want the stack to pick up new settings.

The tables below summarise every configurable input exposed by `arrstack.sh` together with practical reasons to change them.

#### Paths and storage
| Variable | Default | Why change it? |
| -------- | ------- | --------------- |
| `ARR_BASE` | `~/srv` | Move the entire stack to a different root without editing every path individually. `ARR_STACK_DIR` and `ARR_DOCKER_DIR` inherit from this value. |
| `ARR_STACK_DIR` | `${ARR_BASE}/arrstack` | Relocate the generated `docker-compose.yml`, scripts, and `.arraliases`. Useful when storing the stack on another disk. |
| `ARR_ENV_FILE` | `${ARR_STACK_DIR}/.env` | Keep the generated `.env` in a separate secrets vault or version-controlled directory. |
| `ARR_DOCKER_DIR` | `${ARR_BASE}/docker-data` | Choose where Docker volumes live (e.g. move to a large external drive). |
| `ARRCONF_DIR` | `<repo>/arrconf` | Relocate Proton credentials and user config if you want them outside the repo tree. |
| `DOWNLOADS_DIR` | `~/Downloads` | Set the root for active qBittorrent downloads. |
| `COMPLETED_DIR` | `${DOWNLOADS_DIR}/completed` | Control where finished downloads are moved. |
| `MEDIA_DIR` | `/media/mediasmb` | Point to the base of your media library share. |
| `TV_DIR` | `${MEDIA_DIR}/Shows` | Tell Sonarr where your TV library lives. |
| `MOVIES_DIR` | `${MEDIA_DIR}/Movies` | Tell Radarr where your movie library lives. |

> Tip: The defaults already place the stack under `~/srv`, but you can set `ARR_BASE` to another path (for example `/mnt/fastdisk`) and the inherited values for `ARR_STACK_DIR` and `ARR_DOCKER_DIR` will follow automatically.

#### Identity and networking
| Variable | Default | Why change it? |
| -------- | ------- | --------------- |
| `PUID` | Current user ID (`id -u`) | Run containers as another user (e.g. a dedicated media account). |
| `PGID` | Current group ID (`id -g`) | Match the media group so containers can write to shared folders. |
| `TIMEZONE` | `Australia/Sydney` | Align container logs and cron tasks with your local timezone. |
| `LAN_IP` | Auto-detected (falls back to `0.0.0.0`) | Bind services to a specific RFC1918 address instead of all interfaces. |
| `LOCALHOST_IP` | `127.0.0.1` | Change where the Gluetun control API binds on the host (advanced). |
| `SERVER_COUNTRIES` | `Switzerland,Iceland,Romania,Czech Republic,Netherlands` | Limit ProtonVPN exits to countries that support port forwarding or suit your latency. |
| `GLUETUN_CONTROL_PORT` | `8000` | Adjust the host port for the Gluetun control API when 8000 is taken. |

#### Credentials and WebUI access
| Variable | Default | Why change it? |
| -------- | ------- | --------------- |
| `GLUETUN_API_KEY` | Generated on first run | Reuse an existing key when migrating installs. Leave blank to auto-generate. |
| `QBT_USER` | `admin` | Set your desired qBittorrent username before the first login. |
| `QBT_PASS` | `adminadmin` | Seed a temporary qBittorrent password (update in WebUI afterwards). |
| `QBT_DOCKER_MODS` | `ghcr.io/vuetorrent/vuetorrent-lsio-mod:latest` | Swap to a different qBittorrent WebUI mod or remove mods entirely. |
| `QBT_AUTH_WHITELIST` | `127.0.0.1/8,::1/128` | Allow extra CIDR ranges to bypass the qBittorrent login page (useful on trusted LANs). |

#### Behaviour toggles
| Variable | Default | Why change it? |
| -------- | ------- | --------------- |
| `ARR_PERMISSION_PROFILE` | `strict` | Switch to `collaborative` to make non-secret files group-readable (`0640`/`0750`) when sharing the host with other users. |
| `ASSUME_YES` | `0` | Set to `1` for unattended installs that must skip prompts (avoid enabling on first run). |
| `FORCE_ROTATE_API_KEY` | `0` | Set to `1` to regenerate the Gluetun API key on the next run (useful if the key leaked). |

#### Container images
| Variable | Default | Why change it? |
| -------- | ------- | --------------- |
| `GLUETUN_IMAGE` | `qmcgaw/gluetun:v3.39.1` | Pin to a newer Gluetun tag after validating compatibility. |
| `QBITTORRENT_IMAGE` | `lscr.io/linuxserver/qbittorrent:5.1.2-r2-ls415` | Track a newer qBittorrent release. |
| `SONARR_IMAGE` | `lscr.io/linuxserver/sonarr:4.0.15.2941-ls291` | Upgrade/downgrade Sonarr carefully when required. |
| `RADARR_IMAGE` | `lscr.io/linuxserver/radarr:5.27.5.10198-ls283` | Change Radarr tag once confirmed stable. |
| `PROWLARR_IMAGE` | `lscr.io/linuxserver/prowlarr:latest` | Pin to a specific version to avoid unexpected updates. |
| `BAZARR_IMAGE` | `lscr.io/linuxserver/bazarr:latest` | Pin to a specific version to avoid unexpected updates. |
| `FLARESOLVERR_IMAGE` | `ghcr.io/flaresolverr/flaresolverr:v3.3.21` | Track newer FlareSolverr releases when needed. |

### Service ports
Each service publishes a configurable LAN port. Edit the matching variable in `arrconf/userconf.sh` (or `.env`) if a port clashes with something else on your network.

| Service      | Variable | Default port | LAN URL pattern |
| ------------ | -------- | ------------- | --------------- |
| qBittorrent  | `QBT_HTTP_PORT_HOST` | `8080` | `http://${LAN_IP:-0.0.0.0}:${QBT_HTTP_PORT_HOST:-8080}` |
| Sonarr       | `SONARR_PORT` | `8989` | `http://${LAN_IP:-0.0.0.0}:${SONARR_PORT:-8989}` |
| Radarr       | `RADARR_PORT` | `7878` | `http://${LAN_IP:-0.0.0.0}:${RADARR_PORT:-7878}` |
| Prowlarr     | `PROWLARR_PORT` | `9696` | `http://${LAN_IP:-0.0.0.0}:${PROWLARR_PORT:-9696}` |
| Bazarr       | `BAZARR_PORT` | `6767` | `http://${LAN_IP:-0.0.0.0}:${BAZARR_PORT:-6767}` |
| FlareSolverr | `FLARESOLVERR_PORT` | `8191` | `http://${LAN_IP:-0.0.0.0}:${FLARESOLVERR_PORT:-8191}` |

Set `LAN_IP` to a single RFC1918 address to restrict access or leave it blank to bind on all interfaces (the installer warns when it falls back to `0.0.0.0`).

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
- Secrets are never echoed to stdout; the strict profile writes files with `0600` and directories with `0700`, while the collaborative profile keeps secrets at `0600` but allows non-secret files/dirs to land as `0640`/`0750`.

## Logging and diagnostics
- Re-run the installer with `--rotate-api-key` to regenerate credentials if needed.
- Use `docker logs gluetun` (or the `arrstack-logs` alias) to monitor VPN connectivity.
- `docker compose ps` from `${ARR_STACK_DIR}` surfaces container state and health checks.
- `docker logs port-sync --tail 50` shows the helper container polling Gluetun and pushing the forwarded port into qBittorrent.
- Run `${ARR_STACK_DIR}/diagnose-vpn.sh` from the stack root to execute the autogenerated diagnostics (checks Gluetun health, validates the forwarded port, and restarts the VPN container when required).

## Troubleshooting
Refer to [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) for Proton port-forward validation, health check tips, and common fixes. If Docker reports `manifest unknown` for a LinuxServer image, run `${ARR_STACK_DIR}/scripts/fix-versions.sh` to back up `.env`, swap in safe fallbacks, and then re-run the installer.

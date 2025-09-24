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
- Caddy (reverse proxy inside the Gluetun namespace that fronts every service on LAN ports 80/443)
- Sonarr, Radarr, Prowlarr, Bazarr
- FlareSolverr

Only the Caddy reverse proxy is published on the LAN (ports 80/443). Every application continues to run inside Gluetun’s network namespace so traffic egresses the VPN while health probes and helpers stay local.

## Stack highlights
- **Reproducible bootstrap** – `arrstack.sh` verifies Docker Compose prerequisites, creates the directory tree, generates secrets, writes `.env`, and starts the stack non-interactively when `--yes` is supplied.
- **Opinionated defaults** – all configuration inputs inherit from `arrconf/userconf.defaults.sh`, allowing simple overrides in `arrconf/userconf.sh` (ignored by Git) without editing the script.
- **Alias-driven operations** – `.arraliases` exposes helper commands (`arr.up`, `arr.logs`, `arr.vpn.status`, `arr.help`, etc.) for routine management.
- **Unified reverse proxy** – Caddy shares the Gluetun network namespace and is the only container publishing LAN ports (80/443). LAN clients bypass credentials while non-LAN clients authenticate via Basic Auth before reaching the apps.
- **Native port forwarding** – OpenVPN Proton credentials are massaged into the `+pmp` form and Gluetun's `VPN_PORT_FORWARDING_UP_COMMAND` now updates qBittorrent directly. No sidecar containers or watchdog scripts are required.

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
3. **(Optional) Adjust defaults before installation.** Copy `arrconf/userconf.sh.example` to `arrconf/userconf.sh` and tweak values such as `LAN_IP`, `SERVER_COUNTRIES`, `PVPN_ROTATE_COUNTRIES`, media directories, or host port overrides. Skip this if the defaults suit you—the installer can be rerun whenever you want to apply changes.
5. **Run the installer.**
   ```bash
   ./arrstack.sh
   ```
   - Review the summary shown before containers launch and confirm to proceed.
   - `--yes` skips the confirmation prompt but is meant for scripted or repeat runs—leave it off on your first install. It can be combined with other flags when you need hands-free upgrades.
   - Flags such as `--rotate-api-key`, `--rotate-caddy-auth`, and `--setup-host-dns` can run together in a single invocation so long as you want those actions during the same pass. See [Installer flags](#installer-flags) for a full breakdown.
   - Use `--refresh-aliases` on its own when you only want to regenerate helper aliases; it exits immediately after writing `.arraliases`.

The script installs Docker Compose prerequisites when needed, creates the required directory tree under `${ARR_STACK_DIR}`, generates secrets (including `.env`), waits for Gluetun health/port forwarding, then launches the remaining containers. Any blockers surface as warnings when safe fallbacks exist, so first-time installs should still complete.

### Installer flags

| Flag | Description | Can it be combined? |
| --- | --- | --- |
| `--yes` | Assume confirmation prompts are approved. Mirrors `ASSUME_YES=1`. | ✅ Combine freely with other actions. |
| `--rotate-api-key` | Regenerate the Gluetun API key before writing `.env`. Sets `FORCE_ROTATE_API_KEY=1`. | ✅ Safe alongside `--yes`, `--rotate-caddy-auth`, or `--setup-host-dns`. |
| `--rotate-caddy-auth` | Rotate the Caddy Basic Auth username/password and update `${ARR_DOCKER_DIR}/caddy/credentials`. Sets `FORCE_REGEN_CADDY_AUTH=1`. | ✅ Can run with other install-time actions. |
| `--setup-host-dns` | Run `scripts/host-dns-setup.sh` after the stack is written, using the current `LAN_IP`, suffix, and upstream DNS values. Sets `SETUP_HOST_DNS=1`. | ✅ Combine with other install flags once `LAN_IP` points at a local interface. |
| `--refresh-aliases` | Regenerate `.arraliases`, update the repo copy, and exit without touching the rest of the installer. Sets `REFRESH_ALIASES=1`. | ⚠️ Should be run alone—other flags are ignored once aliases are refreshed. |

You can combine the first four flags as needed—for example, `./arrstack.sh --yes --rotate-api-key --rotate-caddy-auth --setup-host-dns` applies all requested maintenance tasks in one pass. When you only need fresh helper functions, call `./arrstack.sh --refresh-aliases` by itself.

## Important notes

- ✅ **Pinned container versions with validation** – every service ships with a known-good tag. During startup the installer now validates each image and automatically falls back to LinuxServer's `:latest` tag when a pinned build disappears (the default for Prowlarr and Bazarr). Override tags in `.env`/`arrconf/userconf.sh` and review the [version management guide](docs/VERSION_MANAGEMENT.md) before upgrading.
- 🆘 **Recovery helper** – `${ARR_STACK_DIR}/scripts/fix-versions.sh` repairs `.env` if an old LinuxServer tag is removed. It creates a timestamped backup and replaces missing images with the safe fallback before rerunning the installer.
- ⚠️ **Warnings over failures** – the installer continues when it cannot detect a LAN IP or when default credentials remain. Read the summary at the end of the run and remediate highlighted risks.
- 🪪 **Helper aliases** – a rendered `.arraliases` file lands in `${ARR_STACK_DIR}` and can be sourced for `arr.vpn.*`, `arr.help`, `arr.health`, and other shortcuts.
- ⚠️🔐 **Credentials** – the installer captures the temporary qBittorrent password from container logs and stores it as `QBT_PASS` in `.env`. The Gluetun hook authenticates with those credentials whenever the WebUI demands it, while Caddy allows LAN clients straight through and prompts non-LAN clients for the Basic Auth user recorded in `${ARR_DOCKER_DIR}/caddy/credentials`. That file (mode `0600`) contains the current username/password pair, while `.env` retains only the bcrypt hash.
- 🛡️ **LAN auth model** – qBittorrent keeps `LocalHostAuth`, CSRF, clickjacking, and host-header protections enabled while the installer maintains a LAN whitelist so the WebUI mirrors Caddy’s “no password on LAN” stance. Sonarr, Radarr, Prowlarr, and Bazarr retain their native logins by default; rely on Caddy’s `remote_ip` matcher for the LAN bypass unless you opt into per-app tweaks manually.
- 🌐 **LAN DNS & TLS** – the optional `local_dns` service (enabled by default) runs dnsmasq on `${LAN_IP}`, answering for `*.${LAN_DOMAIN_SUFFIX}` (`home.arpa` unless overridden). It binds both UDP and TCP :53 and now runs with `--local-service` to avoid serving non-LAN subnets. Choose how clients learn `${LAN_IP}` via `DNS_DISTRIBUTION_MODE` (`router` vs `per-device`), and import the Caddy CA from `${ARR_DOCKER_DIR}/caddy/ca-pub/root.crt`, fetch it via `http://ca.${LAN_DOMAIN_SUFFIX}/root.crt`, or run `./scripts/export-caddy-ca.sh` for a local copy. The CA host stays reachable over plain HTTP to avoid bootstrap loops, while HTTPS works once the root is trusted. Use `--setup-host-dns` to replace Debian Bookworm’s `systemd-resolved` stub cleanly and rebind port 53; roll back with `./scripts/host-dns-rollback.sh` if needed.

## ✅ LAN DNS: choose one (set in `DNS_DISTRIBUTION_MODE`)

`arrstack-mini` ships a dnsmasq resolver that answers `*.${LAN_DOMAIN_SUFFIX}` (`home.arpa` by default). Decide how clients learn `${LAN_IP}`:

- **`router` (recommended):** Point your router’s DHCP server at `${LAN_IP}` with a public resolver as the fallback. Follow the step-by-step checklist in [docs/ROUTER_DNS_SETUP.md](docs/ROUTER_DNS_SETUP.md) to apply the change safely; TP-Link VX230v instructions are included.[^tplink]
- **`per-device`:** Leave the router untouched and manually set DNS=`${LAN_IP}` on key devices (Android/PC/TV). Keep Android **Private DNS** set to **Off** or **Automatic** so queries stay on the LAN.[^android]

Set your preference in `arrconf/userconf.sh`:

```bash
DNS_DISTRIBUTION_MODE=router    # or per-device
```

### Why `home.arpa`

The stack defaults to `home.arpa`, the IETF special-use domain for residential networks, so queries never escape to the public Internet.[^rfc8375]

### Host DNS helper (Bookworm)

Debian Bookworm ships `systemd-resolved`, which binds 127.0.0.53 and symlinks `/etc/resolv.conf`. Run:

```bash
./scripts/host-dns-setup.sh
```

to back up the stub, disable the service non-destructively, and write a static resolver that points at `${LAN_IP}` plus validated upstreams. Restore the previous state any time with `./scripts/host-dns-rollback.sh`. Background on the stub resolver is covered in the resolved.conf man page and community explanations.[^resolvconf]

### CA bootstrap

The installer copies Caddy’s public root certificate into `${ARR_DOCKER_DIR}/caddy/ca-pub/root.crt` and serves it from `http://ca.${LAN_DOMAIN_SUFFIX}/root.crt`. Only the public root is exposed; private PKI material remains inside `/data/caddy/pki/authorities/local` within the container.[^caddy]

### Risk mitigations / things to watch

- **Port 53 conflicts:** `scripts/doctor.sh` flags listeners such as `systemd-resolved` and recommends running the host helper.
- **UDP *and* TCP DNS:** dnsmasq listens on both transports per RFC 5966, and the doctor probes both query types.[^rfc5966]
- **Scope restriction:** `--local-service` keeps dnsmasq from answering requests routed in from outside the LAN.[^dnsmasq]
- **Android Private DNS:** Hostname mode bypasses LAN resolvers; leave it Off/Automatic when using `per-device` mode.[^android]

[^tplink]: [How to change DNS settings on TP-Link ISP-Customized Modems/Routers](https://www.tp-link.com/au/support/faq/4369/)
[^android]: [How to Enable Private DNS on Android Devices?](https://www.geeksforgeeks.org/android/how-to-enable-private-dns-on-android/)
[^rfc8375]: [RFC 8375 – Special-Use Domain 'home.arpa.'](https://datatracker.ietf.org/doc/html/rfc8375)
[^resolvconf]: [Why does /etc/resolv.conf point at 127.0.0.53?](https://unix.stackexchange.com/questions/612416/why-does-etc-resolv-conf-point-at-127-0-0-53)
[^caddy]: [Caddy documentation – Local PKI](https://caddyserver.com/docs/modules/pki)
[^rfc5966]: [RFC 5966 – DNS Transport over TCP](https://www.rfc-editor.org/rfc/rfc5966)
[^dnsmasq]: [dnsmasq(8) Manual](https://dnsmasq.org/docs/dnsmasq-man.html)

### First-time checklist
After `./arrstack.sh` (or `./arrstack.sh --yes` when automating) finishes:

1. **Change the qBittorrent password.** Log in with the credentials stored in `.env` (`QBT_USER`/`QBT_PASS`), update them in Settings → WebUI, then mirror the new values in `.env`.
2. **Rotate the Caddy Basic Auth credentials.** Run `./arrstack.sh --rotate-caddy-auth` (or set `FORCE_REGEN_CADDY_AUTH=1 ./arrstack.sh --yes`) to mint a fresh username/password pair. The plaintext is written to `${ARR_DOCKER_DIR}/caddy/credentials`, and the bcrypt hash is saved to `.env`. Prefer manual control? You can still generate a hash yourself with `docker run --rm caddy caddy hash-password --plaintext 'yourpass'` and update `.env` accordingly.
3. **Decide how LAN DNS resolves the stack.** Leave `ENABLE_LOCAL_DNS=1`, pick `DNS_DISTRIBUTION_MODE=router` to advertise `${LAN_IP}` via DHCP, or choose `per-device` and configure key clients manually (see [LAN DNS options](#-lan-dns-choose-one-set-in-dns_distribution_mode)). Disabling local DNS still works—add `/etc/hosts` entries that map each service (`qbittorrent.${CADDY_DOMAIN_SUFFIX}`, `sonarr.${CADDY_DOMAIN_SUFFIX}`, etc.) to `LAN_IP`.
4. **Set a fixed `LAN_IP`.** Edit `arrconf/userconf.sh` if the summary warned about `0.0.0.0` exposure.
5. **Reload aliases.** Run `./arrstack.sh --refresh-aliases` to regenerate the helper file and reload your shell (or `source ${ARR_STACK_DIR}/.arraliases` manually) to gain `arr.vpn.status`, `arr.help`, `arr.logs`, and other useful aliased quick commands.
6. **Verify VPN status.** `docker logs gluetun --tail 100` should show a healthy tunnel and forwarded port.
7. **Review version guidance when upgrading.** Refer to [docs/VERSION_MANAGEMENT.md](docs/VERSION_MANAGEMENT.md) for image pinning strategy and manual upgrade steps.

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
`arrstack.sh` renders `.env` from `arrconf/userconf.defaults.sh` plus any overrides you place in `arrconf/userconf.sh`. Copy `arrconf/userconf.sh.example` and adjust the variables relevant to your environment—then rerun `./arrstack.sh` so Docker Compose picks up the changes.

#### Paths & storage
| Variable | Default | Purpose |
| --- | --- | --- |
| `ARR_BASE` | `~/srv` | Root directory that holds the generated stack. |
| `ARR_STACK_DIR` | `${ARR_BASE}/arrstack` | Location of the compose file, scripts, and helper aliases. |
| `ARR_ENV_FILE` | `${ARR_STACK_DIR}/.env` | Rendered secrets/environment file. |
| `ARR_DOCKER_DIR` | `${ARR_BASE}/docker-data` | Docker volumes and persistent application data. |
| `ARRCONF_DIR` | `<repo>/arrconf` | Proton credential directory (move it outside the repo if you prefer). |
| `DOWNLOADS_DIR` | `${HOME}/Downloads` | Active qBittorrent download folder. |
| `COMPLETED_DIR` | `${DOWNLOADS_DIR}/completed` | Destination for completed downloads. |
| `MEDIA_DIR` | `/media/mediasmb` | Root of the media library. |
| `TV_DIR` | `${MEDIA_DIR}/Shows` | Sonarr library path. |
| `MOVIES_DIR` | `${MEDIA_DIR}/Movies` | Radarr library path. |
| `SUBS_DIR` | *(unset)* | Optional Bazarr subtitles directory (leave empty to disable). |

#### Identity & permissions
| Variable | Default | Purpose |
| --- | --- | --- |
| `PUID` / `PGID` | Current user/group IDs | Container processes run as this user so downloads inherit the right permissions. |
| `TIMEZONE` | `Australia/Sydney` | Controls cron schedules and timestamps inside the containers. |
| `ARR_PERMISSION_PROFILE` | `strict` | `strict` keeps secrets at `600/700`; `collaborative` relaxes non-secret files/dirs to `640/750`. |

#### Networking & DNS
| Variable | Default | Purpose |
| --- | --- | --- |
| `LAN_IP` | `0.0.0.0` (auto-detected) | Bind services to a specific LAN interface instead of all addresses. |
| `LOCALHOST_IP` | `127.0.0.1` | Loopback used by the Gluetun control API. |
| `LAN_DOMAIN_SUFFIX` | `home.arpa` | Suffix used for generated hostnames and optional local DNS records. |
| `CADDY_DOMAIN_SUFFIX` | `LAN_DOMAIN_SUFFIX` | Override just the Caddy hostname suffix if you diverge from LAN DNS. |
| `ENABLE_LOCAL_DNS` | `1` | Turn the bundled dnsmasq container on/off. |
| `DNS_DISTRIBUTION_MODE` | `router` | Document how clients learn `${LAN_IP}` (`router` DHCP Option 6 vs `per-device`). |
| `UPSTREAM_DNS_1` / `UPSTREAM_DNS_2` | `1.1.1.1` / `1.0.0.1` | Public resolvers local DNS forwards to. |
| `CADDY_LAN_CIDRS` | `127.0.0.1/32,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16` | Networks allowed to bypass Caddy Basic Auth. |
| `GLUETUN_CONTROL_PORT` | `8000` | Host port that exposes the Gluetun HTTP control server. |
| `SERVER_COUNTRIES` | `Switzerland,…,Netherlands` | ProtonVPN exit countries Gluetun rotates through. |
| `PVPN_ROTATE_COUNTRIES` | `SERVER_COUNTRIES` | Override the rotation order used by `arr.vpn.switch`. |
| `EXPOSE_DIRECT_PORTS` | `0` | Publish application ports directly on the LAN alongside Caddy for troubleshooting. |

#### Credentials & security
| Variable | Default | Purpose |
| --- | --- | --- |
| `GLUETUN_API_KEY` | *(generated)* | API key for Gluetun’s control server (auto-generated when blank). |
| `QBT_USER` / `QBT_PASS` | `admin` / `adminadmin` | Initial qBittorrent credentials—change them after first login. |
| `QBT_DOCKER_MODS` | `ghcr.io/vuetorrent/vuetorrent-lsio-mod:latest` | Alternate WebUI image injected into the qBittorrent container. |
| `QBT_AUTH_WHITELIST` | `127.0.0.1/8,::1/128` | CIDRs allowed to skip the qBittorrent login prompt. |
| `CADDY_BASIC_AUTH_USER` | `user` | Username non-LAN clients must supply to reach services via Caddy. |
| `CADDY_BASIC_AUTH_HASH` | *(generated)* | Bcrypt hash stored in `.env`; leave empty to rotate credentials automatically. |

#### Service ports
| Variable | Default | Purpose |
| --- | --- | --- |
| `QBT_HTTP_PORT_HOST` | `8080` | qBittorrent WebUI port exposed on the LAN. |
| `SONARR_PORT` | `8989` | Sonarr WebUI port. |
| `RADARR_PORT` | `7878` | Radarr WebUI port. |
| `PROWLARR_PORT` | `9696` | Prowlarr WebUI port. |
| `BAZARR_PORT` | `6767` | Bazarr WebUI port. |
| `FLARESOLVERR_PORT` | `8191` | FlareSolverr service port. |

#### Container images
| Variable | Default |
| --- | --- |
| `GLUETUN_IMAGE` | `qmcgaw/gluetun:v3.39.1` |
| `QBITTORRENT_IMAGE` | `lscr.io/linuxserver/qbittorrent:5.1.2-r2-ls415` |
| `SONARR_IMAGE` | `lscr.io/linuxserver/sonarr:4.0.15.2941-ls291` |
| `RADARR_IMAGE` | `lscr.io/linuxserver/radarr:5.27.5.10198-ls283` |
| `PROWLARR_IMAGE` | `lscr.io/linuxserver/prowlarr:latest` |
| `BAZARR_IMAGE` | `lscr.io/linuxserver/bazarr:latest` |
| `FLARESOLVERR_IMAGE` | `ghcr.io/flaresolverr/flaresolverr:v3.3.21` |
| `CADDY_IMAGE` | `caddy:2.8.4` |

#### Behaviour toggles
| Variable | Default | Purpose |
| --- | --- | --- |
| `ASSUME_YES` | `0` | Skip confirmation prompts (equivalent to passing `--yes`). |
| `FORCE_ROTATE_API_KEY` | `0` | Force a new Gluetun API key on the next run. |
| `FORCE_REGEN_CADDY_AUTH` | `0` | Rotate the Caddy Basic Auth credentials on the next run. |
| `SETUP_HOST_DNS` | `0` | Trigger the host DNS takeover helper automatically (also available via `--setup-host-dns`). |
| `REFRESH_ALIASES` | `0` | Regenerate helper aliases and exit without running the full installer. |

### Service hostnames
Caddy is the primary entrypoint on the LAN, terminating HTTP/HTTPS on 80/443 and proxying to each application by hostname. When `local_dns` is enabled, dnsmasq already resolves each `<service>.${CADDY_DOMAIN_SUFFIX}` entry to `LAN_IP`; otherwise point your LAN DNS (or `/etc/hosts`) at the host manually. Enable `EXPOSE_DIRECT_PORTS=1` if you need Gluetun to expose each application on its native port (8080, 8989, 7878, 9696, 6767) as a fallback during troubleshooting.

| Service      | Hostname pattern | Internal port variable | Default port |
| ------------ | ---------------- | ---------------------- | ------------- |
| qBittorrent  | `qbittorrent.${CADDY_DOMAIN_SUFFIX}` | `QBT_HTTP_PORT_HOST` | `8080` |
| Sonarr       | `sonarr.${CADDY_DOMAIN_SUFFIX}` | `SONARR_PORT` | `8989` |
| Radarr       | `radarr.${CADDY_DOMAIN_SUFFIX}` | `RADARR_PORT` | `7878` |
| Prowlarr     | `prowlarr.${CADDY_DOMAIN_SUFFIX}` | `PROWLARR_PORT` | `9696` |
| Bazarr       | `bazarr.${CADDY_DOMAIN_SUFFIX}` | `BAZARR_PORT` | `6767` |
| FlareSolverr | `flaresolverr.${CADDY_DOMAIN_SUFFIX}` | `FLARESOLVERR_PORT` | `8191` |

If you reconfigure an application to listen on a different internal port, update the corresponding variable so Caddy continues routing correctly.

## Daily operations
The installer adds two aliases to `~/.bashrc` when possible:

```bash
arrstack       # rerun the installer from the repo
arrstack-logs  # follow Gluetun logs
source ${ARR_STACK_DIR:-/path/to/arrstack}/.arraliases  # load helper functions
```

The generated `.arraliases` file enables:

```bash
arr.help       # Show the full alias catalogue
arr.vpn.status # Inspect VPN status and forwarded port
arr.vpn.switch # Rotate Proton exit countries (or pick one explicitly)
arr.health     # Summarise container health checks
arr.open       # Print (or open) service URLs in your browser
```

The installer also drops `/gluetun/hooks/update-qbt-port.sh`, which Gluetun executes whenever Proton assigns a new port so qBittorrent's listen socket is updated immediately.

Manage the stack directly with Docker Compose commands from `${ARR_STACK_DIR}` if you prefer finer-grained control.

## Security posture
### Gluetun control API
The control server listens inside the VPN namespace and is published to the host at `${LOCALHOST_IP:-127.0.0.1}:${GLUETUN_CONTROL_PORT:-8000}`. It is forced to bind on IPv4 loopback to avoid `localhost` resolving to IPv6 and breaking the control client. API-key authentication is enforced via Gluetun's `HTTP_CONTROL_SERVER_AUTH=apikey` and `HTTP_CONTROL_SERVER_APIKEY=${GLUETUN_API_KEY}` environment variables. Legacy `/gluetun/auth/config.toml` files are removed automatically to avoid schema drift, so requests must include `X-API-Key: ${GLUETUN_API_KEY}` when calling the limited set of endpoints the stack uses (`/v1/publicip/ip`, `/v1/openvpn/status`, `/v1/forwardedport`, `/v1/openvpn/portforwarded`):

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
- `docker logs gluetun --tail 50 | grep update-qbt-port` shows the hook applying Proton's forwarded port to qBittorrent.
- Run `${ARR_STACK_DIR}/diagnose-vpn.sh` from the stack root to execute the autogenerated diagnostics (checks Gluetun health, validates the forwarded port, and restarts the VPN container when required).

## Troubleshooting
Refer to [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) for Proton port-forward validation, health check tips, and common fixes. If Docker reports `manifest unknown` for a LinuxServer image, run `${ARR_STACK_DIR}/scripts/fix-versions.sh` to back up `.env`, swap in safe fallbacks, and then re-run the installer.

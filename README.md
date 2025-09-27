# arrstack-mini

Self-host the *arr ecosystem on a Raspberry Pi 5 or any Debian Bookworm box with Proton VPN port forwarding. Designed for beginners who want a fast, reproducible home media stack.

> **Note:** `.env.example` is deprecated. Copy `arrconf/userr.conf.example` to `${ARR_BASE:-$HOME/srv}/userr.conf`, edit that file (along with `arrconf/proton.auth`), then rerun `./arrstack.sh` to regenerate everything. Do not modify `.env.example`; it will be removed in a future release.

## Prerequisites
- Raspberry Pi 5 (or similar 64-bit Debian Bookworm host) with static LAN IP, 4 CPU cores, 4 GB RAM.
- Proton VPN Plus or Unlimited account for port forwarding.
- Git, `curl`, `jq`, and `openssl` installed on the host.
- [Install Docker](https://docs.docker.com/engine/install/) and [Docker Compose](https://docs.docker.com/engine/install/#docker-compose-plugin) before running the stack.

On Debian Bookworm, install the command-line prerequisites non-interactively so `apt-get` never pauses for `debconf` prompts:

```bash
sudo DEBIAN_FRONTEND=noninteractive apt-get update -y
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends git curl jq openssl
```

## Quick start (about 5 minutes)
1. **Clone the repo.**
   ```bash
   mkdir -p ~/srv && cd ~/srv
   git clone https://github.com/cbkii/arrstackmini.git
   cd arrstackmini
   ```
2. **Copy Proton credentials.**
   ```bash
   cp arrconf/proton.auth.example arrconf/proton.auth
   nano arrconf/proton.auth  # set PROTON_USER / PROTON_PASS (+pmp is added automatically)
   ```
3. **Copy and edit user overrides.**
   ```bash
   cp arrconf/userr.conf.example ../userr.conf
   nano ../userr.conf  # set LAN_IP, media paths, and any overrides
   ```
   Keep this file at `${ARR_BASE:-$HOME/srv}/userr.conf`; the installer regenerates `.env` and other artifacts from it each run.
4. **Optional toggles.** Edit `${ARR_BASE:-$HOME/srv}/userr.conf` to set `ENABLE_CADDY=1` (EXPERIMENTAL), `ENABLE_LOCAL_DNS=1` (EXPERIMENTAL), or `ENABLE_CONFIGARR=0/1` before running the stack (or pass `./arrstack.sh --enable-caddy` for a one-off enable).
5. **Run the installer.**
   ```bash
   ./arrstack.sh        # add --yes for non-interactive mode
   ```
   This idempotently installs prerequisites, renders `.env`, `docker-compose.yml`, and `Caddyfile`, and launches the stack—rerun it anytime instead of editing generated files.
6. **Load helper aliases.**
   ```bash
   source "${ARR_STACK_DIR:-$(pwd)}/.aliasarr"
   ```
   Reload after each installer run so commands like `arr.vpn.status` and `arr.logs` stay current.
7. **Check health.** Use `arr.vpn.status` and `arr.logs` to confirm services booted, and browse to `http://LAN_IP:PORT` dashboards to verify connectivity.
8. **Grab the qBittorrent temporary password.** If still on defaults, run `docker logs qbittorrent | grep 'temporary password'` and reset it via the WebUI immediately.
9. **Optional HTTPS/DNS extras.** Install the internal CA with `scripts/install-caddy-ca.sh` or take over host DNS via `./arrstack.sh --setup-host-dns` (**CAUTION:** modifies resolver; roll back with `scripts/host-dns-rollback.sh`).

### Configuration flow
- **Defaults:** `arrconf/userr.conf.defaults.sh`
- **User overrides:** `${ARR_BASE:-$HOME/srv}/userr.conf`
- **Proton credentials:** `arrconf/proton.auth` (`PROTON_USER` / `PROTON_PASS`; `+pmp` is enforced automatically)
- **Run `./arrstack.sh`:** renders `.env`, `docker-compose.yml`, and `Caddyfile` (never edit the generated files directly)
- **Safe to rerun anytime:** the installer is idempotent and reconciles changes back into the stack

> Generated files: `.env`, `docker-compose.yml`, and `Caddyfile`. Edit `${ARR_BASE:-$HOME/srv}/userr.conf` instead, then rerun `./arrstack.sh` to apply changes.

### Core services vs optional extras
- **Core:** gluetun, qbittorrent, sonarr, radarr, prowlarr, bazarr, flaresolverr
- **Optional:** Caddy (`ENABLE_CADDY=1`) — EXPERIMENTAL, Local DNS (`ENABLE_LOCAL_DNS=1`) — EXPERIMENTAL, Configarr, VueTorrent (LSIO mod or manual fallback)

Caddy reverse proxy and Local DNS are **EXPERIMENTAL / in development** and may change or break. Enable them only if you need internal HTTPS hostnames or LAN DNS integration. Local DNS auto-disables when port 53 is already claimed (for example by `systemd-resolved`).

### Security notes
- Set `LAN_IP` to your host address so services avoid binding to `0.0.0.0` unintentionally.
- Proton logins automatically append `+pmp`; never remove it or the forwarded port will fail.
- The Gluetun control API is bound to `LOCALHOST_IP` to keep VPN management local.
- Keep `EXPOSE_DIRECT_PORTS=0` unless you intentionally publish raw service ports.
- Caddy basic-auth secrets live in `docker-data/caddy/credentials`; rotate them periodically.
- Install the internal CA before trusting HTTPS hostnames issued by Caddy.

> ⚠️ Do not expose these services directly to the public internet without additional hardening, a proxy, and authentication layers.

### VueTorrent WebUI modes

VueTorrent is delivered through the LSIO mod by default; the installer auto-attempts a manual fallback when `QBT_DOCKER_MODS` is unset and warns in the summary if the manual files are incomplete.

- **Default (LSIO mod):** `QBT_DOCKER_MODS` defaults to the VueTorrent LSIO Docker mod so `/vuetorrent` is provisioned automatically inside the container. Leave the value in `${ARR_BASE}/userr.conf` and rerun `./arrstack.sh` to stay on this mode.
- **Manual install:** Clear `QBT_DOCKER_MODS`, rerun `./arrstack.sh`, and the installer downloads VueTorrent into `/config/vuetorrent`, verifies `public/index.html` and `version.txt`, and points qBittorrent at that folder.
- **Switch safely:** Changing `QBT_DOCKER_MODS` and rerunning the installer flips modes idempotently. The script rewrites qBittorrent’s `WebUI\RootFolder`, removes stale manual files when the mod is active, and disables the Alternate WebUI if the manual folder is incomplete so the default qBittorrent UI still loads.
- **Do not mix:** Avoid copying VueTorrent files by hand once the installer runs. Update `QBT_DOCKER_MODS` instead so the scripts keep qBittorrent aligned with the chosen mode.

## Common tasks
- `./arrstack.sh --rotate-api-key` regenerates the Gluetun API key and writes it back to `.env`.
- `./arrstack.sh --rotate-caddy-auth` rotates the Caddy basic-auth credentials and stores the cleartext copy in `docker-data/caddy/credentials`.
- `./arrstack.sh --refresh-aliases` rebuilds `.aliasarr` so helpers like `arr.vpn.status`, `arr.vpn.port`, and `arr.logs` stay current.
- `./arrstack.sh --setup-host-dns` takes over the host resolver (**CAUTION:** modifies `/etc/resolv.conf`; undo with `scripts/host-dns-rollback.sh`).
- `arr.vpn.port` or `arr.vpn.status` confirms Proton forwarding and overall VPN health.
- `arr.config.sync` triggers Configarr to refresh Sonarr/Radarr settings after updating API keys in `docker-data/configarr/secrets.yml`.
- `./scripts/qbt-helper.sh {show|reset|whitelist}` inspects or resets qBittorrent credentials and LAN access rules.
- `./scripts/doctor.sh` reruns the LAN DNS and port diagnostics the installer executes automatically.

## Troubleshooting
- **Port conflicts:** rerun `./arrstack.sh` without `--yes` to use the interactive resolver and unblock the offending service.
- **Local DNS auto-disabled:** port 53 was already bound (commonly by `systemd-resolved`); free it or leave `ENABLE_LOCAL_DNS=0`.
- **Caddy hostnames untrusted:** download `http://ca.<suffix>/root.crt` or run `scripts/install-caddy-ca.sh` to trust the internal CA.
- **qBittorrent password unknown:** `docker logs qbittorrent | grep 'temporary password'` prints the autogenerated secret.
- **Proton forwarded port reports 0:** wait a few minutes, run `arr.vpn.port.sync`, and optionally pin `SERVER_COUNTRIES` in `${ARR_BASE:-$HOME/srv}/userr.conf`.
- **Configarr changes not applying:** populate API keys in `docker-data/configarr/secrets.yml` and rerun `arr.config.sync`.

## Configarr (TRaSH-Guides Sync)

Configarr runs as a one-shot helper to import TRaSH-Guides quality definitions, profiles, and custom formats into Sonarr v4 and Radarr v5. It is enabled by default; set `ENABLE_CONFIGARR=0` in `${ARR_BASE}/userr.conf` to omit the container on the next install run. Run Configarr only after Sonarr and Radarr have completed their first boot and database migrations.

- The installer seeds `docker-data/configarr/config.yml` with the default TRaSH-Guides templates and creates `docker-data/configarr/secrets.yml` with placeholder API keys. Populate that secrets file (or swap to `!env` in `config.yml`) before syncing.
- Trigger a manual sync with `arr.config.sync` (added to `.aliasarr` when Configarr is enabled) or directly via `docker compose run --rm configarr` from the stack directory. The container exits after a single run.
- To schedule recurring updates on the host, add a cron entry such as:<br>`10 3 * * SUN cd /path/to/arrstack && docker compose run --rm configarr >> logs/configarr-sync.log 2>&1`
- Local custom formats can be stored in `docker-data/configarr/cfs` and referenced from `config.yml` as needed.
- Update `CONFIGARR_IMAGE` in `${ARR_BASE}/userr.conf` if you want to pin a specific Configarr image tag (the installer writes the generated `.env`).

### Configarr policy (1080p-focused baseline)

Arrstack seeds Configarr with a conservative WEB/Bluray 720p–1080p window, MB/minute caps, and optional language/junk reinforcements:

- Size guardrails: Sonarr & Radarr quality definitions are clamped to the derived per-minute ceiling (default `ARR_EP_MAX_GB=5` over `ARR_TV_RUNTIME_MIN=45`).
- Language bias: opt-in penalties for non-English or multi-audio releases, plus optional x265 discouragement for HD tiers.
- Junk filters: stronger negative scores for LQ, Microsized/Upscaled, and other noisy releases when `ARR_STRICT_JUNK_BLOCK=1`.
- Local overrides live under `docker-data/configarr/cfs/` so advanced users can edit YAML directly; deleting a file lets the installer regenerate it on the next run.

**Limitations**

- Sonarr does not expose a true season-level size cap; `ARR_SEASON_MAX_GB` is informational only.
- Radarr guardrails reuse the same MB/minute heuristic—double-check before applying to large remux libraries.
- Negative scores influence import priority but cannot completely block releases if nothing else matches.

**Tweaking the policy**

1. Adjust the variables below in `${ARR_BASE}/userr.conf` (the installer regenerates `.env`).
2. Re-run the installer or `arr.config.sync` to apply regenerated templates.
3. Review `/docker-data/configarr/cfs/` to ensure no manual edits were overwritten.

| Variable | Default | Purpose |
| --- | --- | --- |
| `ARR_VIDEO_MIN_RES` / `ARR_VIDEO_MAX_RES` | `720p` / `1080p` | Lowest/highest qualities referenced in local overrides. |
| `ARR_EP_MAX_GB` | `5` | Single-episode size ceiling; drives the MB/minute maximum. |
| `ARR_EP_MIN_MB` | `250` | Lower bound used to compute the MB/minute minimum. |
| `ARR_TV_RUNTIME_MIN` | `45` | Expected runtime (minutes) when deriving MB/minute caps. |
| `ARR_SEASON_MAX_GB` | `30` | Informational season target shown in the summary. |
| `ARR_ENGLISH_ONLY` | `1` | Reinforce English-only scoring (penalises non-English releases). |
| `ARR_DISCOURAGE_MULTI` | `1` | Apply a score penalty to multi-audio releases. |
| `ARR_PENALIZE_HD_X265` | `1` | Apply a mild negative score to HD x265 encodes. |
| `ARR_STRICT_JUNK_BLOCK` | `1` | Enable LQ/Upscaled negative reinforcements. |
| `ARR_JUNK_NEGATIVE_SCORE` | `-1000` | Score applied to LQ/Upscaled CFs when strict junk blocking is enabled. |
| `ARR_MULTI_NEGATIVE_SCORE` | `-50` | Score applied to MULTi releases when discouraged. |
| `ARR_X265_HD_NEGATIVE_SCORE` | `-200` | Score applied to HD x265 releases when penalised. |
| `ARR_ENGLISH_POSITIVE_SCORE` | `50` | Magnitude of the language penalty (converted to a negative score for “Not English”). |
| `ARR_MBMIN_DECIMALS` | `1` | Decimal precision used when rounding the MB/minute limits. |
| `ARR_LANG_PRIMARY` | `en` | Informational primary language shown in the summary. |
| `SONARR_TRASH_TEMPLATE` | `sonarr-v4-quality-profile-web-1080p` | Base TRaSH Sonarr quality profile template. |
| `RADARR_TRASH_TEMPLATE` | `radarr-v5-quality-profile-hd-bluray-web` | Base TRaSH Radarr quality profile template. |


## Permission profiles
`ARR_PERMISSION_PROFILE=strict` is the default (secret files `600`, data directories `700`); switch to `collab` for group write access (`770`) when `PGID` is non-root, and reference the defaults file for override knobs.
`arrstack.sh` defaults to the **strict** permission profile so secrets stay private (files `600`, data directories `700`, umask `0077`). Switch to the **collab** profile when you run multiple media managers, SMB/NFS shares, or post-processing scripts that need to write into the stack:

- Set `ARR_PERMISSION_PROFILE="collab"` in `${ARR_BASE}/userr.conf`.
- Choose a `PGID` that represents your shared media group (for example `getent group media`). The installer uses that group when applying permissions so secondary users can write downloads and libraries.
- Collab enables group read/write by default (`umask 0007`, directories `770`, files `660`). Secret files (`.env`, `userr.conf`, Proton credentials) remain `600`.
- If you leave `PGID=0` (root group) the installer warns and keeps the safer `750/640` defaults instead of exposing write access to every root user.

Advanced operators can override the profile defaults with environment variables before launching the installer:

| Variable | Purpose |
| --- | --- |
| `ARR_UMASK_OVERRIDE` | Force a specific umask (octal such as `0007`). |
| `ARR_DATA_DIR_MODE_OVERRIDE` | Override directory mode for stack data (`770`, `755`, etc.). |
| `ARR_NONSECRET_FILE_MODE_OVERRIDE` | Override non-secret file mode (defaults to `660` for collab). |
| `ARR_SECRET_FILE_MODE_OVERRIDE` | Override secret file mode (defaults to `600`). |

Overrides apply after the profile loads, so you can fine-tune behaviour per environment while keeping the docs/examples aligned with the defaults.

## Docs
- [LAN DNS & network pre-start](docs/lan-dns-network-setup.md)
- [Host DNS helper](docs/host-dns-helper.md)
- [Local HTTPS and CA trust](docs/https-and-ca.md)
- [Service overview](docs/services.md)
- [Script reference](docs/script-reference.md)
- [Config reference](docs/config.md)
- [Security notes](docs/security-notes.md)
- [FAQ](docs/faq.md)
- [Glossary](docs/glossary.md)
- [Version management](docs/VERSION_MANAGEMENT.md)

## Need help?
Start with [Troubleshooting](docs/troubleshooting.md) for quick fixes, then review the other docs above if the issue persists.

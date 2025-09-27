# arrstack-mini

Self-host the *arr ecosystem on a Raspberry Pi 5 or any Debian Bookworm box with Proton VPN port forwarding. Designed for beginners who want a fast, reproducible home media stack.

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
1. **Clone the repo into your projects directory.**
   ```bash
   mkdir -p ~/srv && cd ~/srv
   git clone https://github.com/cbkii/arrstackmini.git
   cd arrstackmini
   ```
2. **Copy the user config template.** This stores your overrides at `${ARR_BASE}/userr.conf` (defaults to `~/srv/userr.conf`).
  ```bash
  cp arrconf/userr.conf.example ../userr.conf
  ```
3. **Set your LAN details.** Edit `~/srv/userr.conf` (or `${ARR_BASE}/userr.conf` if you exported a different base) and set `LAN_IP` to your Pi (example `192.168.1.50`). Reserve that address in your router so it never changes. Leave `LAN_DOMAIN_SUFFIX` blank unless you plan to enable the optional DNS/proxy features later.
4. **Add Proton credentials.**
   ```bash
   cp arrconf/proton.auth.example arrconf/proton.auth
   nano arrconf/proton.auth
   ```
5. **Run the installer.**
   ```bash
   ./arrstack.sh --yes
   ```
   The script installs dependencies if needed, renders `${ARR_STACK_DIR}/.env` (default `~/srv/arrstack/.env`), and launches the stack with Docker Compose from that directory.
   Compose reads that `.env` automatically per [Docker’s env-file guidance](https://docs.docker.com/compose/environment-variables/set-environment-variables/#use-the-env-file).
6. **Open the WebUIs directly by IP.** As soon as the installer finishes, browse to each service using your Pi’s LAN IP (example `192.168.1.50`). The installer refuses to expose ports until `LAN_IP` is a private address, so set the value and re-run if you skipped it the first time:
   - `http://192.168.1.50:8080` (qBittorrent)
   - `http://192.168.1.50:8989` (Sonarr)
   - `http://192.168.1.50:7878` (Radarr)
   - `http://192.168.1.50:9696` (Prowlarr)
   - `http://192.168.1.50:6767` (Bazarr)
   - `http://192.168.1.50:8191` (FlareSolverr health page)
   The default qBittorrent credentials are `admin` / `adminadmin` — change them immediately.
7. **(Optional) Enable extras later.** Either set `ENABLE_CADDY=1` (or run `./arrstack.sh --enable-caddy`) for HTTPS reverse proxying, or set `ENABLE_LOCAL_DNS=1` for dnsmasq, then rerun `./arrstack.sh`. Using DNS alone keeps the apps on plain `http://LAN_IP:PORT`, so enable Caddy only when you want hostname-based HTTPS. The defaults keep both disabled so IP:PORT access works everywhere without touching your router.

**Verify:**
```bash
curl -I http://192.168.1.50:8080
```
You should see an HTTP 200/302 response. If not, re-run the installer and confirm `LAN_IP` matches the host you’re testing from.

### VueTorrent WebUI modes

- **Default (LSIO mod):** `QBT_DOCKER_MODS` defaults to the VueTorrent LSIO Docker mod so `/vuetorrent` is provisioned automatically inside the container. Leave the value in `.env`/`userr.conf` to stay on this mode.
- **Manual install:** Clear `QBT_DOCKER_MODS`, rerun `./arrstack.sh`, and the installer downloads VueTorrent into `/config/vuetorrent`, verifies `public/index.html` and `version.txt`, and points qBittorrent at that folder.
- **Switch safely:** Changing `QBT_DOCKER_MODS` and rerunning the installer flips modes idempotently. The script rewrites qBittorrent’s `WebUI\RootFolder`, removes stale manual files when the mod is active, and disables the Alternate WebUI if the manual folder is incomplete so the default qBittorrent UI still loads.
- **Do not mix:** Avoid copying VueTorrent files by hand once the installer runs. Update `QBT_DOCKER_MODS` instead so the scripts keep qBittorrent aligned with the chosen mode.

## Useful commands
- `./arrstack.sh --rotate-api-key --yes` regenerates the Gluetun API key and writes it back to `.env`.
- `./arrstack.sh --rotate-caddy-auth --yes` creates a new Caddy basic-auth password and saves the plaintext copy in `docker-data/caddy/credentials`.
- `./arrstack.sh --setup-host-dns --yes` runs the host helper so Debian Bookworm frees port 53 before the installer exits.
- `./arrstack.sh --refresh-aliases` rebuilds `.aliasarr` and reloads your shell so helper commands (such as `arr.vpn status`) stay up to date.
- `./scripts/qbt-helper.sh {show|reset|whitelist}` shows connection info, clears the qBittorrent password, or enables LAN whitelisting.
- `./scripts/doctor.sh` performs the same LAN DNS and port checks the installer runs automatically; re-run it when troubleshooting.
- `ARRSTACK_DEBUG_PORTS=1 ./arrstack.sh` writes `logs/port-scan-*.jsonl` snapshots for each port check so you can diagnose who bound a port.

## Permission profiles
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

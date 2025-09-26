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
2. **Copy the user config template.**
   ```bash
   cp arrconf/userconf.sh.example arrconf/userconf.sh
   ```
3. **Set your LAN details.** Edit `arrconf/userconf.sh` and set `LAN_IP` to your Pi (example `192.168.1.50`). Reserve that address in your router so it never changes. Leave `LAN_DOMAIN_SUFFIX` blank unless you plan to enable the optional DNS/proxy features later.
4. **Add Proton credentials.**
   ```bash
   cp arrconf/proton.auth.example arrconf/proton.auth
   nano arrconf/proton.auth
   ```
5. **Run the installer.**
   ```bash
   ./arrstack.sh --yes
   ```
   The script installs dependencies if needed, renders `.env`, and launches the stack with Docker Compose.
   Compose reads `.env` automatically per [Docker’s env-file guidance](https://docs.docker.com/compose/environment-variables/set-environment-variables/#use-the-env-file).
6. **Open the WebUIs directly by IP.** As soon as the installer finishes, browse to each service using your Pi’s LAN IP (example `192.168.1.50`). The installer refuses to expose ports until `LAN_IP` is a private address, so set the value and re-run if you skipped it the first time:
   - `http://192.168.1.50:8080` (qBittorrent)
   - `http://192.168.1.50:8989` (Sonarr)
   - `http://192.168.1.50:7878` (Radarr)
   - `http://192.168.1.50:9696` (Prowlarr)
   - `http://192.168.1.50:6767` (Bazarr)
   - `http://192.168.1.50:8191` (FlareSolverr health page)
   The default qBittorrent credentials are `admin` / `adminadmin` — change them immediately.
7. **(Optional) Enable extras later.** Set `ENABLE_CADDY=1` for HTTPS reverse proxying (Caddy issues its own LAN certificates) or `ENABLE_LOCAL_DNS=1` for dnsmasq, then rerun `./arrstack.sh`. Using DNS alone keeps the apps on plain `http://LAN_IP:PORT`, so enable Caddy only when you want hostname-based HTTPS. The defaults keep both disabled so IP:PORT access works everywhere without touching your router.

**Verify:**
```bash
curl -I http://192.168.1.50:8080
```
You should see an HTTP 200/302 response. If not, re-run the installer and confirm `LAN_IP` matches the host you’re testing from.

## Useful commands
- `./arrstack.sh --rotate-api-key --yes` regenerates the Gluetun API key and writes it back to `.env`.
- `./arrstack.sh --rotate-caddy-auth --yes` creates a new Caddy basic-auth password and saves the plaintext copy in `docker-data/caddy/credentials`.
- `./arrstack.sh --setup-host-dns --yes` runs the host helper so Debian Bookworm frees port 53 before the installer exits.
- `./arrstack.sh --refresh-aliases` rebuilds `.arraliases` and reloads your shell so helper commands (such as `arr.vpn status`) stay up to date.
- `./scripts/qbt-helper.sh {show|reset|whitelist}` shows connection info, clears the qBittorrent password, or enables LAN whitelisting.
- `./scripts/doctor.sh` performs the same LAN DNS and port checks the installer runs automatically; re-run it when troubleshooting.
- `ARRSTACK_DEBUG_PORTS=1 ./arrstack.sh` writes `logs/port-scan-*.jsonl` snapshots for each port check so you can diagnose who bound a port.

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

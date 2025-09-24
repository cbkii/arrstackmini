# arrstack-mini

Self-host the *arr ecosystem on a Raspberry Pi 5 or any Debian Bookworm box with Proton VPN port forwarding. Designed for beginners who want a fast, reproducible home media stack.

## Prerequisites
- Raspberry Pi 5 (or similar 64-bit Debian Bookworm host) with static LAN IP, 4 CPU cores, 4 GB RAM.
- Proton VPN Plus or Unlimited account for port forwarding.
- Git, `curl`, `jq`, and `openssl` installed on the host.
- [Install Docker](https://docs.docker.com/engine/install/) and [Docker Compose](https://docs.docker.com/engine/install/#dockers-compose-plugin) before running the stack.

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
3. **Set your LAN details.** Edit `arrconf/userconf.sh` and set `LAN_IP` to your Pi (example `192.168.1.50`). Keep `LAN_DOMAIN_SUFFIX=home.arpa` unless you already use another private suffix.
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
6. **If you run Debian Bookworm, free port 53 for dnsmasq.**
   ```bash
   ./scripts/host-dns-setup.sh
   ```
7. **Choose how clients learn the DNS server.** Follow [LAN DNS distribution](docs/lan-dns.md) to configure router DHCP or per-device DNS.
8. **Open qBittorrent to confirm access.** Visit `https://qbittorrent.home.arpa` (replace the suffix if you changed it) and change the default password.

**Verify:**
```bash
dig @192.168.1.50 qbittorrent.home.arpa
```
You should see the Pi’s IP in the answer. If not, revisit steps 6–7.

## Useful commands
- `./arrstack.sh --rotate-api-key --yes` regenerates the Gluetun API key and writes it back to `.env`.
- `./arrstack.sh --rotate-caddy-auth --yes` creates a new Caddy basic-auth password and saves the plaintext copy in `docker-data/caddy/credentials`.
- `./arrstack.sh --setup-host-dns --yes` runs the host helper so Debian Bookworm frees port 53 before the installer exits.
- `./arrstack.sh --refresh-aliases` rebuilds `.arraliases` and reloads your shell so helper commands (such as `arr.vpn status`) stay up to date.
- `./scripts/qbt-helper.sh {show|reset|whitelist}` shows connection info, clears the qBittorrent password, or enables LAN whitelisting.
- `./scripts/doctor.sh` performs the same LAN DNS and port checks the installer runs automatically; re-run it when troubleshooting.

## Docs
- [LAN DNS distribution](docs/lan-dns.md)
- [Host DNS helper](docs/host-dns-helper.md)
- [Local HTTPS and CA trust](docs/https-and-ca.md)
- [Service overview](docs/services.md)
- [Script reference](docs/script-reference.md)
- [Config reference](docs/config.md)
- [Router configuration examples](docs/router-examples.md)
- [Security notes](docs/security-notes.md)
- [FAQ](docs/faq.md)
- [Glossary](docs/glossary.md)
- [Version management](docs/VERSION_MANAGEMENT.md)

## Need help?
Start with [Troubleshooting](docs/troubleshooting.md) for quick fixes, then review the other docs above if the issue persists.

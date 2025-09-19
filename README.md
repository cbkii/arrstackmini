# arrstack-mini (Raspberry Pi 5 / Debian Bookworm)

Minimal, reproducible ARR stack routed via Gluetun (ProtonVPN). One command brings up:

- Gluetun (Proton OpenVPN with native port-forwarding)
- qBittorrent (WebUI + Vuetorrent-compatible)
- Sonarr, Radarr, Prowlarr, Bazarr
- FlareSolverr

LAN‑only exposure by default; *arr + qBittorrent egress through Gluetun namespace.

## Requirements
- Raspberry Pi 5, Debian Bookworm
- Docker Engine & Compose v2 (`sudo apt-get install docker.io docker-compose-plugin`)
- ProtonVPN Plus/Unlimited

## Quick start

### OpenVPN (with port forwarding)
```bash
mkdir -p arrconf docker-data
cat > arrconf/proton.auth <<'EOF'
PROTON_USER=your_proton_username
PROTON_PASS=your_proton_password
EOF
chmod 600 arrconf/proton.auth

# Optional: pin server countries in .env (comma separated)
cp .env.example .env && sed -i 's/^SERVER_COUNTRIES=.*/SERVER_COUNTRIES=Netherlands,Germany,Switzerland/' .env

# Non-interactive install
./arrstack.sh --yes
```

### Service ports on your LAN IP (configurable via `.env`)
```
qBittorrent : http://${LAN_IP:=0.0.0.0}:${QBT_HTTP_PORT_HOST:=8081} (container ${QBT_HTTP_PORT_CONTAINER:=8080})
Sonarr      : http://${LAN_IP:=0.0.0.0}:${SONARR_PORT:=8989}
Radarr      : http://${LAN_IP:=0.0.0.0}:${RADARR_PORT:=7878}
Prowlarr    : http://${LAN_IP:=0.0.0.0}:${PROWLARR_PORT:=9696}
Bazarr      : http://${LAN_IP:=0.0.0.0}:${BAZARR_PORT:=6767}
FlareSolverr: http://${LAN_IP:=0.0.0.0}:${FLARESOLVERR_PORT:=8191}
```

Defaults are shown in `.env.example`. Set `LAN_IP` in `arrconf/userconf.sh` to bind to a single RFC1918 address.

## Security
- Gluetun control API bound via `${GLUETUN_CONTROL_HOST:=127.0.0.1}:${GLUETUN_CONTROL_PORT:=8000}` with RBAC (basic auth; random API key).
- Health probes and forwarded port sync stay inside the shared namespace via `${GLUETUN_LOOPBACK_HOST:=127.0.0.1}`.
- Secrets never printed to console; on disk files are `0600`, dirs `0700`.
- Only LAN ports are published; no public exposure by default.

## Operations
```bash
# Start/stop
arr.up        # docker compose up -d
arr.down      # docker compose down
arr.logs      # follow logs
pvpn.status   # public IP + forwarded port (OpenVPN)
qbt.port.sync # re-apply forwarded port to qBittorrent
```

## Troubleshooting
See [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) for PF checks, health checks, and common fixes.

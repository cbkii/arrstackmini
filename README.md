# arrstack-mini (Raspberry Pi 5 / Debian Bookworm)

Minimal, reproducible ARR stack routed via Gluetun (ProtonVPN). One command brings up:

- Gluetun (Proton, OpenVPN with native port‑forwarding; optional WireGuard w/o PF)
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

# Non‑interactive install
./arrstack.sh --openvpn --yes
```

### WireGuard (no port forwarding)
```bash
# Place your Proton WireGuard config (proton.conf) into arrconf/
cp ~/Downloads/proton.conf arrconf/
chmod 600 arrconf/proton.conf
./arrstack.sh --wireguard --yes
```

### Default service ports on your LAN IP
```
qBittorrent : http://$LAN_IP:8081
Sonarr      : http://$LAN_IP:8989
Radarr      : http://$LAN_IP:7878
Prowlarr    : http://$LAN_IP:9696
Bazarr      : http://$LAN_IP:6767
FlareSolverr: http://$LAN_IP:8191
```

> Set `LAN_IP` in `arrconf/userconf.sh` to bind to a single RFC1918 address.

## Security
- Gluetun control API bound to `127.0.0.1` with RBAC (basic auth; random API key).
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

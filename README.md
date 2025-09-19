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
**Control API**

The Gluetun control server runs inside the VPN namespace on
`${GLUETUN_CONTROL_LISTEN_IP:=0.0.0.0}:${GLUETUN_CONTROL_PORT:=8000}` and is
published to the host as `${GLUETUN_CONTROL_HOST:=127.0.0.1}`. The generator
enforces API-key-only auth:

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

**Firewall variables**

- `GLUETUN_LAN_INPUT_PORTS` → passed to `FIREWALL_INPUT_PORTS` (host/LAN
  access into the Gluetun container).
- `GLUETUN_VPN_INPUT_PORTS` → passed to `FIREWALL_VPN_INPUT_PORTS` (VPN
  provider forwarded ingress only).
- Scope exposure via `${GLUETUN_CONTROL_HOST}`: `127.0.0.1` keeps the control
  API loopback-only; `0.0.0.0` opens it to all interfaces.

- Health probes and forwarded port sync stay inside the shared namespace via
  `${GLUETUN_LOOPBACK_HOST:=127.0.0.1}`.
- Secrets never printed to console; on disk files are `0600`, dirs `0700`.
- Only LAN ports are published; no public exposure by default.

## Logging
- Pass `--debug` to `arrstack.sh` for comprehensive tracing of each installation step.
- Timestamped logs are archived under `${ARRSTACK_LOG_ARCHIVE_DIR:=$ARR_STACK_DIR/logs/archive}` with the latest run symlinked at
  `${ARRSTACK_LOG_FILE:=$ARR_STACK_DIR/logs/arrstack-install.log}`.
- Override `ARRSTACK_LOG_DIR`, `ARRSTACK_LOG_ARCHIVE_DIR`, or `ARRSTACK_LOG_FILE` in `arrconf/userconf.sh` to relocate debug output.

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

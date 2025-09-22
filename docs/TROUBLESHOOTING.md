# Troubleshooting

## Common issues

### Stack will not start
1. **Verify Docker is running.**
   ```bash
   docker --version
   docker compose version
   systemctl status docker
   ```
2. **Check permissions on secrets.**
   ```bash
   ls -l .env arrconf/proton.auth
   # Expect -rw------- on both files
   ```
3. **Inspect recent logs.**
   ```bash
   docker compose logs gluetun
   docker compose logs qbittorrent
   ```

### VPN connection problems
```bash
# Gluetun status
docker logs gluetun --tail 100

# Validate API key wiring
grep GLUETUN_API_KEY .env

# Query public IP via control API
curl -fsS -H "X-Api-Key: $GLUETUN_API_KEY" \
  "http://${LOCALHOST_IP:-127.0.0.1}:${GLUETUN_CONTROL_PORT:-8000}/v1/publicip/ip" | jq
```

If the API key query fails, regenerate credentials with:
```bash
./arrstack.sh --rotate-api-key --yes
```

### qBittorrent login errors
- Default credentials are `admin/adminadmin` (change them immediately and update `.env`).
- If you changed them and forgot:
  ```bash
  docker compose stop qbittorrent
  mv docker-data/qbittorrent/qBittorrent.conf{,.bak}
  docker compose up -d qbittorrent
  docker logs qbittorrent | grep "password"
  ```
- Update `.env` with the new `QBT_USER`/`QBT_PASS` values so the port-sync helper and Gluetun hook can authenticate whenever the WebUI requires it.

### Port forwarding not updating
```bash
# Check Gluetun forwarded port (integer response on recent releases)
curl -fsS -H "X-Api-Key: $GLUETUN_API_KEY" \
  "http://${LOCALHOST_IP:-127.0.0.1}:${GLUETUN_CONTROL_PORT:-8000}/v1/forwardedport"

# Fallback for older Gluetun versions that return JSON
curl -fsS -H "X-Api-Key: $GLUETUN_API_KEY" \
  "http://${LOCALHOST_IP:-127.0.0.1}:${GLUETUN_CONTROL_PORT:-8000}/v1/openvpn/portforwarded" | jq '.port'

# Review port-sync logs inside the shared Gluetun namespace
docker logs port-sync --tail 50
```
If the helper reports authentication failures, confirm that `QBT_USER`/`QBT_PASS` in `.env` match the WebUI credentials. LAN browsers traverse Caddy, so the qBittorrent “bypass” checkboxes are optional. Gluetun also executes `/gluetun/hooks/update-qbt-port.sh` whenever Proton allocates a new port—if the hook is missing or not executable, rerun the installer.

#### Port forwarding timeouts or RPC failures
- Inspect Gluetun logs for NAT-PMP activity to spot slow or stalled negotiations:
  ```bash
  docker logs gluetun | grep -i 'portforward'
  ```
- Confirm `.env` still contains a Proton username with the `+pmp` suffix. The installer adds it automatically, but edits to `.env` can remove it and prevent Proton from enabling port forwarding.
- Ensure `/gluetun/hooks/update-qbt-port.sh` exists and is executable inside the Gluetun container (rerun the installer if it is missing). The hook uses the qBittorrent Web API directly, so keep `.env` credentials accurate for seamless authentication.
- Switch to another Proton exit in `arrconf/userconf.sh` by adjusting `SERVER_COUNTRIES`. Busy servers are more likely to drop the UDP 5351 NAT-PMP handshake.
- Give the tunnel time to settle. Port-sync uses exponential backoff (up to five minutes) and will automatically apply the forwarded port as soon as Gluetun reports it.
- Keep the control API locked down: `GLUETUN_API_KEY` must be present and `LOCALHOST_IP` should stay on a loopback or other trusted address. Gluetun 3.40+ enforces authentication on `/v1/openvpn/portforwarded`, and the stack already ships with API-key protection—regenerate the key with `./arrstack.sh --rotate-api-key --yes` if required.
- If Proton still never assigns a port, double-check that nothing on the host blocks outbound UDP 5351 to 10.16.0.1.


### Services exposed on all interfaces
If the summary warns that `LAN_IP=0.0.0.0`, set a specific address:
```bash
ip addr show | grep "inet "

cat <<'CFG' > arrconf/userconf.sh
LAN_IP="192.168.1.50"  # replace with your host IP
CFG

./arrstack.sh --yes
```

## qBittorrent Authentication Issues

### Getting Access Credentials

qBittorrent generates a temporary password on first run or after a config reset:

```bash
# Method 1: Use the helper script
${ARR_STACK_DIR}/scripts/qbt-helper.sh show

# Method 2: Check logs directly
docker logs qbittorrent 2>&1 | grep "temporary password" | tail -1
```

### Common Solutions

1. **"Unauthorized" error**:
   - You need the temporary password from logs
   - URL must be `http://qbittorrent.${CADDY_DOMAIN_SUFFIX:-lan}/` (or `https://` with the Caddy internal CA)

2. **Enable passwordless LAN access** (optional for direct connections bypassing Caddy):
   ```bash
   ${ARR_STACK_DIR}/scripts/qbt-helper.sh whitelist
   ```

3. **Reset authentication completely**:
   ```bash
   ${ARR_STACK_DIR}/scripts/qbt-helper.sh reset
   ```

### Important Notes
- Port 8080 is exposed on Gluetun for qBittorrent's WebUI
- Temporary passwords change with each restart
- Always set a permanent password after first login and update `.env`

## Health and status
```bash
# Container state
arr.health          # via aliases
# or
cd ${ARR_STACK_DIR:-arrstack}
docker compose ps
```

```bash
# Port currently used by qBittorrent (query from inside the Gluetun namespace)
docker exec gluetun curl -fsS "http://127.0.0.1:8080/api/v2/app/preferences" | jq '.listen_port'
```

## Resetting everything
```bash
docker compose down -v
rm -rf docker-data/ .env
./arrstack.sh --yes
```

## Further reading
- [Version management](VERSION_MANAGEMENT.md)
- [Changelog](../CHANGELOG.md)

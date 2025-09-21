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
  "http://localhost:${GLUETUN_CONTROL_PORT:-8000}/v1/publicip/ip" | jq
```

If the API key query fails, regenerate credentials with:
```bash
./arrstack.sh --rotate-api-key --yes
```

### qBittorrent login errors
- Default credentials are `admin/adminadmin`.
- If you changed them and forgot:
  ```bash
  docker compose stop qbittorrent
  mv docker-data/qbittorrent/qBittorrent.conf{,.bak}
  docker compose up -d qbittorrent
  docker logs qbittorrent | grep "password"
  ```
- Update `.env` with the new `QBT_USER`/`QBT_PASS` values so the port sync helper can authenticate if the WebUI requires it.

### Port forwarding not updating
```bash
# Check Gluetun forwarded port
curl -fsS -H "X-Api-Key: $GLUETUN_API_KEY" \
  "http://localhost:${GLUETUN_CONTROL_PORT:-8000}/v1/openvpn/portforwarded" | jq

# Review port-sync logs
docker logs port-sync --tail 50
```
If the helper reports authentication failures, confirm that `QBT_USER`/`QBT_PASS` in `.env` match the WebUI credentials.

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
   - URL must be `http://YOUR_IP:8080/`

2. **Enable passwordless LAN access**:
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
# Port currently used by qBittorrent
curl -fsS "http://localhost:${QBT_HTTP_PORT_HOST:-8080}/api/v2/app/preferences" | jq '.listen_port'
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

# Troubleshooting

## Check health
```bash
docker ps
docker logs gluetun --tail 100
```

## VPN status & PF
> Ensure your shell has loaded values from the generated `.env` (for example, `set -a; source .env; set +a`).

```bash
curl -u "gluetun:$GLUETUN_API_KEY" "http://${GLUETUN_CONTROL_HOST}:${GLUETUN_CONTROL_PORT}/v1/publicip/ip"
curl -u "gluetun:$GLUETUN_API_KEY" "http://${GLUETUN_CONTROL_HOST}:${GLUETUN_CONTROL_PORT}/v1/openvpn/portforwarded"
```

## qBittorrent port
```bash
curl "http://${LOCALHOST_IP}:${QBT_HTTP_PORT_HOST}/api/v2/app/preferences" | jq '.listen_port'
```

## Idempotent re-runs
Safe to re-run `./arrstack.sh`. Destructive operations require explicit flags.

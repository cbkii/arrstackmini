# Troubleshooting

## Check health
```bash
docker ps
docker logs gluetun --tail 100
```

## VPN status & PF
> Ensure your shell has loaded values from the generated `.env` (for example, `set -a; source .env; set +a`).

```bash
curl -fsS -H "X-API-Key: $GLUETUN_API_KEY" \
  "http://${LOCALHOST_IP:-127.0.0.1}:${GLUETUN_CONTROL_PORT:-8000}/v1/publicip/ip"
curl -fsS -H "X-API-Key: $GLUETUN_API_KEY" \
  "http://${LOCALHOST_IP:-127.0.0.1}:${GLUETUN_CONTROL_PORT:-8000}/v1/openvpn/status"
curl -fsS -H "X-API-Key: $GLUETUN_API_KEY" \
  "http://${LOCALHOST_IP:-127.0.0.1}:${GLUETUN_CONTROL_PORT:-8000}/v1/openvpn/portforwarded"
```

## qBittorrent port
```bash
curl "http://${LOCALHOST_IP}:${QBT_HTTP_PORT_HOST}/api/v2/app/preferences" | jq '.listen_port'
```

## Idempotent re-runs
Safe to re-run `./arrstack.sh`. Destructive operations require explicit flags.

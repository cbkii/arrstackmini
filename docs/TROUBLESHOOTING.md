# Troubleshooting

## Check health
```bash
docker ps
docker logs gluetun --tail 100
```

## VPN status & PF
```bash
curl -u "gluetun:$GLUETUN_API_KEY" http://127.0.0.1:8000/v1/publicip/ip
curl -u "gluetun:$GLUETUN_API_KEY" http://127.0.0.1:8000/v1/openvpn/portforwarded
```

## qBittorrent port
```bash
curl http://127.0.0.1:8081/api/v2/app/preferences | jq '.listen_port'
```

## Idempotent re-runs
Safe to re-run `./arrstack.sh`. Destructive operations require explicit flags.

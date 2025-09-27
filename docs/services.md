← [Back to Start](../README.md)

# Service overview

Use this table to find each container’s default URL and credential guidance after the stack boots.

## Why
Knowing the entry points makes first verification easy and helps you decide which ports or passwords to change.

## Do
| Service | Default LAN URL | Credentials at first boot | Change ports in |
| --- | --- | --- | --- |
| [qBittorrent](https://www.qbittorrent.org/) | `http://<LAN_IP>:8080` | Uses the username/password stored in `.env` (`QBT_USER`/`QBT_PASS`). Rotate them on first login under **Tools → Options → Web UI**. | `.env` (`QBT_HTTP_PORT_HOST`) or `${ARR_BASE}/userr.conf` overrides |
| [Sonarr](https://sonarr.tv/) | `http://<LAN_IP>:8989` | Default login disabled; set your own under **Settings → General → Security**. | `.env` (`SONARR_PORT`) |
| [Radarr](https://radarr.video/) | `http://<LAN_IP>:7878` | No password by default; enable authentication in **Settings → General**. | `.env` (`RADARR_PORT`) |
| [Prowlarr](https://prowlarr.com/) | `http://<LAN_IP>:9696` | Prompts for setup wizard; create an admin account during onboarding. | `.env` (`PROWLARR_PORT`) |
| [Bazarr](https://www.bazarr.media/) | `http://<LAN_IP>:6767` | Set a password at **Settings → General → Authentication**. | `.env` (`BAZARR_PORT`) |
| [FlareSolverr](https://flaresolverr.com/) | `http://<LAN_IP>:8191` | No UI; used by other services. Protect access when exposing remotely. | `.env` (`FLARESOLVERR_PORT`) |
| [Gluetun control API](https://github.com/qdm12/gluetun) | `http://127.0.0.1:8000` (host loopback) | Requires the API key stored in `.env` (`GLUETUN_API_KEY`). | `.env` (`GLUETUN_CONTROL_PORT`) |
| [Caddy status page](https://caddyserver.com/) *(optional)* | `https://caddy.<suffix>` (if `ENABLE_CADDY=1`) | LAN clients bypass basic auth. Regenerate remote credentials with `./arrstack.sh --rotate-caddy-auth`. | `.env` (`CADDY_DOMAIN_SUFFIX`) |

Notes:
- Replace `<LAN_IP>` with the address detected by the installer (example `192.168.1.50`).
- If you enable Caddy and local DNS later, hostnames such as `https://qbittorrent.<suffix>` become available in addition to the raw IP:PORT URLs.
- Use [Config reference](config.md) to locate additional overrides and credentials.

## Verify
After `docker compose up -d`, open `http://<LAN_IP>:8080` in a browser to confirm qBittorrent is reachable. Enable the proxy profile later if you need HTTPS hostnames.

## See also
- [Quick start](../README.md)
- [Config reference](config.md)
- [LAN DNS & network pre-start](lan-dns-network-setup.md)
- [Troubleshooting](troubleshooting.md)

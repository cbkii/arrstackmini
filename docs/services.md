← [Back to Start](../README.md)

# Service overview

Use this table to find each container’s default URL and credential guidance after the stack boots.

## Why
Knowing the entry points makes first verification easy and helps you decide which ports or passwords to change.

## Do
| Service | Default LAN URL | Credentials at first boot | Change ports in |
| --- | --- | --- | --- |
| [qBittorrent](https://www.qbittorrent.org/) | `https://qbittorrent.home.arpa` | Uses the username/password stored in `.env` (`QBT_USER`/`QBT_PASS`). Rotate them on first login under **Tools → Options → Web UI**. | `.env` (`QBT_WEBUI_PORT`) or `arrconf/userconf.sh` overrides |
| [Sonarr](https://sonarr.tv/) | `https://sonarr.home.arpa` | Default login disabled; set your own under **Settings → General → Security**. | `.env` (`SONARR_PORT`) |
| [Radarr](https://radarr.video/) | `https://radarr.home.arpa` | No password by default; enable authentication in **Settings → General**. | `.env` (`RADARR_PORT`) |
| [Prowlarr](https://prowlarr.com/) | `https://prowlarr.home.arpa` | Prompts for setup wizard; create an admin account during onboarding. | `.env` (`PROWLARR_PORT`) |
| [Bazarr](https://www.bazarr.media/) | `https://bazarr.home.arpa` | Set a password at **Settings → General → Authentication**. | `.env` (`BAZARR_PORT`) |
| [FlareSolverr](https://flaresolverr.com/) | `http://flaresolverr.home.arpa` | No UI; used by other services. Protect access with Caddy basic auth when exposing remotely. | `.env` (`FLARESOLVERR_PORT`) |
| [Gluetun control API](https://github.com/qdm12/gluetun) | `http://gluetun.home.arpa:8000` (LAN only) | Requires the API key stored in `.env` (`GLUETUN_API_KEY`). | `.env` (`GLUETUN_CONTROL_PORT`) |
| [Caddy status page](https://caddyserver.com/) | `https://caddy.home.arpa` | LAN clients bypass basic auth. Regenerate remote credentials with `./arrstack.sh --rotate-caddy-auth`. | `.env` (`CADDY_HTTP_PORT`, `CADDY_HTTPS_PORT`) |

Notes:
- The URLs assume `LAN_DOMAIN_SUFFIX=home.arpa`. Replace the suffix if you customised it.
- Local DNS must point clients at the Pi (see [LAN DNS distribution](lan-dns.md)). Without DNS, use `https://<LAN_IP>` with the exact port numbers from `.env`.
- Use [Config reference](config.md) to locate additional overrides and credentials.

## Verify
After `docker compose up -d`, open `https://qbittorrent.home.arpa` in a browser. If it loads without certificate warnings, HTTPS and DNS are set up correctly.

## See also
- [Quick start](../README.md)
- [Config reference](config.md)
- [LAN DNS distribution](lan-dns.md)
- [Troubleshooting](troubleshooting.md)

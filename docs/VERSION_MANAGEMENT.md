# Version management

The stack pins every container to a known-good tag. Update the versions deliberately and record changes in the changelog.

## Current versions

| Service      | Image                                             | Version              | Notes                |
| ------------ | ------------------------------------------------- | -------------------- | -------------------- |
| Gluetun      | `qmcgaw/gluetun`                                  | `v3.39.1`            | ProtonVPN OpenVPN    |
| qBittorrent  | `lscr.io/linuxserver/qbittorrent`                 | `5.1.2-r2-ls415`     | Vuetorrent-ready     |
| Sonarr       | `lscr.io/linuxserver/sonarr`                      | `4.0.15.2941-ls291`  | v4 branch            |
| Radarr       | `lscr.io/linuxserver/radarr`                      | `5.27.5.10198-ls283` | v5 stable            |
| Prowlarr     | `lscr.io/linuxserver/prowlarr`                    | `1.28.2-ls207`       | Stable               |
| Bazarr       | `lscr.io/linuxserver/bazarr`                      | `1.5.1-ls288`        | Stable               |
| FlareSolverr | `ghcr.io/flaresolverr/flaresolverr`               | `v3.3.21`            | Challenge solver     |

## Updating a single service

1. Edit `.env` (or `arrconf/userconf.sh`) and bump the image tag.
2. Pull the new image and restart the service:
   ```bash
   docker compose pull sonarr
   docker compose up -d sonarr
   ```
3. Verify logs and functionality before proceeding.

## Updating everything
```bash
docker compose pull
docker compose up -d
```

## Rolling back
1. Restore the previous `.env` from backup.
2. Pull the recorded tags again:
   ```bash
   docker compose pull
   docker compose up -d
   ```
3. Re-run the installer if configuration files need regeneration.

## Tracking upstream releases
- LinuxServer.io publishes tags at https://fleet.linuxserver.io/.
- Gluetun releases are on GitHub: https://github.com/qdm12/gluetun/releases.
- FlareSolverr releases live at https://github.com/FlareSolverr/FlareSolverr/releases.

Document meaningful changes in [CHANGELOG.md](../CHANGELOG.md) and include upgrade guidance for operators.

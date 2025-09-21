# Version management

This repository normally pins each container to a known-good tag so reproducible installs match the validated stack. In September 2024 LinuxServer.io removed several historical tags for Prowlarr and Bazarr, which caused `manifest unknown` errors for fresh pulls. The stack now validates image availability during startup, falls back to `:latest` when necessary, and ships a recovery helper for existing deployments.

## Current image guidance

| Service      | Image                                | Recommended tag        | Alternatives                 | Notes |
| ------------ | ------------------------------------ | ---------------------- | ---------------------------- | ----- |
| Gluetun      | `qmcgaw/gluetun`                     | `v3.39.1`              | `latest`                     | Keep pinned; controls VPN routing. |
| qBittorrent  | `lscr.io/linuxserver/qbittorrent`    | `5.1.2-r2-ls415`       | `latest`, `develop`          | Falls back to `:latest` if the pin disappears. |
| Sonarr       | `lscr.io/linuxserver/sonarr`         | `4.0.15.2941-ls291`    | `latest`, `develop`, `main`  | `:latest` fallback applied automatically. |
| Radarr       | `lscr.io/linuxserver/radarr`         | `5.27.5.10198-ls283`   | `latest`, `develop`          | `:latest` fallback applied automatically. |
| Prowlarr     | `lscr.io/linuxserver/prowlarr`       | `latest`               | `develop`, `nightly`         | Specific tags churn; defaults to floating tag. |
| Bazarr       | `lscr.io/linuxserver/bazarr`         | `latest`               | `develop`, `nightly`         | Specific tags churn; defaults to floating tag. |
| FlareSolverr | `ghcr.io/flaresolverr/flaresolverr`  | `v3.3.21`              | `latest`                     | Pin to known good due to upstream flux. |

### Why `:latest` for Prowlarr and Bazarr?

LinuxServer.io's automated builds occasionally retire old tags once upstream changes ship. When a tag disappears Docker returns `manifest unknown` during `docker pull`. Using `:latest` guarantees a published tag exists, and the installer verifies availability before starting the stack.

## Checking available tags manually

```bash
# Replace IMAGE with linuxserver/<service> to inspect via Docker Hub
IMAGE="linuxserver/prowlarr"
curl -s "https://hub.docker.com/v2/repositories/${IMAGE}/tags/?page_size=10" |
  jq -r '.results[].name'
```

Alternatively browse the LinuxServer Fleet: https://fleet.linuxserver.io/

## Safe update workflow

1. **Back up the current environment.**
   ```bash
   cd "${ARR_STACK_DIR:-$PWD}/.."
   tar -czf "arrstack-backup-$(date +%Y%m%d).tar.gz" arrstack docker-data
   ```
2. **Adjust versions.** Edit `.env` or `arrconf/userconf.sh` to change image tags.
3. **Validate first.** Re-run the installer (`./arrstack.sh --yes`). The new validation step checks every configured image and automatically switches LinuxServer images to `:latest` when a pin goes missing.
4. **Confirm runtime.** Use `docker compose ps` from `${ARR_STACK_DIR}` and inspect individual logs before resuming automation.

## Recovering from `manifest unknown`

If an existing deployment references a removed tag:

1. Run the generated helper to repair `.env`:
   ```bash
   ${ARR_STACK_DIR}/scripts/fix-versions.sh
   ```
2. Re-run the installer to regenerate Compose files and restart services:
   ```bash
   ./arrstack.sh --yes
   ```
3. Optionally edit `.env` afterwards to pin to a newly released specific tag and re-run the installer again.

The recovery script performs a timestamped backup of `.env` and replaces the affected tags with `:latest`. You can compare backups with `diff` if manual adjustments are needed.

## Troubleshooting

- `docker manifest inspect lscr.io/linuxserver/prowlarr:latest` – verify the tag exists.
- `docker pull lscr.io/linuxserver/prowlarr:latest` – ensure the host can pull the fallback image.
- `docker compose pull` – refresh all images defined in `${ARR_STACK_DIR}/docker-compose.yml`.
- Review the installer output: any images that still fail validation are listed with corrective guidance.

Document any future tag changes in this file and the changelog so operators know when manual intervention is required.

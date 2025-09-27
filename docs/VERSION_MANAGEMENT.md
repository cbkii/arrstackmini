← [Back to Start](../README.md)

# Version management

Track container tags safely so installs stay reproducible.

## Why
The stack pins each image to a tested tag. Occasionally a registry removes an old build, which can break `docker pull` unless you fall back to a known good alternative.

## Do
### Current image guidance
| Service | Image | Recommended tag | Notes |
| --- | --- | --- | --- |
| Gluetun | `qmcgaw/gluetun` | `v3.39.1` | Keep pinned; controls VPN routing. |
| qBittorrent | `lscr.io/linuxserver/qbittorrent` | `5.1.2-r2-ls415` | Falls back to `:latest` if the pin disappears. |
| Sonarr | `lscr.io/linuxserver/sonarr` | `4.0.15.2941-ls291` | Installer switches to `:latest` when a tag vanishes. |
| Radarr | `lscr.io/linuxserver/radarr` | `5.27.5.10198-ls283` | Same fallback as Sonarr. |
| Prowlarr | `lscr.io/linuxserver/prowlarr` | `latest` | Floating tag to avoid churn. |
| Bazarr | `lscr.io/linuxserver/bazarr` | `latest` | Floating tag to avoid churn. |
| FlareSolverr | `ghcr.io/flaresolverr/flaresolverr` | `v3.3.21` | Keep pinned to a stable release. |
| Caddy | `caddy` | `2.8.4` | Use upstream stable. |

### Update workflow
1. **Back up your data.**
   ```bash
   cd "${ARR_STACK_DIR:-$PWD}/.."
   tar -czf "arrstack-backup-$(date +%Y%m%d).tar.gz" arrstack docker-data
   ```
2. **Adjust tags.** Edit `${ARR_BASE}/userr.conf` (default `~/srv/userr.conf`) to change any `*_IMAGE` values; the installer will regenerate `.env` for you.
3. **Apply changes.**
   ```bash
   ./arrstack.sh --yes
   ```
   The installer validates each image and swaps LinuxServer pins to `:latest` if a tag has vanished.
4. **Confirm runtime.**
   ```bash
   docker compose ps
   ```
   Ensure every container reports `running` before resuming automation.

### Recover from `manifest unknown`
1. Run the helper to repair the generated `.env`:
   ```bash
   ${ARR_STACK_DIR}/scripts/fix-versions.sh
   ```
2. Re-run the installer:
   ```bash
   ./arrstack.sh --yes
   ```
3. Optionally pin to a new tag afterward and repeat the installer if you need a specific release.

### Check tags manually
```bash
IMAGE="linuxserver/prowlarr"
curl -s "https://hub.docker.com/v2/repositories/${IMAGE}/tags/?page_size=10" |
  jq -r '.results[].name'
```
Or browse the LinuxServer Fleet at https://fleet.linuxserver.io/ for official tag status.

## Verify
List the images in use and confirm the expected tags appear:
```bash
docker compose images
```
Check the `TAG` column for each service you updated.

## See also
- [Config reference](config.md)
- [Security notes](security-notes.md)
- [Troubleshooting](troubleshooting.md)
- [FAQ](faq.md)

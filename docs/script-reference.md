← [Back to Start](../README.md)

# Script reference

Use this guide to understand what the installer does behind the scenes and how to run the helper scripts safely.

## Why
The project relies on Bash automation. Knowing what each script is responsible for makes it easier to diagnose issues and rerun pieces of the setup without guessing.

## Do
### `./arrstack.sh`
The main installer orchestrates the whole build:
- Loads defaults from `arrconf/userconf.defaults.sh` and your overrides in `arrconf/userconf.sh` before running any tasks.【F:arrstack.sh†L7-L32】
- Accepts flags such as `--yes`, `--rotate-api-key`, `--rotate-caddy-auth`, `--setup-host-dns`, and `--refresh-aliases` for non-interactive runs, credential rotation, or alias regeneration.【F:arrstack.sh†L34-L92】
- Runs preflight checks that ensure Docker, Docker Compose v2, `curl`, `jq`, `openssl`, and your Proton credentials are present before anything else happens.【F:scripts/preflight.sh†L1-L74】【F:scripts/preflight.sh†L90-L128】
- Creates required directories with safe permissions, migrates legacy files, and cleans old Compose projects before writing new assets.【F:scripts/files.sh†L12-L87】【F:scripts/migrations.sh†L1-L46】【F:scripts/services.sh†L44-L69】
- Generates secrets and configuration files: `.env`, `docker-compose.yml`, Gluetun hook scripts, Caddy credentials, helper aliases, and the qBittorrent config.【F:arrstack.sh†L102-L114】【F:scripts/files.sh†L40-L345】【F:scripts/files.sh†L604-L672】【F:scripts/files.sh†L674-L921】【F:scripts/aliases.sh†L1-L62】
- Starts containers with retries, installs the VueTorrent WebUI theme, waits for Gluetun to report healthy, and records the forwarded port before launching other services.【F:scripts/services.sh†L1-L199】【F:scripts/services.sh†L233-L403】
- Runs LAN diagnostics when local DNS is enabled and prints a summary of URLs, credentials, and next steps.【F:arrstack.sh†L123-L143】【F:scripts/summary.sh†L1-L78】

### Core library modules
`arrstack.sh` sources multiple helpers from the `scripts/` directory. The most visible ones are:
- **`defaults.sh`** – sets calculated defaults, permission profiles, and image tags before any user overrides run.【F:scripts/defaults.sh†L1-L92】【F:scripts/defaults.sh†L117-L148】
- **`network.sh`** – validates IPs/ports and warns about missing tools that Gluetun health checks depend on.【F:scripts/network.sh†L1-L54】
- **`config.sh`** – enforces Proton credential format, previews the configuration, and validates ports before writing `.env`.【F:scripts/config.sh†L1-L69】【F:scripts/config.sh†L72-L113】【F:scripts/config.sh†L115-L127】
- **`permissions.sh`** – keeps secrets (`.env`, `proton.auth`, qBittorrent config) at `600` and tightens data directories according to the chosen profile.【F:scripts/permissions.sh†L1-L69】
- **`dns.sh`** – populates `/etc/hosts` via `scripts/setup-lan-dns.sh` and optionally runs the host takeover helper when you pass `--setup-host-dns`.【F:scripts/dns.sh†L1-L64】

### Utility commands
Run these helpers individually when you need to make targeted adjustments:

| Script | When to run it | What it does |
| --- | --- | --- |
| `scripts/host-dns-setup.sh` | Debian Bookworm still owns port 53 | Escalates to root, backs up `systemd-resolved`, writes a static `/etc/resolv.conf`, and starts the `local_dns` container so LAN clients can resolve `*.home.arpa`.【F:scripts/host-dns-setup.sh†L1-L146】 |
| `scripts/host-dns-rollback.sh` | Undo the takeover | Stops `local_dns`, re-enables `systemd-resolved`, and restores `/etc/resolv.conf` symlinks.【F:scripts/host-dns-rollback.sh†L1-L43】 |
| `scripts/setup-lan-dns.sh` | `/etc/hosts` or Docker DNS need updating | Adds Pi hostnames to `/etc/hosts`, configures Docker to prefer the LAN resolver, and handles privilege escalation for you.【F:scripts/setup-lan-dns.sh†L1-L211】 |
| `scripts/doctor.sh` | Something feels off after install | Runs port, DNS, HTTPS, and LAN reachability checks using the values in `.env` and prints hints to fix conflicts.【F:scripts/doctor.sh†L1-L235】 |
| `scripts/install-caddy-ca.sh` | Trust the Caddy HTTPS certificate on Debian/Ubuntu | Locates `root.crt` in the stack, then installs it into `/usr/local/share/ca-certificates` and runs `update-ca-certificates` (requires sudo).【F:scripts/install-caddy-ca.sh†L1-L118】 |
| `scripts/export-caddy-ca.sh` | Copy the Caddy CA to another device | Writes the public `root.crt` to a path of your choice with safe permissions so you can import it manually.【F:scripts/export-caddy-ca.sh†L1-L35】 |
| `scripts/qbt-helper.sh` | View or reset qBittorrent WebUI access | Shows current URLs, reads temporary passwords from logs, resets the PBKDF2 hash, or whitelists your LAN subnet.【F:scripts/qbt-helper.sh†L1-L153】 |
| `scripts/fix-versions.sh` | Docker Hub removed a pinned tag | Backs up `.env`, checks pinned LinuxServer images, and swaps to `:latest` when a manifest goes missing.【F:scripts/fix-versions.sh†L1-L55】 |
| `scripts/dev/find-unescaped-dollar.sh` | Compose reports `variable is not set` warnings | Scans a Compose file for `${...}` tokens, compares them to `.env`/defaults, and prints context for any unresolved entries so you can escape literal `$` values or define the variable.【F:scripts/dev/find-unescaped-dollar.sh†L1-L99】 |
| `scripts/aliases.sh` (`arrstack.sh --refresh-aliases`) | Helper aliases look outdated | Regenerates `.arraliases`, installs convenient shell aliases, and drops `diagnose-vpn.sh` alongside the stack.【F:scripts/aliases.sh†L1-L120】 |
| `scripts/gluetun.sh` | Reference for custom automation | Provides reusable functions to call the Gluetun control API, parse public IP info, and read the forwarded port without writing your own curl logic.【F:scripts/gluetun.sh†L1-L165】【F:scripts/gluetun.sh†L167-L229】 |

## Verify
When you finish editing configs or running helpers, rerun the installer to apply everything cleanly:
```bash
./arrstack.sh --yes
```
Check the printed summary and URLs. If a service fails to start, run `scripts/doctor.sh` for detailed diagnostics.

## See also
- [Quick start](../README.md)
- [Config reference](config.md)
- [LAN DNS & network pre-start](lan-dns-network-setup.md)
- [Local HTTPS and CA trust](https-and-ca.md)
- [Troubleshooting](troubleshooting.md)

← [Back to Start](../README.md)

# Frequently asked questions

Quick answers to common beginner questions about arrstack-mini.

## Why
Reading these first can save time before you run the installer or change defaults.

## Do
### Do I need a Raspberry Pi 5?
The stack targets Raspberry Pi 5 or any 64-bit Debian Bookworm host with similar resources (4 cores, 4 GB RAM). Slower hardware may work but downloads and transcoding will lag.

### Which Proton plan should I buy?
Use Proton VPN Plus or Unlimited. Those plans support port forwarding, which qBittorrent needs for good performance.

### Can I skip the DNS helper?
Yes, but you must add host entries manually or set DNS per device. Using [LAN DNS & network pre-start](lan-dns-network-setup.md) gives the smoothest experience.

### Where do I put my Proton credentials?
Copy `arrconf/proton.auth.example` to `arrconf/proton.auth` and fill in `PROTON_USER` and `PROTON_PASS`. The installer locks down the permissions automatically.

### Which group should `PGID` use when enabling the collaborative profile?
Use the group that owns your shared downloads or media storage (for example `getent group media`). The installer grants group read/write access only when `PGID` matches that group. Leaving `PGID=0` (root group) keeps the safer `750/640` defaults and prints a warning so you can avoid exposing write access to every root user on the host.

### How do I update to new container versions?
Read [Version management](VERSION_MANAGEMENT.md). Back up your configuration (including `${ARR_BASE}/userr.conf`), adjust tags there, rerun `./arrstack.sh --yes`, and confirm services start.

### What if I want to rerun the installer safely?
It is idempotent. Run `./arrstack.sh --yes` anytime after editing `${ARR_BASE}/userr.conf` (default `~/srv/userr.conf`). The script shows a summary before it restarts containers.

### Can I expose services to the Internet?
Only through Gluetun and Caddy with strong basic auth. Forwarding ports directly from the Pi bypasses VPN protection and is not recommended.

### Is `home.arpa` required?
It is the recommended LAN suffix because it never leaks to the public Internet. Change it only if another system already uses it.

## Verify
After following any answer above, confirm the stack responds:
```bash
docker compose ps
```
All containers should show `running`. If not, check [Troubleshooting](troubleshooting.md).

## See also
- [Quick start](../README.md)
- [Config reference](config.md)
- [LAN DNS & network pre-start](lan-dns-network-setup.md)
- [Troubleshooting](troubleshooting.md)

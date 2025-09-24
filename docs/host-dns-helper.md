← [Back to Start](../README.md)

# Host DNS helper (Debian Bookworm)

Run these scripts when the host still owns port 53 or rewrites `/etc/resolv.conf` during setup.

## Why
Debian Bookworm ships `systemd-resolved`, which binds `127.0.0.53:53` and overwrites `/etc/resolv.conf`. The helper disables it safely so the `local_dns` container can listen on the Pi’s LAN address.

## Do
1. **Take over DNS on the host.**
   ```bash
   ./scripts/host-dns-setup.sh
   ```
   The script escalates with `sudo` when needed, backs up the current resolver config, stops `systemd-resolved` only if it is still active, disables it when enabled, writes a static `/etc/resolv.conf`, and starts the `local_dns` container.
2. **Roll back when finished testing.**
   ```bash
   ./scripts/host-dns-rollback.sh
   ```
   This reenables `systemd-resolved`, relinks `/etc/resolv.conf`, and stops `local_dns` if it is running.
3. **Re-run after config changes.** If you edit `LAN_IP`, `LAN_DOMAIN_SUFFIX`, or upstream DNS values, run the setup script again so the host picks up the new details.

## Verify
```bash
ss -ulpn | grep ':53 '
dig +tcp @192.168.1.50 qbittorrent.home.arpa
```
The first command should show `dnsmasq` (the `local_dns` container) bound to `192.168.1.50:53`, and `dig` should return the Pi address over TCP.

If either check fails, view logs with `docker logs local_dns` and repeat the setup script once the issue is resolved.

## See also
- [LAN DNS & network pre-start](lan-dns-network-setup.md)
- [Troubleshooting](troubleshooting.md)
- [Security notes](security-notes.md)
- [Config reference](config.md)

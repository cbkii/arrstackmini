← [Back to Start](../README.md)

# LAN DNS distribution

Use this guide to choose how the stack shares DNS with devices on your home network.

## Why
A single LAN resolver lets `qbittorrent.home.arpa` and other service names point to your Pi while keeping public Internet lookups working.

## Do
1. **Set your preference in the config.**
   ```bash
   cp arrconf/userconf.sh.example arrconf/userconf.sh  # skip if already copied
   nano arrconf/userconf.sh
   ```
   Set `LAN_IP` to your Pi (example `192.168.1.50`) and pick a mode:
   ```bash
   LAN_IP=192.168.1.50
   LAN_DOMAIN_SUFFIX=home.arpa
   DNS_DISTRIBUTION_MODE=router  # or per-device
   ```
2. **Pick a distribution mode.**
   - **`router` (recommended):** Update the DHCP page so **Primary DNS = 192.168.1.50** (your Pi) and **Secondary DNS = 1.1.1.1** or another public resolver. Leave any **Default Domain** box empty. Reboot or reconnect clients so they receive the new lease. Use [router examples](router-examples.md) for screenshots.
   - **`per-device`:** Leave the router alone. On each important device set the DNS server to the Pi’s IP. On Android go to **Settings → Network & Internet → Internet → Private DNS** and choose **Off** or **Automatic** so lookups stay on the LAN.
3. **Reserve the Pi address.** In the router’s DHCP reservation list, bind the Pi’s MAC to `192.168.1.50` so leases never drift.
4. **Apply changes.** Re-run the installer when you finish editing:
   ```bash
   ./arrstack.sh --yes
   ```
   This rewrites `.env` and restarts services with the new DNS mode.

## Verify
Run the check from any LAN device:
```bash
dig @192.168.1.50 qbittorrent.home.arpa
```
Expect to see:
- `SERVER: 192.168.1.50#53`
- `qbittorrent.home.arpa.  IN  A  192.168.1.50`

If the server is a public resolver, swap the DNS order so the Pi is listed first.

## Pitfalls
- **Public DNS listed first:** Clients skip the Pi entirely. Reorder the entries so the Pi is Primary.
- **Device still using DNS-over-TLS:** Disable Android Private DNS or other DoT profiles while you are on the LAN.
- **Pi IP changed:** Keep the DHCP reservation in place; otherwise `LAN_IP` and leases diverge.
- **IPv6 resolvers overriding IPv4:** Either advertise the Pi as the IPv6 DNS server as well or disable IPv6 DNS on clients that ignore the IPv4 list.

## See also
- [Host DNS helper](host-dns-helper.md)
- [Router examples](router-examples.md)
- [Troubleshooting](troubleshooting.md)
- [Config reference](config.md)

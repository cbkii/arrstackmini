← [Back to Start](../README.md)

# Glossary

Learn the key terms used throughout the docs.

## Why
Understanding these words makes the setup steps easier to follow.

## Do
| Term | Meaning |
| --- | --- |
| **DNS (Domain Name System)** | Service that turns a name like `qbittorrent.home.arpa` into the Pi’s IP address. |
| **DHCP (Dynamic Host Configuration Protocol)** | Router feature that hands out IP addresses and DNS servers to devices when they join the network. |
| **LAN (Local Area Network)** | Your home network. Everything with `192.168.x.x`, `10.x.x.x`, or `172.16-31.x.x` lives here. |
| **LAN domain suffix** | Ending added to service names (default `home.arpa`). It stays inside your LAN and never resolves on the public Internet. |
| **CA (Certificate Authority)** | Trusted signer that lets browsers accept HTTPS certificates. Caddy runs its own CA for your LAN. |
| **Root certificate** | Public file (`root.crt`) you import so devices trust the local CA. |
| **Gluetun** | VPN container that routes traffic through Proton VPN and provides a control API. |
| **Caddy** | Reverse proxy that terminates HTTPS on ports 80/443 and enforces basic auth for remote access. |
| **dnsmasq** | Lightweight DNS server used by the `local_dns` container to answer `*.home.arpa`. |
| **Docker compose** | Tool that starts all services together using the provided `docker-compose.yml`. |
| **Port forwarding** | Proton VPN feature that assigns a TCP port so peers can reach qBittorrent through the VPN tunnel. |
| **Private DNS / DoT** | Android feature for DNS-over-TLS. Leave it Off/Automatic so lookups stay inside your LAN. |

## Verify
If a term still feels unclear, follow its link in the other docs or run `man <term>` on Debian (for example, `man resolv.conf`).

## See also
- [Quick start](../README.md)
- [LAN DNS distribution](lan-dns.md)
- [Local HTTPS and CA trust](https-and-ca.md)
- [FAQ](faq.md)

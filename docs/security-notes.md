← [Back to Start](../README.md)

# Security notes

Keep the stack private on your LAN and review these reminders before exposing anything remotely.

## Why
The deployment holds VPN credentials, API keys, and a local certificate authority. Simple hygiene steps prevent leaks and keep automation safe.

## Do
- **Lock down secrets.** Leave the default permission profile at `strict` so `.env`, `arrconf/proton.auth`, and Caddy credentials stay readable only by your user.
- **Do not publish the PKI directory.** Serve only `caddy/ca-pub/root.crt`. Never map `caddy/pki` or other certificate folders outside the stack.
- **Rotate passwords.** Change qBittorrent credentials after first login, then update `.env` to match. Run `./arrstack.sh --rotate-caddy-auth` when sharing access outside your LAN.
- **Keep VPN egress inside Gluetun.** Do not expose application containers directly unless you understand the risk. Leave `EXPOSE_DIRECT_PORTS=0` and rely on Caddy for LAN access.
- **Use basic auth remotely.** If you forward ports through your router, keep the generated Caddy basic auth credentials secret and rotate them regularly.
- **Check commits for personal data.** Before pushing changes, run:
  ```bash
  git grep -nE '(yourname|@|MAC:|VX|home\.local|cbkii|arrstackminirepo)'
  git grep -nE 'http(s)?://(?!docs\.docker\.com|hub\.docker\.com|caddyserver\.com|proton\.me|tp-link|.*official.*|.*\.arpa)'
  ```
  This catches stray emails, router IDs, or unofficial links.

## Verify
Periodically confirm only the expected ports are open on the Pi:
```bash
sudo ss -tulpn | grep -E ':80|:443|:53'
```
Expect to see Caddy on 80/443 and dnsmasq on 53 bound to `192.168.1.50`. Anything else should be reviewed.

## See also
- [Config reference](config.md)
- [Local HTTPS and CA trust](https-and-ca.md)
- [Troubleshooting](troubleshooting.md)
- [LAN DNS distribution](lan-dns.md)

← [Back to Start](../README.md)

# Security notes

Keep the stack private on your LAN and review these reminders before exposing anything remotely.

## Why
The deployment holds VPN credentials, API keys, and a local certificate authority. Simple hygiene steps prevent leaks and keep automation safe.

## Do
- **Lock down secrets.** Leave the default permission profile at `strict` so `.env`, `arrconf/proton.auth`, and Caddy credentials stay readable only by your user.
- **Do not publish the PKI directory.** Serve only `caddy/ca-pub/root.crt`. Never map `caddy/pki` or other certificate folders outside the stack.
- **Rotate passwords.** Change qBittorrent credentials after first login, then update `.env` to match. Run `./arrstack.sh --rotate-caddy-auth` when sharing access outside your LAN.
- **Keep LAN exposure limited.** Direct IP ports are enabled by default for simplicity—set `LAN_IP` to your private address and never forward these ports through your router. Enable the Caddy proxy only when you need HTTPS or external access.
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
sudo ss -tulpn | grep -E ':8080|:8989|:7878|:9696|:6767|:8191|:80|:443|:53'
```
Expect to see the *arr ports bound to your LAN IP, with 80/443 present only when Caddy is enabled and 53 only when local DNS is active. Anything else should be reviewed.

## See also
- [Config reference](config.md)
- [Local HTTPS and CA trust](https-and-ca.md)
- [Troubleshooting](troubleshooting.md)
- [LAN DNS & network pre-start](lan-dns-network-setup.md)

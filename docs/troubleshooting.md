← [Back to Start](../README.md)

# Troubleshooting

Use these quick fixes when a service fails to load or DNS stops working.

## Why
Most issues come from DNS conflicts, VPN startup delays, or missing certificates. Short checks solve them faster than reimaging the Pi.

## Do
### Symptom: `ERR_NAME_NOT_RESOLVED`
- **Fix:** Ensure clients use the Pi as their first DNS server. Follow [LAN DNS distribution](lan-dns.md) and reboot the device or renew its DHCP lease.
- **Verify:**
  ```bash
  nslookup qbittorrent.home.arpa
  ```
  The output should list `Server: 192.168.1.50`.

### Symptom: Port 53 already in use on the Pi
- **Fix:** Run the host helper to disable `systemd-resolved` and start the `local_dns` container.
  ```bash
  ./scripts/host-dns-setup.sh
  ```
- **Verify:**
  ```bash
  ss -ulpn | grep ':53 '
  ```
  Expect to see `dnsmasq` bound to `192.168.1.50:53`.

### Symptom: Android ignores LAN DNS (DoT enabled)
- **Fix:** On the device open **Settings → Network & Internet → Internet → Private DNS** and choose **Off** or **Automatic**. Remove any custom DoT hostname.
- **Verify:** Re-run `nslookup` or `dig` from the device and confirm the server is the Pi.

### Symptom: Browser warns about HTTPS certificate
- **Fix:** Import `root.crt` using [Local HTTPS and CA trust](https-and-ca.md). Make sure you fetched it from `http://ca.home.arpa/root.crt`.
- **Verify:** Visit `https://qbittorrent.home.arpa` and confirm the lock icon is present.

### Symptom: Containers stuck in `starting`
- **Fix:** Gluetun must be healthy before other apps load. Restart Gluetun first, wait for the port-forward log line, then bring up the rest.
  ```bash
  docker compose up -d gluetun
  sleep 30
  docker compose up -d
  ```
- **Verify:**
  ```bash
  docker compose ps
  ```
  All services should report `running`.

### Symptom: Caddy healthcheck failing
- **Fix:** Use curl inside the Gluetun namespace to confirm Caddy answers. If not, restart Caddy after Gluetun is ready.
  ```bash
  docker compose exec -T gluetun curl -fsS http://127.0.0.1/healthz
  ```
- **Verify:** The command should print `ok`. Check `docker logs caddy` if it does not.

### Symptom: VPN tunnel not ready
- **Fix:** Review Gluetun logs and ensure Proton credentials are correct. Rotate the API key if authentication fails.
  ```bash
  docker logs gluetun --tail 100
  ./arrstack.sh --rotate-api-key --yes
  ```
- **Verify:**
  ```bash
  curl -fsS -H "X-Api-Key: $GLUETUN_API_KEY" \
    "http://${LOCALHOST_IP:-127.0.0.1}:${GLUETUN_CONTROL_PORT:-8000}/v1/publicip/ip"
  ```
  The command should return your Proton exit IP.

## Verify
When issues clear, run the stack doctor checks:
```bash
./arrstack.sh --yes
```
Review the summary, then browse to `https://qbittorrent.home.arpa` to confirm everything loads.

## See also
- [LAN DNS distribution](lan-dns.md)
- [Host DNS helper](host-dns-helper.md)
- [Local HTTPS and CA trust](https-and-ca.md)
- [Security notes](security-notes.md)

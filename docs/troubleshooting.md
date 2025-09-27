← [Back to Start](../README.md)

# Troubleshooting

Use these quick fixes when a service fails to load or DNS stops working.

## Why
Most issues come from DNS conflicts, VPN startup delays, or missing certificates. Short checks solve them faster than reimaging the Pi.

## Do
### Symptom: `ERR_NAME_NOT_RESOLVED`
- **Fix:** (Only applies if you enabled the optional local DNS profile.) Ensure clients use the Pi as their first DNS server. Follow [LAN DNS & network pre-start](lan-dns-network-setup.md) and reboot the device or renew its DHCP lease.
- **Verify:**
  ```bash
  nslookup qbittorrent.home.arpa
  ```
  The output should list `Server: 192.168.1.50`.

### Symptom: VueTorrent returns HTTP 500 or the login page is blank
- **Fix:** Rerun `./arrstack.sh` and ensure `QBT_DOCKER_MODS` matches the mode you expect. A non-empty value keeps the LSIO Docker mod active and points qBittorrent at `/vuetorrent`. Setting it blank triggers the manual installer, which refreshes `/config/vuetorrent`, verifies `public/index.html` and `version.txt`, and disables the Alternate WebUI if those files are missing so the default qBittorrent UI still loads.
- **Verify:**
  ```bash
  docker exec qbittorrent test -f /vuetorrent/public/index.html   # LSIO mod
  docker exec qbittorrent test -f /config/vuetorrent/public/index.html   # Manual install
  ```
  Only one of the checks should pass based on the configured mode. Edit `${ARR_BASE}/userr.conf` and rerun `./arrstack.sh` if the wrong path succeeds.

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

### Symptom: Installer reports port conflicts
- **Fix:** The installer now collects a full snapshot of `ss`, `lsof`, and Docker listeners before showing the menu. Review the summary and choose among:
  1. **Stop existing arrstack containers** (only offered if *all* conflicts belong to the same compose project).
  2. **Force stop/kill other services** — prints the exact PID/container list and requires typing `FORCE`. `systemd-resolved` bindings are skipped with a warning.
  3. **Apply contextual override** — currently offers to disable local DNS for this run when port 53 is occupied.
  4. **Re-scan** after you clear listeners in another terminal.
- **Debug:** set `ARRSTACK_DEBUG_PORTS=1` (or `ARRSTACK_PORT_TRACE=1`) before running `./arrstack.sh`. The installer writes JSONL snapshots to `logs/port-scan-YYYYmmdd-HHMMSS.jsonl` so you can inspect who owned each port.
- **Tip:** The detailed diagnostics (`D`) option prints a table showing protocol, binding, process/container, and classification so you can decide whether to kill a listener or adjust ports.

### Symptom: Android ignores LAN DNS (DoT enabled)
- **Fix:** On the device open **Settings → Network & Internet → Internet → Private DNS** and choose **Off** or **Automatic**. Remove any custom DoT hostname.
- **Verify:** Re-run `nslookup` or `dig` from the device and confirm the server is the Pi.

### Symptom: Browser warns about HTTPS certificate
- **Fix:** (Only when `ENABLE_CADDY=1`.) Import `root.crt` using [Local HTTPS and CA trust](https-and-ca.md). Make sure you fetched it from `http://ca.home.arpa/root.crt`.
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

### Symptom: ProtonVPN port forwarding fails or reports 0
- **Fix:** Use the enhanced P2P diagnostics to identify the issue.
  ```bash
  arr.vpn.troubleshoot
  ```
  This runs comprehensive tests for NAT-PMP connectivity, P2P server compatibility, and firewall issues.
- **Fix:** If your current server doesn't support P2P, get recommended P2P servers:
  ```bash
  arr.vpn.p2p list Netherlands 5    # List top 5 P2P servers for Netherlands
  arr.vpn.p2p config Netherlands    # Generate SERVER_HOSTNAMES configuration
  ```
  Add the generated `SERVER_HOSTNAMES` line to your `userr.conf` and restart Gluetun.
- **Fix:** For persistent NAT-PMP timeout errors, ensure you're using P2P-enabled servers:
  ```bash
  # Check if current server supports P2P
  arr.vpn.diag p2p
  
  # If not, switch to explicit P2P servers
  echo 'SERVER_HOSTNAMES="nl-01.protonvpn.net,nl-02.protonvpn.net"' >> ~/srv/userr.conf
  docker restart gluetun
  ```

### Symptom: Unsure which component failed
- **Fix:** Run the bundled doctor script for a full set of port, DNS, HTTPS, and LAN reachability checks.
  ```bash
  ./scripts/doctor.sh
  ```
  It reads the same environment values as the installer and prints targeted hints for any conflicts it finds.【F:scripts/doctor.sh†L1-L235】

## Verify
When issues clear, rerun the LAN diagnostics:
```bash
./scripts/doctor.sh
```
The script repeats the DNS, port, and HTTPS checks that the installer performs automatically.

If you edited configuration files, follow up with:
```bash
./arrstack.sh --yes
```
This regenerates `.env` and restarts containers. Review the summary, then browse to `http://<LAN_IP>:8080` to confirm everything loads.

## See also
- [LAN DNS & network pre-start](lan-dns-network-setup.md)
- [Host DNS helper](host-dns-helper.md)
- [Local HTTPS and CA trust](https-and-ca.md)
- [Security notes](security-notes.md)

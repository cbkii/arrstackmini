# LAN DNS & Network Pre-Start (Router-distributed DNS on Raspberry Pi OS Bookworm)

This guide prepares your network so **every device on the LAN** reaches the stack’s WebUIs and APIs using hostnames like `*.home.arpa`.
It assumes the stack’s **`local_dns` container (dnsmasq)** will bind port **53** on the Pi and answer local names while forwarding other queries upstream.

---

## Assumptions & scope

- Hardware: **Raspberry Pi 5 (aarch64)** on **Raspberry Pi OS Bookworm**.
- Host IP: **192.168.1.50** reserved via DHCP or set manually.
- Project config: `LAN_DOMAIN_SUFFIX="home.arpa"`, `DNS_DISTRIBUTION_MODE="router"`, `LAN_IP="192.168.1.50"`.
- Router control: you can edit DHCP Option 6 (IPv4 DNS) and, if you run IPv6, RDNSS/DNSSL or DHCPv6 DNS options.
- Goal: the router tells clients “use the Pi first for DNS,” while the Pi keeps clean upstream resolvers so Docker image pulls and recursive lookups succeed during install.

---

## 0. Update the project configuration

Copy the example configuration if you have not already created `~/srv/userr.conf` (or `${ARR_BASE}/userr.conf` if you exported a different base):

```bash
cp arrconf/userr.conf.example ../userr.conf
```

Open the file and set the Pi details:

```bash
nano ~/srv/userr.conf
```

Use the reserved LAN IP and suffix so the stack renders the correct DNS records and service URLs:

```bash
LAN_IP=192.168.1.50
LAN_DOMAIN_SUFFIX=home.arpa
DNS_DISTRIBUTION_MODE=router
```

If you cannot modify the router and must keep per-device overrides, change `DNS_DISTRIBUTION_MODE` to `per-device` and follow your platform’s manual DNS instructions instead of the router steps below. The remaining guidance assumes the router will distribute DNS.

## 1. Router: advertise the Pi as DNS (with fallback)

1. **Reserve the Pi’s address.** Create a static DHCP lease mapping the Pi’s MAC to `192.168.1.50`.
2. **Publish DNS servers in order of preference.**
   - **IPv4:** set **DHCP Option 6** to `192.168.1.50` **first**, then a fallback such as `1.1.1.1`. Clients typically query servers in list order.
   - **IPv6 (if enabled):** enable **RDNSS/DNSSL** or DHCPv6 DNS options with the Pi’s IPv6 address first, followed by any public fallback. Remove stale link-local DNS entries if your router adds them automatically.
3. **Renew leases on a few clients.** Reboot or trigger DHCP renew (`ipconfig /renew`, `nmcli dev disconnect/connect`, etc.) so they learn the Pi as primary DNS. Clients often cache old DNS servers until renewal.

Once the stack is installed, those clients will resolve `*.home.arpa` locally and recurse upstream for everything else.

### Router UI quick reference

Interfaces differ, but these examples show how the Pi’s DNS address maps onto common router forms.

**Generic DHCP form**

1. Open the router admin page (often `http://192.168.1.1`).
2. Sign in with administrator credentials.
3. Navigate to **LAN**, **Network**, or **DHCP Server** settings.
4. Fill the form with:
   - **Primary DNS** → `192.168.1.50`
   - **Secondary DNS** → `1.1.1.1` (or your preferred public resolver)
   - **Domain Name / Default Domain** → leave blank
5. Save the page and reconnect clients so they receive the new lease.

**TP-Link VX230v (ISP firmware)**

1. Go to **Advanced → Network → LAN Settings → DHCP Server**.
2. Set:
   - **Primary DNS** = `192.168.1.50`
   - **Secondary DNS** = `1.1.1.1`
   - **Domain Name** = leave empty
3. Save changes.

**Fritz!Box**

1. Open **Home Network → Network → Network Settings**.
2. Choose **IPv4 Addresses** and click **Edit**.
3. Enter:
   - **Preferred DNSv4 server** = `192.168.1.50`
   - **Alternative DNSv4 server** = `1.1.1.1`
4. Leave the **Local DNS domain name** field blank.
5. Apply and restart affected clients.

**Netgear Nighthawk**

1. Visit **Advanced → Setup → LAN Setup**.
2. Under **Address Reservation**, reserve the Pi at `192.168.1.50` first.
3. In **LAN TCP/IP Setup**, set:
   - **Primary DNS** = `192.168.1.50`
   - **Secondary DNS** = `1.1.1.1`
   - Leave **Domain Name** blank
4. Click **Apply**.

---

## 2. Pi setup (NetworkManager) — keep 192.168.1.50 stable and DNS predictable

> Bookworm uses **NetworkManager (NM)** by default. NM should own the interface configuration and `/etc/resolv.conf`. Manual edits to `/etc/resolv.conf` are temporary because NM rewrites the file whenever a connection changes.

### 2.1 Identify the connection and confirm the IP

```bash
nmcli connection show
ip -4 addr show eth0
```

You should see `192.168.1.50/24` assigned to `eth0`. Note the connection name (commonly `"Wired connection 1"`).

### 2.2 Choose how NM assigns IPv4

**Preferred: DHCP with explicit DNS fallback** — relies on the router lease while pinning upstream resolvers until `local_dns` is online.

```bash
sudo nmcli connection modify "Wired connection 1" ipv4.method auto
sudo nmcli connection modify "Wired connection 1" ipv4.ignore-auto-dns yes
sudo nmcli connection modify "Wired connection 1" ipv4.dns "1.1.1.1 8.8.8.8"
sudo nmcli connection up "Wired connection 1"
```

**Optional: Manual static** — use only if the router cannot lock the lease reliably.

```bash
sudo nmcli connection modify "Wired connection 1" \
  ipv4.method manual ipv4.addresses 192.168.1.50/24 \
  ipv4.gateway 192.168.1.1 ipv4.dns "1.1.1.1 8.8.8.8" ipv4.ignore-auto-dns yes
sudo nmcli connection up "Wired connection 1"
```

If you use IPv6, mirror the approach with `ipv6.method auto` (or `manual`) and set `ipv6.ignore-auto-dns yes` plus an explicit list that leads with the Pi and includes a fallback.

### 2.3 Ensure NM manages `/etc/resolv.conf`

```bash
ls -l /etc/resolv.conf
```

If the path is a stub (for example, points to `systemd-resolved`), force NM control:

```bash
echo -e "[main]\ndns=default" | sudo tee /etc/NetworkManager/conf.d/dns.conf >/dev/null
sudo systemctl restart NetworkManager
```

Re-check NM’s view of DNS:

```bash
nmcli -g IP4.DNS,IP6.DNS device show eth0
cat /etc/resolv.conf
```

> **Note for netboot or externally managed interfaces:** some Pi netboot images mark `eth0` as “externally managed,” preventing NM from touching `/etc/resolv.conf`. Clear any `managed=false` flags (for example with `nmcli connection modify eth0 connection.autoconnect yes`) so NM updates the resolver as expected.

Remove any unwanted link-local nameservers from the NM connection if they appear; they can slow lookups before `local_dns` starts.

### 2.4 Free port 53 for the container

```bash
sudo ss -ulpn | grep ':53' || echo "port 53 is free"
```

If a service is holding the port (commonly `systemd-resolved` or a host `dnsmasq`), disable it before installation:

```bash
sudo systemctl disable --now systemd-resolved 2>/dev/null || true
sudo systemctl disable --now dnsmasq 2>/dev/null || true
```

`local_dns` will bind `192.168.1.50:53` once the stack is running; nothing else on the host should occupy that port.

---

## 3. Verify host DNS before installation

Docker pulls and the installer itself rely on external resolution. Confirm upstream DNS works **before** running `arrstack.sh`:

```bash
cat /etc/resolv.conf
ping -c1 google.com
```

Adjust NM DNS settings if queries fail or unexpected nameservers appear. Docker’s embedded DNS forwards to these host resolvers, so clean results here prevent downstream container issues.

---

## 4. Install the stack

```bash
cd ~/srv/arrstackmini
./arrstack.sh --yes
```

The installer renders `docker-compose.yml`, validates it with `docker compose config -q`, and starts services. The `local_dns` container (dnsmasq) becomes authoritative for `*.home.arpa` and forwards other lookups to the upstream resolvers you configured.

---

## 5. Post-install checks (from LAN clients and the host)

1. **Client DNS list:** after a lease renew, confirm `192.168.1.50` is the first DNS server on a few devices.
2. **Authoritative responses:**

   ```bash
   dig @192.168.1.50 qbittorrent.home.arpa
   dig @192.168.1.50 sonarr.home.arpa
   ```

   Expect A/AAAA records pointing to your Pi (or the reverse proxy). If you changed the suffix, adjust the queries accordingly.

   ```bash
   nslookup qbittorrent.home.arpa
   ```

   The DNS server in the reply should list `192.168.1.50`, confirming clients are using the Pi first.

3. **Recursive lookups via the Pi:**

   ```bash
   dig @192.168.1.50 google.com
   ```

4. **From a container:**

   ```bash
   docker exec -it caddy getent hosts google.com
   ```

   Replace `caddy` with any running container to prove Docker → host DNS forwarding works.

5. **Open WebUIs:** visit `https://qbittorrent.home.arpa` (and others). Trust the stack’s local CA or accept the initial warning so HTTPS works smoothly on subsequent visits.

---

## 6. Troubleshooting checklist

- **Clients still show router DNS:** confirm the router puts `192.168.1.50` first, then renew the client lease. Some routers require saving twice or rebooting before DHCP changes apply.
- **Port 53 conflicts:** re-run the port check and disable any host resolver still active. The installer will skip `local_dns` if the port is busy.
- **`/etc/resolv.conf` keeps changing unexpectedly:** revisit NM settings rather than editing the file directly. Ensure no other service (for example, `resolvconf`) is managing it.
- **IPv6-only clients slow to resolve:** prune link-local DNS servers from NM and ensure the router’s RDNSS advertises the Pi first.
- **Client using DNS-over-TLS/DoH:** disable Private DNS on Android or other encrypted resolver profiles so queries stay on the LAN.
- **Pi IP drifted:** confirm the DHCP reservation still maps the Pi’s MAC to `192.168.1.50` so hostnames and leases match.
- **Containers cannot resolve the internet:** verify `cat /etc/resolv.conf` shows reachable upstream resolvers and consider adding a Docker daemon fallback.
- **Local names fail:** check `docker ps` to ensure `local_dns` is running, then inspect logs with `docker logs local_dns`.

---

## 7. Optional enhancements

- **Docker daemon DNS fallback:** create or edit `/etc/docker/daemon.json` so containers prefer the Pi but retain a public fallback:

  ```json
  {
    "dns": ["192.168.1.50", "1.1.1.1"]
  }
  ```

  Restart the Docker daemon after changing this file.
- **`arrstack.sh doctor --lan`:** extend the doctor command to check NM status, port 53 availability, `local_dns` health, and run sample `dig` queries.
- **Preflight script:** add a helper that validates resolver state, port 53 ownership, and router Option 6 guidance before the main installer runs.
- **Router cookbook:** collect screenshots for popular router UIs showing where to configure Option 6 and RDNSS/DNSSL.
- **Client self-test page:** serve a static page via Caddy listing diagnostic commands and direct WebUI links.

---

## Appendix — quick NM reset for upstream DNS

Set `CONN` to your actual NM connection name, then:

```bash
CONN="Wired connection 1"
sudo nmcli con mod "$CONN" ipv4.method auto ipv4.ignore-auto-dns yes
sudo nmcli con mod "$CONN" ipv4.dns "1.1.1.1 8.8.8.8"
echo -e "[main]\ndns=default" | sudo tee /etc/NetworkManager/conf.d/dns.conf >/dev/null
sudo systemctl restart NetworkManager
```

---

## See also

- [Config reference](config.md)
- [Host DNS helper](host-dns-helper.md)
- [HTTPS and local CA guidance](https-and-ca.md)
- [Troubleshooting](troubleshooting.md)

After you confirm `local_dns` is healthy, you may remove the explicit upstreams if the router reliably advertises the Pi and a fallback via DHCP.


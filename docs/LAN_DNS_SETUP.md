# LAN DNS setup guide

Configure your home network so every device uses your arrstack-mini host for LAN service lookups while still falling back to the public Internet when needed. These steps target beginners and use the default variables from `arrconf/userconf.defaults.sh`:

- `LAN_IP=192.168.1.50` – static IP of the Raspberry Pi running arrstack-mini.
- `LAN_DOMAIN_SUFFIX=home.arpa` – RFC 8375 home-LAN domain used by the stack.
- `DNS_DISTRIBUTION_MODE=router` – tells the installer and docs you are distributing DNS via router DHCP.

If your router cannot advertise custom DNS servers, skip to [Unable to change router DNS?](#10-unable-to-change-router-dns) for per-device guidance.

If your environment differs, substitute the equivalent values.

---

## 1. Reserve your Pi's IP address

1. Connect to your router's admin page (commonly `http://192.168.1.1` or the address listed on the router label).
2. Sign in with the administrator credentials.
3. Locate **Address Reservation**, **Static DHCP**, or **Client List**.
4. Reserve the Raspberry Pi's MAC address to the IP in `LAN_IP` (default `192.168.1.50`).

> **Why:** DHCP reservation ensures the Pi keeps the same LAN IP so clients never learn an outdated DNS address.

---

## 2. Open the DHCP / LAN settings page

1. In the router menu, look for **LAN**, **Network**, or **Advanced** settings.
2. Choose **DHCP Server**, **LAN Setup**, or similar wording. On TP-Link VX230v firmware the path is `Advanced → Network → LAN Settings → DHCP Server`.

If your router exposes separate **WAN** and **LAN** DNS forms, only change the **LAN DHCP** section. Leave WAN DNS alone to preserve Internet connectivity.

---

## 3. Enter DNS servers in the correct order

1. Set **Primary DNS** (sometimes labelled *DNS 1* or *Preferred DNS*) to your Pi's IP (`LAN_IP`).
2. Set **Secondary DNS** (a.k.a. *DNS 2* or *Alternate DNS*) to a public resolver that already works in your home, for example Cloudflare `1.1.1.1` or Google `8.8.8.8`.
3. Leave additional DNS boxes blank unless your ISP requires them.

> **Why:** The router instructs clients to query the Pi first so hostnames like `qbittorrent.home.arpa` resolve locally. If the Pi is offline, devices automatically fall back to the public resolver and keep Internet access.

---

## 4. Clear any default domain suffix

1. Find a field called **Default Domain**, **DNS Suffix**, or **Domain Name**.
2. Leave it empty (recommended). Do **not** set `.local`; that suffix is reserved for mDNS and causes conflicts on macOS, iOS, and recent Windows versions.

arrstack-mini already provides the safe suffix from `LAN_DOMAIN_SUFFIX` (`home.arpa` by default), so no router override is required.

---

## 5. Save and restart clients

1. Click **Save** or **Apply** on the router page.
2. Reboot or reconnect your laptops, phones, and TVs so they receive the refreshed DHCP lease containing the new DNS servers. Power-cycling the router is **not** necessary.

---

## 6. Verify from a client device

After a device reconnects, open a terminal (Command Prompt on Windows, Terminal on macOS/Linux) and run:

```bash
nslookup qbittorrent.home.arpa
```

Check the output:

- **Server** (or **Address**) should report your Pi's IP (for example `192.168.1.50`).
- The answer should resolve to the same IP.

If the command shows your ISP DNS or fails to resolve, renew the DHCP lease (`ipconfig /renew` on Windows, toggle Wi-Fi off/on on mobile) and ensure the DNS order in step 3 is correct.

---

## 7. TP-Link VX230v example

TP-Link's ISP-customised firmware labels the inputs slightly differently. Use these mappings:

1. Go to `Advanced → Network → LAN Settings`.
2. Under **DHCP Server**, set:
   - **Primary DNS** = `192.168.1.50` (your Pi).
   - **Secondary DNS** = `1.1.1.1` (or your preferred public resolver).
3. Leave **Domain Name** blank.
4. Save the page and reconnect your clients.

---

## 8. Common pitfalls

- **Primary/secondary reversed:** If a public resolver remains in the first slot, clients will never contact your Pi and LAN hostnames will fail.
- **Android Private DNS enabled:** Set **Settings → Network & Internet → Internet → (gear icon) → Private DNS** to **Off** or **Automatic**; a hostname forces DNS-over-TLS and bypasses your LAN DNS.
- **systemd-resolved still bound to port 53 on the Pi:** Run `./scripts/host-dns-setup.sh` on the host to disable the stub listener and write `/etc/resolv.conf` with your upstream DNS pair.
- **Pi address not reserved:** Without DHCP reservation the Pi may obtain a new IP, breaking the mapping advertised to clients.

---

## 9. Link to `userconf`

After confirming the router path works in your environment:

1. Copy `arrconf/userconf.sh.example` to `arrconf/userconf.sh` if you have not already done so.
2. Set the variables to match your network:

   ```bash
   LAN_IP=192.168.1.50
   LAN_DOMAIN_SUFFIX=home.arpa
   DNS_DISTRIBUTION_MODE=router
   ```

3. Rerun `./arrstack.sh` (or `./arrstack.sh --yes`) so the installer re-renders `.env` with the updated values.
4. Optionally run `./scripts/doctor.sh` to confirm UDP/TCP DNS and the CA download succeed.

---

## 10. Unable to change router DNS?

Some ISP routers lock down DHCP DNS. If you cannot change the settings above, fall back to per-device DNS:

1. Set `DNS_DISTRIBUTION_MODE=per-device` in `arrconf/userconf.sh`.
2. Manually configure each important client (Android/PC/TV) with DNS=`192.168.1.50` and keep Android Private DNS Off/Automatic.
3. The rest of this guide still applies when you migrate to a configurable router.

---

Following these steps ensures LAN devices resolve `*.home.arpa` through arrstack-mini while retaining reliable Internet connectivity via the secondary resolver.

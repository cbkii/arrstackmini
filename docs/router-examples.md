← [Back to Start](../README.md)

# Router configuration examples

Follow these patterns when editing DHCP pages on common home routers.

## Why
Seeing field names in advance makes it easier to map the Pi’s IP into the right boxes without guessing.

## Do
### Generic DHCP form
1. Open your router admin page (often `http://192.168.1.1`).
2. Sign in with the administrator credentials.
3. Navigate to **LAN**, **Network**, or **DHCP Server** settings.
4. Fill the form using this mapping:
   - **Primary DNS** → `192.168.1.50`
   - **Secondary DNS** → `1.1.1.1` (or your preferred public resolver)
   - **Domain Name / Default Domain** → leave blank
5. Save the page and reconnect clients so they receive the new lease.

### TP-Link VX230v (ISP firmware)
<screenshot-placeholder: tplink-vx230v-dhcp.png>
1. Go to **Advanced → Network → LAN Settings → DHCP Server**.
2. Set:
   - **Primary DNS** = `192.168.1.50`
   - **Secondary DNS** = `1.1.1.1`
   - **Domain Name** = leave empty
3. Save changes.

### Fritz!Box
<screenshot-placeholder: fritzbox-dhcp.png>
1. Open **Home Network → Network → Network Settings**.
2. Choose **IPv4 Addresses** and click **Edit**.
3. Enter:
   - **Preferred DNSv4 server** = `192.168.1.50`
   - **Alternative DNSv4 server** = `1.1.1.1`
4. Leave the **Local DNS domain name** field blank.
5. Apply and restart affected clients.

### Netgear Nighthawk
<screenshot-placeholder: netgear-dhcp.png>
1. Visit **Advanced → Setup → LAN Setup**.
2. Under **Address Reservation**, reserve the Pi at `192.168.1.50` first.
3. In **LAN TCP/IP Setup**, set:
   - **Primary DNS** = `192.168.1.50`
   - **Secondary DNS** = `1.1.1.1`
   - Leave **Domain Name** blank
4. Click **Apply**.

## Verify
Renew the DHCP lease on a client and run:
```bash
nslookup qbittorrent.home.arpa
```
The server address should be `192.168.1.50`. If not, double-check the saved settings or reboot the router if it caches the old lease list.

## See also
- [LAN DNS distribution](lan-dns.md)
- [Host DNS helper](host-dns-helper.md)
- [Local HTTPS and CA trust](https-and-ca.md)
- [Troubleshooting](troubleshooting.md)

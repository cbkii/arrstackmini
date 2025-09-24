← [Back to Start](../README.md)

# Local HTTPS and CA trust

This guide shows how to trust the stack’s local certificate authority so browsers accept `https://` on your LAN.

## Why
Caddy creates a private certificate authority (CA) for `*.home.arpa`. Importing its root certificate stops browser warnings while keeping the private keys on the Pi.

## Do
1. **Fetch the public root certificate.** Use HTTP for the first download:
   ```bash
   curl -o root.crt http://ca.home.arpa/root.crt
   ```
   Only the public `root.crt` file is served from `caddy/ca-pub`. Never expose the rest of the Caddy PKI directory.
2. **Import the certificate on your devices.**
   - **Windows:** Open **Manage user certificates → Trusted Root Certification Authorities → Certificates → Action → All Tasks → Import** and choose `root.crt`.
   - **macOS:** Open **Keychain Access**, drag `root.crt` into **System**, then double-click it and set **When using this certificate → Always Trust**.
   - **Linux (system-wide):**
     ```bash
     sudo cp root.crt /usr/local/share/ca-certificates/arrstackmini-root.crt
     sudo update-ca-certificates
     ```
   - **Android:** Transfer `root.crt` to the device, then go to **Settings → Security → Encryption & credentials → Install a certificate → CA certificate** and select the file.
   - **iOS/iPadOS:** Email or AirDrop `root.crt`, install the profile, then enable full trust under **Settings → General → About → Certificate Trust Settings**.
3. **Store the file safely.** Keep `root.crt` in your password manager or a trusted share so you can reinstall it quickly on new devices.

On Debian or Ubuntu, run `./scripts/install-caddy-ca.sh` to copy the certificate into `/usr/local/share/ca-certificates` and refresh the trust store automatically (the script escalates with `sudo`).【F:scripts/install-caddy-ca.sh†L1-L118】 Use `./scripts/export-caddy-ca.sh ~/Downloads/arrstack-root.crt` when you just need to copy the public root certificate to another machine with the correct permissions.【F:scripts/export-caddy-ca.sh†L1-L35】

## Verify
Open a browser and visit:
```
https://qbittorrent.home.arpa
```
You should see the lock icon without warnings. For a command-line check:
```bash
curl -I https://qbittorrent.home.arpa
```
The response should show `HTTP/1.1 200 OK` (or `301` if Caddy redirects you to HTTPS).

If you still see warnings, confirm the certificate was imported into the correct trust store and that the device is using the LAN DNS resolver.

## See also
- [LAN DNS distribution](lan-dns.md)
- [Security notes](security-notes.md)
- [Troubleshooting](troubleshooting.md)
- [Router examples](router-examples.md)

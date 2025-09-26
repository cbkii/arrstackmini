# Port Troubleshooting Guide

This guide covers common port conflicts and resolution strategies for arrstackmini.

## Overview

Arrstackmini uses several ports for its services:

- **8000**: Gluetun VPN control API (TCP, localhost only)
- **53**: Local DNS server (TCP/UDP, LAN IP) - when `ENABLE_LOCAL_DNS=1`
- **80/443**: Caddy reverse proxy (TCP, LAN IP) - when `EXPOSE_DIRECT_PORTS=1`
- **Service ports**: qBittorrent, Sonarr, Radarr, etc. (LAN IP) - when `EXPOSE_DIRECT_PORTS=1`

## Enhanced Port Conflict Detection

Arrstackmini now includes advanced port conflict detection with:

### Multi-Source Detection
- **ss command**: Primary network monitoring tool
- **lsof command**: Fallback for older systems
- **/proc/net**: Basic fallback when tools unavailable
- **Docker inspection**: Containers with compose project/service info
- **systemd-resolved**: Special handling for DNS conflicts on port 53

### Debounced Snapshots
- Takes two snapshots 1 second apart
- Only reports persistent conflicts (reduces false positives)
- Special handling for arrstack containers (includes even if transient)

### Strict Classification
Processes are classified as:
- **arrstack**: Based on compose project name, service names, or known executables
- **systemd-resolved**: PID-verified system DNS resolver
- **other**: Everything else requiring manual attention

## Environment Variables

### Debug and Tracing
```bash
# Enable structured debug logging to logs/port-scan-YYYYMMDD.jsonl
export ARRSTACK_DEBUG_PORTS=1

# Also output debug info to stderr in real-time
export ARRSTACK_PORT_TRACE=1

# Use legacy port detection (pre-enhancement behavior)
export ARRSTACK_LEGACY_PORTCHECK=1
```

### Usage Examples
```bash
# Debug port conflicts during installation
ARRSTACK_DEBUG_PORTS=1 ./arrstack.sh

# Full tracing with real-time output
ARRSTACK_DEBUG_PORTS=1 ARRSTACK_PORT_TRACE=1 ./arrstack.sh

# Use old detection method if needed
ARRSTACK_LEGACY_PORTCHECK=1 ./arrstack.sh
```

## Interactive Resolution Options

When port conflicts are detected, you'll see an enhanced menu:

### Standard Options
1. **Edit ports**: Pause installation to manually configure ports in `userconf.sh`
2. **Stop existing arrstack**: Automatically stop arrstack containers and continue
3. **Use existing services**: Cancel installation, keep current services running

### Advanced Options
4. **Force stop/kill**: ⚠️ **DANGEROUS** - Force-kill non-arrstack processes
5. **Contextual auto-remediation**: Smart resolution based on conflict type

### Utility Options
- **D**: Toggle detailed diagnostics display
- **R**: Rescan port conflicts (useful after manual changes)

## Contextual Auto-Remediation (Option 5)

Smart resolution strategies based on conflict analysis:

### DNS Conflicts (Port 53)
- **Option A**: Disable local DNS (`ENABLE_LOCAL_DNS=0`)
- **Option B**: Host DNS takeover (replace systemd-resolved with arrstack DNS)

### Gluetun Control Port Conflicts (Port 8000)
- **Option C**: Auto-find alternative port (scans 8001-8020)

These changes are applied temporarily for the current installation. To make permanent, update `userconf.sh`.

## Non-Interactive Mode (--yes)

Enhanced `--yes` behavior:

### Auto-Resolution
- **All conflicts are arrstack**: Automatically stops arrstack and continues
- **Mixed or non-arrstack conflicts**: Outputs JSON conflict details and fails

### JSON Output Format
When `--yes` fails due to non-arrstack conflicts:
```json
{"port":53,"protocol":"udp","label":"Local DNS (UDP)","host":"*","description":"systemd-resolved (pid 1234)","classification":"other"}
{"port":8000,"protocol":"tcp","label":"Gluetun control API","host":"127.0.0.1","description":"some-app (pid 5678)","classification":"other"}
```

## Common Port Conflicts

### Port 53 (DNS)

**systemd-resolved** is the most common conflict:

```bash
# Option 1: Disable local DNS
echo 'ENABLE_LOCAL_DNS=0' >> arrconf/userconf.sh

# Option 2: Use host DNS takeover (if available)
# This replaces systemd-resolved with arrstack DNS
./scripts/host-dns-setup.sh

# Option 3: Force kill (DANGEROUS)
sudo systemctl stop systemd-resolved
sudo systemctl disable systemd-resolved
```

**Other DNS servers** (dnsmasq, unbound, etc.):
- Stop the conflicting service
- Change its port configuration
- Use arrstack's contextual resolution

### Port 8000 (Gluetun Control)

**Web servers or development tools**:
```bash
# Change Gluetun control port
echo 'GLUETUN_CONTROL_PORT=8001' >> arrconf/userconf.sh

# Or use auto-detection (Option 5C in menu)
```

### Ports 80/443 (Caddy)

Only relevant when `EXPOSE_DIRECT_PORTS=1`:
```bash
# Disable direct port exposure
echo 'EXPOSE_DIRECT_PORTS=0' >> arrconf/userconf.sh

# Or stop conflicting web server
sudo systemctl stop apache2  # or nginx
```

## Debugging Port Issues

### View Debug Logs
```bash
# Enable debug logging
export ARRSTACK_DEBUG_PORTS=1

# Run installation
./arrstack.sh

# View structured logs
cat ~/srv/arrstack/logs/port-scan-$(date +%Y%m%d).jsonl | jq .
```

### Manual Port Checking
```bash
# Check specific port
ss -lntp | grep :8000
lsof -iTCP:8000 -sTCP:LISTEN

# Docker containers
docker ps --format "table {{.Names}}\t{{.Ports}}"
```

### systemd-resolved Specific
```bash
# Check systemd-resolved status
systemctl status systemd-resolved

# Get PID
systemctl show systemd-resolved --property MainPID --value

# Check what it's listening on
ss -lnp | grep "$(systemctl show systemd-resolved --property MainPID --value)"
```

## Port Configuration Best Practices

### Planning Port Usage
1. **Survey existing services**: Check what's already running
2. **Document port assignments**: Keep track in `userconf.sh` comments
3. **Use high ports**: Avoid well-known ports (< 1024) when possible
4. **Group by function**: Keep related services on consecutive ports

### Example userconf.sh
```bash
# Port configuration - checked 2024-01-01
GLUETUN_CONTROL_PORT=8001          # Default 8000 conflicts with dev server
QBT_HTTP_PORT_HOST=8080            # Default, no conflicts
SONARR_PORT=8989                   # Default, no conflicts
RADARR_PORT=7878                   # Default, no conflicts

# DNS configuration
ENABLE_LOCAL_DNS=0                 # Disabled due to systemd-resolved conflict
# Alternative: Use host DNS takeover instead

# Direct ports disabled to avoid Caddy conflicts
EXPOSE_DIRECT_PORTS=0              # Nginx already uses 80/443
```

## Legacy Fallback

If the enhanced detection causes issues:

```bash
# Use old detection method
export ARRSTACK_LEGACY_PORTCHECK=1
./arrstack.sh
```

This restores the original fuzzy-matching behavior and simpler conflict resolution.

## Getting Help

1. **Enable debug logging** (`ARRSTACK_DEBUG_PORTS=1`)
2. **Check the logs** in `~/srv/arrstack/logs/`
3. **Use diagnostics mode** (Option D in conflict menu)
4. **Try legacy mode** if enhanced detection fails
5. **Report issues** with debug logs attached

## Security Considerations

### Force Kill (Option 4)
- ⚠️ **Can cause data loss** - processes may have unsaved work
- ⚠️ **System instability** - critical services may be killed
- Requires explicit confirmation tokens
- All actions are logged for audit

### DNS Takeover (Option 5B)
- Replaces system DNS resolver
- May affect system behavior
- Reversible with rollback script
- Requires root privileges

### In-Memory Overrides
- Temporary for current installation only
- Don't persist across sessions
- Safe for testing configurations
- Update `userconf.sh` to make permanent
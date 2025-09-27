← [Back to Start](../README.md)

# ProtonVPN P2P Port Forwarding Guide

Enhanced port forwarding support with automatic P2P server selection and comprehensive diagnostics.

## Why

ProtonVPN port forwarding requires specific P2P-enabled servers. Using random servers often results in NAT-PMP timeout errors and failed port forwarding. This guide helps you reliably get working forwarded ports.

## Quick Fix

If port forwarding isn't working, run these commands:

```bash
# Check current status and get diagnostics
arr.vpn.troubleshoot

# Get recommended P2P servers for your country
arr.vpn.p2p config Netherlands 3

# Add the output to your userr.conf and restart
echo 'SERVER_HOSTNAMES="nl-01.protonvpn.com,nl-02.protonvpn.com,nl-03.protonvpn.com"' >> ~/srv/userr.conf
docker restart gluetun
```

## Understanding the Problem

### NAT-PMP Timeout Errors
When you see logs like:
```
connection timeout to 10.16.0.1:5351 during NAT-PMP negotiation
```

This indicates:
1. **Wrong server type**: You're connected to a non-P2P server
2. **Network routing issues**: NAT-PMP traffic is blocked
3. **Server overload**: P2P server is too busy to respond

### Server Selection Issues
- `SERVER_COUNTRIES=Netherlands` doesn't guarantee P2P servers
- ProtonVPN has many servers per country, not all support P2P
- Random server selection often picks non-P2P servers

## P2P Server Management

### List Available P2P Servers
```bash
# List P2P servers for specific country
arr.vpn.p2p list Netherlands 10

# List all P2P servers (limited to 10)
arr.vpn.p2p list
```

Output shows:
- Server names (for SERVER_HOSTNAMES)
- Current load percentage
- Server scores
- Domain names

### Generate Configuration
```bash
# Generate SERVER_HOSTNAMES for top 3 P2P servers
arr.vpn.p2p config Netherlands 3

# Output: SERVER_HOSTNAMES=nl-01.protonvpn.com,nl-02.protonvpn.com,nl-03.protonvpn.com
```

### Refresh Server Cache
```bash
# Update server list from ProtonVPN API
arr.vpn.p2p refresh
```

Server cache is stored in `${ARR_DOCKER_DIR}/gluetun/p2p-servers.json` and refreshes automatically every 24 hours.

## Configuration Options

### User Configuration (`~/srv/userr.conf`)

```bash
# Traditional country-based selection (may pick non-P2P servers)
SERVER_COUNTRIES="Netherlands,Switzerland"

# Explicit P2P server selection (recommended for reliable port forwarding)
SERVER_HOSTNAMES="nl-01.protonvpn.com,nl-02.protonvpn.com,nl-03.protonvpn.com"

# Port forwarding retry settings
PF_MAX_TOTAL_WAIT="120"           # Total wait time before giving up
PF_MAX_SERVER_RETRIES="3"         # Number of server rotations to attempt
PF_CYCLE_AFTER="45"               # Seconds before trying OpenVPN restart
```

### Priority Order
1. `SERVER_HOSTNAMES` takes precedence over `SERVER_COUNTRIES`
2. If `SERVER_HOSTNAMES` is set, `SERVER_COUNTRIES` is ignored by Gluetun
3. Empty `SERVER_HOSTNAMES` falls back to `SERVER_COUNTRIES`

## Diagnostics and Troubleshooting

### Comprehensive Diagnostics
```bash
# Run all port forwarding tests
arr.vpn.troubleshoot

# Individual test categories
arr.vpn.diag connectivity  # Test Gluetun API access
arr.vpn.diag vpn          # Check VPN connection
arr.vpn.diag pf           # Test port forwarding status
arr.vpn.diag natpmp       # Test NAT-PMP connectivity
arr.vpn.diag p2p          # Check if current server supports P2P
arr.vpn.diag network      # Test Docker networking
arr.vpn.diag firewall     # Check firewall rules
```

### Understanding Diagnostic Output

#### ✅ Success Indicators
- **VPN connected**: Shows exit IP and country
- **Port forwarding active**: Shows forwarded port number
- **NAT-PMP gateway reachable**: Can connect to 10.16.0.1:5351
- **Current server supports P2P**: Server is in P2P server list

#### ❌ Failure Indicators
- **VPN connection status unknown**: Gluetun not running or misconfigured
- **Port forwarding not active**: No port assigned or NAT-PMP failed
- **Cannot reach NAT-PMP gateway**: Server doesn't support P2P or network issues
- **Current server may not support P2P**: Need to switch to P2P servers

### Common Issues and Fixes

#### Issue: "connection timeout to 10.16.0.1:5351"
**Cause**: Connected to non-P2P server
**Fix**: Use explicit P2P servers
```bash
arr.vpn.p2p config Netherlands 3 >> ~/srv/userr.conf
docker restart gluetun
```

#### Issue: Port forwarding reports 0
**Cause**: Multiple possible causes
**Fix**: Run diagnostics to identify root cause
```bash
arr.vpn.troubleshoot
# Follow the specific recommendations in the output
```

#### Issue: Port forwarding works initially then fails
**Cause**: Server rotation picked non-P2P server
**Fix**: Pin to known P2P servers to prevent rotation
```bash
# Use SERVER_HOSTNAMES instead of SERVER_COUNTRIES
arr.vpn.p2p config > ~/srv/userr.conf
```

## Advanced Configuration

### Custom OpenVPN Configuration
For advanced users who need custom OpenVPN settings:

```yaml
# In docker-compose.yml environment section
OPENVPN_CUSTOM_CONFIG: |
  # Enhanced NAT-PMP settings
  script-security 2
  up /gluetun/scripts/port-forward-up.sh
  down /gluetun/scripts/port-forward-down.sh
```

### Firewall Rules
Ensure NAT-PMP traffic isn't blocked:

```bash
# Check current firewall input ports
echo $GLUETUN_FIREWALL_INPUT_PORTS

# Add NAT-PMP port if needed (usually automatic)
GLUETUN_FIREWALL_INPUT_PORTS="5351/udp,${existing_ports}"
```

### Multiple Country Support
```bash
# Get P2P servers for multiple countries
arr.vpn.p2p config Netherlands 2  # Get 2 from Netherlands
arr.vpn.p2p config Switzerland 2  # Get 2 from Switzerland

# Manually combine in userr.conf:
SERVER_HOSTNAMES="nl-01.protonvpn.com,nl-02.protonvpn.com,ch-01.protonvpn.com,ch-02.protonvpn.com"
```

## Monitoring and Maintenance

### Regular Health Checks
```bash
# Check port forwarding status
arr.vpn.port

# Full VPN status including location
arr.vpn.status

# Monitor logs for issues
docker logs gluetun --tail 50 | grep -i "port\|natpmp\|forward"
```

### Automated Server Rotation
The enhanced port forwarding logic automatically:
1. Tries current configuration first
2. Rotates to different P2P servers on timeout
3. Reports which servers were attempted
4. Suggests manual fixes if all attempts fail

### Server Cache Maintenance
```bash
# Check cache age
ls -la ${ARR_DOCKER_DIR}/gluetun/p2p-servers.json

# Force refresh if needed
arr.vpn.p2p refresh

# View cached server count
jq length ${ARR_DOCKER_DIR}/gluetun/p2p-servers.json
```

## Integration with Existing Tools

### qBittorrent Port Sync
```bash
# Sync qBittorrent listen port with forwarded port
arr.qbt.port.sync

# Check current qBittorrent port
arr.qbt.port.get
```

### Arr Services
The forwarded port is automatically:
- Written to `${ARR_DOCKER_DIR}/gluetun/forwarded_port`
- Updated in qBittorrent via the update hook
- Available to other containers in the Docker network

### Monitoring Integration
```bash
# Add to cron for regular checks
*/15 * * * * cd /path/to/arrstack && arr.vpn.diag pf >/dev/null || logger -t arrstack "Port forwarding check failed"
```

## Troubleshooting Checklist

When port forwarding fails:

1. **Check VPN connection**: `arr.vpn.status`
2. **Run comprehensive diagnostics**: `arr.vpn.troubleshoot`
3. **Verify P2P server usage**: `arr.vpn.diag p2p`
4. **Test NAT-PMP connectivity**: `arr.vpn.diag natpmp`
5. **Check Gluetun logs**: `docker logs gluetun --tail 100`
6. **Switch to explicit P2P servers**: `arr.vpn.p2p config`
7. **Restart Gluetun**: `docker restart gluetun`
8. **Verify port assignment**: `arr.vpn.port`
9. **Sync with qBittorrent**: `arr.qbt.port.sync`

## API Reference

### P2P Server Commands
- `arr.vpn.p2p list [country] [limit]` - List P2P servers
- `arr.vpn.p2p config [country] [limit]` - Generate configuration
- `arr.vpn.p2p refresh` - Update server cache

### Diagnostic Commands  
- `arr.vpn.diag [test]` - Run specific or all diagnostics
- `arr.vpn.troubleshoot` - Comprehensive troubleshooting
- `arr.vpn.port.diag` - Quick port forwarding test

### Configuration Variables
- `SERVER_HOSTNAMES` - Explicit P2P server list (recommended)
- `PF_MAX_SERVER_RETRIES` - Server rotation attempts (default: 2)
- `PF_SERVER_CACHE_MAX_AGE` - Cache lifetime in seconds (default: 86400)

For more help, see [Troubleshooting](troubleshooting.md) or run `arr.help` for the complete command reference.
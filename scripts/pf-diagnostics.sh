#!/usr/bin/env bash
# shellcheck shell=bash
# Comprehensive ProtonVPN port forwarding diagnostics

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=scripts/common.sh
. "$SCRIPT_DIR/common.sh"

# shellcheck source=scripts/gluetun.sh
. "$SCRIPT_DIR/gluetun.sh"

msg() {
  printf '[pf-diag] %s\n' "$1" >&2
}

warn() {
  printf '[pf-diag][warn] %s\n' "$1" >&2
}

die() {
  printf '[pf-diag][error] %s\n' "$1" >&2
  exit 1
}

# Check if required commands are available
check_dependencies() {
  local -a missing_deps=()
  
  for cmd in curl jq docker; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      missing_deps+=("$cmd")
    fi
  done
  
  if ((${#missing_deps[@]} > 0)); then
    die "Missing required dependencies: ${missing_deps[*]}"
  fi
}

# Test basic Gluetun connectivity
test_gluetun_connectivity() {
  msg "Testing Gluetun control API connectivity..."
  
  local api_base
  api_base="$(_gluetun_control_base)"
  
  if ! gluetun_control_get "/v1/publicip/ip" >/dev/null 2>&1; then
    warn "Cannot connect to Gluetun control API at $api_base"
    warn "Check if Gluetun container is running and GLUETUN_API_KEY is correct"
    return 1
  fi
  
  msg "✅ Gluetun control API is accessible"
  return 0
}

# Get current VPN connection status
get_vpn_status() {
  msg "Checking VPN connection status..."
  
  local ip_payload
  if ip_payload=$(gluetun_control_get "/v1/publicip/ip" 2>/dev/null); then
    if gluetun_public_ip_details "$ip_payload"; then
      msg "✅ VPN connected: $GLUETUN_PUBLIC_IP"
      if [[ -n "${GLUETUN_PUBLIC_IP_COUNTRY:-}" ]]; then
        msg "   Country: $GLUETUN_PUBLIC_IP_COUNTRY"
      fi
      if [[ -n "${GLUETUN_PUBLIC_IP_HOSTNAME:-}" ]]; then
        msg "   Server: $GLUETUN_PUBLIC_IP_HOSTNAME"
      fi
      return 0
    fi
  fi
  
  warn "❌ VPN connection status unknown or not connected"
  return 1
}

# Test port forwarding status
test_port_forwarding() {
  msg "Testing port forwarding status..."
  
  local pf_payload
  if pf_payload=$(gluetun_control_get "/v1/openvpn/portforwarded" 2>/dev/null); then
    if gluetun_port_forward_details "$pf_payload"; then
      if [[ -n "$GLUETUN_PORT_FORWARD_PORT" && "$GLUETUN_PORT_FORWARD_PORT" != "0" ]]; then
        msg "✅ Port forwarding active: $GLUETUN_PORT_FORWARD_PORT"
        if [[ -n "$GLUETUN_PORT_FORWARD_STATUS" ]]; then
          msg "   Status: $GLUETUN_PORT_FORWARD_STATUS"
        fi
        if [[ -n "$GLUETUN_PORT_FORWARD_EXPIRES_AT" ]]; then
          msg "   Expires: $GLUETUN_PORT_FORWARD_EXPIRES_AT"
        fi
        return 0
      else
        warn "❌ Port forwarding not active"
        if [[ -n "$GLUETUN_PORT_FORWARD_MESSAGE" ]]; then
          warn "   Message: $GLUETUN_PORT_FORWARD_MESSAGE"
        fi
        return 1
      fi
    fi
  fi
  
  warn "❌ Unable to get port forwarding status"
  return 1
}

# Test NAT-PMP connectivity (ProtonVPN specific)
test_natpmp_connectivity() {
  msg "Testing NAT-PMP connectivity to ProtonVPN gateway..."
  
  # ProtonVPN uses 10.16.0.1:5351 for NAT-PMP
  local natpmp_host="10.16.0.1"
  local natpmp_port="5351"
  
  if command -v nc >/dev/null 2>&1; then
    if timeout 5 nc -u -w 2 "$natpmp_host" "$natpmp_port" </dev/null >/dev/null 2>&1; then
      msg "✅ NAT-PMP gateway reachable at $natpmp_host:$natpmp_port"
      return 0
    else
      warn "❌ Cannot reach NAT-PMP gateway at $natpmp_host:$natpmp_port"
      warn "   This may indicate routing issues or non-P2P server"
      return 1
    fi
  else
    warn "⚠️  nc (netcat) not available, cannot test NAT-PMP connectivity"
    return 1
  fi
}

# Check if current server supports P2P
check_p2p_server() {
  msg "Checking if current server supports P2P..."
  
  local p2p_script="$SCRIPT_DIR/proton-pf-servers.sh"
  if [[ ! -f "$p2p_script" ]]; then
    warn "P2P server checker not found: $p2p_script"
    return 1
  fi
  
  # Get current server hostname from VPN status
  local ip_payload
  if ip_payload=$(gluetun_control_get "/v1/publicip/ip" 2>/dev/null); then
    if gluetun_public_ip_details "$ip_payload" && [[ -n "${GLUETUN_PUBLIC_IP_HOSTNAME:-}" ]]; then
      local current_server="$GLUETUN_PUBLIC_IP_HOSTNAME"
      msg "Current server: $current_server"
      
      # Check if this server is in our P2P list
      local country="${SERVER_COUNTRIES:-Netherlands}"
      country="${country%%,*}"  # Take first country
      
      if "$p2p_script" list "$country" 50 2>/dev/null | grep -q "$current_server"; then
        msg "✅ Current server supports P2P"
        return 0
      else
        warn "❌ Current server may not support P2P"
        msg "   Consider using explicit P2P servers via SERVER_HOSTNAMES"
        return 1
      fi
    fi
  fi
  
  warn "Cannot determine current server hostname"
  return 1
}

# Suggest P2P servers for current country
suggest_p2p_servers() {
  msg "Suggesting P2P servers for better port forwarding..."
  
  local p2p_script="$SCRIPT_DIR/proton-pf-servers.sh"
  if [[ ! -f "$p2p_script" ]]; then
    warn "P2P server script not found"
    return 1
  fi
  
  local country="${SERVER_COUNTRIES:-Netherlands}"
  country="${country%%,*}"  # Take first country
  
  msg "Top P2P servers for $country:"
  if ! "$p2p_script" list "$country" 5; then
    warn "Failed to get P2P server recommendations"
    return 1
  fi
  
  msg ""
  msg "To use P2P servers, add this to your userr.conf:"
  if "$p2p_script" config "$country" 3; then
    msg "Then restart Gluetun: docker restart gluetun"
  fi
}

# Test comprehensive network health
test_network_health() {
  msg "Testing network health..."
  
  local net_script="$SCRIPT_DIR/network-troubleshoot.sh"
  if [[ ! -f "$net_script" ]]; then
    warn "Network troubleshooting script not found"
    return 1
  fi
  
  # Run basic network tests relevant to VPN
  local network_issues=0
  
  # Test internet connectivity
  if ! "$net_script" internet >/dev/null 2>&1; then
    warn "❌ Internet connectivity issues detected"
    network_issues=$((network_issues + 1))
  fi
  
  # Test DNS resolution
  if ! "$net_script" dns >/dev/null 2>&1; then
    warn "❌ DNS resolution issues detected"
    network_issues=$((network_issues + 1))
  fi
  
  # Test ProtonVPN API connectivity
  if ! "$net_script" proton >/dev/null 2>&1; then
    warn "❌ ProtonVPN API connectivity issues detected"
    network_issues=$((network_issues + 1))
  fi
  
  # Test UDP connectivity (crucial for NAT-PMP)
  if ! "$net_script" udp >/dev/null 2>&1; then
    warn "❌ UDP connectivity issues detected"
    network_issues=$((network_issues + 1))
  fi
  
  if ((network_issues == 0)); then
    msg "✅ Network health checks passed"
    return 0
  else
    warn "❌ Network health issues detected ($network_issues issues)"
    warn "   Run 'arr.network.diag' for detailed network diagnostics"
    return 1
  fi
}

# Check firewall rules
check_firewall_rules() {
  msg "Checking Gluetun firewall configuration..."
  
  # Check if port forwarding is blocked by firewall
  local pf_port
  pf_port=$(fetch_forwarded_port 2>/dev/null || echo "0")
  
  if [[ "$pf_port" != "0" ]]; then
    msg "Testing if forwarded port $pf_port is accessible..."
    
    if docker exec gluetun ss -ln | grep -q ":$pf_port "; then
      msg "✅ Port $pf_port is bound inside container"
    else
      warn "❌ Port $pf_port is not bound inside container"
    fi
  fi
  
  # Check firewall input ports configuration
  local firewall_ports="${GLUETUN_FIREWALL_INPUT_PORTS:-}"
  if [[ -n "$firewall_ports" ]]; then
    msg "Firewall input ports configured: $firewall_ports"
  else
    msg "No specific firewall input ports configured"
  fi
}

# Run comprehensive diagnostics
run_full_diagnostics() {
  msg "Running comprehensive ProtonVPN port forwarding diagnostics..."
  msg "================================================================"
  
  local -a failed_tests=()
  
  if ! test_gluetun_connectivity; then
    failed_tests+=("gluetun_connectivity")
  fi
  
  if ! get_vpn_status; then
    failed_tests+=("vpn_status")
  fi
  
  if ! test_port_forwarding; then
    failed_tests+=("port_forwarding")
  fi
  
  if ! test_natpmp_connectivity; then
    failed_tests+=("natpmp_connectivity")
  fi
  
  if ! check_p2p_server; then
    failed_tests+=("p2p_server")
  fi
  
  if ! test_network_health; then
    failed_tests+=("network_health")
  fi
  
  check_firewall_rules
  
  msg "================================================================"
  
  if ((${#failed_tests[@]} == 0)); then
    msg "✅ All diagnostics passed!"
  else
    warn "❌ Failed tests: ${failed_tests[*]}"
    msg ""
    suggest_p2p_servers
    msg ""
    msg "Common fixes:"
    msg "1. Ensure Gluetun container is running: docker restart gluetun"
    msg "2. Check GLUETUN_API_KEY is set correctly"
    msg "3. Use P2P-enabled servers via SERVER_HOSTNAMES"
    msg "4. Verify ProtonVPN account has port forwarding enabled"
    msg "5. Check firewall rules don't block NAT-PMP (UDP 5351)"
  fi
}

# Main command dispatcher
main() {
  local command="${1:-full}"
  shift || true
  
  check_dependencies
  
  case "$command" in
    full|all)
      run_full_diagnostics
      ;;
    connectivity|conn)
      test_gluetun_connectivity
      ;;
    vpn)
      get_vpn_status
      ;;
    pf|port)
      test_port_forwarding
      ;;
    natpmp)
      test_natpmp_connectivity
      ;;
    p2p)
      check_p2p_server
      ;;
    network)
      test_network_health
      ;;
    firewall)
      check_firewall_rules
      ;;
    suggest)
      suggest_p2p_servers
      ;;
    help|--help|-h)
      cat <<EOF
Usage: $0 <command>

Commands:
  full              Run all diagnostics (default)
  connectivity      Test Gluetun control API connectivity
  vpn               Check VPN connection status
  pf, port          Test port forwarding status
  natpmp            Test NAT-PMP connectivity to ProtonVPN gateway
  p2p               Check if current server supports P2P
  network           Test network health (internet, DNS, ProtonVPN API, UDP)
  firewall          Check firewall configuration
  suggest           Suggest P2P servers for better port forwarding
  help              Show this help

Examples:
  $0                # Run full diagnostics
  $0 pf             # Test only port forwarding
  $0 suggest        # Get P2P server recommendations
EOF
      ;;
    *)
      die "Unknown command: $command. Use '$0 help' for usage."
      ;;
  esac
}

main "$@"
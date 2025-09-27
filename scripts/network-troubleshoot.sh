#!/usr/bin/env bash
# shellcheck shell=bash
# Network troubleshooting tools for Docker and VPN connectivity

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=scripts/common.sh
. "$SCRIPT_DIR/common.sh"

msg() {
  printf '[net-diag] %s\n' "$1" >&2
}

warn() {
  printf '[net-diag][warn] %s\n' "$1" >&2
}

die() {
  printf '[net-diag][error] %s\n' "$1" >&2
  exit 1
}

# Check basic network utilities
check_network_tools() {
  local -a missing_tools=()
  
  for tool in ping curl dig ss netstat; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      missing_tools+=("$tool")
    fi
  done
  
  if ((${#missing_tools[@]} > 0)); then
    warn "Missing network tools: ${missing_tools[*]}"
    warn "Install with: sudo apt-get install -y iputils-ping curl dnsutils net-tools iproute2"
  fi
}

# Test basic internet connectivity
test_internet_connectivity() {
  msg "Testing internet connectivity..."
  
  local -a test_hosts=("1.1.1.1" "8.8.8.8" "9.9.9.9")
  local success_count=0
  
  for host in "${test_hosts[@]}"; do
    if ping -c 1 -W 2 "$host" >/dev/null 2>&1; then
      success_count=$((success_count + 1))
    fi
  done
  
  if ((success_count > 0)); then
    msg "✅ Internet connectivity working ($success_count/${#test_hosts[@]} hosts reachable)"
    return 0
  else
    warn "❌ No internet connectivity (0/${#test_hosts[@]} hosts reachable)"
    return 1
  fi
}

# Test DNS resolution
test_dns_resolution() {
  msg "Testing DNS resolution..."
  
  local -a test_domains=("google.com" "cloudflare.com" "protonvpn.com")
  local success_count=0
  
  for domain in "${test_domains[@]}"; do
    if dig +short +time=3 +tries=1 "$domain" >/dev/null 2>&1; then
      success_count=$((success_count + 1))
    fi
  done
  
  if ((success_count > 0)); then
    msg "✅ DNS resolution working ($success_count/${#test_domains[@]} domains resolved)"
    return 0
  else
    warn "❌ DNS resolution failing (0/${#test_domains[@]} domains resolved)"
    warn "   Check /etc/resolv.conf and DNS server accessibility"
    return 1
  fi
}

# Test ProtonVPN specific connectivity
test_protonvpn_connectivity() {
  msg "Testing ProtonVPN API connectivity..."
  
  local proton_api="https://api.protonmail.ch"
  local timeout=10
  
  if curl -fsS --max-time "$timeout" "$proton_api/tests/ping" >/dev/null 2>&1; then
    msg "✅ ProtonVPN API reachable"
    return 0
  else
    warn "❌ Cannot reach ProtonVPN API"
    warn "   This may indicate network restrictions or firewall issues"
    return 1
  fi
}

# Check Docker daemon and network status
test_docker_networking() {
  msg "Testing Docker networking..."
  
  if ! docker info >/dev/null 2>&1; then
    warn "❌ Docker daemon not accessible"
    return 1
  fi
  
  # Check Docker networks
  local networks
  networks=$(docker network ls --format "{{.Name}}" 2>/dev/null || echo "")
  
  if [[ -z "$networks" ]]; then
    warn "❌ No Docker networks found"
    return 1
  fi
  
  msg "✅ Docker daemon accessible"
  msg "   Available networks: $(echo "$networks" | tr '\n' ' ')"
  
  # Check specific project network
  local compose_project="${COMPOSE_PROJECT_NAME:-arrstack}"
  if echo "$networks" | grep -q "${compose_project}_default"; then
    msg "✅ Project network exists: ${compose_project}_default"
  else
    warn "⚠️  Project network not found: ${compose_project}_default"
    warn "   Run 'docker compose up -d' to create it"
  fi
  
  return 0
}

# Test port accessibility
test_port_accessibility() {
  local port="${1:-8000}"
  local host="${2:-127.0.0.1}"
  
  msg "Testing port accessibility: $host:$port"
  
  if command -v nc >/dev/null 2>&1; then
    if timeout 3 nc -z "$host" "$port" 2>/dev/null; then
      msg "✅ Port $host:$port is accessible"
      return 0
    else
      warn "❌ Port $host:$port is not accessible"
      return 1
    fi
  elif command -v telnet >/dev/null 2>&1; then
    if timeout 3 bash -c "echo '' | telnet $host $port" >/dev/null 2>&1; then
      msg "✅ Port $host:$port is accessible"
      return 0
    else
      warn "❌ Port $host:$port is not accessible"
      return 1
    fi
  else
    warn "⚠️  No port testing tools available (nc or telnet)"
    return 1
  fi
}

# Check firewall status
check_firewall_status() {
  msg "Checking firewall status..."
  
  # Check iptables
  if command -v iptables >/dev/null 2>&1; then
    local iptables_rules
    iptables_rules=$(sudo iptables -L -n 2>/dev/null | wc -l || echo "0")
    
    if ((iptables_rules > 10)); then
      msg "⚠️  iptables has $((iptables_rules - 3)) active rules"
      msg "   Some rules may affect VPN connectivity"
    else
      msg "✅ iptables appears minimal"
    fi
  fi
  
  # Check ufw
  if command -v ufw >/dev/null 2>&1; then
    local ufw_status
    ufw_status=$(sudo ufw status 2>/dev/null | head -1 || echo "unknown")
    
    if echo "$ufw_status" | grep -q "Status: active"; then
      warn "⚠️  ufw firewall is active"
      warn "   May need to allow Docker and VPN ports"
    else
      msg "✅ ufw firewall inactive or not found"
    fi
  fi
  
  # Check systemd firewall services
  if systemctl is-active --quiet firewalld 2>/dev/null; then
    warn "⚠️  firewalld is active"
    warn "   May need firewall rules for Docker and VPN"
  fi
}

# Check for common port conflicts
check_port_conflicts() {
  msg "Checking for port conflicts..."
  
  local -a important_ports=()
  
  # Load ports from environment if available
  if [[ -f "${ARR_ENV_FILE:-}" ]]; then
    while IFS='=' read -r key value; do
      case "$key" in
        GLUETUN_CONTROL_PORT|QBT_HTTP_PORT_HOST|SONARR_PORT|RADARR_PORT|PROWLARR_PORT|BAZARR_PORT)
          value="${value//\"/}"  # Remove quotes
          if [[ "$value" =~ ^[0-9]+$ ]]; then
            important_ports+=("$value")
          fi
          ;;
      esac
    done < "${ARR_ENV_FILE:-}"
  else
    # Default ports if no env file
    important_ports=(8000 8080 8989 7878 9696 6767)
  fi
  
  local conflicts=0
  for port in "${important_ports[@]}"; do
    if ss -ln 2>/dev/null | grep -q ":${port} "; then
      local process
      process=$(ss -lnp 2>/dev/null | grep ":${port} " | head -1 || echo "unknown")
      warn "⚠️  Port $port is in use: $process"
      conflicts=$((conflicts + 1))
    fi
  done
  
  if ((conflicts == 0)); then
    msg "✅ No port conflicts detected for important services"
  else
    warn "❌ Found $conflicts port conflicts"
    warn "   Use 'sudo ss -lnp | grep :<PORT>' to identify processes"
  fi
}

# Test UDP connectivity (important for NAT-PMP)
test_udp_connectivity() {
  msg "Testing UDP connectivity..."
  
  # Test with a known UDP service (DNS)
  if command -v nc >/dev/null 2>&1; then
    if timeout 3 nc -u -z 8.8.8.8 53 2>/dev/null; then
      msg "✅ UDP connectivity working (tested with DNS)"
    else
      warn "❌ UDP connectivity may be blocked"
      warn "   This affects NAT-PMP (ProtonVPN port forwarding)"
    fi
  else
    # Fallback DNS test
    if dig +short @8.8.8.8 google.com >/dev/null 2>&1; then
      msg "✅ UDP connectivity working (DNS resolution)"
    else
      warn "❌ UDP connectivity issues detected"
    fi
  fi
}

# Check Docker container networking
test_container_networking() {
  msg "Testing container networking..."
  
  # Check if Gluetun container exists and is running
  local gluetun_status
  gluetun_status=$(docker inspect gluetun --format '{{.State.Status}}' 2>/dev/null || echo "not found")
  
  case "$gluetun_status" in
    running)
      msg "✅ Gluetun container is running"
      
      # Test network connectivity inside container
      if docker exec gluetun ping -c 1 -W 2 1.1.1.1 >/dev/null 2>&1; then
        msg "✅ Internet connectivity inside Gluetun container"
      else
        warn "❌ No internet connectivity inside Gluetun container"
      fi
      
      # Check if Gluetun API is responding
      local gluetun_port="${GLUETUN_CONTROL_PORT:-8000}"
      if test_port_accessibility "$gluetun_port" "127.0.0.1"; then
        msg "✅ Gluetun control API is accessible"
      else
        warn "❌ Gluetun control API not accessible"
      fi
      ;;
    exited)
      warn "❌ Gluetun container has exited"
      warn "   Check logs: docker logs gluetun"
      ;;
    *)
      warn "❌ Gluetun container not found or in unknown state: $gluetun_status"
      ;;
  esac
}

# Check routing table for VPN routes
check_routing_table() {
  msg "Checking routing table..."
  
  if command -v ip >/dev/null 2>&1; then
    local tun_routes
    tun_routes=$(ip route show | grep -c "tun" || echo "0")
    
    if ((tun_routes > 0)); then
      msg "✅ Found $tun_routes VPN routes in routing table"
    else
      warn "⚠️  No VPN (tun) routes found"
      warn "   VPN may not be properly connected"
    fi
    
    # Check for ProtonVPN specific routes
    if ip route show | grep -q "10\.16\.0"; then
      msg "✅ ProtonVPN internal routes detected"
    else
      warn "⚠️  No ProtonVPN internal routes found"
    fi
  else
    warn "⚠️  Cannot check routing table (ip command not available)"
  fi
}

# Generate network configuration summary
show_network_summary() {
  msg "Network Configuration Summary:"
  msg "=========================================="
  
  # Show network interfaces
  if command -v ip >/dev/null 2>&1; then
    msg "Network Interfaces:"
    ip addr show | grep -E "^[0-9]+:|inet " | while read -r line; do
      msg "  $line"
    done
  fi
  
  # Show DNS configuration
  if [[ -f /etc/resolv.conf ]]; then
    msg ""
    msg "DNS Configuration:"
    grep -E "^(nameserver|search|domain)" /etc/resolv.conf | while read -r line; do
      msg "  $line"
    done
  fi
  
  # Show default route
  if command -v ip >/dev/null 2>&1; then
    msg ""
    msg "Default Route:"
    ip route show default | while read -r line; do
      msg "  $line"
    done
  fi
}

# Run comprehensive network diagnostics
run_full_diagnostics() {
  msg "Running comprehensive network diagnostics..."
  msg "============================================="
  
  local -a failed_tests=()
  
  check_network_tools
  
  if ! test_internet_connectivity; then
    failed_tests+=("internet_connectivity")
  fi
  
  if ! test_dns_resolution; then
    failed_tests+=("dns_resolution")
  fi
  
  if ! test_protonvpn_connectivity; then
    failed_tests+=("protonvpn_api")
  fi
  
  if ! test_docker_networking; then
    failed_tests+=("docker_networking")
  fi
  
  check_firewall_status
  check_port_conflicts
  test_udp_connectivity
  
  if ! test_container_networking; then
    failed_tests+=("container_networking")
  fi
  
  check_routing_table
  
  msg ""
  msg "============================================="
  
  if ((${#failed_tests[@]} == 0)); then
    msg "✅ All network diagnostics passed!"
  else
    warn "❌ Failed tests: ${failed_tests[*]}"
    msg ""
    msg "Common fixes:"
    msg "1. Check internet connection: ping 1.1.1.1"
    msg "2. Verify DNS servers: cat /etc/resolv.conf"
    msg "3. Check firewall rules: sudo ufw status"
    msg "4. Restart networking: sudo systemctl restart systemd-networkd"
    msg "5. Restart Docker: sudo systemctl restart docker"
    msg "6. Check Docker logs: docker logs gluetun"
  fi
  
  msg ""
  show_network_summary
}

# Main command dispatcher
main() {
  local command="${1:-full}"
  shift || true
  
  case "$command" in
    full|all)
      run_full_diagnostics
      ;;
    internet|inet)
      test_internet_connectivity
      ;;
    dns)
      test_dns_resolution
      ;;
    proton|protonvpn)
      test_protonvpn_connectivity
      ;;
    docker)
      test_docker_networking
      ;;
    ports)
      check_port_conflicts
      ;;
    firewall|fw)
      check_firewall_status
      ;;
    udp)
      test_udp_connectivity
      ;;
    containers)
      test_container_networking
      ;;
    routes|routing)
      check_routing_table
      ;;
    summary|config)
      show_network_summary
      ;;
    port)
      if [[ $# -eq 0 ]]; then
        die "Usage: $0 port <port> [host]"
      fi
      test_port_accessibility "$@"
      ;;
    help|--help|-h)
      cat <<EOF
Usage: $0 <command> [options]

Commands:
  full              Run all network diagnostics (default)
  internet          Test basic internet connectivity
  dns               Test DNS resolution
  proton            Test ProtonVPN API connectivity
  docker            Test Docker daemon and networks
  ports             Check for port conflicts
  firewall          Check firewall status
  udp               Test UDP connectivity (important for NAT-PMP)
  containers        Test container networking (Gluetun)
  routes            Check routing table for VPN routes
  summary           Show network configuration summary
  port <port> [host] Test specific port accessibility

Examples:
  $0                    # Run full diagnostics
  $0 docker             # Test only Docker networking
  $0 port 8000          # Test if port 8000 is accessible
  $0 port 5351 10.16.0.1 # Test NAT-PMP port
EOF
      ;;
    *)
      die "Unknown command: $command. Use '$0 help' for usage."
      ;;
  esac
}

main "$@"
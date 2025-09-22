# shellcheck shell=bash
configure_local_dns_entries() {
  msg "🧭 Ensuring local DNS entries exist for Caddy hostnames"

  local helper_script="${REPO_ROOT}/scripts/setup-lan-dns.sh"

  if [[ "${ENABLE_LOCAL_DNS:-1}" -ne 1 || ${LOCAL_DNS_SERVICE_ENABLED:-0} -ne 1 ]]; then
    LOCAL_DNS_HELPER_STATUS="skipped-disabled"
    msg "  Local DNS container disabled; skipping host entries helper"
    return 0
  fi

  if [[ ! -f "$helper_script" ]]; then
    warn "Local DNS helper script ${helper_script} not found"
    LOCAL_DNS_HELPER_STATUS="missing-script"
    return 0
  fi

  if [[ ! -x "$helper_script" ]]; then
    warn "Local DNS helper script is not executable; fix permissions on ${helper_script}"
    LOCAL_DNS_HELPER_STATUS="not-executable"
    return 0
  fi

  if [[ -z "${LAN_IP:-}" ]]; then
    warn "LAN_IP is unset; skipping local DNS helper"
    LOCAL_DNS_HELPER_STATUS="skipped-missing-ip"
    return 0
  fi

  if [[ "${LAN_IP}" == "0.0.0.0" ]]; then
    warn "LAN_IP is 0.0.0.0; skipping local DNS helper"
    LOCAL_DNS_HELPER_STATUS="skipped-missing-ip"
    return 0
  fi

  if ! ip_assigned "$LAN_IP"; then
    warn "LAN_IP ${LAN_IP} is not assigned on this host; skipping local DNS helper"
    LOCAL_DNS_HELPER_STATUS="skipped-unassigned"
    return 0
  fi

  if ! "$helper_script" "$ARR_DOMAIN_SUFFIX_CLEAN" "$LAN_IP"; then
    local exit_code=$?
    if ((exit_code == 3)); then
      warn "Local DNS helper refused to update hosts because LAN_IP is 0.0.0.0; provide a valid address and rerun."
      LOCAL_DNS_HELPER_STATUS="failed-invalid-ip"
    else
      warn "Local DNS helper was unable to update host mappings; rerun arrstack.sh with sudo to grant access"
      LOCAL_DNS_HELPER_STATUS="failed"
    fi
    return 0
  fi

  LOCAL_DNS_HELPER_STATUS="succeeded"
  msg "✅ Local DNS helper completed"
}

run_host_dns_setup() {
  if [[ "${ENABLE_LOCAL_DNS:-1}" -ne 1 ]]; then
    msg "Skipping host DNS setup (--setup-host-dns) because ENABLE_LOCAL_DNS=0"
    return 0
  fi

  if [[ -z "${LAN_IP:-}" || "${LAN_IP}" == "0.0.0.0" ]]; then
    warn "Cannot run --setup-host-dns automatically: LAN_IP is ${LAN_IP:-<unset>}"
    warn "Set LAN_IP to a specific address and rerun arrstack.sh --setup-host-dns once available."
    return 0
  fi

  if ! ip_assigned "$LAN_IP"; then
    warn "Cannot run --setup-host-dns automatically: LAN_IP ${LAN_IP} is not assigned on this host"
    warn "Verify the address with 'ip -4 addr show' or remove LAN_IP to auto-detect."
    return 0
  fi

  local helper_script="${REPO_ROOT}/scripts/host-dns-setup.sh"

  if [[ ! -f "$helper_script" ]]; then
    warn "Host DNS helper script not found at ${helper_script}; skipping --setup-host-dns"
    return 0
  fi

  if [[ ! -x "$helper_script" ]]; then
    warn "Host DNS helper script is not executable; fix permissions on ${helper_script} or rerun manually."
    return 0
  fi

  msg "🔧 Running host DNS setup helper (--setup-host-dns)"

  if (
    cd "$ARR_STACK_DIR" 2>/dev/null &&
      LAN_IP="${LAN_IP}" \
      LAN_DOMAIN_SUFFIX="${LAN_DOMAIN_SUFFIX}" \
      UPSTREAM_DNS_1="${UPSTREAM_DNS_1}" \
      UPSTREAM_DNS_2="${UPSTREAM_DNS_2}" \
      bash "$helper_script"
  ); then
    msg "✅ Host DNS setup helper completed"
  else
    warn "Host DNS setup helper reported an error; review the output above or run scripts/host-dns-setup.sh manually."
  fi
}


#!/usr/bin/env bash
set -euo pipefail

# Diagnostics for LAN DNS + Caddy access

SUFFIX="${LAN_DOMAIN_SUFFIX:-}"
DNS_IP="${LAN_IP:-127.0.0.1}"

printf '[doctor] LAN domain suffix: %s\n' "${SUFFIX:-<unset>}"
printf '[doctor] Using DNS server at: %s\n' "${DNS_IP}"

echo "[doctor] Checking if port 53 is free (or already bound):"
if command -v ss >/dev/null 2>&1; then
  if ss -ulpn 2>/dev/null | grep -q ':53 '; then
    echo "[doctor][warn] Something is listening on port 53. Could conflict with local_dns service."
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet systemd-resolved; then
      echo "[doctor][hint] systemd-resolved is active and commonly owns :53 on Bookworm."
      echo "[doctor][hint] Run: ./arrstack.sh --setup-host-dns (automated) or ./scripts/host-dns-setup.sh (manual)."
    fi
  else
    echo "[doctor][ok] Port 53 appears free."
  fi
else
  echo "[doctor][warn] 'ss' command not found; skipping port 53 check."
fi

echo "[doctor] Testing DNS resolution of qbittorrent.${SUFFIX} via local resolver"
res="$(dig +short @"${DNS_IP}" qbittorrent."${SUFFIX}" 2>/dev/null || true)"
if ! command -v dig >/dev/null 2>&1; then
  echo "[doctor][warn] 'dig' command not found; skipping DNS lookup."
elif [ -z "${res}" ]; then
  echo "[doctor][error] qbittorrent.${SUFFIX} did NOT resolve via ${DNS_IP}"
else
  echo "[doctor][ok] qbittorrent.${SUFFIX} resolves to ${res}"
fi

echo "[doctor] Testing HTTPS endpoint"
if ! command -v curl >/dev/null 2>&1; then
  echo "[doctor][warn] 'curl' command not found; skipping HTTPS probe."
elif curl -k --silent --max-time 5 "https://qbittorrent.${SUFFIX}/" -o /dev/null; then
  echo "[doctor][ok] HTTPS endpoint reachable"
else
  echo "[doctor][warn] HTTPS endpoint not reachable. Could be DNS, Caddy, or firewall issue."
fi

exit 0

#!/usr/bin/env bash
set -euo pipefail

log() {
  printf '%s\n' "$*"
}

warn() {
  printf 'WARN: %s\n' "$*" >&2
}

CA_ROOT="${ARR_DOCKER_DIR:-${HOME}/srv/docker-data}/caddy/data/caddy/pki/authorities/local"
CA_FILE="${CA_ROOT}/root.crt"
DEST_FILE="${1:-${HOME}/arrstack-ca.crt}"

if [[ ! -f "$CA_FILE" ]]; then
  warn "Caddy internal CA not found at ${CA_FILE}"
  warn "Start the stack at least once so Caddy can generate its local CA."
  exit 1
fi

if [[ -d "${DEST_FILE}" ]]; then
  warn "Destination ${DEST_FILE} is a directory; provide a file path."
  exit 1
fi

dest_dir="$(dirname "${DEST_FILE}")"
if [[ ! -d "${dest_dir}" ]]; then
  if ! mkdir -p "${dest_dir}" 2>/dev/null; then
    warn "Unable to create destination directory ${dest_dir}"
    exit 1
  fi
fi

if cp "$CA_FILE" "$DEST_FILE" 2>/dev/null; then
  chmod 600 "$DEST_FILE" 2>/dev/null || true
  log "CA certificate exported to ${DEST_FILE}"
  log "Install this on LAN devices to trust HTTPS connections"
else
  warn "Failed to copy ${CA_FILE} to ${DEST_FILE}" >&2
  exit 1
fi


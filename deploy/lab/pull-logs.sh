#!/usr/bin/env bash
# Pull logs from the sensor and SIEM VMs into the P4B VM, then optionally ingest.
#
#   install -m 0755 deploy/lab/pull-logs.sh /usr/local/bin/p4b-pull-logs
#   p4b-pull-logs            # pull only
#   p4b-pull-logs --ingest   # pull and parse into findings
#
# Override hosts with SENSOR_HOST / SIEM_HOST / DEST.

set -euo pipefail

SENSOR_HOST="${SENSOR_HOST:-192.168.56.20}"
SIEM_HOST="${SIEM_HOST:-192.168.56.30}"
DEST="${DEST:-/data/ingest}"
MODE="${1:-pull}"

warn() { printf '[!] %s\n' "$*" >&2; }

mkdir -p "${DEST}/zeek" "${DEST}/suricata" "${DEST}/wazuh"

# --delete matters for Zeek: `current/` rotates, and stale files would be re-read
log() { printf '==> %s\n' "$*"; }

log "zeek      <- ${SENSOR_HOST}:/opt/zeek/logs/current"
if ! rsync -az --delete "${SENSOR_HOST}:/opt/zeek/logs/current/" "${DEST}/zeek/" 2>/dev/null; then
    warn "zeek pull failed (wrong host, no SSH key, or no logs yet)"
fi

log "suricata  <- ${SENSOR_HOST}:/var/log/suricata/eve.json"
if ! rsync -az "${SENSOR_HOST}:/var/log/suricata/eve.json" "${DEST}/suricata/eve.json" 2>/dev/null; then
    warn "suricata pull failed"
fi

log "wazuh     <- ${SIEM_HOST}:/data/wazuh/logs/alerts/alerts.json"
if ! rsync -az "${SIEM_HOST}:/data/wazuh/logs/alerts/alerts.json" "${DEST}/wazuh/alerts.json" 2>/dev/null; then
    warn "wazuh pull failed"
fi

printf 'zeek files: %s\n' "$(find "${DEST}/zeek" -name '*.log' 2>/dev/null | wc -l)"

if [[ "${MODE}" == "--ingest" ]]; then
    command -v p4b >/dev/null 2>&1 || { warn "p4b not on PATH; activate the venv first"; exit 1; }
    log "ingesting"
    p4b ingest zeek "${DEST}/zeek" || warn "zeek ingest failed"
    [[ -s "${DEST}/suricata/eve.json" ]] && p4b ingest suricata "${DEST}/suricata/eve.json" || true
    [[ -s "${DEST}/wazuh/alerts.json" ]] && p4b ingest wazuh "${DEST}/wazuh/alerts.json" || true
    p4b findings --limit 10
fi

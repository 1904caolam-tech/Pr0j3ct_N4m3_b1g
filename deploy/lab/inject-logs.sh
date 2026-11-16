#!/usr/bin/env bash
# Inject deterministic events into an enrolled Wazuh agent's localfile.
#
#   sudo bash inject-logs.sh [count]
#
# Why: a lab agent on a quiet VM produces nothing, so the manager has no alerts to
# ingest. These lines travel through the real agent -> manager path (logcollector,
# decoders, rules) and end up in alerts.json like any other event.
#
# Requires deploy/lab/wazuh-agent.sh to have run: it mounts /data/wazuh-agent/logs
# at /var/log/p4b-agent inside the container, and points one localfile there.
# Matching rules: deploy/lab/wazuh-lab-rules.xml (ids 100100/100101/100102).

set -euo pipefail

COUNT="${1:-10}"
LOG="${LOG:-/data/wazuh-agent/logs/lab.log}"

[[ ${EUID} -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }

mkdir -p "$(dirname "${LOG}")"
touch "${LOG}"
chmod 755 "$(dirname "${LOG}")"
chmod 644 "${LOG}"

HOST="$(hostname -s)"
for i in $(seq 1 "${COUNT}"); do
    stamp="$(date '+%b %d %H:%M:%S')"
    case $((i % 3)) in
        0) msg="P4B_LAB_CRIT simulated critical event #${i}" ;;
        1) msg="P4B_LAB_ALERT simulated detection event #${i}" ;;
        *) msg="P4B_LAB_INFO simulated informational event #${i}" ;;
    esac
    echo "${stamp} ${HOST} p4b-inject: ${msg}" >> "${LOG}"
done

echo "wrote ${COUNT} event(s) to ${LOG} as ${HOST}"
echo "the manager should show them for this agent within ~15s:"
echo "  sudo docker exec <manager> tail -n 5 /var/ossec/logs/alerts/alerts.json"

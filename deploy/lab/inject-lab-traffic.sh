#!/usr/bin/env bash
# Emit a varied mix of lab events through a real Wazuh agent's localfile.
#
#   sudo bash inject-lab-traffic.sh [--count 200] [--seed 42] [--log PATH]
#
# 13 markers -> 13 rules -> several severities and ATT&CK techniques. The manager
# attributes every event to the agent that forwarded it, so run it on each host.
# Matching rules: deploy/lab/wazuh-lab-rules.xml.

set -euo pipefail

COUNT=200
SEED=42
LOG="/data/wazuh-agent/logs/lab.log"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --count) COUNT="$2"; shift 2 ;;
        --seed)  SEED="$2";  shift 2 ;;
        --log)   LOG="$2";   shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

[[ ${EUID} -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }

mkdir -p "$(dirname "${LOG}")"
touch "${LOG}"
chmod 755 "$(dirname "${LOG}")"
chmod 644 "${LOG}"

MARKERS=(
    P4B_LAB_ALERT P4B_LAB_INFO P4B_LAB_CRIT
    P4B_SIM_PS P4B_SIM_LSASS P4B_SIM_WEB P4B_SIM_PHISH
    P4B_SIM_RDP P4B_SIM_SYSINFO P4B_SIM_ACCT P4B_SIM_SUDO
    P4B_SIM_RANSOM P4B_SIM_DELETE
)
DETAILS=(
    "failed password for admin from 198.51.100.23"
    "port scan observed from 203.0.113.7"
    "exploit attempt against /api/login"
    "powershell.exe -enc SQBFAFgA..."
    "procdump.exe -ma lsass.exe C:\\temp\\out.dmp"
    "beacon GET /gate.php every 60s to 198.51.100.44"
    "attachment invoice.docm spawned cmd.exe"
    "RDP logon for svc-backup from 10.0.4.99"
    "whoami /all; net user; systeminfo"
    "net user attacker P@ssw0rd /add"
    "sudo -i executed by www-data"
    "412 files renamed to .locked in /srv/share"
    "rm -f /var/log/auth.log"
)
HOST="$(hostname -s)"
RANDOM="${SEED}"

for _ in $(seq 1 "${COUNT}"); do
    idx=$((RANDOM % ${#MARKERS[@]}))
    stamp="$(date '+%b %d %H:%M:%S')"
    echo "${stamp} ${HOST} p4b-sim: ${MARKERS[$idx]} ${DETAILS[$idx]}" >> "${LOG}"
done

echo "wrote ${COUNT} event(s) as ${HOST} with seed ${SEED} to ${LOG}"
echo "the manager should index them within ~30s"

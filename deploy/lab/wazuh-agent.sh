#!/usr/bin/env bash
# Real Wazuh agent (container) enrolled to the lab manager.
#
#   sudo MANAGER=192.168.159.167 bash wazuh-agent.sh
#
# Installs docker if needed, writes a minimal ossec.conf (agent + enrollment +
# one localfile), starts the container, and waits for the registration. The
# manager must already have rule 100100 — run deploy/lab/wazuh-configure.sh there.
#
# Emit an event afterwards:
#   echo "$(date '+%b %d %H:%M:%S') sensor p4b: P4B_LAB_ALERT test" \
#     | sudo tee -a /data/wazuh-agent/logs/lab.log

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "${HERE}/lib.sh"

require_root
require_ubuntu

MANAGER="${MANAGER:-}"
[[ -n "${MANAGER}" ]] || die "set MANAGER=<manager ip> (e.g. MANAGER=192.168.159.167)"
AGENT_NAME="${AGENT_NAME:-$(hostname -s)}"
DIR="${DIR:-/data/wazuh-agent}"
TAG="${WAZUH_TAG:-4.14.10}"

apt_install curl ca-certificates
install_docker

mkdir -p "${DIR}/etc" "${DIR}/logs"
chmod 755 "${DIR}" "${DIR}/etc" "${DIR}/logs"

cat > "${DIR}/etc/ossec.conf" <<XML
<ossec_config>
  <client>
    <server>
      <address>${MANAGER}</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <enrollment>
      <enabled>yes</enabled>
      <manager_address>${MANAGER}</manager_address>
      <port>1515</port>
      <agent_name>${AGENT_NAME}</agent_name>
    </enrollment>
    <notify_time>10</notify_time>
  </client>
  <client_buffer>
    <disabled>yes</disabled>
  </client_buffer>
  <logging>
    <log_alert_level>3</log_alert_level>
  </logging>
  <syscheck>
    <disabled>yes</disabled>
  </syscheck>
  <rootcheck>
    <disabled>yes</disabled>
  </rootcheck>
  <wodle name="syscollector">
    <disabled>yes</disabled>
  </wodle>
  <sca>
    <enabled>no</enabled>
  </sca>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/p4b-agent/lab.log</location>
  </localfile>
</ossec_config>
XML
chmod 644 "${DIR}/etc/ossec.conf"

# The localfile must exist before logcollector starts; otherwise it logs
# "(1103) Could not open file" and never picks the file up afterwards.
touch "${DIR}/logs/lab.log"
chmod 644 "${DIR}/logs/lab.log"

docker rm -f wazuh-agent >/dev/null 2>&1 || true
docker run -d --name wazuh-agent --hostname "${AGENT_NAME}" --restart unless-stopped \
    -v "${DIR}/etc/ossec.conf:/var/ossec/etc/ossec.conf" \
    -v "${DIR}/logs:/var/log/p4b-agent" \
    "wazuh/wazuh-agent:${TAG}" >/dev/null

log "waiting for the agent to connect"
for _ in $(seq 1 30); do
    if docker exec wazuh-agent sh -c 'grep -q "Connected to the server" /var/ossec/logs/ossec.log'; then
        break
    fi
    sleep 2
done
docker exec wazuh-agent sh -c 'grep -E "Connected to the server|ERROR" /var/ossec/logs/ossec.log | tail -3' || true

cat <<EOF

agent is running as '${AGENT_NAME}'.
  emit an event:
    echo "\$(date '+%b %d %H:%M:%S') ${AGENT_NAME} p4b: P4B_LAB_ALERT test" | sudo tee -a ${DIR}/logs/lab.log
  the manager should log rule 100100 within ~15s:
    sudo docker exec wazuh-manager tail -n 3 /var/ossec/logs/alerts/alerts.json
EOF

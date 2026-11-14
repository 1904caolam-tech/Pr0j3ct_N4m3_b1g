#!/usr/bin/env bash
# SIEM VM: Wazuh manager only (no indexer, no dashboard).
#
# P4B consumes /var/ossec/logs/alerts/alerts.json; the indexer and dashboard cost
# 6-8 GB and add nothing to this project.
#
#   sudo bash bootstrap-siem.sh
#   sudo WAZUH_TAG=4.9.2 bash bootstrap-siem.sh

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "${HERE}/lib.sh"

require_root
require_ubuntu

WAZUH_TAG="${WAZUH_TAG:-4.14.10}"
WAZUH_DIR="${WAZUH_DIR:-/data/wazuh}"

apt_install curl ca-certificates
install_docker

log "preparing ${WAZUH_DIR}"
# Only logs are bind-mounted. Bind-mounting an empty directory over /var/ossec/etc
# hides the image's default ossec.conf and rules (Docker only copies image content
# into *named volumes*, never into bind mounts), and the manager then fails to start.
mkdir -p "${WAZUH_DIR}"/{logs,testlogs}
chmod -R 0750 "${WAZUH_DIR}"

if docker ps -a --format '{{.Names}}' | grep -qx wazuh-manager; then
    log "wazuh-manager container already exists; recreating with tag ${WAZUH_TAG}"
    docker rm -f wazuh-manager >/dev/null
fi

log "starting wazuh/wazuh-manager:${WAZUH_TAG}"
docker run -d --name wazuh-manager --restart unless-stopped \
    --hostname siem \
    -p 1514:1514/tcp -p 1515:1515/tcp -p 55000:55000/tcp \
    -v "${WAZUH_DIR}/logs:/var/ossec/logs" \
    -v "${WAZUH_DIR}/testlogs:/var/log/p4b-test" \
    -e INDEXER_URL= \
    -e FILEBEAT_ENABLED=false \
    "wazuh/wazuh-manager:${WAZUH_TAG}" >/dev/null

log "waiting for the manager to answer"
for _ in $(seq 1 30); do
    if docker exec wazuh-manager /var/ossec/bin/wazuh-control status >/dev/null 2>&1; then
        break
    fi
    sleep 2
done

docker exec wazuh-manager /var/ossec/bin/wazuh-control status || warn "manager not reporting yet; check: docker logs wazuh-manager"

show_interfaces
MANAGER_IP="$(hostname -I | tr ' ' '\n' | grep -m1 -E '^192\.168\.(56|159)\.' || true)"
MANAGER_IP="${MANAGER_IP:-$(hostname -I | awk '{print $1}')}"

log "manager is up"
cat <<EOF
  manager address : ${MANAGER_IP}
  alerts file     : ${WAZUH_DIR}/logs/alerts/alerts.json   (host)
                    /var/ossec/logs/alerts/alerts.json      (container)

  enroll one agent on another VM (so alerts come from a different host):
    curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list
    sudo apt update && sudo WAZUH_MANAGER='${MANAGER_IP}' sudo -E apt install -y wazuh-agent

  verify an alert appears within a minute of the agent connecting:
    sudo docker exec wazuh-manager tail -n 5 /var/ossec/logs/alerts/alerts.json

  wire the lab test alert (also disables vulnerability-detection, which otherwise
  downloads multi-GB CVE feeds into the container and can fill a 20 GB VM):
    sudo bash deploy/lab/wazuh-configure.sh
EOF

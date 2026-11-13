#!/usr/bin/env bash
# P4B application VM: python, docker, project install, database init.
#
# Expects the repository to be copied to $PROJECT_DIR before running.
#   scp -r . lab@192.168.56.10:~/p4b
#   sudo PROJECT_DIR=/home/lab/p4b bash bootstrap-p4b.sh

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "${HERE}/lib.sh"

require_root
require_ubuntu

PROJECT_DIR="${PROJECT_DIR:-/home/lab/p4b}"
LAB_USER="${LAB_USER:-lab}"
export DEBIAN_FRONTEND=noninteractive

apt_install python3-venv python3-pip git rsync curl ca-certificates sqlite3
install_docker

if ! id "${LAB_USER}" >/dev/null 2>&1; then
    die "user '${LAB_USER}' does not exist; create it or pass LAB_USER=<name>"
fi
usermod -aG docker "${LAB_USER}"
warn "group 'docker' added to ${LAB_USER}; run 'newgrp docker' or log out/in before using docker without sudo"

[[ -f "${PROJECT_DIR}/pyproject.toml" ]] || die \
    "no project at ${PROJECT_DIR}; copy the repository first (scp -r . lab@<ip>:~/p4b)"

log "creating virtualenv and installing p4b (editable + dev extras)"
runuser -u "${LAB_USER}" -- bash -lc "
    cd '${PROJECT_DIR}'
    python3 -m venv .venv
    . .venv/bin/activate
    python -m pip install --quiet --upgrade pip
    python -m pip install --quiet -e '.[dev]'
    p4b init
    p4b doctor
"

log "ingesting fixture data (no sensors required)"
runuser -u "${LAB_USER}" -- bash -lc "
    cd '${PROJECT_DIR}'
    . .venv/bin/activate
    p4b ingest wazuh    demo/fixtures/wazuh/alerts.json
    p4b ingest suricata demo/fixtures/suricata/eve.json
    p4b ingest zeek     demo/fixtures/zeek
    p4b findings --limit 10
"

show_interfaces
log "next steps"
cat <<'EOF'
  1. Add the host-only NIC (vmnet1, 192.168.56.0/24) if you want a stable lab IP.
  2. Copy the pull script for sensor/siem logs:
       install -m 0755 deploy/lab/pull-logs.sh /usr/local/bin/p4b-pull-logs
     then schedule it:
       (crontab -u lab -l 2>/dev/null; echo '* * * * * /usr/local/bin/p4b-pull-logs >/dev/null 2>&1') | crontab -u lab -
  3. Run the api later with:  p4b serve    (available from M3)
EOF

#!/usr/bin/env bash
# Sensor VM: Zeek + Suricata + tcpreplay, listening on the host-only interface.
#
#   sudo bash bootstrap-sensor.sh
#
# Traffic strategy: replay pcaps onto the lab interface instead of relying on
# VMware's virtual switch to flood traffic between VMs (it does not).

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "${HERE}/lib.sh"

require_root
require_ubuntu
export DEBIAN_FRONTEND=noninteractive

apt_install curl gnupg ca-certificates software-properties-common tcpdump tcpreplay

# -- zeek ------------------------------------------------------------------ #
if ! command -v zeek >/dev/null 2>&1; then
    log "adding the Zeek repository for Ubuntu ${UBUNTU_VERSION}"
    echo "deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_${UBUNTU_VERSION}/ /" \
        > /etc/apt/sources.list.d/zeek.list
    curl -fsSL "https://download.opensuse.org/repositories/security:/zeek/xUbuntu_${UBUNTU_VERSION}/Release.key" \
        | gpg --dearmor > /etc/apt/trusted.gpg.d/zeek.gpg
    apt_install zeek
else
    log "zeek already present: $(zeek --version | head -1)"
fi

# -- suricata -------------------------------------------------------------- #
if ! command -v suricata >/dev/null 2>&1; then
    log "adding the Suricata stable PPA"
    add-apt-repository -y ppa:oisf/suricata-stable >/dev/null
    apt_install suricata
else
    log "suricata already present: $(suricata --build-info | head -1)"
fi

log "updating Suricata rules (without this, replays produce zero alerts)"
suricata-update --no-test >/dev/null 2>&1 || warn "suricata-update failed; run it manually to see why"

# The packaged zeek service would also capture traffic; two readers on one
# interface is confusing when debugging, so keep only our manual instance.
systemctl disable --now zeek >/dev/null 2>&1 || true

mkdir -p /data/pcap
install -d -m 0755 /var/log/suricata

show_interfaces
IFACE="$(ip -br addr | awk '$3 ~ /^192\.168\.56\./ {print $1; exit}')"
if [[ -z "${IFACE}" ]]; then
    iface="$(ip route get 1.1.1.1 | awk '{print $5; exit}')"
    IFACE="${iface:-eth0}"
    warn "no 192.168.56.x interface found; falling back to ${IFACE} (the NAT interface)"
    warn "traffic replayed there leaves the lab network - add the host-only NIC if that matters"
fi

log "sensor is ready"
cat <<EOF
  lab interface : ${IFACE}
  zeek logs     : /opt/zeek/logs/current
  suricata eve  : /var/log/suricata/eve.json

  run the sensors (foreground once to see errors, then -D):
    sudo suricata -i ${IFACE}
    cd /opt/zeek && sudo zeek -i ${IFACE} local

  generate deterministic traffic:
    sudo cp your-capture.pcap /data/pcap/sample.pcap
    sudo tcpreplay --intf1=${IFACE} /data/pcap/sample.pcap

  smoke test:
    sudo tcpdump -i ${IFACE} -c 5
EOF

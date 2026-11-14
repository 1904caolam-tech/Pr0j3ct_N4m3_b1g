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

# -- suricata -------------------------------------------------------------- #
if ! command -v suricata >/dev/null 2>&1; then
    candidate="$(apt-cache policy suricata 2>/dev/null | sed -n 's/^  Candidate: //p' | head -1)"
    if [[ -n "${candidate}" && "${candidate}" != "(none)" ]]; then
        log "installing Suricata ${candidate} from the Ubuntu archive"
        apt_install suricata
    else
        log "adding the Suricata stable PPA"
        add-apt-repository -y ppa:oisf/suricata-stable >/dev/null
        apt_install suricata
    fi
else
    log "suricata already present: $(suricata --build-info | head -1)"
fi

# -- zeek ------------------------------------------------------------------ #
# The OBS repo only builds for the LTS releases it knows about, so probe which
# suite actually exists instead of trusting $VERSION_ID. Zeek is optional: a
# missing repository must not block a working Suricata sensor.
if ! command -v zeek >/dev/null 2>&1; then
    ZEEK_REPO=""
    for candidate in "${UBUNTU_VERSION}" 24.04 22.04; do
        if curl -fsI "https://download.opensuse.org/repositories/security:/zeek/xUbuntu_${candidate}/Release.key" >/dev/null 2>&1; then
            ZEEK_REPO="${candidate}"
            break
        fi
    done
    if [[ -n "${ZEEK_REPO}" ]]; then
        log "adding the Zeek repository for Ubuntu ${ZEEK_REPO}"
        echo "deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_${ZEEK_REPO}/ /" \
            > /etc/apt/sources.list.d/zeek.list
        curl -fsSL "https://download.opensuse.org/repositories/security:/zeek/xUbuntu_${ZEEK_REPO}/Release.key" \
            | gpg --dearmor > /etc/apt/trusted.gpg.d/zeek.gpg
        if ! apt_install zeek; then
            warn "zeek install failed for ${ZEEK_REPO}; continuing with Suricata only"
            rm -f /etc/apt/sources.list.d/zeek.list /etc/apt/trusted.gpg.d/zeek.gpg
        fi
    else
        warn "no Zeek repository found; continuing with Suricata only"
    fi
else
    log "zeek already present: $(zeek --version | head -1)"
fi

log "updating Suricata rules (without this, replays produce zero alerts)"
suricata-update --no-test >/dev/null 2>&1 || warn "suricata-update failed; run it manually to see why"

# The packaged zeek service would also capture traffic; two readers on one
# interface is confusing when debugging, so keep only our manual instance.
# Zeek installs to /opt/zeek/bin, so link it where every other tool expects it.
if [[ -x /opt/zeek/bin/zeek ]]; then
    ln -sf /opt/zeek/bin/zeek /usr/local/bin/zeek
    ln -sf /opt/zeek/bin/zeekctl /usr/local/bin/zeekctl 2>/dev/null || true
fi
if command -v zeek >/dev/null 2>&1; then
    systemctl disable --now zeek >/dev/null 2>&1 || true
fi

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
  suricata eve  : /var/log/suricata/eve.json
EOF

if command -v zeek >/dev/null 2>&1; then
cat <<EOF
  zeek logs     : /opt/zeek/logs/current

  run the sensors (foreground once to see errors, then -D):
    sudo suricata -i ${IFACE}
    cd /opt/zeek && sudo zeek -i ${IFACE} local
EOF
else
cat <<EOF
  zeek          : not installed (no repository for this release)

  run the sensor (foreground once to see errors, then -D):
    sudo suricata -i ${IFACE}
EOF
fi

cat <<EOF

  generate deterministic traffic:
    sudo cp your-capture.pcap /data/pcap/sample.pcap
    sudo tcpreplay --intf1=${IFACE} /data/pcap/sample.pcap

  smoke test:
    sudo tcpdump -i ${IFACE} -c 5
EOF

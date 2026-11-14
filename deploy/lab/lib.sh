#!/usr/bin/env bash
# Shared helpers for the P4B lab bootstrap scripts.
# Sourced by bootstrap-p4b.sh / bootstrap-sensor.sh / bootstrap-siem.sh.
# Target: Ubuntu Server 22.04 or 24.04. Run as root (sudo bash <script>).

set -euo pipefail

log()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m[!] %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31m[x] %s\033[0m\n' "$*" >&2; exit 1; }

require_root() {
    [[ ${EUID} -eq 0 ]] || die "run with sudo: sudo bash $0"
}

require_ubuntu() {
    [[ -r /etc/os-release ]] || die "not an Ubuntu/Debian system"
    # shellcheck disable=SC1091
    . /etc/os-release
    case "${VERSION_ID}" in
        22.04|24.04|26.04) : ;;
        *) die "unsupported Ubuntu ${VERSION_ID}; this lab targets 22.04, 24.04 or 26.04" ;;
    esac
    # 26.04 is newer than what the Zeek OBS repo builds for; the sensor script
    # probes which repository actually exists instead of trusting the version.
    export UBUNTU_VERSION="${VERSION_ID}"
    export UBUNTU_CODENAME="${VERSION_CODENAME:-}"
}

apt_install() {
    log "installing packages: $*"
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@"
}

install_docker() {
    if command -v docker >/dev/null 2>&1; then
        log "docker already present: $(docker --version)"
        return
    fi
    log "installing docker engine"
    # get.docker.com lags new Ubuntu releases, so fall back to the distro package
    # rather than failing the whole bootstrap.
    if ! curl -fsSL https://get.docker.com | sh; then
        warn "get.docker.com failed; installing docker.io from the Ubuntu archive"
        apt_install docker.io
    fi
    systemctl enable --now docker
}

# Print the interfaces with their addresses, so interface names are never guessed.
show_interfaces() {
    log "network interfaces"
    ip -br addr || true
    warn "use the host-only interface (192.168.56.x) for lab services, not the NAT one"
}

for p in suricata zeek docker.io docker-ce python3-venv tcpreplay libpcap-dev; do
    c=$(apt-cache policy "$p" 2>/dev/null | sed -n 's/^  Candidate: //p' | head -1)
    printf '%-14s %s\n' "$p" "${c:-MISSING}"
done
. /etc/os-release
echo "distro: $PRETTY_NAME ($VERSION_CODENAME)"

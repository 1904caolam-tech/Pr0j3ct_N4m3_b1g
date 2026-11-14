#!/bin/bash
# Configure a running Wazuh manager for the P4B lab and emit one test alert.
#
#   sudo bash wazuh-configure.sh
#
# Why this exists: the stock 4.14 manager image enables vulnerability-detection,
# which downloads CVE feeds into the container's writable layer (multiple GB on a
# 20 GB VM) and can fill the disk during a lab. It also has no localfile for our
# test event. This script rebuilds the config from the image's pristine file, so
# repeated runs never accumulate duplicate blocks, turns VD off, adds one
# localfile, adds rule 100100, restarts the manager, and writes one event.
#
# Prerequisite: the container was started by bootstrap-siem.sh, which mounts
# /data/wazuh/testlogs at /var/log/p4b-test.

set -euo pipefail

CONTAINER="${CONTAINER:-wazuh-manager}"
TAG="${WAZUH_TAG:-4.14.10}"
TESTLOG_DIR="${TESTLOG_DIR:-/data/wazuh/testlogs}"
ALERTS="${ALERTS:-/data/wazuh/logs/alerts/alerts.json}"

[[ ${EUID} -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }
docker ps --format '{{.Names}}' | grep -qx "${CONTAINER}" || {
    echo "container ${CONTAINER} is not running" >&2
    exit 1
}

echo "== pristine config from the image =="
docker run --rm --entrypoint cat "wazuh/wazuh-manager:${TAG}" /var/ossec/etc/ossec.conf > /tmp/p4b-ossec.conf

python3 - <<'PY'
import re

text = open("/tmp/p4b-ossec.conf", encoding="utf-8").read()
text, disabled = re.subn(
    r"(<vulnerability-detection>\s*<enabled>)yes(</enabled>)", r"\1no\2", text
)
print(f"vulnerability-detection disabled: {disabled}")

block = """  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/p4b-test/lab.log</location>
  </localfile>
"""
head, sep, tail = text.rpartition("</ossec_config>")
assert sep, "config has no closing </ossec_config>"
text = head + block + sep + tail
open("/tmp/p4b-ossec.conf", "w", encoding="utf-8").write(text)
print(f"localfile occurrences: {text.count('/var/log/p4b-test/lab.log')}")
PY

docker cp /tmp/p4b-ossec.conf "${CONTAINER}:/var/ossec/etc/ossec.conf" >/dev/null
docker exec "${CONTAINER}" sh -c 'chown root:wazuh /var/ossec/etc/ossec.conf; chmod 660 /var/ossec/etc/ossec.conf'

echo "== custom rule =="
docker exec "${CONTAINER}" sh -c 'grep -q 100100 /var/ossec/etc/rules/local_rules.xml || cat >> /var/ossec/etc/rules/local_rules.xml <<'"'"'XML'"'"'
<!-- P4B lab rule -->
<group name="p4b_lab,">
  <rule id="100100" level="10">
    <match>P4B_LAB_ALERT</match>
    <description>P4B lab test alert from Wazuh manager</description>
    <group>p4b_lab,</group>
  </rule>
</group>
XML'
echo "rule lines: $(docker exec "${CONTAINER}" grep -c 100100 /var/ossec/etc/rules/local_rules.xml)"

echo "== restart =="
docker restart "${CONTAINER}" >/dev/null
for _ in $(seq 1 45); do
    docker exec "${CONTAINER}" sh -c '/var/ossec/bin/wazuh-control status 2>/dev/null | grep -q "wazuh-analysisd is running"' && break
    sleep 2
done
sleep 8

echo "== emit one event =="
mkdir -p "${TESTLOG_DIR}"
touch "${TESTLOG_DIR}/lab.log"
echo "$(date '+%b %d %H:%M:%S') lab p4b: P4B_LAB_ALERT integration check" >> "${TESTLOG_DIR}/lab.log"
chmod 755 "$(dirname "${TESTLOG_DIR}")" "${TESTLOG_DIR}"
chmod 644 "${TESTLOG_DIR}/lab.log"
sleep 15

if [[ -f ${ALERTS} ]] && grep -q P4B_LAB_ALERT "${ALERTS}"; then
    echo "alert written:"
    grep -m1 P4B_LAB_ALERT "${ALERTS}" | cut -c1-300
else
    echo "no alert yet; check: docker exec ${CONTAINER} tail -20 /var/ossec/logs/ossec.log" >&2
    exit 1
fi

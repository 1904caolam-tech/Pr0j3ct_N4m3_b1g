#!/usr/bin/env bash
# Verify a freshly wired lab from the P4B VM.
#
#   ./verify-lab.sh [zeek_dir] [eve.json] [alerts.json]
#
# Defaults match docs/LAB.md phase 4 (/data/ingest/...). Every check prints PASS,
# FAIL or SKIP; the script exits non-zero if anything failed.

set -uo pipefail

ZEEK_DIR="${1:-/data/ingest/zeek}"
EVE="${2:-/data/ingest/suricata/eve.json}"
ALERTS="${3:-/data/ingest/wazuh/alerts.json}"

pass=0
fail=0
skip=0

ok()   { printf '  \033[32mPASS\033[0m  %s\n' "$*"; pass=$((pass + 1)); }
bad()  { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; fail=$((fail + 1)); }
miss() { printf '  \033[33mSKIP\033[0m  %s\n' "$*"; skip=$((skip + 1)); }

echo "== P4B lab verification =="

if command -v p4b >/dev/null 2>&1; then
    ok "p4b on PATH ($(p4b version 2>/dev/null | head -1))"
else
    bad "p4b on PATH - run: pip install -e . && . .venv/bin/activate"
fi

if p4b init >/dev/null 2>&1; then
    ok "database initialised"
else
    bad "database initialised"
fi

count_findings() {
    p4b --json findings --limit 1000 2>/dev/null \
        | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))' 2>/dev/null \
        || echo 0
}

ingest_file() {
    local tool=$1 path=$2
    if [[ ! -f ${path} ]]; then
        miss "${tool}: ${path} not present"
        return
    fi
    if out=$(p4b ingest "${tool}" "${path}" 2>&1); then
        ok "${tool}: $(printf '%s' "${out}" | tr '\n' ' ' | sed 's/  */ /g' | cut -c1-90)"
    else
        bad "${tool}: ${out}"
    fi
}

ingest_file wazuh "${ALERTS}"
ingest_file suricata "${EVE}"

if [[ -d ${ZEEK_DIR} ]]; then
    if out=$(p4b ingest zeek "${ZEEK_DIR}" 2>&1); then
        ok "zeek: $(printf '%s' "${out}" | tr '\n' ' ' | sed 's/  */ /g' | cut -c1-90)"
    else
        bad "zeek: ${out}"
    fi
else
    miss "zeek: ${ZEEK_DIR} not present"
fi

stored=$(count_findings)
if [[ ${stored} -gt 0 ]]; then
    ok "findings stored: ${stored}"
else
    bad "findings stored: 0 (did the sensors produce logs?)"
fi

# Idempotency: re-ingesting must not create new findings.
before=$(count_findings)
if [[ -f ${ALERTS} ]]; then
    p4b ingest wazuh "${ALERTS}" >/dev/null 2>&1
    after=$(count_findings)
    if [[ ${before} -eq ${after} ]]; then
        ok "idempotent re-ingest (${after} findings)"
    else
        bad "re-ingest changed the count: ${before} -> ${after}"
    fi
fi

# Asset resolution: fewer assets than findings when one host reports several times.
if command -v sqlite3 >/dev/null 2>&1; then
    db="${P4B_DATA_DIR:-data}/p4b.db"
    if [[ -f ${db} ]]; then
        assets=$(sqlite3 "${db}" 'select count(*) from assets;')
        findings=$(sqlite3 "${db}" 'select count(*) from findings;')
        if [[ ${assets} -le ${findings} ]]; then
            ok "asset graph shared (${assets} assets / ${findings} findings)"
        else
            bad "more assets than findings: ${assets} / ${findings}"
        fi
    fi
else
    miss "sqlite3 not installed - skipping asset check"
fi

echo
echo "passed=${pass} failed=${fail} skipped=${skip}"
[[ ${fail} -eq 0 ]]

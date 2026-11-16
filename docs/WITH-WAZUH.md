# P4B next to Wazuh

This is the integration shape from the M4 lab: Wazuh 4.14 manager + agent as the
collection/alerting platform, P4B as the detection-engineering layer reading its
alerts. They are complements, not competitors.

## 1. What Wazuh already does

An all-in-one install (manager + indexer + dashboard) gives you: agent enrollment,
log collection, decoders and XML rules, alerts, indexer storage and search, dashboards
with MITRE ATT&CK counts, file-integrity monitoring, SCA, vulnerability detection,
active response and compliance mapping. That is most of a SIEM.

## 2. Three questions Wazuh does not answer

1. **Did the rule actually fire when the technique ran?** Wazuh has no test
   execution/correlation loop. It shows alerts, not whether a rule was exercised.
2. **Which techniques have no rule at all?** The ATT&CK dashboard counts techniques
   *observed in alerts*. A technique that never fired looks the same as one with no
   coverage.
3. **What exactly backs this claim?** There is no per-technique evidence chain of
   rule + test + observation, and no score that moves when you edit content.

P4B answers those three by modelling coverage as three bits — `rule` (Sigma/YARA),
`test` (Atomic), `observed` (real finding) — and scoring `validated / total`.

## 3. What P4B adds on top

| P4B capability | What it gives a Wazuh shop |
|---|---|
| Canonical findings + fingerprint dedupe | same alert replayed never duplicates; counts are honest |
| Case grouping by asset + time window | Wazuh, Suricata and Trivy findings on one asset become one case |
| Sigma/YARA inventory | which techniques have portable content, independent of Wazuh XML |
| Atomic execution matching | proves a rule fires, or marks it `unvalidated` |
| Coverage matrix + score | the blind spots, with the evidence for each cell |
| Remediation links | OWASP cheat sheet per finding class |
| ECS / OCSF export | hand normalized findings to another SIEM |
| Markdown report | an audit-ready snapshot of coverage |

## 4. Wiring it up

### 4.1 Install

Wazuh all-in-one on the `siem` host (their installer). P4B on the `p4b` host, or on
the same machine. Keep sensors (Suricata/Zeek) where they can see traffic.

### 4.2 Get alerts in

**Pull (batch).** `alerts.json` is append-only; ingest it on a schedule:

```bash
p4b ingest wazuh /var/ossec/logs/alerts/alerts.json
```

Fingerprint dedupe makes re-ingesting safe, but the file grows forever — for a
long-running deployment prefer the push path or rotate the file.

**Push (real time).** `deploy/wazuh/custom-p4b.py` as an `integratord` integration;
each alert is posted to `POST /api/v1/ingest/wazuh`. The endpoint is idempotent.

### 4.3 Content

```bash
git clone --depth 1 https://github.com/SigmaHQ/sigma vendor/sigma
# p4b.yaml: sigma_path: vendor/sigma/rules
p4b content sync          # load Sigma + YARA into the rules table
p4b rules --kind sigma
```

### 4.4 Tests

Run Atomic Red Team in a lab host (never production), save the results JSON, then:

```bash
p4b validate --results atomic-results.json --window 900
```

Executions are matched to findings by technique, asset and time window (host filter
only when the asset is a host).

### 4.5 Coverage

```bash
p4b coverage
p4b coverage --status blind         # nothing at all
p4b coverage --status unvalidated   # rule + test, test never fired
p4b coverage --status rule-only     # rule never exercised
```

The same data is in the UI (**Coverage**, **Purple team**).

### 4.6 Cases, report, export

```bash
p4b cases
p4b report --out data/reports/report.md
p4b export --format ocsf --out data/exports/ocsf.jsonl
```

## 5. The weekly loop

1. Pick a technique from `coverage --status blind` or `rule-only`.
2. Write the Sigma/YARA rule (and/or the Wazuh XML rule).
3. Deploy it to Wazuh and to the lab.
4. Run the Atomic test, save the results JSON.
5. `p4b validate` then `p4b coverage` — did the cell move?
6. Commit the content and the evidence.

That is the whole product: a loop that turns "we think we detect this" into a cell
with evidence.

## 6. Honest limits

- **The `rule` bit is Sigma/YARA only.** Wazuh XML rules are not ingested as content;
  a detection that exists only as a Wazuh rule shows up as *observed*, and can read
  `no-rule`. Keep Sigma as the portable source of truth, or extend the model to parse
  Wazuh `ruleset/` later.
- **No raw log storage.** The Wazuh indexer keeps logs; P4B keeps findings.
- **No real-time correlation or alerting.** Ingest is file/HTTP; analysis is on demand.
- **Sigma → Wazuh is not automated.** `p4b content translate` targets SPL/KQL/Lucene,
  not Wazuh XML.
- **Scale.** SQLite single writer; fine for a lab or a small team, not for
  enterprise EPS. Postgres is supported but untested at scale.

## 7. Division of labour

| Job | Owner |
|---|---|
| collect, decode, store, search, alert, compliance | Wazuh all-in-one |
| sensors | Suricata / Zeek / Wazuh agent |
| content inventory, test correlation, coverage, evidence | P4B |

# Demo script (3 minutes)

For a portfolio walkthrough. Every number below comes from `p4b demo --reset` and is
asserted by the test suite, so the demo cannot silently drift.

## 0. Setup (once)

```bash
python -m pip install -e ".[dev]"
p4b init
```

## 1. The loop, one command

```bash
p4b demo --reset
```

Expected:

```
ingest:
  wazuh 2 · suricata 2 · zeek 3 · nuclei 2 · trivy 4 · gitleaks 2 · yara 2
content:
  sigma 3 · yara 2 · atomic 6
validation  3/5 detected (60.0%)
coverage    2/8 validated (25.0%)
cases       4
findings    17 (open 17, max risk 10.0)
```

Say: *seven sources, one schema; the report is at `data/reports/report.md`.*

## 2. The UI

```bash
p4b serve        # http://127.0.0.1:8080
```

Point at, in order:

1. **Overview** — 17 findings, coverage 25%, tool strip (2/10 detected: the content
   repositories are present, no binaries on this laptop).
2. **Findings** — filter `critical`, open the Log4j row: evidence, remediation with
   the OWASP link, ATT&CK tag.
3. **Coverage** — the three dots per technique. `T1003.001` and `T1110` are
   `validated`; `T1059.001` is `unvalidated` (rule + test, but the test was not
   detected); `T1136.001` is `test-only` (blind). This is the point of the project.
4. **Purple team** — 3 of 5 tests detected, with the source that caught each one.
5. **Cases** — four cases; open `acme/payments-api` and show the timeline. The Trivy
   image and the Gitleaks repository are one artifact only because of an asset alias.

## 3. Triage writes history

In the finding drawer, click **triaged**, then **assign…**. Reopen the finding: the
history table has one row per change (actor, field, old → new). The same data is in
`finding_history`, so an auditor can reconstruct who changed what.

## 4. Export

```bash
p4b export --format ocsf --out /tmp/p4b-ocsf.jsonl
head -c 400 /tmp/p4b-ocsf.jsonl
```

One OCSF Detection Finding (class 2004) per line, ready for another SIEM.

## 5. Scheduling (optional, 20 seconds)

```bash
p4b job add --name nightly --tool yara \
  --target demo/fixtures/yara --rules demo/fixtures/yara/lab_rules.yar --every 30
p4b job list
p4b worker --once     # runs what is due, records a run row, reschedules
```

## What to say when asked "why not just use Wazuh + Sigma?"

Because none of those tools answer *"which techniques am I blind to, with evidence?"*
They produce findings. P4B turns findings, rules and test runs into one coverage
matrix where every cell is backed by something observable — and it refuses to count a
rule as coverage until a test has actually fired.

## Numbers to quote

| Metric | Value |
|---|---|
| Sources normalized | 7 |
| Findings | 17 |
| Cases | 4 |
| Techniques tracked | 8 |
| Validated | 2 (25%) |
| Tests detected | 3/5 (60%) |
| Test suite | 282 tests |

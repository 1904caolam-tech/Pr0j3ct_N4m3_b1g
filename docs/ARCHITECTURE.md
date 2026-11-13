# System Architecture — Pr0j3ct_N4m3_b1g (P4B)

> Status: **approved** · Version: 0.2 · Date: 2026-11-13
> Owner: project owner · Author: engineering

## 0. TL;DR

P4B is a **detection engineering workbench**. It ingests telemetry from
Wazuh/Zeek/Suricata, runs scanners (Nuclei/Trivy/Gitleaks/YARA), manages
Sigma/YARA as *code*, and uses Atomic Red Team to **prove** that detections
actually work.

It is not a SIEM. It is not a scanner wrapper. The product is the loop:

```
telemetry + scans  →  findings  →  ATT&CK  →  coverage  →  tests  →  fix rules  →  repeat
```

The value is answering one question: *"Which techniques am I blind to, and what
is the evidence?"*

## 1. Goals and scope

### 1.1 Goals

| # | Goal | Measured by |
|---|---|---|
| G1 | Funnel 10 sources into one model, one place | 10 adapters, 1 `Finding` schema |
| G2 | Dedupe, risk scoring, asset resolution | 1 fingerprint per finding, 1 asset graph |
| G3 | ATT&CK coverage with explicit states | 3-bit matrix (rule / test / observed) |
| G4 | Prove detections with real tests | purple-team scoreboard |
| G5 | Runs in one command, no cloud | `docker compose up` or `p4b demo` |
| G6 | Portfolio-ready | 3-minute demo, docs, tests, screenshots |

### 1.2 In scope

- Ingest: Wazuh `alerts.json`, Zeek logs, Suricata `eve.json` (file, tail, HTTP).
- Scan: Nuclei, Trivy, Gitleaks, YARA (scoped jobs).
- Content: inventory + version + Sigma translation (SPL/KQL/Lucene); YARA index.
- Validation: Atomic inventory + execution results → detected/missed.
- Product: REST API, web UI, CLI, report, triage, cases, minimal auth, compose deploy.

### 1.3 Out of scope (deliberate)

SIEM query engine · own packet capture/DPI · EDR · full SOAR · multi-tenant SaaS ·
replacing the Wazuh manager · offensive exploitation · machine learning.

## 2. Constraints

| Type | Constraint | Architectural consequence |
|---|---|---|
| License | Wazuh GPLv2, Suricata GPLv2 | **No code linking**; process/file/HTTP only |
| License | Sigma rules: DRL 1.1 | Do not redistribute rules; point upstream except in-house rules |
| License | OWASP CheatSheetSeries: CC BY-SA 4.0 | **Link only**, do not embed content |
| Operations | Each tool ships on its own cadence | Versioned adapters, pinned digests, no forks |
| Environment | Windows dev laptop, Linux containers | Pure Python, careful path handling |
| Budget | One machine, no cloud | SQLite, static UI, no message broker in v1 |

## 3. Overall architecture

### 3.1 Context

```
        ┌──────────┐   ┌──────────┐   ┌──────────┐        ┌────────────┐
        │  SOC     │   │  CI/CD   │   │  Lab     │        │ Target SIEM│
        │ analyst  │   │ pipeline │   │ sensors  │        │(Splunk/ES) │
        └────┬─────┘   └────┬─────┘   └────┬─────┘        └─────▲──────┘
             │ browser      │ job          │ logs/HTTP          │ export
             ▼              ▼              ▼                    │
        ┌──────────────────────────────────────────────────────────────┐
        │                         P4B                                  │
        │  ingest · canon · assets · content · scan · validate · api   │
        └───────┬───────────────────────────────┬──────────────────────┘
                │ spawn (subprocess/container)  │ read
                ▼                               ▼
        ┌───────────────┐               ┌────────────────┐
        │ nuclei/trivy/ │               │ wazuh/zeek/    │
        │ gitleaks/yara │               │ suricata logs  │
        └───────────────┘               └────────────────┘
```

### 3.2 Style: modular monolith

One image, two processes (`api`, `worker`), modules split by bounded context.
Rationale: the portfolio requirement is `docker compose up` in under a minute;
microservices at this scale only add operational burden. Module boundaries are
kept strict so they can be extracted later.

```
┌─────────────────────────── p4b (1 codebase) ───────────────────────────┐
│                                                                        │
│  api ────────┐                                                         │
│  cli ────────┼──> canon ──> store <── validate                         │
│  worker ─────┘      ▲          ▲          ▲                            │
│                     │          │          │                            │
│  adapters ──────────┘      content ───────┘                            │
│  (10 tools)                  (sigma/yara)                              │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
     ▲                     ▲                        ▲
  sensors/scanners     rule repos              atomic results
```

### 3.3 Modules and responsibilities

| Module | Responsibility | Does not |
|---|---|---|
| `adapters` | parse native output → `Finding`/`Rule`/`Execution`; build commands | decide risk, write DB |
| `canon` | severity, asset resolution, fingerprint, dedupe, risk, redaction | know about specific tools |
| `assets` | registry + alias graph (host↔ip↔image↔repo) | scan anything |
| `content` | rule store, versioning, translation, lint, deploy bundle | run detection |
| `scan` | job spec, scope check, execution, raw capture | parse (hands back to adapters) |
| `validate` | execution ingest, correlation window, coverage | mutate findings |
| `store` | repositories, migrations, transactions | contain business rules |
| `api` | HTTP, auth, serialization | contain logic |
| `web` | static UI reading the API | touch the database |
| `worker` | job loop (scan/validate/sync) | serve requests |

## 4. Contracts between modules

If these five interfaces are right, everything else is filling in.

### 4.1 `Adapter`

```python
class Adapter(Protocol):
    spec: ToolSpec                  # name, layer, repo, license, native_format
    def available(self) -> bool: ...
    def version(self) -> str: ...
    def parse(self, path: Path, ctx: dict) -> ParseResult
    def build_command(self, target: str, out: Path, opts: dict) -> list[str]
    def scan(self, target: str, out: Path, opts: dict) -> ScanResult
```

`ParseResult = { findings: list[Finding], rules: list[Rule], executions: list[Execution],
stats: dict, warnings: list[str] }`

**Invariant:** `parse()` is pure — no network, no database writes. This makes every
adapter testable from a fixture and deterministic on re-run.

### 4.2 `Source` (pull) and `Sink` (push/export)

```python
class Source(Protocol):
    def poll(self, cursor: str | None) -> tuple[list[bytes], str]

class Sink(Protocol):
    def emit(self, findings: list[Finding], events: list[Event]) -> None
```

v1 sinks: `ecs-jsonl` and `ocsf-jsonl` (files). v2: Elastic `_bulk`, Splunk HEC.

### 4.3 `JobSpec`

```yaml
kind: scan            # scan | validate | sync
tool: nuclei
targets: [https://app.acme.io]
scope:                # mandatory for active tools
  allow: ["app.acme.io", "10.0.4.0/24"]
  deny:  ["10.0.4.31"]
limits: { timeout_s: 1800, rate_limit: 50, max_findings: 5000 }
```

### 4.4 `Finding` (canonical)

```
fingerprint = sha256(source, rule_id|title, asset.kind:asset.key, locator)
fields: id, source, category, title, severity, asset_id, rule_id, rule_name,
        locator, attack[], cwe[], cve[], tags[], refs[], remediation,
        evidence{redacted}, confidence, risk, status, first_seen, last_seen, count
```

### 4.5 `RawArtifact`

```
sha256 (id), source, media_type, size, storage_ref, received_at, run_id
```

Immutable, write-once. Every finding points back to `raw_id` so it can be reproduced.

## 5. Data model

```
tenants ─┬─< assets ─< asset_aliases
         ├─< findings ─< finding_history
         ├─< raw_artifacts
         ├─< rules ─< rule_translations
         ├─< executions
         ├─< cases ─< case_findings >── findings
         ├─< runs
         ├─< jobs
         └─< api_tokens / audit_log
```

| Table | PK | Notes |
|---|---|---|
| `tenants` | id | v1 has one row (`default`) but the column exists everywhere |
| `assets` | id | `kind` ∈ host/ip/url/image/repo/filesystem/cloud; `canonical_key` unique per tenant |
| `asset_aliases` | (asset_id, type, value) | type ∈ hostname/ip/mac/image/repo/url; carries `source`, `confidence` |
| `findings` | id | `fingerprint` unique per tenant; `asset_id` FK; `attack/cwe/cve` arrays |
| `finding_history` | id | every status/severity/assignee change → audit |
| `raw_artifacts` | sha256 | bytes in object store (local dir); DB holds only the ref |
| `rules` | id | kind ∈ sigma/yara/suricata; `content_hash` for version diffing |
| `rule_translations` | (rule_id, backend) | generated query + warnings; reproducible |
| `executions` | id | atomic run; `detected` nullable (NULL = not yet evaluated) |
| `cases` | id | groups findings; `status` open/triage/contained/closed |
| `case_findings` | (case_id, finding_id) | membership + `added_at` + `reason` |
| `runs` | id | one scan/ingest/validate run; stats + errors |
| `jobs` | id | schedule; `enabled`, `last_run_id` |
| `api_tokens` | id | stores only `token_hash`, plus `scopes` |
| `audit_log` | id | actor, action, object, meta |

Coverage is **not** a table in v1 — it is computed from `rules` + `executions` +
`findings`. Materialize later with the same shape if it gets slow.

### 5.1 Why `assets` is a first-class table

This is where the system either joins or falls apart:

```
Wazuh:     WIN-DC01 (agent.name), 10.0.4.31 (agent.ip)
Zeek:      10.0.4.31                (id.resp_h)
Suricata:  10.0.4.31:445            (dest_ip:dest_port)
Trivy:     acme/payments-api:1.8.2  (ArtifactName)
Gitleaks:  acme/payments-api        (repo path)
Nuclei:    app.acme.io              (host)
```

Resolution algorithm (v1, deterministic, logged):

1. Normalize the key per `kind` (host lowercase/no trailing dot; ip strips port;
   image strips digest).
2. Look up `asset_aliases` (type, value) → reuse that asset if found.
3. Otherwise create a new asset and record the originating alias.
4. Learn aliases only from evidence: `agent.name` + `agent.ip` in the same alert
   adds a hostname↔ip alias with confidence 0.9. Never auto-merge existing assets
   on conflict — flag it as `conflict`.
5. Cross-kind merges (image ↔ repo) are **manual** in v1, via the alias API.
   The demo uses one such alias to show why the registry matters.

## 6. Core flows

### 6.1 Continuous ingest

```
sensor ──POST /api/v1/ingest/{tool} (jsonl, gzip)──> adapter.parse
   │                                                      │
   └─ or `p4b ingest --tool wazuh <file>`                 ▼
                                                   canon.normalize
                                                   ├─ severity mapping
                                                   ├─ asset resolution
                                                   ├─ secret redaction
                                                   └─ fingerprint
                                                         │
                                                   upsert (dedupe)
                                                         │
                                             case grouping + audit
```

- Idempotent: re-posting the same file creates no new finding (fingerprint) and
  stores no duplicate raw blob (sha256).
- Backpressure: body over `max_body_mb` → 413; bounded queue drops raw before findings.
- Parse errors: raw is stored, `warnings` returned, HTTP 200.

### 6.2 Scan job

```
job ─> scope.check(target) ─┬─ deny ─> reject, audit
                            └─ allow ─> runner
                                          ├─ spawn (container/bin) + timeout + rate limit
                                          ├─ capture raw artifact
                                          ├─ adapter.parse
                                          └─ canon → upsert
```

`scope.check` is **deny-by-default**: no matching `allow` entry means no execution.
Hard-blocked: `0.0.0.0/0`, `*`, `169.254.169.254`, link-local.

### 6.3 Validation loop

```
atomic results ─> executions ─┐
                              ├─> per execution: find findings with the same technique,
findings ────────────────────┘   same asset (when known), inside ±window
                                        │
                                   detected / missed
                                        │
                                   coverage update + scoreboard
```

The match is deliberately strict: same technique, same asset, inside the window.
Reporting a false *missed* is cheaper than a false *detected* — the point is
finding blind spots, not inflating a score.

### 6.4 Content pipeline (rules as code)

```
vendor/sigma ──sync──> parse ──diff (content_hash)──> rules
                                                     │
                                        translate ───┼──> rule_translations
                                                     │
                                        build bundle ┴──> dist/{splunk,kql,lucene}.json
```

`p4b content diff` reports added/removed/changed rules between two syncs, so it can
gate CI.

### 6.5 Case grouping

A **finding** is a signal. A **case** is a unit of human work that groups related
findings so one decision covers them.

v1 heuristic (deliberately simple and explainable):

1. On every upsert, look for an `open`/`triage` case on the **same asset** whose
   `last_seen` is within `case_window_hours` (default 24h).
2. If found, attach the finding (`case_findings.reason = "same-asset-window"`).
3. If not found **and** the asset already has ≥2 findings in the window, create a
   case titled `<top severity> activity on <asset>`.
4. A single finding on a quiet asset stays uncased — this avoids case spam.
5. Manual merge/split is API-only in v1; UX arrives in M3.

Case status transitions are owned by humans and always recorded in `audit_log`.

## 7. Coverage semantics (3-bit)

Each technique carries three independent bits: `rule` (a stored detection rule —
Sigma or YARA — maps this technique), `test` (an Atomic test exists), `observed` (a
detection was actually seen).

| rule | test | observed | status | Meaning |
|---|---|---|---|---|
| ✓ | ✓ | ✓ | `validated` | Proven to work |
| ✓ | ✓ | ✗ | `unvalidated` | Rule + test exist but the test was not detected → **real gap** |
| ✓ | ✗ | ✓ | `detected` | Works, but no regression test |
| ✓ | ✗ | ✗ | `rule-only` | Dead rule, unverified |
| ✗ | ✓ | ✓ | `no-rule` | Caught by luck; no rule maps this technique |
| ✗ | ✓ | ✗ | `test-only` | Test exists, no rule, nothing seen → **blind** |
| ✗ | ✗ | ✓ | `no-rule` | Same as above |
| ✗ | ✗ | ✗ | `gap` | Nothing at all |

`coverage_score = validated / total techniques` — coarse but honest. We deliberately
do not report "detection rate" as a rule count: 1000 untested rules is zero evidence.

## 8. Severity and risk

Everything normalizes to five levels plus `unknown` (never folded into `info`):

| Source | Mapping |
|---|---|
| Nuclei / Trivy / Sigma | text (`critical/high/...`) |
| Trivy | `UNKNOWN` → `unknown` |
| Wazuh | `rule.level` 0–15: ≥12 critical, 10–11 high, 7–9 medium, 4–6 low |
| Suricata | priority 1→high, 2→medium, 3→low |
| Gitleaks | inferred from rule: private-key/cloud → critical, SaaS token → high |
| YARA | `meta.severity`, else tags (apt/ransomware → critical) |
| Zeek | mapped per notice type |

`risk = base(severity) × exposure(asset) × (0.75 + 0.25×confidence) × kev_boost`
→ 0–10, rounded to 2 decimals. Base: critical 9.5, high 7.5, medium 5, low 2.5,
info 0.5. Exposure: internet 1.25, cloud 1.15, dmz 1.10, internal 1.0, repo 0.90.

## 9. API surface (v1)

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/health` | liveness + version |
| GET | `/api/v1/summary` | counts by severity/source/category, max risk |
| GET | `/api/v1/findings` | filters: severity, source, category, status, attack, q, min_risk, order, limit/offset |
| GET | `/api/v1/findings/{id}` | detail + raw ref + history |
| PATCH | `/api/v1/findings/{id}` | status/assignee (writes history) |
| POST | `/api/v1/ingest/{tool}` | body JSON/JSONL; `?dry_run=1` to validate |
| GET | `/api/v1/assets`, `/api/v1/assets/{id}` | registry + aliases |
| GET | `/api/v1/coverage` | matrix; `?status=unvalidated` |
| GET | `/api/v1/executions` | executed tests + detection result |
| POST | `/api/v1/validate` | accept results (JSON) → score |
| GET | `/api/v1/cases`, `/api/v1/cases/{id}` | case list + timeline |
| PATCH | `/api/v1/cases/{id}` | status/assignee |
| GET | `/api/v1/rules` | rules + translation status |
| POST | `/api/v1/content/sync` | sync from configured path |
| POST | `/api/v1/jobs/{id}/run` | run a job now |
| GET | `/api/v1/report.md` | markdown report |
| GET | `/` | UI |

Rule: **everything the UI shows is reachable through the API.** The UI holds no logic.

## 10. UI

Static SPA (HTML + vanilla JS + CSS), no build step. Five screens:

1. **Overview** — four large numbers (open, critical, validated %, missed tests),
   breakdown by source.
2. **Findings** — filter/sort table, detail drawer (evidence, remediation with OWASP
   links, ATT&CK).
3. **Coverage** — technique × (rule/test/observed) matrix, click through to lists.
4. **Purple team** — test → detected/missed, detecting source, timing.
5. **Cases** — grouped activity with timeline (M3).

No React: a reviewer clones and runs immediately, without `npm install`. The cost is
hand-written rendering for a handful of screens, which is acceptable.

## 11. Deployment

```
compose profiles:
  default   api + worker (image p4b:latest)
  scanners  image p4b-scanner (bundles nuclei/trivy/gitleaks/yara)
  lab       + zeek, suricata sensors, wazuh single-node
  siem      + elastic/splunk to test export
```

| Topology | Used for | Components |
|---|---|---|
| dev | editing code | `p4b serve --reload` + SQLite file, no Docker |
| demo | portfolio | `docker compose up` → http://localhost:8080 |
| lab | real traffic | add `scanners` + `lab`, sensors write to a shared volume |
| prod-ish | practising ops | Postgres, TLS reverse proxy, api tokens, backups |

The worker never mounts the Docker socket (avoids privilege escalation). Scanners are
binaries inside the `p4b-scanner` image, executed via subprocess with `timeout` and
`nice`.

## 12. Security (short threat model)

| Risk | Mitigation |
|---|---|
| Scanner abused for SSRF / out-of-scope scans | deny-by-default `scope.allow`, metadata-IP block, audited targets |
| Secrets leaking into DB/UI/report | masked during `parse` (not only in UI); raw artifacts redacted too |
| API token theft | hashed at rest, scoped, revocable, `last_used_at` |
| Malicious rule (regex DoS, injection during translation) | lint + length/complexity caps; translations are plain text, never eval'd |
| Ingest flooding | body limit, per-token rate limit, drop raw before findings |
| Path traversal on raw/report reads | resolve + prefix check |
| Tool supply chain | pinned versions and digests, version recorded in `tool_health` |

Principle: **tool output is untrusted data.** Validate shape before it reaches the DB.

## 13. Non-functional requirements and operations

| Area | v1 target |
|---|---|
| Throughput | 2k EPS ingest, 50 sensors |
| Data | 5M findings, 90-day retention; raw 7 days (rotated) |
| Latency | alert→API p95 < 5s; query p95 < 200ms at 100k findings |
| Availability | single node, restart < 10s, no loss of acknowledged findings |
| Observability | JSON logs, `/metrics` (Prometheus text), `p4b doctor`, `runs.errors` |
| Backup | `p4b backup` → SQLite dump + raw manifest |
| Migrations | Alembic; automatic on start in dev, explicit command in prod |

## 14. Testing

| Type | Content | Required |
|---|---|---|
| Unit | severity mapping, fingerprint, dedupe, risk, scope check, sigma parser/translator | yes |
| Golden | per adapter: native fixture → expected findings (JSON snapshot) | yes |
| Property | dedupe idempotency: merge(A,A)=A; merge associativity | yes |
| API | every endpoint contract, auth, 4xx paths | yes |
| E2E | `p4b demo` → exactly 8 techniques / 2 validated / 3-of-5 detected / 3 cases | yes |
| Soak | 100k synthetic findings, measure query p95 | later |

CI: `ruff` + `pytest` + `docker compose build` (full lab not run in CI).

## 15. Roadmap

### M0 — Foundation (0.5–1 day)
Repo layout, `pyproject`, config, schema + migrations, CLI skeleton (`init`, `doctor`,
`version`), CI, README skeleton.
**AC:** `pip install -e . && p4b doctor` works; `pytest` green.

### M1 — Closed loop (2–3 days) ← **the critical milestone**
Adapters Wazuh + Suricata + Zeek; Sigma inventory + translation; Atomic inventory +
results; 3-bit coverage; validation; case grouping; CLI + read-only API; markdown
report; demo fixtures.
**AC:** `p4b demo` yields **8 techniques, 2 validated (25%), 3/5 tests detected (60%),
2 cases** (the third case needs scanner data from M2); `report.md` renders; tests
cover parsers, coverage math and the case heuristic.

### M2 — Scanners in the loop (2 days)
Nuclei/Trivy/Gitleaks/YARA, scan jobs, scope enforcement, raw artifacts, job schedule.
**AC:** scanning a local directory produces findings; a target outside scope is refused.

### M3 — Product (2–3 days)
UI (5 screens), token auth, case UX (timeline, merge/split, assign), ECS export,
`docker compose up`.
**AC:** browser shows coverage + findings + case timeline; triage writes history.

### M4 — Real lab (2 days, later)
Compose profile with real Zeek/Suricata + Wazuh integration script; 24h soak.
**AC:** real alerts flow into P4B and coverage updates.

> Rule: do not start M(n+1) until the AC of M(n) passes.

## 16. Target repository layout

```
Pr0j3ct_N4m3_b1g/
├─ pyproject.toml            # package p4b, CLI p4b
├─ README.md                 # quickstart in 3 commands + demo images
├─ docs/
│  ├─ ARCHITECTURE.md        # this file
│  ├─ ADR.md                 # architecture decisions
│  └─ DEMO.md                # 3-minute demo script
├─ src/p4b/
│  ├─ cli.py  __main__.py  config.py
│  ├─ domain/    models.py severity.py risk.py fingerprint.py
│  ├─ adapters/  base.py + 10 adapters
│  ├─ canon/     normalize.py assets.py dedupe.py attack.py remediation.py
│  ├─ content/   store.py sigma_compile.py sigma_query.py yara_index.py
│  ├─ scan/      runner.py scope.py jobs.py
│  ├─ validate/  executions.py coverage.py
│  ├─ store/     engine.py tables.py repositories.py migrations/
│  ├─ api/       app.py routes/ auth.py
│  └─ web/       index.html app.js style.css
├─ tests/        unit/ golden/ api/ e2e/ fixtures/
├─ demo/         fixtures/ scenarios/
├─ deploy/       Dockerfile  scanner.Dockerfile  docker-compose.yml  wazuh/
└─ scripts/      demo.sh  seed.sh
```

## 17. Demo scenario (M1 acceptance contract)

Deterministic fixture data, no network required:

| Source | Findings | Technique |
|---|---|---|
| Nuclei | Log4j RCE (critical), .git config (medium) | T1190 |
| Trivy | 2 CVEs, 1 misconfig, 1 secret | — |
| Gitleaks | Stripe key, private key | — |
| YARA | `Log4j_Exploit_Attempt`, `CobaltStrike_Beacon` | T1190, T1071.001 |
| Suricata | SSH brute force, Log4j exploit | T1110, T1190 |
| Zeek | Port scan, SSH guessing, DNS tunneling heuristic | T1046, T1110, T1071.004 |
| Wazuh | LSASS dump (T1003.001), unknown-user login (T1110) | T1003.001, T1110 |

Rules: Sigma covers T1003.001, T1059.001, T1110. Atomic covers T1003.001, T1059.001,
T1046, T1110, T1136.001.

Expected: **8 techniques** — validated: T1003.001, T1110; unvalidated: T1059.001;
no-rule: T1046, T1190, T1071.001, T1071.004; test-only: T1136.001.
Score = 2/8 = 25%. Validation = 3/5 = 60%. Cases = 2 with telemetry only; the
secrets case (Trivy image + Gitleaks repo joined by an asset alias) arrives with the
scanner fixtures in M2.

## 18. Resolved decisions

| Question | Decision |
|---|---|
| Package name | `p4b`; repo stays `Pr0j3ct_N4m3_b1g` |
| Existing prototype | deleted; fresh start |
| Documentation language | English |
| Cases timing | hybrid (C): tables in M0, grouping in M1, UX in M3 |
| HTTP framework | FastAPI + uvicorn (ADR-013) |

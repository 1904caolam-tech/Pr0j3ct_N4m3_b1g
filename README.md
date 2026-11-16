# Pr0j3ct_N4m3_b1g — P4B

**A detection engineering workbench for ten open-source security tools.**

P4B normalizes telemetry from Wazuh, Zeek and Suricata, runs Nuclei / Trivy /
Gitleaks / YARA scans, manages Sigma and YARA content as code, and uses Atomic Red
Team to *prove* that detections actually fire.

```
telemetry + scans → findings → ATT&CK → coverage → tests → fix rules → repeat
```

The question it answers: **which ATT&CK techniques am I blind to, and what is the
evidence?**

## Install in two minutes

Requires Python 3.10+ (SQLite comes with Python). Docker and the scanner binaries are
optional.

**Where it has been tested**

| Platform | Status | Notes |
|---|---|---|
| Windows 11, Python 3.10 | tested | host that produced the soak/pytest artifacts |
| Windows Server 2022 | prepared, not executed | native Python install (see below); Docker Desktop unsupported |
| Ubuntu 26.04 LTS, Python 3.14 | tested | the three-VM lab (`p4b` VM) |
| Debian slim container, Python 3.12 | tested | the `p4b` image |
| ubuntu-latest CI, Python 3.10/3.11/3.12 | tested | GitHub Actions matrix |
| macOS | not tested | pure Python, expected to work; venv activation is `source .venv/bin/activate` |

The lab guide ([docs/LAB.md](docs/LAB.md)) assumes a **Windows host with VMware
Workstation** and **Ubuntu guests**. The Docker section works on any OS with Docker.

```bash
git clone https://github.com/1904caolam-tech/Pr0j3ct_N4m3_b1g.git
cd Pr0j3ct_N4m3_b1g

python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
python -m pip install -e ".[dev]"

p4b init                           # schema (Alembic) + default tenant
p4b demo --reset                   # bundled fixtures, no scanner binaries needed
p4b serve                          # UI at http://127.0.0.1:8080, API docs at /docs
```

Expected demo output:

```
ingest     wazuh 2 · suricata 2 · zeek 3 · nuclei 2 · trivy 4 · gitleaks 2 · yara 2
validation 3/5 detected (60.0%)
coverage   2/8 validated (25.0%)
cases      4
findings   17 (open 17, max risk 10.0)
report     data/reports/report.md
```

Everything lives under `data/` (`data/p4b.db`, `data/reports/`). To start over:
`p4b demo --reset` or delete `data/`.

In the UI: **Coverage** shows the eight techniques with the rule/test/observed bits,
**Purple team** the five test runs, **Cases** the findings grouped by asset.

Next: [docs/DEMO.md](docs/DEMO.md) is a 3-minute walkthrough, and
[docs/LAB.md](docs/LAB.md) builds the real three-VM lab.

### Troubleshooting

| Symptom | Fix |
|---|---|
| `p4b: command not found` | activate the venv (`source .venv/bin/activate` / `.venv\Scripts\activate`) |
| `demo fixtures not found` | run from the repository root, or set `P4B_DEMO_ROOT=/path/to/demo` |
| `address already in use` | `p4b serve --port 8081` |
| Docker: `cannot connect to the Docker daemon` | start Docker Desktop (or `systemctl start docker`) |

![Ingest and normalization](assets/Input_Normalizing.png)

![Detection loop](assets/detection_loop.png)

Editable diagrams live in [docs/FLOWS.md](docs/FLOWS.md).

> Repository name is `Pr0j3ct_N4m3_b1g`; the package, CLI and images are `p4b`
> (see [ADR-010](docs/ADR.md)).

## The UI

![Overview with demo data](assets/ui-overview.png)

Demo dataset: 17 findings, 2/8 techniques validated (25%), one blind and one
unvalidated technique. The same UI over the lab database — 22 findings from Wazuh,
Suricata and Zeek — is [assets/ui-lab.png](assets/ui-lab.png).

## What is integrated

| Layer | Tools | How P4B consumes them |
|---|---|---|
| Active scan | Nuclei, Trivy, Gitleaks | subprocess, native JSON output |
| Detection content | Sigma, YARA | rule inventory, translation, indexing |
| Telemetry | Wazuh, Zeek, Suricata | log/HTTP ingest, never embedded |
| Validation | Atomic Red Team | test inventory + execution results |
| Knowledge | OWASP CheatSheetSeries | remediation links (not copied text) |

Nothing is linked in-process: Wazuh and Suricata are GPLv2, Sigma rules are DRL,
cheatsheets are CC BY-SA. Adapters talk to tools through processes, files and HTTP
(see [ADR-002](docs/ADR.md)).

`p4b doctor` lists the ten tools and marks what is installed. Without binaries,
`p4b ingest` and `p4b demo` still work; `p4b scan` needs the tool (or the scanner
image below).

## Run it in Docker

```bash
docker compose -f deploy/docker-compose.yml up --build
# UI + API at http://localhost:8080   (OpenAPI docs at /docs)

# demo inside the container (the data volume survives restarts)
docker compose -f deploy/docker-compose.yml run --rm p4b demo --reset

# one-shot scanner: nuclei/trivy/gitleaks/yara are baked into this image
docker compose -f deploy/docker-compose.yml run --rm scanners scan \
  --tool yara \
  --rules /app/demo/fixtures/yara/lab_rules.yar \
  --target /app/demo/fixtures/yara/samples/access.log
```

Two build targets share one Dockerfile: `app` (API + UI, no offensive tooling) and
`scanner` (adds the four binaries, pinned by version). Compose keeps `scanners`
behind a profile so `up` never starts it.

## Windows Server 2022

Native Python install — Docker Desktop does not run on Windows Server, and the Wazuh
manager/sensors stay on Linux.

```powershell
.\deploy\windows\install-service.ps1 -InstallDir C:\p4b
.\deploy\windows\verify-windows.ps1 -InstallDir C:\p4b
```

The installer creates the venv, writes `p4b.yaml` (bind `0.0.0.0:8080`,
`require_auth: true`, SQLite under `C:\p4b\data`), issues one bearer token and
registers a startup scheduled task running `p4b serve` as `SYSTEM`.
Details, TLS/ARR and data-collection options: [deploy/windows/README.md](deploy/windows/README.md).

## Real lab

Three Ubuntu 26.04 VMs on VMware (`p4b`, `sensor`, `siem`), all three sources run
for real:

| Source | Version | Result |
|---|---|---|
| Wazuh manager + agent | 4.14.10, agent id 001 | rule 100100 alert from agent `sensor` |
| Suricata | 8.0.3, live on `ens33` | ET Open alerts on real cross-host HTTP |
| Zeek | 9.0.1 | conn/http/notice logs |

`p4b` ends with **22 findings / 13 assets**, re-ingest is idempotent, and
`deploy/lab/verify-lab.sh` reports **8 pass / 0 fail / 0 skip**.
Build notes and traps: [docs/LAB.md](docs/LAB.md).

## Verification

Repeatability is checked, not assumed. The committed artifacts in
[`artifacts/soak/`](artifacts/soak/) were produced by the scripts beside them:

| Artifact | Evidence |
|---|---|
| [`soak-50.md`](artifacts/soak/soak-50.md) | 50 consecutive full loops (fresh DB → demo → re-ingest → re-validate → ECS + OCSF → 9 API reads): **0 failures, 0 drift** |
| [`pytest-50.md`](artifacts/soak/pytest-50.md) | the 292-test suite run 50 times: **292 passed on every run** |

```bash
python deploy/soak/soak.py --iterations 50
python deploy/soak/tests.py --iterations 50
```

The raw ECS export hash differs between runs because Gitleaks findings carry no
timestamp and are stamped at ingestion; the artifact reports both the stable hash
(identical) and the raw-hash variance. The `soak` GitHub workflow runs the same
scripts on demand and uploads the artifacts.

## Status

| Milestone | Content | State |
|---|---|---|
| **M0** | foundation: config, schema, migrations, CLI, tests | **done** |
| **M1** | closed loop: Wazuh + Suricata + Zeek + Sigma + Atomic → coverage | **done** |
| **M2** | scanners in the loop: Nuclei / Trivy / Gitleaks / YARA | **done** |
| **M3** | product: UI, auth, cases, export, containers | **done** |
| **M4** | real lab: Ubuntu 26.04 VMs, Wazuh + agent, Suricata, Zeek | **done** |

The design lives in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md); decisions and
trade-offs in [docs/ADR.md](docs/ADR.md).

## Layout

```
src/p4b/
  domain/     severity, risk, fingerprint, dataclasses
  canon/      asset normalization (pure functions)
  store/      SQLAlchemy Core tables, repositories, migrations bridge
  api/        FastAPI app, auth, triage and ingest endpoints
  web/        single-file UI (no build step)
  adapters/   one parser per tool
  content/    Sigma/YARA inventory and query translation
  scan/       scope-enforced runner
  sinks/      ECS and OCSF exports
  validate/   coverage matrix and execution matching
  cli.py      the p4b command
migrations/   Alembic environment and revisions
tests/        unit and API tests
deploy/       Dockerfile, compose, lab and soak scripts
docs/         architecture, ADRs, lab guide, demo script
```

Python 3.10+ and SQLite (bundled) are enough. For Postgres:
`pip install -e ".[postgres]"` (psycopg 3) and set
`db_url: postgresql+psycopg://user:pass@host:5432/p4b`; the schema avoids
SQLite-only constructs.

## License

Application code: MIT. Vendored rule repositories keep their own licenses
(Sigma DRL 1.1, YARA BSD-3-Clause, Atomic Apache-2.0, OWASP CC BY-SA 4.0).

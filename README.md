# Pr0j3ct_N4m3_b1g — P4B

**A detection engineering workbench for ten open-source security tools.**

P4B normalizes telemetry from Wazuh, Zeek and Suricata, runs Nuclei / Trivy /
Gitleaks / YARA scans, manages Sigma and YARA content as code, and uses Atomic Red
Team to *prove* that detections actually fire.

The product is one loop:

```
telemetry + scans → findings → ATT&CK → coverage → tests → fix rules → repeat
```

The question it answers: **which ATT&CK techniques am I blind to, and what is the
evidence?**

> Repository name is `Pr0j3ct_N4m3_b1g`; the package, CLI and images are `p4b`
> (see [ADR-010](docs/ADR.md)).

## Status

| Milestone | Content | State |
|---|---|---|
| **M0** | foundation: config, schema, migrations, CLI, tests | **done** |
| **M1** | closed loop: Wazuh + Suricata + Zeek + Sigma + Atomic → coverage | **done** |
| **M2** | scanners in the loop: Nuclei / Trivy / Gitleaks / YARA | **done** |
| **M3** | product: UI, auth, cases, export, containers | **done** |
| M4 | real lab: live sensors, soak test | next |

The design is approved and lives in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md);
decisions and their trade-offs are in [docs/ADR.md](docs/ADR.md).

## Quickstart

```bash
python -m pip install -e ".[dev]"
p4b init          # data dir, schema (Alembic), default tenant
p4b doctor        # detect the ten tools, record versions
p4b demo          # full loop on bundled fixtures -> data/reports/report.md
p4b serve         # UI at / and read-only API + OpenAPI docs at /docs
p4b export --format ocsf   # NDJSON for another SIEM (ecs or ocsf)
p4b config        # show effective settings
pytest -q
```

`p4b doctor` reports which binaries are present. Missing tools are expected on a
laptop — install them, or use the `p4b-scanner` image described below.

## Run it in Docker

```bash
docker compose -f deploy/docker-compose.yml up --build
# UI + API at http://localhost:8080   (OpenAPI docs at /docs)

# demo inside the container (the data volume survives restarts)
docker compose -f deploy/docker-compose.yml run --rm p4b demo --reset

# one-shot scanner: nuclei/trivy/gitleaks/yara are baked into this image
docker compose -f deploy/docker-compose.yml run --rm scanners scan \
  --tool yara --rules /data/rules/lab.yar --target /data
```

Two build targets share one Dockerfile: `app` (API + UI, no offensive tooling) and
`scanner` (adds the four binaries, pinned by version). Compose keeps `scanners`
behind a profile so `up` never starts it.

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

## Layout

```
src/p4b/
  domain/     severity, risk, fingerprint, dataclasses
  canon/      asset normalization (pure functions)
  store/      SQLAlchemy Core tables, repositories, migrations bridge
  tooling.py  the ten tools: availability, version, license
  cli.py      p4b init | doctor | config | version
migrations/   Alembic environment and revisions
tests/        unit tests (in-memory SQLite)
docs/         architecture + ADRs + lab guide
```

## Requirements

Python 3.10+, SQLite (bundled). Postgres is supported by changing `db_url`; the
schema avoids SQLite-only constructs.

## License

Application code: MIT. Vendored rule repositories keep their own licenses
(Sigma DRL 1.1, YARA BSD-3-Clause, Atomic Apache-2.0, OWASP CC BY-SA 4.0).

# Architecture Decision Records — P4B

Each entry records a decision that has been made, with its rationale and its cost.
To change a decision, do not edit the old entry — add a new one with
`Supersedes: ADR-00x`.

---

## ADR-001 — Modular monolith instead of microservices

**Status:** Accepted · 2026-11-12

**Context.** Ten data sources, two workloads (ingest / scan), one UI. Microservices
would give clean boundaries but require a broker, service discovery, tracing and six
containers — incompatible with "clone and run in one command" on a single machine.

**Decision.** One codebase, one image, two entrypoints (`api`, `worker`). Modules are
split by bounded context and talk through Python interfaces, never HTTP.

**Consequences.**
- (+) Simple compose, one place to debug, fast tests, minimal ops.
- (+) Still extractable later because `scan` and `canon` never import from `api`.
- (−) No independent scaling: a heavy scan can slow ingest. Mitigated by running the
  worker as its own process with `timeout` and `nice`.
- (−) One bad import can break the app. Mitigated by import tests and lazy imports for
  heavy modules (`scan`, `web`).

---

## ADR-002 — Adapters call tools out-of-process; nothing is embedded

**Status:** Accepted

**Context.** Wazuh and Suricata are GPLv2; Sigma rules are DRL; OWASP cheatsheets are
CC BY-SA. Linking GPL code into the same process creates legal obligations nobody
needs. Each tool also has its own release cadence and native dependencies.

**Decision.** Every tool runs as its own process/container. An adapter only
(1) builds a command, or (2) parses existing output.

**Consequences.**
- (+) Crash isolation, independent upgrades, no license entanglement.
- (+) Parsers are pure, so they are testable from fixtures without installing tools.
- (−) Ten adapters and ten output schemas to maintain.
- (−) No access to a tool's internal API (e.g. Zeek cluster management). Accepted.

---

## ADR-003 — Internal canonical model with ECS/OCSF projections

**Status:** Accepted

**Context.** ECS is capable but Elastic-specific; OCSF is well normalized but heavy
and still uncommon among OSS tools. Persisting ECS directly would make schema changes
painful.

**Decision.** A small internal model (`Finding`, `Asset`, `Execution`, `Rule`) is the
source of truth. Export happens through `Sink`: `ecs-jsonl` and `ocsf-jsonl` in v1.

**Consequences.**
- (+) No hard dependency on Elastic; changing destination does not change the database.
- (−) Projections must be written and tested; some mappings are lossy (ECS
  `threat.technique` differs structurally from OCSF), and the gap must be documented.

---

## ADR-004 — ATT&CK is the join key; coverage is a 3-bit vector

**Status:** Accepted

**Context.** The common approach counts rules or alerts and calls it coverage. That
proves nothing: 1000 untested rules is zero evidence.

**Decision.** Each technique carries three independent bits — `rule` (Sigma mapping),
`test` (Atomic test), `observed` (a detection was seen). Status is derived from the
8-row truth table in ARCHITECTURE §7. `coverage_score = validated / total`.

**Consequences.**
- (+) Honest reporting; blind spots (`test-only`, `unvalidated`) become visible.
- (+) Answers "what is the evidence?", not "do I feel safe?".
- (−) A good score requires all three sources, so content work cannot be skipped.
  That is the point of the product.

---

## ADR-005 — SQLite by default; SQLAlchemy Core + Alembic; Postgres path

**Status:** Accepted

**Context.** A portfolio project must run without a server, but "complete system"
implies migrations, transactions and a credible upgrade path.

**Decision.** Default DSN `sqlite:///data/p4b.db` (WAL mode). Use SQLAlchemy **Core**
(no ORM) plus Alembic. Domain objects are dataclasses; repositories map rows to
dataclasses. Postgres is a DSN change plus a migration run.

**Consequences.**
- (+) One codebase supports both; versioned schema; reviewers see migration discipline.
- (−) Two more dependencies; must avoid SQLite-only syntax (JSON operators, `RETURNING`).
- (−) More verbose than hand-written SQL. Accepted for portability.

---

## ADR-006 — Active scanning is deny-by-default

**Status:** Accepted

**Context.** Nuclei is a real attack tool. A bad config can scan the Internet or hit a
cloud metadata endpoint.

**Decision.** `JobSpec.scope.allow` is mandatory for active tools. No match means no
execution, and the refusal is audited. Hard-block `0.0.0.0/0`, `*`, `169.254.169.254`
and link-local ranges. `--dry-run` prints targets before anything runs.

**Consequences.**
- (+) No accidents; "who scanned what" is auditable.
- (−) Extra friction when using the tool. Intentional.

---

## ADR-007 — Immutable raw artifacts; secrets masked at ingest

**Status:** Accepted

**Context.** Debugging needs raw output, but Gitleaks/Trivy raw output contains
verbatim secrets.

**Decision.** Raw artifacts are stored by sha256, written once, never mutated.
**Masking happens in `parse()`**, not in the UI, so secrets never reach the database.
Evidence is redacted too, and payloads are never logged.

**Consequences.**
- (+) Leaking secrets through the platform itself is impossible by construction.
- (−) Cannot re-read the original secret later; investigate at the source instead.

---

## ADR-008 — In-house Sigma translator; pySigma optional

**Status:** Accepted

**Context.** pySigma plus backend plugins is the standard, but each backend is a
separate package with drifting versions and output that does not always run. For three
backends (SPL/KQL/Lucene) and a common rule subset, a focused translator is cheaper.

**Decision.** Own translator (`content/sigma_query.py`) covering selection
AND/OR/NOT, `all of`/`1 of`/`them`, and modifiers contains/startswith/endswith/re/
all/gt/lt, plus null handling. Anything unsupported (aggregations, base64offset, cidr)
produces an explicit warning instead of silently wrong output. If `pysigma` is
installed, it is used as a cross-check in tests only, never at runtime.

**Consequences.**
- (+) No plugin dependency; controlled output; honest warnings.
- (−) Does not cover all of Sigma; the report must state the translation rate.
- (−) Hand-written condition parser means our own bugs; mitigated with property and
  golden tests.

---

## ADR-009 — Static UI, no build step

**Status:** Accepted

**Context.** React/Vite produces a prettier UI but adds `node_modules`, a build step,
and forces reviewers to `npm install` before seeing anything.

**Decision.** HTML + CSS + vanilla JS served by the API itself, talking to `/api/v1`.
Charts are hand-drawn SVG.

**Consequences.**
- (+) `git clone && p4b serve` is enough. No frontend toolchain.
- (−) No component model; complex state must be managed by hand, so the UI stays at
  five screens and no more.

---

## ADR-010 — Names: repo `Pr0j3ct_N4m3_b1g`, package `p4b`

**Status:** Accepted

**Context.** The repository name is fixed by the owner, but it is unusable as a Python
package or CLI command (long, easy to mistype).

**Decision.** Repository and project: `Pr0j3ct_N4m3_b1g`. Package, CLI, images and DB
prefix: `p4b`. Docs refer to the system as **P4B**.

**Consequences.**
- (+) Short commands: `p4b demo`, `p4b serve`.
- (−) Two names to explain once in the README.

---

## ADR-011 — Separate worker process; scheduling through a `jobs` table

**Status:** Accepted

**Context.** Scans and validation need to run periodically. APScheduler/celery add
dependencies and concepts; external cron is hard to test.

**Decision.** `p4b worker` is a loop that reads the `jobs` table (simple interval/cron
fields), runs sequentially and records `runs`. It supports `--once` for tests and CI.

**Consequences.**
- (+) Testable via `--once`; no dependency; schedule state lives in the database.
- (−) No parallelism or distributed locking; one worker only (fine for a lab).

---

## ADR-012 — Cases: schema in M0, grouping in M1, UX in M3

**Status:** Accepted · 2026-11-13

**Context.** Findings are machine-generated signals; cases are units of human work.
Without cases, an analyst sees 17 unrelated rows and has to remember that a port scan
and a brute force hit the same host. With cases, one decision covers a chain.
Adding case tables later means a migration plus API and UI churn; adding them during
schema design costs almost nothing. But auto-grouping heuristics need real findings to
tune, and a full case UX only pays off once there is data.

**Decision (hybrid option C).**
- M0: create `cases` and `case_findings`, wire foreign keys, no behaviour.
- M1: implement the same-asset/24h grouping heuristic (≈100 lines) plus read API.
- M3: full UX — timeline, merge/split, assignment — and manual case creation.

**Consequences.**
- (+) No schema churn later; coverage work in M1 is not derailed.
- (+) The heuristic gets exercised against real demo data from day one.
- (−) Until M3, cases are read-only in the UI and can only be merged through the API.
- (−) The 24h/asset heuristic may over-group; accepted for v1 and tuneable via
  `case_window_hours`.

---

## ADR-013 — FastAPI + uvicorn for the HTTP layer

**Status:** Accepted · 2026-11-13

**Context.** The API needs validation, auth hooks, and auto-generated documentation
that looks professional in a portfolio. Options considered: stdlib `http.server`
(zero dependencies, but hand-rolled routing/validation), Flask (minimal, no schema
generation), FastAPI (typed models, OpenAPI, dependency injection).

**Decision.** FastAPI with uvicorn. Request/response models are Pydantic; the OpenAPI
schema at `/docs` doubles as portfolio documentation and as a contract for tests.
The domain layer stays framework-free, so the API is a thin shell over `canon`,
`store` and `validate`.

**Consequences.**
- (+) Request validation, typed handlers, free OpenAPI, easy `TestClient` in tests.
- (+) Swapping to another framework only touches `api/`.
- (−) Adds FastAPI/uvicorn/pydantic to the dependency set and an async layer that is
  mostly unnecessary at this scale (handlers stay sync; FastAPI runs them in a pool).
- (−) Slight risk of pydantic version drift; pin ranges in `pyproject.toml`.

# Soak report — 50 iterations

- generated: 2026-11-14T19:28:09+00:00
- p4b 0.1.0 on Python 3.10.11 (Windows)
- failures: **0**
- drift: **none**

## Timing (ms)

| min | median | p95 | max |
|---|---|---|---|
| 12742.0 | 12984.5 | 13240.4 | 14735.7 |

## Stable values

| metric | value |
|---|---|
| findings | 17 |
| cases | 4 |
| executions | 5 |
| validated | 2 |
| detected | 3 |
| ecs_lines | 17 |
| ocsf_lines | 17 |
| ecs_stable_sha256 | 7c424f065b5a493237cdac60c70c0e5e33e0b67443dc0ed0198f912b88ec5e90 |
| ocsf_uid_sha256 | 25a274338482c3342ce91de09a768fa3670555ba62ed6bb5ccc8fd30f9b800ae |

ECS stable hash identical: `True` (raw ECS hashes: 50 distinct — `@timestamp` only, because Gitleaks output carries no time and is stamped at ingestion)
OCSF finding-UID set identical: `True`

Each iteration: fresh database → `demo --reset` → second ingest (must create 0) →
second validate (must not add executions) → ECS + OCSF export → 9 API reads.

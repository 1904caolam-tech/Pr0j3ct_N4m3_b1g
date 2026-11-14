# Data flows

Two diagrams explain the whole system. Rendered copies live in `assets/`; the sources
below stay in the repo so they can be edited.

## 1. Ingest and normalization

![Ingest pipeline](../assets/Input_Normalizing.png)

```mermaid
%%{init: {"flowchart": {"curve": "basis", "nodeSpacing": 45, "rankSpacing": 55}}}%%
flowchart LR
    subgraph SRC["sources"]
        direction TB
        SENS["sensors<br/>Wazuh · Zeek · Suricata"]
        SCANNERS["scanners<br/>Nuclei · Trivy · Gitleaks · YARA"]
    end

    ING["ingest<br/>HTTP / file"]
    JOB["scan job<br/>scope + limits"]
    RAW[("raw artifact<br/>sha256, immutable")]
    PARSE["adapter.parse<br/>pure function"]
    CANON["canon<br/>severity · asset · redact · fingerprint"]
    DUP{"known<br/>fingerprint?"}
    NEW["insert finding"]
    MERGE["merge<br/>count · max severity · union"]
    CASE["case<br/>same asset / 24h"]
    DB[("findings · assets · cases")]

    SENS --> ING --> RAW
    SCANNERS --> JOB --> RAW
    RAW --> PARSE --> CANON --> DUP
    DUP -->|no| NEW --> CASE
    DUP -->|yes| MERGE --> CASE
    CASE --> DB
```

## 2. Detection loop

![Detection loop](../assets/detection_loop.png)

```mermaid
%%{init: {"flowchart": {"curve": "basis", "nodeSpacing": 45, "rankSpacing": 55}}}%%
flowchart LR
    subgraph CONTENT["content"]
        direction TB
        SIG["Sigma rules"] --> TR["translate<br/>SPL / KQL / Lucene"] --> RULES[("rules")]
        ATO["Atomic tests"] --> INV["inventory"] --> ATOM[("atomics")]
    end

    subgraph RUNTIME["runtime"]
        direction TB
        FIND[("findings")]
        RES["test results"] --> EXEC[("executions")]
    end

    RULES --> COV["coverage<br/>rule? · test? · observed?"]
    ATOM --> COV
    FIND --> COV

    FIND --> MATCH["match<br/>technique + asset +/- window"]
    EXEC --> MATCH
    MATCH --> VERDICT{"detected?"}
    VERDICT -->|yes| COV
    VERDICT -->|no| GAP["missed<br/>coverage gap"]
    GAP --> COV

    COV --> API["REST API"] --> OUT["UI · report.md · ECS/OCSF"]
```

## Reading the coverage matrix

| rule | test | observed | status |
|---|---|---|---|
| yes | yes | yes | `validated` — proven |
| yes | yes | no | `unvalidated` — test did not fire |
| yes | no | yes | `detected` — works, no regression test |
| yes | no | no | `rule-only` — never exercised |
| no | yes | no | `test-only` — blind |
| no | yes | yes | `no-rule` — caught by luck |
| no | no | no | `gap` — nothing |

`coverage_score = validated / total`. Nothing else counts.

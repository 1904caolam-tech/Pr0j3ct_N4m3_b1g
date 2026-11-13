"""Read-only HTTP API.

Thin by design: every handler maps a query to a repository call. No business logic
lives here, so the CLI and the API can never disagree.

Auth and write endpoints arrive in M3; this is the read surface the UI and a Wazuh
integration script need.
"""

from __future__ import annotations

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import PlainTextResponse

from .. import __version__
from ..report import build_report
from ..store.repositories import Repositories
from ..validate import build_coverage, summarize

DESCRIPTION = """
P4B detection engineering workbench.

Read-only surface over normalized findings, ATT&CK coverage, purple-team results
and grouped cases. Generated documentation for this API is what `/docs` shows.
"""


def _split(value: str | None) -> list[str] | None:
    items = [item.strip() for item in (value or "").split(",") if item.strip()]
    return items or None


def create_app(repos: Repositories) -> FastAPI:
    app = FastAPI(title="P4B", version=__version__, description=DESCRIPTION)

    @app.get("/", include_in_schema=False)
    def root() -> dict:
        return {"service": "p4b", "version": __version__, "docs": "/docs", "api": "/api/v1"}

    @app.get("/api/v1/health", tags=["system"])
    def health() -> dict:
        return {"status": "ok", "version": __version__}

    @app.get("/api/v1/summary", tags=["findings"])
    def summary() -> dict:
        return repos.summary()

    @app.get("/api/v1/findings", tags=["findings"])
    def findings(
        severity: str | None = Query(None, description="comma separated, e.g. critical,high"),
        source: str | None = Query(None, description="comma separated, e.g. wazuh,zeek"),
        category: str | None = None,
        status: str | None = None,
        attack: str | None = Query(None, description="ATT&CK technique, e.g. T1003.001"),
        q: str | None = Query(None, description="substring of title, locator, rule id or asset"),
        min_risk: float | None = None,
        order: str = Query("risk", pattern="^(risk|recent|severity|asset)$"),
        limit: int = Query(100, ge=1, le=1000),
        offset: int = Query(0, ge=0),
    ) -> list[dict]:
        return repos.list_findings(
            severities=_split(severity),
            sources=_split(source),
            categories=_split(category),
            statuses=_split(status),
            attack=attack,
            query=q,
            min_risk=min_risk,
            order=order,
            limit=limit,
            offset=offset,
        )

    @app.get("/api/v1/findings/{finding_id}", tags=["findings"])
    def finding(finding_id: str) -> dict:
        row = repos.get_finding(finding_id)
        if row is None:
            raise HTTPException(status_code=404, detail=f"finding not found: {finding_id}")
        return row

    @app.get("/api/v1/coverage", tags=["coverage"])
    def coverage(status: str | None = None) -> dict:
        rows = build_coverage(
            repos.list_rules(limit=100_000),
            repos.list_atomics(),
            repos.list_findings(limit=100_000),
        )
        wanted = _split(status)
        if wanted:
            rows = [row for row in rows if row.status in wanted]
        return {"summary": summarize(rows), "rows": [row.to_dict() for row in rows]}

    @app.get("/api/v1/executions", tags=["validation"])
    def executions() -> list[dict]:
        return repos.list_executions()

    @app.get("/api/v1/cases", tags=["cases"])
    def cases(limit: int = Query(50, ge=1, le=500)) -> list[dict]:
        return repos.list_cases(limit=limit)

    @app.get("/api/v1/cases/{case_id}", tags=["cases"])
    def case(case_id: str) -> dict:
        row = repos.get_case(case_id)
        if row is None:
            raise HTTPException(status_code=404, detail=f"case not found: {case_id}")
        return row

    @app.get("/api/v1/rules", tags=["content"])
    def rules(
        kind: str | None = Query(None, pattern="^(sigma|yara)$"),
        attack: str | None = None,
        limit: int = Query(200, ge=1, le=5000),
    ) -> list[dict]:
        return repos.list_rules(kind=kind, attack=attack, limit=limit)

    @app.get("/api/v1/report.md", response_class=PlainTextResponse, tags=["report"])
    def report() -> PlainTextResponse:
        return PlainTextResponse(build_report(repos), media_type="text/markdown; charset=utf-8")

    return app

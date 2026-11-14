"""Read-only HTTP API.

Thin by design: every handler maps a query to a repository call. No business logic
lives here, so the CLI and the API can never disagree.

Auth and write endpoints arrive in M3; this is the read surface the UI and a Wazuh
integration script need.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel

from .. import __version__
from ..report import build_report
from ..sinks import documents as export_documents
from ..sinks import render_jsonl
from ..store.repositories import Repositories
from ..validate import build_coverage, summarize
from .auth import Principal, bearer_token, hash_token

WEB_INDEX = Path(__file__).resolve().parents[1] / "web" / "index.html"

DESCRIPTION = """
P4B detection engineering workbench.

Normalized findings, ATT&CK coverage, purple-team results and grouped cases. Reads
are open by default for local use; set `require_auth: true` before exposing the API,
and use `p4b token create` to issue a bearer token for writes.
"""

FINDING_STATUSES = {"open", "triaged", "suppressed", "fixed", "false_positive"}
CASE_STATUSES = {"open", "triage", "contained", "closed"}


class FindingPatch(BaseModel):
    status: str | None = None
    assignee: str | None = None


class CasePatch(BaseModel):
    status: str | None = None
    assignee: str | None = None


def _split(value: str | None) -> list[str] | None:
    items = [item.strip() for item in (value or "").split(",") if item.strip()]
    return items or None


def create_app(repos: Repositories, *, require_auth: bool = False) -> FastAPI:
    app = FastAPI(title="P4B", version=__version__, description=DESCRIPTION)

    @app.middleware("http")
    async def enforce_auth(request: Request, call_next):
        path = request.url.path
        if require_auth and path.startswith("/api/v1") and path != "/api/v1/health":
            token = bearer_token(request.headers.get("authorization"))
            row = repos.principal_for_token(hash_token(token)) if token else None
            if row is None:
                return JSONResponse(
                    {"detail": "missing or invalid bearer token"},
                    status_code=401,
                    headers={"WWW-Authenticate": "Bearer"},
                )
            request.state.principal = Principal(name=row["name"], scopes=tuple(row["scopes"]))
        return await call_next(request)

    def current(request: Request) -> Principal:
        who = getattr(request.state, "principal", None)
        if who is not None:
            return who
        if require_auth:  # pragma: no cover - middleware already refused
            raise HTTPException(status_code=401, detail="missing bearer token")
        return Principal(name="anonymous", scopes=("admin",))

    def require_write(request: Request) -> Principal:
        who = current(request)
        if not who.can("write"):
            raise HTTPException(status_code=403, detail="token lacks the 'write' scope")
        return who

    @app.get("/", include_in_schema=False)
    def root():
        if WEB_INDEX.is_file():
            return FileResponse(WEB_INDEX, media_type="text/html")
        return {"service": "p4b", "version": __version__, "docs": "/docs", "api": "/api/v1"}

    @app.get("/api/v1", include_in_schema=False)
    def api_root() -> dict:
        return {"service": "p4b", "version": __version__, "docs": "/docs"}

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

    @app.get("/api/v1/export", response_class=PlainTextResponse, tags=["report"])
    def export(
        fmt: str = Query("ecs", alias="format", pattern="^(ecs|ocsf)$"),
        limit: int = Query(100_000, ge=1, le=500_000),
    ) -> PlainTextResponse:
        rows = repos.list_findings(limit=limit)
        return PlainTextResponse(
            render_jsonl(export_documents(rows, fmt)),
            media_type="application/x-ndjson",
            headers={"Content-Disposition": f'attachment; filename="p4b-{fmt}.jsonl"'},
        )

    # -- triage (writes) ---------------------------------------------------- #

    @app.patch("/api/v1/findings/{finding_id}", tags=["triage"])
    def patch_finding(finding_id: str, payload: FindingPatch, request: Request) -> dict:
        who = require_write(request)
        if payload.status is not None and payload.status not in FINDING_STATUSES:
            raise HTTPException(
                status_code=422, detail=f"status must be one of {sorted(FINDING_STATUSES)}"
            )
        row = repos.update_finding(
            finding_id, status=payload.status, assignee=payload.assignee, actor=who.name
        )
        if row is None:
            raise HTTPException(status_code=404, detail=f"finding not found: {finding_id}")
        return row

    @app.get("/api/v1/findings/{finding_id}/history", tags=["triage"])
    def finding_history(finding_id: str) -> list[dict]:
        return repos.finding_history(finding_id)

    @app.patch("/api/v1/cases/{case_id}", tags=["triage"])
    def patch_case(case_id: str, payload: CasePatch, request: Request) -> dict:
        who = require_write(request)
        if payload.status is not None and payload.status not in CASE_STATUSES:
            raise HTTPException(
                status_code=422, detail=f"status must be one of {sorted(CASE_STATUSES)}"
            )
        row = repos.update_case(
            case_id, status=payload.status, assignee=payload.assignee, actor=who.name
        )
        if row is None:
            raise HTTPException(status_code=404, detail=f"case not found: {case_id}")
        return row

    @app.post("/api/v1/cases/{case_id}/findings/{finding_id}", tags=["triage"])
    def attach_finding(case_id: str, finding_id: str, request: Request) -> dict:
        who = require_write(request)
        if repos.get_case(case_id) is None:
            raise HTTPException(status_code=404, detail=f"case not found: {case_id}")
        repos.attach_finding(case_id, finding_id, reason=f"manual:{who.name}")
        return repos.get_case(case_id) or {}

    @app.delete("/api/v1/cases/{case_id}/findings/{finding_id}", tags=["triage"])
    def detach_finding(case_id: str, finding_id: str, request: Request) -> dict:
        require_write(request)
        if repos.get_case(case_id) is None:
            raise HTTPException(status_code=404, detail=f"case not found: {case_id}")
        repos.detach_finding(case_id, finding_id)
        return repos.get_case(case_id) or {}

    return app

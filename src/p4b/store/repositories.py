"""Repositories: the only place that speaks SQL.

Business rules live elsewhere. Everything here takes domain objects, returns plain
dicts (ready for JSON), and never lets a raw SQLAlchemy row escape.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from typing import Any

import sqlalchemy as sa

from ..domain.models import Asset, Finding, utcnow
from ..domain.severity import Severity
from . import tables as t


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _asset_id(tenant: str, kind: str, key: str) -> str:
    digest = hashlib.sha1(f"{tenant}|{kind}|{key}".encode()).hexdigest()
    return f"ast_{digest[:16]}"


def _unions(*values: Iterable[str] | None) -> list[str]:
    out: list[str] = []
    for value in values:
        for item in value or []:
            if item not in out:
                out.append(item)
    return out


class Repositories:
    def __init__(self, engine: sa.Engine, tenant: str = "default"):
        self.engine = engine
        self.tenant = tenant

    # -- tenants ----------------------------------------------------------- #

    def ensure_tenant(self, name: str = "Default") -> str:
        with self.engine.begin() as conn:
            exists = conn.scalar(sa.select(t.tenants.c.id).where(t.tenants.c.id == self.tenant))
            if not exists:
                conn.execute(
                    sa.insert(t.tenants).values(id=self.tenant, name=name, created_at=utcnow())
                )
        return self.tenant

    # -- tool health ------------------------------------------------------- #

    def save_tool_health(self, rows: Iterable[dict[str, Any]]) -> int:
        count = 0
        with self.engine.begin() as conn:
            for row in rows:
                values = {
                    "name": row["name"],
                    "layer": row["layer"],
                    "available": bool(row.get("available")),
                    "version": str(row.get("version") or ""),
                    "path": str(row.get("path") or ""),
                    "checked_at": utcnow(),
                    "note": str(row.get("note") or ""),
                }
                exists = conn.scalar(
                    sa.select(t.tool_health.c.name).where(t.tool_health.c.name == values["name"])
                )
                if exists:
                    conn.execute(
                        sa.update(t.tool_health)
                        .where(t.tool_health.c.name == values["name"])
                        .values(**{k: v for k, v in values.items() if k != "name"})
                    )
                else:
                    conn.execute(sa.insert(t.tool_health).values(**values))
                count += 1
        return count

    def list_tool_health(self) -> list[dict[str, Any]]:
        with self.engine.connect() as conn:
            rows = conn.execute(
                sa.select(t.tool_health).order_by(t.tool_health.c.layer, t.tool_health.c.name)
            ).mappings()
            return [dict(row) for row in rows]

    # -- assets ------------------------------------------------------------ #

    def asset_id_for_alias(self, alias_type: str, alias_value: str) -> str | None:
        with self.engine.connect() as conn:
            return conn.scalar(
                sa.select(t.asset_aliases.c.asset_id).where(
                    t.asset_aliases.c.alias_type == alias_type,
                    t.asset_aliases.c.alias_value == alias_value,
                )
            )

    def get_or_create_asset(
        self,
        asset: Asset,
        *,
        alias_type: str = "",
        alias_value: str = "",
        source: str = "",
    ) -> str:
        alias_type = alias_type or asset.kind
        alias_value = alias_value or asset.key
        now = utcnow()
        with self.engine.begin() as conn:
            if alias_value:
                found = conn.scalar(
                    sa.select(t.asset_aliases.c.asset_id).where(
                        t.asset_aliases.c.alias_type == alias_type,
                        t.asset_aliases.c.alias_value == alias_value,
                    )
                )
                if found:
                    conn.execute(
                        sa.update(t.assets).where(t.assets.c.id == found).values(last_seen=now)
                    )
                    return found

            existing = conn.scalar(
                sa.select(t.assets.c.id).where(
                    t.assets.c.tenant_id == self.tenant,
                    t.assets.c.kind == asset.kind,
                    t.assets.c.canonical_key == asset.key,
                )
            )
            if existing:
                asset_id = existing
                conn.execute(
                    sa.update(t.assets).where(t.assets.c.id == asset_id).values(last_seen=now)
                )
            else:
                asset_id = _asset_id(self.tenant, asset.kind, asset.key)
                conn.execute(
                    sa.insert(t.assets).values(
                        id=asset_id,
                        tenant_id=self.tenant,
                        kind=asset.kind,
                        canonical_key=asset.key,
                        name=asset.name,
                        ip=asset.ip,
                        exposure=asset.exposure,
                        attrs={},
                        first_seen=now,
                        last_seen=now,
                    )
                )
            if alias_value:
                conn.execute(
                    sa.insert(t.asset_aliases).values(
                        id=f"als_{hashlib.sha1(f'{asset_id}|{alias_type}|{alias_value}'.encode()).hexdigest()[:16]}",
                        asset_id=asset_id,
                        alias_type=alias_type,
                        alias_value=alias_value,
                        source=source,
                        confidence=1.0,
                        created_at=now,
                    )
                )
            return asset_id

    def add_alias(
        self, asset_id: str, alias_type: str, alias_value: str, source: str = "manual"
    ) -> bool:
        """Attach an alias to an asset. Returns False if it is already taken.

        Cross-kind aliases (image pushed to a repository, container running on a host)
        are what make one incident out of findings that arrive from different tools.
        """
        now = utcnow()
        with self.engine.begin() as conn:
            existing = conn.scalar(
                sa.select(t.asset_aliases.c.asset_id).where(
                    t.asset_aliases.c.alias_type == alias_type,
                    t.asset_aliases.c.alias_value == alias_value,
                )
            )
            if existing:
                return str(existing) == str(asset_id)
            conn.execute(
                sa.insert(t.asset_aliases).values(
                    id="als_" + hashlib.sha1(
                        f"{asset_id}|{alias_type}|{alias_value}".encode()
                    ).hexdigest()[:16],
                    asset_id=asset_id,
                    alias_type=alias_type,
                    alias_value=alias_value,
                    source=source,
                    confidence=1.0,
                    created_at=now,
                )
            )
        return True

    # -- findings ---------------------------------------------------------- #

    def upsert_finding(self, finding: Finding) -> tuple[bool, str]:
        """Insert or merge by fingerprint. Returns ``(created, id)``."""
        finding.compute_risk()
        fingerprint = finding.fingerprint
        finding_id = finding.id
        asset_id = self.get_or_create_asset(finding.asset, source=finding.source)

        values = {
            "id": finding_id,
            "tenant_id": self.tenant,
            "fingerprint": fingerprint,
            "source": finding.source,
            "category": finding.category,
            "title": finding.title,
            "severity": finding.severity.value,
            "severity_rank": finding.severity.rank,
            "asset_id": asset_id,
            "rule_id": finding.rule_id,
            "rule_name": finding.rule_name,
            "locator": finding.locator,
            "attack": sorted(set(finding.attack)),
            "cwe": sorted(set(finding.cwe)),
            "cve": sorted(set(finding.cve)),
            "tags": sorted(set(finding.tags)),
            "refs": list(dict.fromkeys(finding.references)),
            "remediation": finding.remediation,
            "evidence": finding.evidence,
            "confidence": float(finding.confidence),
            "risk": float(finding.risk),
            "status": finding.status,
            "first_seen": finding.first_seen,
            "last_seen": finding.last_seen,
            "count": max(1, int(finding.count)),
        }

        with self.engine.begin() as conn:
            row = (
                conn.execute(
                    sa.select(t.findings).where(
                        t.findings.c.tenant_id == self.tenant,
                        t.findings.c.fingerprint == fingerprint,
                    )
                )
                .mappings()
                .first()
            )
            if row is None:
                conn.execute(sa.insert(t.findings).values(**values))
                return True, finding_id

            old_rank = int(row["severity_rank"] or 0)
            new_rank = max(old_rank, finding.severity.rank)
            severity = finding.severity if finding.severity.rank >= old_rank else Severity.from_rank(old_rank)
            first_seen = min(filter(None, [_aware(row["first_seen"]), finding.first_seen]))
            last_seen = max(filter(None, [_aware(row["last_seen"]), finding.last_seen]))
            conn.execute(
                sa.update(t.findings)
                .where(t.findings.c.id == row["id"])
                .values(
                    severity=severity.value,
                    severity_rank=new_rank,
                    first_seen=first_seen,
                    last_seen=last_seen,
                    count=int(row["count"] or 1) + max(1, int(finding.count)),
                    risk=max(float(row["risk"] or 0.0), float(finding.risk)),
                    attack=_unions(row["attack"], finding.attack),
                    cwe=_unions(row["cwe"], finding.cwe),
                    cve=_unions(row["cve"], finding.cve),
                    tags=_unions(row["tags"], finding.tags),
                    refs=_unions(row["refs"], finding.references),
                    evidence=finding.evidence or row["evidence"],
                    status=row["status"] if row["status"] != "open" else finding.status,
                )
            )
            return False, str(row["id"])

    def get_finding(self, ident: str) -> dict[str, Any] | None:
        stmt = self._finding_select().where(
            t.findings.c.tenant_id == self.tenant,
            sa.or_(t.findings.c.id == ident, t.findings.c.fingerprint == ident),
        )
        with self.engine.connect() as conn:
            row = conn.execute(stmt).mappings().first()
        return self._finding_dict(row) if row else None

    def list_findings(
        self,
        *,
        severities: Iterable[str] | None = None,
        sources: Iterable[str] | None = None,
        categories: Iterable[str] | None = None,
        statuses: Iterable[str] | None = None,
        attack: str | None = None,
        query: str | None = None,
        min_risk: float | None = None,
        order: str = "risk",
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        stmt = self._finding_select().where(t.findings.c.tenant_id == self.tenant)
        for column, values in (
            (t.findings.c.severity, severities),
            (t.findings.c.source, sources),
            (t.findings.c.category, categories),
            (t.findings.c.status, statuses),
        ):
            items = [v for v in (values or []) if v]
            if items:
                stmt = stmt.where(column.in_(items))
        if attack:
            stmt = stmt.where(sa.cast(t.findings.c.attack, sa.String).like(f'%"{attack.upper()}%'))
        if min_risk is not None:
            stmt = stmt.where(t.findings.c.risk >= float(min_risk))
        if query:
            needle = f"%{query.lower()}%"
            stmt = stmt.where(
                sa.or_(
                    sa.func.lower(t.findings.c.title).like(needle),
                    sa.func.lower(t.findings.c.locator).like(needle),
                    sa.func.lower(t.assets.c.canonical_key).like(needle),
                    sa.func.lower(t.findings.c.rule_id).like(needle),
                )
            )
        order_by = {
            "risk": (t.findings.c.risk.desc(), t.findings.c.severity_rank.desc()),
            "recent": (t.findings.c.last_seen.desc(),),
            "severity": (t.findings.c.severity_rank.desc(), t.findings.c.risk.desc()),
            "asset": (t.assets.c.canonical_key.asc(), t.findings.c.risk.desc()),
        }.get(order, (t.findings.c.risk.desc(),))
        stmt = stmt.order_by(*order_by).limit(max(1, int(limit))).offset(max(0, int(offset)))
        with self.engine.connect() as conn:
            rows = conn.execute(stmt).mappings().all()
        return [self._finding_dict(row) for row in rows]

    def count_findings(self) -> int:
        with self.engine.connect() as conn:
            return int(
                conn.scalar(
                    sa.select(sa.func.count())
                    .select_from(t.findings)
                    .where(t.findings.c.tenant_id == self.tenant)
                )
                or 0
            )

    def summary(self) -> dict[str, Any]:
        base = t.findings.c.tenant_id == self.tenant

        def grouped(column) -> dict[str, int]:
            with self.engine.connect() as conn:
                rows = conn.execute(
                    sa.select(column, sa.func.count()).where(base).group_by(column)
                ).all()
            return {str(key): int(count) for key, count in rows}

        with self.engine.connect() as conn:
            total = conn.scalar(sa.select(sa.func.count()).select_from(t.findings).where(base)) or 0
            open_count = (
                conn.scalar(
                    sa.select(sa.func.count())
                    .select_from(t.findings)
                    .where(base, t.findings.c.status.in_(["open", "triaged"]))
                )
                or 0
            )
            max_risk = conn.scalar(sa.select(sa.func.max(t.findings.c.risk)).where(base)) or 0.0
            last_seen = conn.scalar(sa.select(sa.func.max(t.findings.c.last_seen)).where(base))
            tech_rows = conn.execute(
                sa.select(t.findings.c.attack).where(base, sa.cast(t.findings.c.attack, sa.String) != "[]")
            ).all()

        techniques: list[str] = []
        for (value,) in tech_rows:
            for item in value or []:
                if item not in techniques:
                    techniques.append(item)

        return {
            "total": int(total),
            "open": int(open_count),
            "max_risk": round(float(max_risk), 2),
            "last_seen": last_seen.isoformat() if last_seen else None,
            "by_severity": grouped(t.findings.c.severity),
            "by_source": grouped(t.findings.c.source),
            "by_category": grouped(t.findings.c.category),
            "techniques": sorted(techniques),
        }

    # -- runs -------------------------------------------------------------- #

    def start_run(self, run_id: str, kind: str, profile: str = "") -> None:
        with self.engine.begin() as conn:
            conn.execute(
                sa.insert(t.runs).values(
                    id=run_id,
                    tenant_id=self.tenant,
                    kind=kind,
                    profile=profile,
                    started=utcnow(),
                    status="running",
                    stats={},
                    errors=[],
                )
            )

    def finish_run(
        self, run_id: str, *, status: str = "ok", stats: dict[str, Any] | None = None, errors: list[str] | None = None
    ) -> None:
        with self.engine.begin() as conn:
            conn.execute(
                sa.update(t.runs)
                .where(t.runs.c.id == run_id)
                .values(
                    finished=utcnow(),
                    status=status,
                    stats=stats or {},
                    errors=errors or [],
                )
            )

    def list_runs(self, limit: int = 20) -> list[dict[str, Any]]:
        with self.engine.connect() as conn:
            rows = conn.execute(
                sa.select(t.runs).order_by(t.runs.c.started.desc()).limit(max(1, int(limit)))
            ).mappings()
            return [dict(row) for row in rows]

    # -- raw artifacts ------------------------------------------------------ #

    def save_raw_artifact(
        self,
        *,
        sha256: str,
        source: str,
        media_type: str,
        size: int,
        storage_ref: str,
        run_id: str = "",
    ) -> bool:
        """Record an immutable raw artifact. Returns False when it was already stored."""
        with self.engine.begin() as conn:
            exists = conn.scalar(
                sa.select(t.raw_artifacts.c.sha256).where(t.raw_artifacts.c.sha256 == sha256)
            )
            if exists:
                return False
            conn.execute(
                sa.insert(t.raw_artifacts).values(
                    sha256=sha256,
                    tenant_id=self.tenant,
                    source=source,
                    media_type=media_type,
                    size=int(size),
                    storage_ref=str(storage_ref),
                    received_at=utcnow(),
                    run_id=run_id or None,
                )
            )
        return True

    def count_raw_artifacts(self) -> int:
        with self.engine.connect() as conn:
            return int(
                conn.scalar(
                    sa.select(sa.func.count())
                    .select_from(t.raw_artifacts)
                    .where(t.raw_artifacts.c.tenant_id == self.tenant)
                )
                or 0
            )

    # -- detection content -------------------------------------------------- #

    def sync_rules(self, kind: str, rows: Iterable[dict[str, Any]]) -> int:
        """Replace every rule of ``kind`` with the supplied set.

        Scoped per kind on purpose: syncing Sigma must not delete the YARA index.
        """
        items = list(rows)
        now = utcnow()
        with self.engine.begin() as conn:
            conn.execute(
                sa.delete(t.rules).where(
                    t.rules.c.tenant_id == self.tenant, t.rules.c.kind == kind
                )
            )
            for row in items:
                native_id = str(row["native_id"])
                conn.execute(
                    sa.insert(t.rules).values(
                        id="rul_" + hashlib.sha1(f"{kind}|{native_id}".encode()).hexdigest()[:16],
                        tenant_id=self.tenant,
                        kind=kind,
                        native_id=native_id,
                        title=str(row.get("title") or native_id),
                        level=str(row.get("level") or "medium"),
                        status=str(row.get("status") or ""),
                        logsource=str(row.get("logsource") or ""),
                        attack=list(row.get("attack") or []),
                        tags=list(row.get("tags") or []),
                        path=str(row.get("path") or ""),
                        content_hash=str(row.get("content_hash") or ""),
                        created_at=now,
                        updated_at=now,
                    )
                )
        return len(items)

    def list_rules(
        self,
        *,
        kind: str | None = None,
        attack: str | None = None,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        stmt = sa.select(t.rules).where(t.rules.c.tenant_id == self.tenant)
        if kind:
            stmt = stmt.where(t.rules.c.kind == kind)
        if attack:
            stmt = stmt.where(sa.cast(t.rules.c.attack, sa.String).like(f'%"{attack.upper()}"%'))
        stmt = stmt.order_by(t.rules.c.kind, t.rules.c.title).limit(max(1, int(limit)))
        with self.engine.connect() as conn:
            rows = conn.execute(stmt).mappings().all()
        result = []
        for row in rows:
            item = dict(row)
            for key in ("attack", "tags"):
                value = item.get(key)
                item[key] = json.loads(value) if isinstance(value, str) else (value or [])
            result.append(item)
        return result

    def count_rules(self, kind: str | None = None) -> int:
        stmt = sa.select(sa.func.count()).select_from(t.rules).where(t.rules.c.tenant_id == self.tenant)
        if kind:
            stmt = stmt.where(t.rules.c.kind == kind)
        with self.engine.connect() as conn:
            return int(conn.scalar(stmt) or 0)

    # -- cases -------------------------------------------------------------- #

    def ingest_finding(
        self, finding: Finding, case_window_hours: int = 24
    ) -> tuple[bool, str, str | None]:
        """Upsert a finding and keep case membership in sync."""
        created, finding_id = self.upsert_finding(finding)
        case_id = self.group_into_case(finding_id, case_window_hours)
        return created, finding_id, case_id

    def group_into_case(self, finding_id: str, window_hours: int = 24) -> str | None:
        """Attach a finding to an open case, or open one if the asset got busy.

        The window is anchored on the finding's own timestamp, not on wall-clock
        time, so replaying historical data produces the same cases as live traffic.
        """
        from ..canon.cases import (
            MIN_FINDINGS_FOR_CASE,
            case_title,
            higher_priority,
            priority_for,
            severity_from_rank,
        )

        window = timedelta(hours=max(1, int(window_hours)))
        now = utcnow()
        with self.engine.begin() as conn:
            finding = (
                conn.execute(
                    sa.select(
                        t.findings.c.asset_id,
                        t.findings.c.severity_rank,
                        t.findings.c.last_seen,
                        t.assets.c.canonical_key,
                    )
                    .join(t.assets, t.assets.c.id == t.findings.c.asset_id)
                    .where(t.findings.c.id == finding_id)
                )
                .mappings()
                .first()
            )
            if finding is None:
                return None

            anchor = _aware(finding["last_seen"]) or now
            neighbours = conn.execute(
                sa.select(t.findings.c.id, t.findings.c.severity_rank)
                .where(
                    t.findings.c.tenant_id == self.tenant,
                    t.findings.c.asset_id == finding["asset_id"],
                    t.findings.c.last_seen >= anchor - window,
                    t.findings.c.last_seen <= anchor + window,
                )
            ).all()
            neighbour_ids = [row.id for row in neighbours]
            top_rank = max((int(row.severity_rank or 0) for row in neighbours), default=0)
            top_severity = severity_from_rank(top_rank)

            existing = None
            if neighbour_ids:
                existing = conn.execute(
                    sa.select(t.case_findings.c.case_id, t.cases.c.priority)
                    .join(t.cases, t.cases.c.id == t.case_findings.c.case_id)
                    .where(
                        t.case_findings.c.finding_id.in_(neighbour_ids),
                        t.cases.c.status.in_(["open", "triage"]),
                    )
                    .limit(1)
                ).first()

            if existing is not None:
                case_id = str(existing[0])
                attached = conn.scalar(
                    sa.select(t.case_findings.c.finding_id).where(
                        t.case_findings.c.case_id == case_id,
                        t.case_findings.c.finding_id == finding_id,
                    )
                )
                if not attached:
                    conn.execute(
                        sa.insert(t.case_findings).values(
                            case_id=case_id,
                            finding_id=finding_id,
                            added_at=now,
                            reason="same-asset-window",
                        )
                    )
                new_priority = higher_priority(
                    str(existing[1] or "low"), priority_for(top_severity)
                )
                values: dict[str, Any] = {"updated_at": now, "priority": new_priority}
                if new_priority != str(existing[1] or "low"):
                    # The title encodes the severity, so it has to follow the escalation;
                    # otherwise a case titled "High activity" sits at critical priority.
                    values["title"] = case_title(top_severity, str(finding["canonical_key"]))
                conn.execute(
                    sa.update(t.cases).where(t.cases.c.id == case_id).values(**values)
                )
                return case_id

            if len(neighbours) < MIN_FINDINGS_FOR_CASE:
                return None

            case_id = "case_" + hashlib.sha1(
                f"{self.tenant}|{finding['asset_id']}|{anchor.isoformat()}".encode()
            ).hexdigest()[:16]
            conn.execute(
                sa.insert(t.cases).values(
                    id=case_id,
                    tenant_id=self.tenant,
                    title=case_title(top_severity, str(finding["canonical_key"])),
                    status="open",
                    priority=priority_for(top_severity),
                    assignee="",
                    asset_id=finding["asset_id"],
                    summary=f"{len(neighbours)} findings within {window_hours}h",
                    created_at=now,
                    updated_at=now,
                )
            )
            for row in neighbours:
                conn.execute(
                    sa.insert(t.case_findings).values(
                        case_id=case_id,
                        finding_id=row.id,
                        added_at=now,
                        reason="same-asset-window",
                    )
                )
            return case_id

    def list_cases(self, limit: int = 50) -> list[dict[str, Any]]:
        findings_count = sa.func.count(t.case_findings.c.finding_id)
        max_risk = sa.func.max(t.findings.c.risk)
        stmt = (
            sa.select(t.cases, findings_count.label("findings"), max_risk.label("max_risk"))
            .select_from(
                t.cases.outerjoin(t.case_findings, t.case_findings.c.case_id == t.cases.c.id).outerjoin(
                    t.findings, t.findings.c.id == t.case_findings.c.finding_id
                )
            )
            .where(t.cases.c.tenant_id == self.tenant)
            .group_by(t.cases.c.id)
            .order_by(sa.desc("max_risk"))
            .limit(max(1, int(limit)))
        )
        with self.engine.connect() as conn:
            rows = conn.execute(stmt).mappings().all()
        result = []
        for row in rows:
            item = dict(row)
            item["findings"] = int(item.get("findings") or 0)
            item["max_risk"] = round(float(item.get("max_risk") or 0.0), 2)
            for key in ("created_at", "updated_at", "closed_at"):
                value = item.get(key)
                if isinstance(value, datetime):
                    item[key] = _aware(value).isoformat(timespec="seconds")
            result.append(item)
        return result

    def get_case(self, case_id: str) -> dict[str, Any] | None:
        with self.engine.connect() as conn:
            case = conn.execute(
                sa.select(t.cases).where(
                    t.cases.c.tenant_id == self.tenant, t.cases.c.id == case_id
                )
            ).mappings().first()
            if case is None:
                return None
            rows = conn.execute(
                self._finding_select()
                .join(t.case_findings, t.case_findings.c.finding_id == t.findings.c.id)
                .where(t.case_findings.c.case_id == case_id)
                .order_by(t.findings.c.last_seen.asc())
            ).mappings().all()
        item = dict(case)
        item["findings"] = [self._finding_dict(row) for row in rows]
        return item

    def count_cases(self) -> int:
        with self.engine.connect() as conn:
            return int(
                conn.scalar(
                    sa.select(sa.func.count())
                    .select_from(t.cases)
                    .where(t.cases.c.tenant_id == self.tenant)
                )
                or 0
            )

    # -- atomics ------------------------------------------------------------ #

    def sync_atomics(self, rows: Iterable[dict[str, Any]]) -> int:
        payload: list[dict[str, Any]] = []
        seen: set[tuple[str, str, str]] = set()
        for row in rows:
            key = (str(row["technique"]), str(row["test_name"]), str(row.get("platform") or ""))
            if key in seen:
                continue
            seen.add(key)
            payload.append(
                {
                    "technique": key[0],
                    "test_name": key[1],
                    "platform": key[2],
                    "executor": str(row.get("executor") or ""),
                    "path": str(row.get("path") or ""),
                }
            )
        with self.engine.begin() as conn:
            conn.execute(sa.delete(t.atomics))
            if payload:
                conn.execute(t.atomics.insert(), payload)
        return len(payload)

    def list_atomics(self) -> list[dict[str, Any]]:
        with self.engine.connect() as conn:
            rows = conn.execute(
                sa.select(t.atomics).order_by(t.atomics.c.technique, t.atomics.c.test_name)
            ).mappings()
            return [dict(row) for row in rows]

    # -- executions --------------------------------------------------------- #

    def save_executions(self, rows: Iterable[dict[str, Any]]) -> int:
        from ..domain.models import parse_ts

        count = 0
        with self.engine.begin() as conn:
            for row in rows:
                execution_id = str(row["id"])
                values = {
                    "technique": str(row.get("technique") or "").upper(),
                    "test_name": str(row.get("test_name") or ""),
                    "host": str(row.get("host") or ""),
                    "started": parse_ts(row.get("started")),
                    "finished": parse_ts(row.get("finished")),
                    "status": str(row.get("status") or "unknown"),
                    "detected": None if row.get("detected") is None else bool(row["detected"]),
                    "sources": list(row.get("sources") or []),
                    "matched": list(row.get("matched") or []),
                    "note": str(row.get("note") or ""),
                }
                exists = conn.scalar(
                    sa.select(t.executions.c.id).where(t.executions.c.id == execution_id)
                )
                if exists:
                    conn.execute(
                        sa.update(t.executions)
                        .where(t.executions.c.id == execution_id)
                        .values(**values)
                    )
                else:
                    conn.execute(
                        sa.insert(t.executions).values(
                            id=execution_id, tenant_id=self.tenant, **values
                        )
                    )
                count += 1
        return count

    def list_executions(self) -> list[dict[str, Any]]:
        with self.engine.connect() as conn:
            rows = conn.execute(
                sa.select(t.executions).order_by(t.executions.c.started.desc())
            ).mappings()
            result = []
            for row in rows:
                item = dict(row)
                for key in ("sources", "matched"):
                    value = item.get(key)
                    item[key] = json.loads(value) if isinstance(value, str) else (value or [])
                for key in ("started", "finished"):
                    value = item.get(key)
                    if isinstance(value, datetime):
                        item[key] = _aware(value).isoformat(timespec="seconds")
                result.append(item)
            return result

    # -- internals --------------------------------------------------------- #

    def _finding_select(self) -> sa.Select:
        return sa.select(
            t.findings,
            t.assets.c.kind.label("asset_kind"),
            t.assets.c.canonical_key.label("asset_key"),
            t.assets.c.name.label("asset_name"),
            t.assets.c.ip.label("asset_ip"),
            t.assets.c.exposure.label("asset_exposure"),
        ).join(t.assets, t.assets.c.id == t.findings.c.asset_id)

    @staticmethod
    def _finding_dict(row: Any) -> dict[str, Any]:
        data = dict(row)
        asset = {
            "id": data.pop("asset_id", ""),
            "kind": data.pop("asset_kind", ""),
            "key": data.pop("asset_key", ""),
            "name": data.pop("asset_name", ""),
            "ip": data.pop("asset_ip", ""),
            "exposure": data.pop("asset_exposure", "internal"),
        }
        for key in ("first_seen", "last_seen"):
            value = data.get(key)
            if isinstance(value, datetime):
                data[key] = _aware(value).isoformat(timespec="seconds")
        data["asset"] = asset
        data["references"] = data.pop("refs", [])
        return data

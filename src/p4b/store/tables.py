"""SQLAlchemy Core table definitions.

SQLite is the default, Postgres is the escape hatch, so everything here sticks to
portable constructs: JSON columns instead of arrays, no SQLite-only syntax, and no
`RETURNING` assumptions.

Naming conventions are explicit so Alembic autogenerate produces stable names.
"""

from __future__ import annotations

import sqlalchemy as sa

metadata = sa.MetaData(
    naming_convention={
        "ix": "ix_%(table_name)s_%(column_0_name)s",
        "uq": "uq_%(table_name)s_%(column_0_name)s",
        "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
        "pk": "pk_%(table_name)s",
    }
)


def _pk(name: str = "id") -> sa.Column:
    return sa.Column(name, sa.String(64), primary_key=True)


def _ts(name: str, nullable: bool = False) -> sa.Column:
    return sa.Column(name, sa.DateTime(timezone=True), nullable=nullable)


def _fk(name: str, table: str, column: str = "id", nullable: bool = True) -> sa.Column:
    return sa.Column(name, sa.String(64), sa.ForeignKey(f"{table}.{column}", ondelete="CASCADE"), nullable=nullable)


tenants = sa.Table(
    "tenants",
    metadata,
    _pk(),
    sa.Column("name", sa.String(200), nullable=False),
    _ts("created_at"),
)

assets = sa.Table(
    "assets",
    metadata,
    _pk(),
    _fk("tenant_id", "tenants", nullable=False),
    sa.Column("kind", sa.String(32), nullable=False),
    sa.Column("canonical_key", sa.String(512), nullable=False),
    sa.Column("name", sa.String(512), nullable=False, server_default=""),
    sa.Column("ip", sa.String(64), nullable=False, server_default=""),
    sa.Column("exposure", sa.String(32), nullable=False, server_default="internal"),
    sa.Column("attrs", sa.JSON, nullable=False),
    _ts("first_seen"),
    _ts("last_seen"),
    sa.UniqueConstraint("tenant_id", "kind", "canonical_key", name="uq_assets_tenant_kind_key"),
)

asset_aliases = sa.Table(
    "asset_aliases",
    metadata,
    _pk(),
    _fk("asset_id", "assets", nullable=False),
    sa.Column("alias_type", sa.String(32), nullable=False),
    sa.Column("alias_value", sa.String(512), nullable=False),
    sa.Column("source", sa.String(64), nullable=False, server_default=""),
    sa.Column("confidence", sa.Float, nullable=False, server_default="1.0"),
    _ts("created_at"),
    sa.UniqueConstraint("asset_id", "alias_type", "alias_value", name="uq_asset_aliases_triple"),
    sa.Index("ix_asset_aliases_lookup", "alias_type", "alias_value"),
)

raw_artifacts = sa.Table(
    "raw_artifacts",
    metadata,
    sa.Column("sha256", sa.String(64), primary_key=True),
    _fk("tenant_id", "tenants", nullable=False),
    sa.Column("source", sa.String(64), nullable=False),
    sa.Column("media_type", sa.String(128), nullable=False, server_default="application/octet-stream"),
    sa.Column("size", sa.Integer, nullable=False, server_default="0"),
    sa.Column("storage_ref", sa.String(512), nullable=False, server_default=""),
    _ts("received_at"),
    sa.Column("run_id", sa.String(64), nullable=True),
)

findings = sa.Table(
    "findings",
    metadata,
    _pk(),
    _fk("tenant_id", "tenants", nullable=False),
    sa.Column("fingerprint", sa.String(64), nullable=False),
    sa.Column("source", sa.String(64), nullable=False),
    sa.Column("category", sa.String(48), nullable=False),
    sa.Column("title", sa.Text, nullable=False),
    sa.Column("severity", sa.String(16), nullable=False),
    sa.Column("severity_rank", sa.Integer, nullable=False),
    _fk("asset_id", "assets", nullable=False),
    sa.Column("rule_id", sa.String(256), nullable=False, server_default=""),
    sa.Column("rule_name", sa.String(512), nullable=False, server_default=""),
    sa.Column("locator", sa.Text, nullable=False, server_default=""),
    sa.Column("attack", sa.JSON, nullable=False),
    sa.Column("cwe", sa.JSON, nullable=False),
    sa.Column("cve", sa.JSON, nullable=False),
    sa.Column("tags", sa.JSON, nullable=False),
    sa.Column("refs", sa.JSON, nullable=False),
    sa.Column("remediation", sa.JSON, nullable=True),
    sa.Column("evidence", sa.JSON, nullable=False),
    sa.Column("confidence", sa.Float, nullable=False, server_default="0.8"),
    sa.Column("risk", sa.Float, nullable=False, server_default="0.0"),
    sa.Column("status", sa.String(24), nullable=False, server_default="open"),
    _ts("first_seen"),
    _ts("last_seen"),
    sa.Column("count", sa.Integer, nullable=False, server_default="1"),
    _fk("raw_id", "raw_artifacts", column="sha256"),
    sa.UniqueConstraint("tenant_id", "fingerprint", name="uq_findings_tenant_fingerprint"),
    sa.Index("ix_findings_risk", "risk"),
    sa.Index("ix_findings_severity", "severity_rank"),
    sa.Index("ix_findings_last_seen", "last_seen"),
    sa.Index("ix_findings_source", "source"),
)

finding_history = sa.Table(
    "finding_history",
    metadata,
    _pk(),
    _fk("finding_id", "findings", nullable=False),
    _fk("tenant_id", "tenants", nullable=False),
    _ts("changed_at"),
    sa.Column("actor", sa.String(128), nullable=False, server_default="system"),
    sa.Column("field", sa.String(64), nullable=False),
    sa.Column("old_value", sa.Text, nullable=True),
    sa.Column("new_value", sa.Text, nullable=True),
)

rules = sa.Table(
    "rules",
    metadata,
    _pk(),
    _fk("tenant_id", "tenants", nullable=False),
    sa.Column("kind", sa.String(24), nullable=False),  # sigma | yara | suricata
    sa.Column("native_id", sa.String(256), nullable=False),
    sa.Column("title", sa.Text, nullable=False),
    sa.Column("level", sa.String(16), nullable=False, server_default="medium"),
    sa.Column("status", sa.String(32), nullable=False, server_default=""),
    sa.Column("logsource", sa.String(256), nullable=False, server_default=""),
    sa.Column("attack", sa.JSON, nullable=False),
    sa.Column("tags", sa.JSON, nullable=False),
    sa.Column("path", sa.Text, nullable=False, server_default=""),
    sa.Column("content_hash", sa.String(64), nullable=False, server_default=""),
    _ts("created_at"),
    _ts("updated_at"),
    sa.UniqueConstraint("tenant_id", "kind", "native_id", name="uq_rules_tenant_kind_native"),
)

rule_translations = sa.Table(
    "rule_translations",
    metadata,
    _pk(),
    _fk("rule_id", "rules", nullable=False),
    sa.Column("backend", sa.String(32), nullable=False),
    sa.Column("query", sa.Text, nullable=False),
    sa.Column("warnings", sa.JSON, nullable=False),
    _ts("generated_at"),
    sa.UniqueConstraint("rule_id", "backend", name="uq_rule_translations_rule_backend"),
)

atomics = sa.Table(
    "atomics",
    metadata,
    sa.Column("technique", sa.String(16), primary_key=True),
    sa.Column("test_name", sa.Text, primary_key=True),
    sa.Column("platform", sa.String(64), primary_key=True),
    sa.Column("executor", sa.String(64), nullable=False, server_default=""),
    sa.Column("path", sa.Text, nullable=False, server_default=""),
)

executions = sa.Table(
    "executions",
    metadata,
    _pk(),
    _fk("tenant_id", "tenants", nullable=False),
    sa.Column("technique", sa.String(16), nullable=False),
    sa.Column("test_name", sa.Text, nullable=False),
    sa.Column("host", sa.String(256), nullable=False, server_default=""),
    _fk("asset_id", "assets", nullable=True),
    _ts("started"),
    _ts("finished", nullable=True),
    sa.Column("status", sa.String(24), nullable=False, server_default="unknown"),
    sa.Column("detected", sa.Boolean, nullable=True),
    sa.Column("sources", sa.JSON, nullable=False),
    sa.Column("matched", sa.JSON, nullable=False),
    sa.Column("note", sa.Text, nullable=False, server_default=""),
    sa.Column("run_id", sa.String(64), nullable=True),
    sa.Index("ix_executions_technique", "technique"),
)

cases = sa.Table(
    "cases",
    metadata,
    _pk(),
    _fk("tenant_id", "tenants", nullable=False),
    sa.Column("title", sa.String(512), nullable=False),
    sa.Column("status", sa.String(24), nullable=False, server_default="open"),
    sa.Column("priority", sa.String(16), nullable=False, server_default="medium"),
    sa.Column("assignee", sa.String(128), nullable=False, server_default=""),
    _fk("asset_id", "assets", nullable=True),
    sa.Column("summary", sa.Text, nullable=False, server_default=""),
    _ts("created_at"),
    _ts("updated_at"),
    _ts("closed_at", nullable=True),
    sa.Index("ix_cases_status", "status"),
)

case_findings = sa.Table(
    "case_findings",
    metadata,
    sa.Column("case_id", sa.String(64), sa.ForeignKey("cases.id", ondelete="CASCADE"), primary_key=True),
    sa.Column("finding_id", sa.String(64), sa.ForeignKey("findings.id", ondelete="CASCADE"), primary_key=True),
    _ts("added_at"),
    sa.Column("reason", sa.String(128), nullable=False, server_default=""),
)

runs = sa.Table(
    "runs",
    metadata,
    _pk(),
    _fk("tenant_id", "tenants", nullable=False),
    sa.Column("kind", sa.String(24), nullable=False),  # scan | ingest | validate | sync
    sa.Column("profile", sa.String(64), nullable=False, server_default=""),
    _ts("started"),
    _ts("finished", nullable=True),
    sa.Column("status", sa.String(24), nullable=False, server_default="running"),
    sa.Column("stats", sa.JSON, nullable=False),
    sa.Column("errors", sa.JSON, nullable=False),
)

jobs = sa.Table(
    "jobs",
    metadata,
    _pk(),
    _fk("tenant_id", "tenants", nullable=False),
    sa.Column("name", sa.String(128), nullable=False),
    sa.Column("kind", sa.String(24), nullable=False),
    sa.Column("cron", sa.String(64), nullable=False, server_default=""),
    sa.Column("spec", sa.JSON, nullable=False),
    sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.true()),
    sa.Column("last_run_id", sa.String(64), nullable=True),
    _ts("next_run_at", nullable=True),
    _ts("created_at"),
)

api_tokens = sa.Table(
    "api_tokens",
    metadata,
    _pk(),
    _fk("tenant_id", "tenants", nullable=False),
    sa.Column("name", sa.String(128), nullable=False),
    sa.Column("token_hash", sa.String(256), nullable=False),
    sa.Column("scopes", sa.JSON, nullable=False),
    _ts("created_at"),
    _ts("last_used_at", nullable=True),
    _ts("revoked_at", nullable=True),
)

audit_log = sa.Table(
    "audit_log",
    metadata,
    _pk(),
    _fk("tenant_id", "tenants", nullable=False),
    _ts("at"),
    sa.Column("actor", sa.String(128), nullable=False, server_default="system"),
    sa.Column("action", sa.String(64), nullable=False),
    sa.Column("object_type", sa.String(48), nullable=False, server_default=""),
    sa.Column("object_id", sa.String(64), nullable=False, server_default=""),
    sa.Column("meta", sa.JSON, nullable=False),
    sa.Index("ix_audit_log_at", "at"),
)

tool_health = sa.Table(
    "tool_health",
    metadata,
    sa.Column("name", sa.String(64), primary_key=True),
    sa.Column("layer", sa.String(32), nullable=False),
    sa.Column("available", sa.Boolean, nullable=False, server_default=sa.false()),
    sa.Column("version", sa.String(64), nullable=False, server_default=""),
    sa.Column("path", sa.String(512), nullable=False, server_default=""),
    sa.Column("checked_at", sa.DateTime(timezone=True), nullable=True),
    sa.Column("note", sa.Text, nullable=False, server_default=""),
)


def create_all(engine: sa.Engine) -> None:
    """Bootstrap helper for tests. Production schema goes through Alembic."""
    metadata.create_all(engine)


__all__ = [
    "metadata",
    "tenants",
    "assets",
    "asset_aliases",
    "raw_artifacts",
    "findings",
    "finding_history",
    "rules",
    "rule_translations",
    "atomics",
    "executions",
    "cases",
    "case_findings",
    "runs",
    "jobs",
    "api_tokens",
    "audit_log",
    "tool_health",
    "create_all",
]

"""Command line interface.

``argparse`` instead of click/typer: one less dependency, and the CLI surface is
small enough that a subparser table is clearer than decorators.
"""

from __future__ import annotations

import argparse
import json
import platform
import sys
import time
from pathlib import Path

from . import __version__, adapters
from .api.auth import hash_token, new_token, parse_scopes
from .config import Settings
from .content import ConditionError, load_sigma, load_yara, translate
from .demo import run_demo
from .jobs import run_due, run_job
from .report import build_report
from .scan import Scope, run_scan
from .sinks import documents as export_documents
from .sinks import write_jsonl
from .store import Repositories, make_engine
from .store.migrate import upgrade
from .tooling import LAYERS, detect_all
from .validate import build_coverage, match_executions, score, summarize

EPILOG = """\
examples:
  p4b init                 create the data directory and database schema
  p4b doctor               detect the ten tools and record their versions
  p4b ingest wazuh demo/fixtures/wazuh/alerts.json
  p4b findings --severity critical
  p4b config               print the effective configuration
"""


def build_parser() -> argparse.ArgumentParser:
    # Accepted both before and after the subcommand: `p4b --json findings`
    # and `p4b findings --json` behave the same.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--json",
        action="store_true",
        default=argparse.SUPPRESS,
        help="machine-readable output",
    )

    parser = argparse.ArgumentParser(
        prog="p4b",
        description="P4B: detection engineering workbench for ten OSS security tools.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--config", help="path to p4b.yaml")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--version", action="version", version=f"p4b {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("version", parents=[common], help="print version information")
    sub.add_parser("config", parents=[common], help="print effective configuration")
    sub.add_parser("init", parents=[common], help="create data directories, schema and default tenant")
    sub.add_parser("doctor", parents=[common], help="detect tools and record their health")

    ingest = sub.add_parser("ingest", parents=[common], help="parse a tool output file into findings")
    ingest.add_argument("tool", choices=adapters.names())
    ingest.add_argument("path", help="file or directory produced by the tool")
    ingest.add_argument("--min-level", type=int, help="Wazuh rule.level threshold (default 7)")
    ingest.add_argument("--repo", help="repository asset for gitleaks")
    ingest.add_argument("--rules", help="rule file for yara (enables metadata lookup)")

    findings = sub.add_parser("findings", parents=[common], help="list stored findings")
    findings.add_argument("--severity", help="comma separated, e.g. critical,high")
    findings.add_argument("--source", help="comma separated, e.g. wazuh,suricata")
    findings.add_argument("--attack", help="ATT&CK technique, e.g. T1003.001")
    findings.add_argument("--query", help="substring of title, rule id, locator or asset")
    findings.add_argument("--limit", type=int, default=25)

    content = sub.add_parser("content", parents=[common], help="sync and translate detection content")
    content_sub = content.add_subparsers(dest="content_command", required=True)
    sync = content_sub.add_parser("sync", parents=[common], help="load rules into the database")
    sync.add_argument("--sigma", help="Sigma rule tree (default: sigma_path from config)")
    sync.add_argument("--yara", help="YARA rule tree")
    sync.add_argument("--atomic", help="Atomic Red Team atomics directory")
    translate_cmd = content_sub.add_parser("translate", parents=[common], help="translate one Sigma rule")
    translate_cmd.add_argument("rule", help="path to a .yml rule")
    translate_cmd.add_argument("--backend", default="splunk", choices=["splunk", "kql", "lucene"])

    rules = sub.add_parser("rules", parents=[common], help="list stored detection rules")
    rules.add_argument("--kind", choices=["sigma", "yara"])
    rules.add_argument("--attack", help="filter by ATT&CK technique")
    rules.add_argument("--limit", type=int, default=30)

    coverage = sub.add_parser("coverage", parents=[common], help="ATT&CK coverage matrix")
    coverage.add_argument("--status", help="filter, e.g. unvalidated,test-only,no-rule")
    coverage.add_argument("--limit", type=int, default=50)

    validate = sub.add_parser("validate", parents=[common], help="score Atomic runs against findings")
    validate.add_argument("--results", help="JSON file with test executions")
    validate.add_argument("--window", type=int, default=900, help="correlation window in seconds")

    cases = sub.add_parser("cases", parents=[common], help="list grouped cases")
    cases.add_argument("--limit", type=int, default=20)

    report = sub.add_parser("report", parents=[common], help="write a markdown report")
    report.add_argument("--out", help="output path (default: data/reports/report.md)")

    demo = sub.add_parser("demo", parents=[common], help="run the full loop on bundled fixtures")
    demo.add_argument("--reset", action="store_true", help="delete the database first")
    demo.add_argument("--window", type=int, default=900, help="correlation window in seconds")

    serve = sub.add_parser("serve", parents=[common], help="run the read-only HTTP API")
    serve.add_argument("--host", help="bind address (default: api_host)")
    serve.add_argument("--port", type=int, help="port (default: api_port)")

    scan = sub.add_parser("scan", parents=[common], help="run a scanner with scope enforcement")
    scan.add_argument("--tool", required=True, choices=["nuclei", "trivy", "gitleaks", "yara"])
    scan.add_argument("--target", action="append", required=True, help="repeatable")
    scan.add_argument("--allow", action="append", default=[], help="allow rule (host, *.domain, CIDR)")
    scan.add_argument("--deny", action="append", default=[], help="deny rule (wins over allow)")
    scan.add_argument("--rules", help="yara rule file")
    scan.add_argument("--kind", help="trivy target kind: image, fs, config")
    scan.add_argument("--severity", help="comma separated severity filter")
    scan.add_argument("--timeout", type=int, help="per-target timeout in seconds")
    scan.add_argument("--dry-run", action="store_true", help="show decisions without scanning")

    token = sub.add_parser("token", parents=[common], help="manage API bearer tokens")
    token_sub = token.add_subparsers(dest="token_command", required=True)
    token_create = token_sub.add_parser("create", parents=[common], help="issue a token (shown once)")
    token_create.add_argument("--name", required=True)
    token_create.add_argument("--scopes", default="read,write", help="read, write or admin")
    token_sub.add_parser("list", parents=[common], help="list issued tokens")
    token_revoke = token_sub.add_parser("revoke", parents=[common], help="revoke a token")
    token_revoke.add_argument("id")

    export = sub.add_parser("export", parents=[common], help="export findings as ECS or OCSF JSONL")
    export.add_argument("--format", choices=["ecs", "ocsf"], default="ecs")
    export.add_argument("--out", help="output path (default: data/exports/<format>.jsonl)")
    export.add_argument("--limit", type=int, default=100_000)

    job = sub.add_parser("job", parents=[common], help="manage scheduled scans")
    job_sub = job.add_subparsers(dest="job_command", required=True)
    job_add = job_sub.add_parser("add", parents=[common], help="store a scheduled scan")
    job_add.add_argument("--name", required=True)
    job_add.add_argument("--tool", required=True, choices=["nuclei", "trivy", "gitleaks", "yara"])
    job_add.add_argument("--target", action="append", required=True)
    job_add.add_argument("--allow", action="append", default=[])
    job_add.add_argument("--deny", action="append", default=[])
    job_add.add_argument("--rules", help="yara rule file")
    job_add.add_argument("--kind", help="trivy target kind")
    job_add.add_argument("--every", type=int, default=60, metavar="MINUTES")
    job_add.add_argument("--not-now", action="store_true", help="wait one interval before the first run")
    job_sub.add_parser("list", parents=[common], help="list scheduled scans")
    job_run = job_sub.add_parser("run", parents=[common], help="run a job immediately")
    job_run.add_argument("id")
    job_enable = job_sub.add_parser("enable", parents=[common], help="enable a job")
    job_enable.add_argument("id")
    job_disable = job_sub.add_parser("disable", parents=[common], help="disable a job")
    job_disable.add_argument("id")

    worker = sub.add_parser("worker", parents=[common], help="run due scheduled scans")
    worker.add_argument("--once", action="store_true", help="run due jobs once and exit")
    worker.add_argument("--sleep", type=int, default=60, help="seconds between scheduler ticks")
    worker.add_argument("--limit", type=int, default=10)
    return parser


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #


def _table(rows: list[list[str]], headers: list[str]) -> str:
    widths = [len(h) for h in headers]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(str(cell)))
    lines = ["  ".join(str(cell).ljust(widths[i]) for i, cell in enumerate(headers)).rstrip()]
    lines.append("  ".join("-" * width for width in widths))
    for row in rows:
        lines.append("  ".join(str(cell).ljust(widths[i]) for i, cell in enumerate(row)).rstrip())
    return "\n".join(lines)


def _print(args: argparse.Namespace, payload: object, render) -> None:
    if args.json:
        print(json.dumps(payload, indent=2, ensure_ascii=False, default=str))
    else:
        print(render(payload))


# --------------------------------------------------------------------------- #
# commands
# --------------------------------------------------------------------------- #


def cmd_version(_args: argparse.Namespace) -> int:
    print(f"p4b {__version__}  (python {platform.python_version()}, {platform.system()})")
    return 0


def cmd_config(args: argparse.Namespace, settings: Settings) -> int:
    _print(args, settings.to_dict(), lambda data: json.dumps(data, indent=2))
    return 0


def cmd_init(args: argparse.Namespace, settings: Settings) -> int:
    settings.ensure_dirs()
    engine = make_engine(settings.database_url())
    try:
        mode = upgrade(engine, settings.database_url())
        Repositories(engine).ensure_tenant()
    finally:
        engine.dispose()

    def render(_: object) -> str:
        return "\n".join(
            [
                f"data dir   {settings.data_dir.resolve()}",
                f"database   {settings.database_url()}",
                f"schema     {mode}",
                "",
                "next: p4b doctor",
            ]
        )

    _print(args, {"database": settings.database_url(), "mode": mode}, render)
    return 0


def cmd_doctor(args: argparse.Namespace, settings: Settings) -> int:
    hints = {
        "sigma": settings.sigma_path,
        "atomic": settings.atomic_path,
        "owasp-cheatsheets": settings.cheatsheet_path,
    }
    rows = detect_all(hints)
    if settings.database_url().startswith("sqlite:///"):
        db_path = settings.database_url().removeprefix("sqlite:///")
        if not Path(db_path).is_file():
            print("(database not initialised - run `p4b init` to record results)\n", file=sys.stderr)
        else:
            engine = make_engine(settings.database_url())
            try:
                Repositories(engine).save_tool_health(rows)
            finally:
                engine.dispose()

    def render(items: list[dict]) -> str:
        table = _table(
            [
                [
                    item["name"],
                    LAYERS.get(item["layer"], item["layer"]),
                    "yes" if item["available"] else "no",
                    item["version"] or "-",
                    item["license"],
                ]
                for item in items
            ],
            ["tool", "layer", "present", "version", "license"],
        )
        missing = [item["name"] for item in items if not item["available"]]
        footer = ""
        if missing:
            footer = (
                f"\n\nmissing or not configured: {', '.join(missing)}"
                "\nbinary tools: install them or use the p4b-scanner image;"
                "\ncontent tools: clone the repository and point p4b.yaml at it."
            )
        return table + footer

    _print(args, rows, render)
    return 0


# --------------------------------------------------------------------------- #


def cmd_ingest(args: argparse.Namespace, settings: Settings) -> int:
    settings.ensure_dirs()
    adapter = adapters.get(args.tool)
    ctx: dict[str, object] = {}
    if args.min_level is not None:
        ctx["min_level"] = args.min_level
    if args.repo:
        ctx["repo"] = args.repo
    if args.rules:
        ctx["rules"] = args.rules
        ctx["rule_file"] = args.rules
    parsed = adapter.parse(Path(args.path), ctx)

    engine = make_engine(settings.database_url())
    try:
        repos = Repositories(engine)
        repos.ensure_tenant()
        created = 0
        touched: set[str] = set()
        for finding in parsed.findings:
            was_created, _, case_id = repos.ingest_finding(finding, settings.case_window_hours)
            created += int(was_created)
            if case_id:
                touched.add(case_id)
        stored = repos.count_findings()
        cases_total = repos.count_cases()
    finally:
        engine.dispose()

    payload = {
        "tool": args.tool,
        "parsed": len(parsed.findings),
        "created": created,
        "merged": len(parsed.findings) - created,
        "stored": stored,
        "cases_touched": len(touched),
        "cases_total": cases_total,
        "stats": parsed.stats,
        "warnings": parsed.warnings,
    }

    def render(data: dict) -> str:
        lines = [
            f"{data['tool']}  {args.path}",
            f"  parsed {data['parsed']}  created {data['created']}"
            f"  merged {data['merged']}  stored {data['stored']}",
            f"  cases {data['cases_total']} (touched {data['cases_touched']})",
        ]
        if data["stats"]:
            lines.append(
                "  stats " + ", ".join(f"{key}={value}" for key, value in sorted(data["stats"].items()))
            )
        lines.extend(f"  ! {warning}" for warning in data["warnings"])
        return "\n".join(lines)

    _print(args, payload, render)
    return 0


def cmd_findings(args: argparse.Namespace, settings: Settings) -> int:
    def split(value: str | None) -> list[str] | None:
        items = [item for item in (value or "").split(",") if item]
        return items or None

    engine = make_engine(settings.database_url())
    try:
        rows = Repositories(engine).list_findings(
            severities=split(args.severity),
            sources=split(args.source),
            attack=args.attack,
            query=args.query,
            limit=args.limit,
        )
    finally:
        engine.dispose()

    def render(items: list[dict]) -> str:
        if not items:
            return "no findings matched"
        table = _table(
            [
                [
                    item["severity"][:4],
                    f"{item['risk']:.1f}",
                    item["source"],
                    str(item["title"])[:58],
                    str(item["asset"]["key"])[:28],
                    ",".join(item.get("attack") or [])[:24],
                ]
                for item in items
            ],
            ["sev", "risk", "tool", "title", "asset", "attack"],
        )
        return f"{table}\n\n{len(items)} row(s)"

    _print(args, rows, render)
    return 0


def cmd_content_sync(args: argparse.Namespace, settings: Settings) -> int:
    sigma_path = Path(args.sigma or settings.sigma_path)
    sigma_rules, sigma_warnings = load_sigma(sigma_path)
    warnings = list(sigma_warnings)

    engine = make_engine(settings.database_url())
    try:
        repos = Repositories(engine)
        repos.ensure_tenant()
        stored_sigma = repos.sync_rules("sigma", [rule.to_row() for rule in sigma_rules])
        stored_yara = 0
        if args.yara:
            yara_rules, yara_warnings = load_yara(Path(args.yara))
            warnings.extend(yara_warnings)
            stored_yara = repos.sync_rules("yara", [rule.to_row() for rule in yara_rules])
        stored_atomics = 0
        if args.atomic:
            atomic_parsed = adapters.get("atomic").parse(Path(args.atomic), {"kind": "inventory"})
            warnings.extend(atomic_parsed.warnings)
            stored_atomics = repos.sync_atomics(atomic_parsed.rules)
    finally:
        engine.dispose()

    coverage: dict[str, dict] = {}
    for backend in ("splunk", "kql", "lucene"):
        ok = 0
        reasons: dict[str, int] = {}
        for rule in sigma_rules:
            try:
                translate(rule.raw, backend)
                ok += 1
            except ConditionError as exc:
                reasons[str(exc)] = reasons.get(str(exc), 0) + 1
        total = len(sigma_rules)
        coverage[backend] = {
            "ok": ok,
            "total": total,
            "pct": round(100.0 * ok / total, 1) if total else 0.0,
            "top_reasons": sorted(reasons.items(), key=lambda item: -item[1])[:3],
        }

    payload = {
        "sigma_path": str(sigma_path),
        "sigma_rules": stored_sigma,
        "yara_rules": stored_yara,
        "atomic_tests": stored_atomics,
        "translation": coverage,
        "warnings": warnings,
    }

    def render(data: dict) -> str:
        lines = [
            f"sigma  {data['sigma_rules']} rule(s)  <- {data['sigma_path']}",
        ]
        if data["yara_rules"]:
            lines.append(f"yara   {data['yara_rules']} rule(s)")
        if data["atomic_tests"]:
            lines.append(f"atomic {data['atomic_tests']} test(s)")
        lines.append("translation coverage:")
        for backend, stats in data["translation"].items():
            lines.append(f"  {backend:<7} {stats['ok']}/{stats['total']}  {stats['pct']}%")
            for reason, count in stats["top_reasons"]:
                lines.append(f"           {count}x {reason[:90]}")
        for warning in data["warnings"][:5]:
            lines.append(f"  ! {warning[:120]}")
        if len(data["warnings"]) > 5:
            lines.append(f"  ! ... {len(data['warnings']) - 5} more warning(s)")
        return "\n".join(lines)

    _print(args, payload, render)
    return 0


def cmd_content_translate(args: argparse.Namespace, settings: Settings) -> int:
    rules, _warnings = load_sigma(Path(args.rule))
    if not rules:
        print(f"no Sigma rule found in {args.rule}", file=sys.stderr)
        return 1

    rule = rules[0]
    try:
        translation = translate(rule.raw, args.backend)
    except ConditionError as exc:
        print(f"cannot translate: {exc}", file=sys.stderr)
        return 1

    payload = {"rule": rule.title, **translation.to_dict()}

    def render(data: dict) -> str:
        lines = [f"rule     {data['rule']}", f"backend  {data['backend']}", f"table    {data['table']}", "", data["query"]]
        if data["warnings"]:
            lines.append("")
            lines.extend(f"! {warning}" for warning in data["warnings"])
        return "\n".join(lines)

    _print(args, payload, render)
    return 0


def cmd_rules(args: argparse.Namespace, settings: Settings) -> int:
    engine = make_engine(settings.database_url())
    try:
        rows = Repositories(engine).list_rules(kind=args.kind, attack=args.attack, limit=args.limit)
    finally:
        engine.dispose()

    def render(items: list[dict]) -> str:
        if not items:
            return "no rules stored (run `p4b content sync --sigma <path>`)"
        table = _table(
            [
                [
                    item["kind"],
                    str(item["native_id"])[:36],
                    str(item["title"])[:52],
                    item["level"],
                    ",".join(item["attack"])[:20],
                ]
                for item in items
            ],
            ["kind", "id", "title", "level", "attack"],
        )
        return f"{table}\n\n{len(items)} rule(s)"

    _print(args, rows, render)
    return 0


# --------------------------------------------------------------------------- #


def cmd_coverage(args: argparse.Namespace, settings: Settings) -> int:
    engine = make_engine(settings.database_url())
    try:
        repos = Repositories(engine)
        rules = repos.list_rules(limit=100_000)
        atomics = repos.list_atomics()
        findings = repos.list_findings(limit=100_000)
    finally:
        engine.dispose()

    all_rows = build_coverage(rules, atomics, findings)
    summary = summarize(all_rows)
    wanted = {item for item in (args.status or "").split(",") if item}
    shown = [row for row in all_rows if not wanted or row.status in wanted][: args.limit]

    payload = {"summary": summary, "rows": [row.to_dict() for row in shown]}

    def render(data: dict) -> str:
        if not data["rows"]:
            return "no coverage data (run `p4b content sync` and ingest some findings first)"
        table = _table(
            [
                [
                    row["technique"],
                    "Y" if row["has_rule"] else "-",
                    "Y" if row["has_test"] else "-",
                    "Y" if row["observed"] else "-",
                    row["status"],
                    ",".join(row["sources"])[:22],
                ]
                for row in data["rows"]
            ],
            ["technique", "rule", "test", "seen", "status", "sources"],
        )
        stats = data["summary"]
        return (
            f"{table}\n\n{stats['techniques']} technique(s) | validated {stats['validated']}"
            f" ({stats['score']}%) | blind {stats['blind']} | unvalidated {stats['unvalidated']}"
        )

    _print(args, payload, render)
    return 0


def cmd_validate(args: argparse.Namespace, settings: Settings) -> int:
    warnings: list[str] = []
    engine = make_engine(settings.database_url())
    try:
        repos = Repositories(engine)
        repos.ensure_tenant()
        if args.results:
            parsed = adapters.get("atomic").parse(Path(args.results), {"kind": "results"})
            warnings = parsed.warnings
            repos.save_executions(parsed.executions)
        executions = repos.list_executions()
        findings = repos.list_findings(limit=100_000)
        rows = match_executions(executions, findings, window_seconds=args.window)
        repos.save_executions(rows)
    finally:
        engine.dispose()

    summary = score(rows)
    payload = {
        "summary": summary,
        "window_seconds": args.window,
        "rows": rows,
        "warnings": warnings,
    }

    def render(data: dict) -> str:
        if not data["rows"]:
            return "no executions (pass --results <file.json> from an Atomic run)"
        table = _table(
            [
                [
                    row["technique"],
                    str(row["test_name"])[:46],
                    str(row.get("host") or "-")[:16],
                    "DETECTED" if row["detected"] else "missed",
                    ",".join(row.get("sources") or [])[:22],
                ]
                for row in data["rows"]
            ],
            ["technique", "test", "host", "result", "sources"],
        )
        stats = data["summary"]
        footer = (
            f"\n\n{stats['detected']}/{stats['tests']} detected ({stats['rate']}%)"
            f" within +/-{data['window_seconds']}s"
        )
        if data["warnings"]:
            footer += "\n" + "\n".join(f"! {warning}" for warning in data["warnings"][:3])
        return table + footer

    _print(args, payload, render)
    return 0


def cmd_cases(args: argparse.Namespace, settings: Settings) -> int:
    engine = make_engine(settings.database_url())
    try:
        rows = Repositories(engine).list_cases(args.limit)
    finally:
        engine.dispose()

    def render(items: list[dict]) -> str:
        if not items:
            return "no cases (ingest at least two findings on the same asset)"
        table = _table(
            [
                [
                    str(item["title"])[:52],
                    item["priority"],
                    str(item["findings"]),
                    item["status"],
                    f"{item['max_risk']:.1f}",
                ]
                for item in items
            ],
            ["case", "priority", "findings", "status", "risk"],
        )
        return f"{table}\n\n{len(items)} case(s)"

    _print(args, rows, render)
    return 0


def cmd_report(args: argparse.Namespace, settings: Settings) -> int:
    engine = make_engine(settings.database_url())
    try:
        text = build_report(Repositories(engine))
    finally:
        engine.dispose()

    path = Path(args.out) if args.out else Path(settings.reports_dir) / "report.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")

    payload = {"path": str(path), "chars": len(text)}
    _print(args, payload, lambda data: f"report written to {data['path']} ({data['chars']} chars)")
    return 0


def cmd_demo(args: argparse.Namespace, settings: Settings) -> int:
    steps = run_demo(settings, reset=args.reset, window_seconds=args.window)

    def render(data: dict) -> str:
        lines = [f"fixtures  {data['root']}", f"schema    {data['schema']}", "", "ingest:"]
        for tool, info in data["ingest"].items():
            lines.append(f"  {tool:<9} parsed {info['parsed']:<3} created {info['created']}")
        content = data["content"]
        lines += [
            "",
            "content:",
            f"  sigma {content['sigma']}  yara {content['yara']}  atomic {content['atomic']}",
            "",
        ]
        validation = data["validation"]
        coverage = data["coverage"]
        summary = data["summary"]
        lines += [
            f"validation  {validation['detected']}/{validation['tests']} detected ({validation['rate']}%)",
            f"coverage    {coverage['validated']}/{coverage['techniques']} validated ({coverage['score']}%)",
            f"cases       {data['cases']}",
            f"findings    {summary['total']} (open {summary['open']}, max risk {summary['max_risk']})",
            "",
            f"report      {data['report']}",
        ]
        warnings = content.get("warnings") or []
        if warnings:
            lines.append("")
            lines.extend(f"! {warning}" for warning in warnings[:3])
        return "\n".join(lines)

    _print(args, steps, render)
    return 0


def cmd_serve(args: argparse.Namespace, settings: Settings) -> int:
    import uvicorn

    from .api import create_app

    settings.ensure_dirs()
    engine = make_engine(settings.database_url())
    upgrade(engine, settings.database_url())
    repos = Repositories(engine)
    repos.ensure_tenant()
    app = create_app(repos, require_auth=settings.require_auth)

    host = args.host or settings.api_host
    port = int(args.port or settings.api_port)
    print(f"P4B API  http://{host}:{port}   (docs: /docs)")
    try:
        uvicorn.run(app, host=host, port=port, log_level="info")
    finally:
        engine.dispose()
    return 0


def cmd_scan(args: argparse.Namespace, settings: Settings) -> int:
    adapter = adapters.get(args.tool)
    scope = Scope(allow=tuple(args.allow), deny=tuple(args.deny))

    opts: dict[str, object] = {}
    if args.rules:
        opts["rules"] = args.rules
        opts["rule_file"] = args.rules
    if args.kind:
        opts["kind"] = args.kind
    if args.timeout:
        opts["timeout"] = args.timeout
    if args.severity:
        opts["severity"] = [item for item in args.severity.split(",") if item]

    settings.ensure_dirs()
    run_id = "run_" + time.strftime("%Y%m%d-%H%M%S")
    engine = None
    repos = None
    if not args.dry_run:
        engine = make_engine(settings.database_url())
        upgrade(engine, settings.database_url())
        repos = Repositories(engine)
        repos.ensure_tenant()

    try:
        outcomes = [
            run_scan(
                adapter,
                target,
                scope=scope,
                settings=settings,
                repos=repos,
                run_id=run_id,
                opts=opts,
                dry_run=args.dry_run,
            ).to_dict()
            for target in args.target
        ]
    finally:
        if engine is not None:
            engine.dispose()

    payload = {"run_id": run_id, "tool": adapter.name, "dry_run": args.dry_run, "outcomes": outcomes}

    def render(data: dict) -> str:
        rows = []
        for item in data["outcomes"]:
            decision = "allowed" if item["allowed"] else "DENIED"
            rows.append(
                [
                    item["target"][:52],
                    decision,
                    str(item["findings"]),
                    str(item["created"]),
                    f"{item['duration_s']:.1f}s",
                    item["raw_sha256"][:12],
                ]
            )
        table = _table(rows, ["target", "decision", "findings", "created", "time", "raw"])
        notes = []
        for item in data["outcomes"]:
            if not item["allowed"]:
                notes.append(f"! {item['target']}: {item['reason']}")
            elif item["skipped"]:
                notes.append(f"! {item['target']}: {item['error'] or 'skipped'}")
            elif item["error"]:
                notes.append(f"! {item['target']}: {item['error']}")
        if data["dry_run"]:
            notes.append("dry-run: nothing was executed or written")
        return table + ("\n" + "\n".join(notes) if notes else "")

    _print(args, payload, render)
    return 0


def cmd_token(args: argparse.Namespace, settings: Settings) -> int:
    engine = make_engine(settings.database_url())
    try:
        upgrade(engine, settings.database_url())
        repos = Repositories(engine)
        repos.ensure_tenant()

        if args.token_command == "create":
            try:
                scopes = parse_scopes(args.scopes)
            except ValueError as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 2
            token = new_token()
            token_id = repos.create_token(args.name, hash_token(token), scopes)
            payload = {"id": token_id, "name": args.name, "scopes": list(scopes), "token": token}

            def render(data: dict) -> str:
                return "\n".join(
                    [
                        f"id      {data['id']}",
                        f"name    {data['name']}",
                        f"scopes  {', '.join(data['scopes'])}",
                        "",
                        f"token   {data['token']}",
                        "",
                        "store it now: only the hash is kept, this token cannot be recovered.",
                    ]
                )

            _print(args, payload, render)
            return 0

        if args.token_command == "list":
            rows = repos.list_tokens()

            def render(items: list[dict]) -> str:
                if not items:
                    return "no tokens (create one with `p4b token create --name ui`)"
                table = _table(
                    [
                        [
                            item["id"],
                            item["name"],
                            ",".join(item["scopes"]),
                            str(item.get("created_at") or "")[:19],
                            str(item.get("last_used_at") or "-")[:19],
                            "revoked" if item.get("revoked_at") else "active",
                        ]
                        for item in items
                    ],
                    ["id", "name", "scopes", "created", "last used", "state"],
                )
                return f"{table}\n\n{len(items)} token(s)"

            _print(args, rows, render)
            return 0

        revoked = repos.revoke_token(args.id)
        print(f"{'revoked' if revoked else 'not found'}: {args.id}")
        return 0 if revoked else 1
    finally:
        engine.dispose()


def cmd_export(args: argparse.Namespace, settings: Settings) -> int:
    engine = make_engine(settings.database_url())
    try:
        rows = Repositories(engine).list_findings(limit=args.limit)
    finally:
        engine.dispose()

    path = Path(args.out) if args.out else Path(settings.data_dir) / "exports" / f"{args.format}.jsonl"
    count = write_jsonl(path, export_documents(rows, args.format))
    payload = {"format": args.format, "path": str(path), "findings": count}

    _print(
        args,
        payload,
        lambda data: f"exported {data['findings']} finding(s) as {data['format']}\n  {data['path']}",
    )
    return 0


def cmd_job(args: argparse.Namespace, settings: Settings) -> int:
    engine = make_engine(settings.database_url())
    try:
        upgrade(engine, settings.database_url())
        repos = Repositories(engine)
        repos.ensure_tenant()

        if args.job_command == "add":
            opts: dict[str, object] = {}
            if args.rules:
                opts["rules"] = args.rules
                opts["rule_file"] = args.rules
            if args.kind:
                opts["kind"] = args.kind
            spec = {
                "tool": args.tool,
                "targets": list(args.target),
                "allow": list(args.allow),
                "deny": list(args.deny),
                "opts": opts,
            }
            job_id = repos.add_job(
                args.name, spec, every_minutes=args.every, run_now=not args.not_now
            )
            print(f"created {job_id}  {args.tool}  every {args.every}m")
            return 0

        if args.job_command == "list":
            rows = repos.list_jobs()

            def render(items: list[dict]) -> str:
                if not items:
                    return "no jobs (create one with `p4b job add --name nightly --tool yara ...`)"
                table = _table(
                    [
                        [
                            item["name"],
                            str((item.get("spec") or {}).get("tool") or "-"),
                            item["cron"],
                            "yes" if item["enabled"] else "no",
                            str(item.get("next_run_at") or "-")[:19],
                            str(item.get("last_run_id") or "-")[:20],
                        ]
                        for item in items
                    ],
                    ["name", "tool", "schedule", "enabled", "next run", "last run"],
                )
                return f"{table}\n\n{len(items)} job(s)"

            _print(args, rows, render)
            return 0

        if args.job_command == "run":
            job = repos.get_job(args.id)
            if job is None:
                print(f"no such job: {args.id}", file=sys.stderr)
                return 1
            result = run_job(repos, settings, job)
            print(
                f"{result.name}: {result.findings} finding(s), {result.created} new, "
                f"{len(result.errors)} error(s)  run={result.run_id}"
            )
            for error in result.errors[:5]:
                print(f"  ! {error}")
            return 0

        enabled = args.job_command == "enable"
        ok = repos.set_job_enabled(args.id, enabled)
        print(f"{'enabled' if enabled else 'disabled'} {args.id}" if ok else f"no such job: {args.id}")
        return 0 if ok else 1
    finally:
        engine.dispose()


def cmd_worker(args: argparse.Namespace, settings: Settings) -> int:
    settings.ensure_dirs()
    engine = make_engine(settings.database_url())
    try:
        upgrade(engine, settings.database_url())
        repos = Repositories(engine)
        repos.ensure_tenant()

        while True:
            results = run_due(repos, settings, limit=args.limit)
            if not results:
                print("no due jobs")
            for result in results:
                print(
                    f"{result.name}: {result.findings} finding(s), {result.created} new, "
                    f"{len(result.errors)} error(s)"
                )
                for error in result.errors[:3]:
                    print(f"  ! {error}")
            if args.once:
                break
            time.sleep(max(5, int(args.sleep)))
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        engine.dispose()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    settings = Settings.load(args.config)

    if args.command == "version":
        return cmd_version(args)
    if args.command == "config":
        return cmd_config(args, settings)
    if args.command == "init":
        return cmd_init(args, settings)
    if args.command == "doctor":
        return cmd_doctor(args, settings)
    if args.command == "ingest":
        return cmd_ingest(args, settings)
    if args.command == "findings":
        return cmd_findings(args, settings)
    if args.command == "content":
        if args.content_command == "sync":
            return cmd_content_sync(args, settings)
        return cmd_content_translate(args, settings)
    if args.command == "rules":
        return cmd_rules(args, settings)
    if args.command == "coverage":
        return cmd_coverage(args, settings)
    if args.command == "validate":
        return cmd_validate(args, settings)
    if args.command == "cases":
        return cmd_cases(args, settings)
    if args.command == "report":
        return cmd_report(args, settings)
    if args.command == "demo":
        return cmd_demo(args, settings)
    if args.command == "serve":
        return cmd_serve(args, settings)
    if args.command == "scan":
        return cmd_scan(args, settings)
    if args.command == "token":
        return cmd_token(args, settings)
    if args.command == "export":
        return cmd_export(args, settings)
    if args.command == "job":
        return cmd_job(args, settings)
    if args.command == "worker":
        return cmd_worker(args, settings)

    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

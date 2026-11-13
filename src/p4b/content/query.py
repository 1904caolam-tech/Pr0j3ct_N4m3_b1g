"""Sigma to query translation.

SigmaHQ defines *what* a detection means; every SIEM needs it in its own language.
This module is a focused translator for the subset that covers most community
rules: selection AND/OR/NOT, `all of` / `1 of` / `them`, and the common field
modifiers.

Anything outside that subset produces an explicit warning instead of silently
wrong output. That is the whole point: a query you cannot trust is worse than no
query.

Supported backends: Splunk SPL, Microsoft KQL, Elastic Lucene.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from typing import Any

# --------------------------------------------------------------------------- #
# Condition AST
# --------------------------------------------------------------------------- #


@dataclass
class Node:
    pass


@dataclass
class Sel(Node):
    name: str


@dataclass
class Not(Node):
    child: Node


@dataclass
class And(Node):
    children: list[Node]


@dataclass
class Or(Node):
    children: list[Node]


@dataclass
class Of(Node):
    quantifier: str  # "all" | "any" | "1"
    pattern: str     # "them" | "selection_*"


class ConditionError(ValueError):
    """Raised when a Sigma condition cannot be parsed.

    Callers should surface this to the operator: a rule they cannot translate is a
    rule that silently does not protect them.
    """


def tokenize(condition: str) -> list[str]:
    return [token for token in re.sub(r"([()])", r" \1 ", condition).split() if token]


def parse_condition(condition: str) -> Node:
    tokens = tokenize(condition)
    if not tokens:
        raise ConditionError("empty condition")
    position = 0

    def peek() -> str | None:
        return tokens[position] if position < len(tokens) else None

    def take() -> str:
        nonlocal position
        if position >= len(tokens):
            raise ConditionError("condition ended unexpectedly")
        token = tokens[position]
        position += 1
        return token

    def parse_or() -> Node:
        items = [parse_and()]
        while peek() and peek().lower() == "or":
            take()
            items.append(parse_and())
        return items[0] if len(items) == 1 else Or(items)

    def parse_and() -> Node:
        items = [parse_not()]
        while peek() and peek().lower() == "and":
            take()
            items.append(parse_not())
        return items[0] if len(items) == 1 else And(items)

    def parse_not() -> Node:
        if peek() and peek().lower() == "not":
            take()
            return Not(parse_not())
        return parse_primary()

    def parse_primary() -> Node:
        token = peek()
        if token is None:
            raise ConditionError("missing operand")
        if token == "(":
            take()
            node = parse_or()
            if peek() != ")":
                raise ConditionError("missing closing parenthesis")
            take()
            return node
        if token.lower() in {"all", "any", "1"} and position + 1 < len(tokens) and tokens[position + 1].lower() == "of":
            quantifier = take().lower()
            take()  # 'of'
            return Of(quantifier, take())
        if token.lower() == "of":
            raise ConditionError("'of' without a quantifier")
        return Sel(take())

    node = parse_or()
    if position != len(tokens):
        raise ConditionError(f"unexpected trailing tokens: {' '.join(tokens[position:])}")
    return node


# --------------------------------------------------------------------------- #
# Predicates
# --------------------------------------------------------------------------- #

MODIFIER_OPS = {
    "contains": "contains",
    "startswith": "startswith",
    "endswith": "endswith",
    "re": "regex",
    "gt": "gt",
    "gte": "gte",
    "lt": "lt",
    "lte": "lte",
    "exists": "exists",
}

UNSUPPORTED_MODIFIERS = {"base64", "base64offset", "cidr", "windash", "fieldref", "expand", "utf16", "utf16le"}


@dataclass
class Predicate:
    field: str
    op: str
    value: Any
    case_sensitive: bool = False


def split_modifiers(key: str) -> tuple[str, list[str]]:
    parts = key.split("|")
    return parts[0], [part.lower() for part in parts[1:]]


def predicates_for(selection: Any, warnings: list[str], logger_name: str = "") -> list[list[Predicate]]:
    """Turn one selection into disjunctive normal form: OR of AND-groups."""
    branches: list[list[Predicate]] = []
    if isinstance(selection, list):
        for item in selection:
            if isinstance(item, dict):
                branches.extend(predicates_for(item, warnings, logger_name))
            else:
                warnings.append(f"skipped non-mapping selection item: {item!r}")
        return branches
    if not isinstance(selection, dict):
        warnings.append(f"skipped non-mapping selection: {selection!r}")
        return branches

    predicates: list[Predicate] = []
    for key, raw in selection.items():
        name, modifiers = split_modifiers(key)
        for modifier in modifiers:
            if modifier in UNSUPPORTED_MODIFIERS:
                warnings.append(f"modifier '{modifier}' is approximated as equality ({key})")

        values = raw if isinstance(raw, list) else [raw]
        is_null = values == [None]
        if is_null:
            predicates.append(Predicate(name, "null", None))
            continue

        op = "eq"
        for modifier, mapped in MODIFIER_OPS.items():
            if modifier in modifiers:
                op = mapped
                break

        group = [Predicate(name, op, value, "cased" in modifiers) for value in values if value is not None]
        if not group:
            continue
        if op == "exists":
            predicates.append(Predicate(name, "exists", bool(values[0])))
        elif "all" in modifiers:
            predicates.extend(group)
        else:
            predicates.append(_merge_or(name, group, warnings))
    if predicates:
        branches.append(predicates)
    return branches


def _merge_or(name: str, group: list[Predicate], warnings: list[str]) -> Predicate:
    if len(group) == 1:
        return group[0]
    if all(item.op == group[0].op for item in group):
        return Predicate(name, group[0].op, [item.value for item in group], group[0].case_sensitive)
    warnings.append(f"field '{name}' mixes operators; only the first is kept")
    return group[0]


# --------------------------------------------------------------------------- #
# Backends
# --------------------------------------------------------------------------- #

FIELD_MAP: dict[str, dict[str, str]] = {
    "kql": {
        "Image": "FolderPath",
        "OriginalFileName": "FileName",
        "CommandLine": "ProcessCommandLine",
        "ParentImage": "InitiatingProcessFolderPath",
        "ParentCommandLine": "InitiatingProcessCommandLine",
        "User": "AccountName",
        "TargetFilename": "FolderPath",
        "DestinationIp": "RemoteIP",
        "DestinationPort": "RemotePort",
        "SourceIp": "LocalIP",
    },
    "lucene": {
        "Image": "process.executable",
        "CommandLine": "process.command_line",
        "ParentImage": "process.parent.executable",
        "User": "user.name",
        "TargetFilename": "file.path",
        "DestinationIp": "destination.ip",
        "DestinationPort": "destination.port",
        "SourceIp": "source.ip",
        "EventID": "winlog.event_id",
    },
    "splunk": {},
}

SPLUNK_INDEX = {
    "windows": "index=windows",
    "linux": "index=linux",
    "aws": "index=aws",
    "azure": "index=azure",
    "okta": "index=okta",
    "gcp": "index=gcp",
    "network": "index=network",
}

KQL_TABLE = {
    ("windows", "process_creation"): "DeviceProcessEvents",
    ("windows", "network_connection"): "DeviceNetworkEvents",
    ("windows", "file_event"): "DeviceFileEvents",
    ("windows", "registry_set"): "DeviceRegistryEvents",
    ("windows", "dns_query"): "DeviceEvents",
    ("linux", "process_creation"): "DeviceProcessEvents",
    ("aws", "cloudtrail"): "AWSCloudTrail",
    ("azure", "signinlogs"): "SigninLogs",
    ("okta", ""): "Okta_CL",
    ("network", "dns"): "DnsEvents",
}

KQL_PRODUCT_FALLBACK = {
    "windows": "SecurityEvent",
    "linux": "Syslog",
    "aws": "AWSCloudTrail",
    "azure": "SigninLogs",
    "okta": "Okta_CL",
}

LUCENE_SPECIAL = set('+-=&&||>!(){}[]^"~*?:\\/')


class Backend:
    name = "generic"

    def __init__(self, logsource: dict[str, Any] | None = None):
        self.logsource = logsource or {}
        self.warnings: list[str] = []

    def field(self, name: str) -> str:
        return FIELD_MAP.get(self.name, {}).get(name, name)

    def quote(self, value: Any) -> str:
        return f'"{value}"'

    def predicate(self, predicate: Predicate) -> str:
        raise NotImplementedError

    def combine_and(self, parts: list[str]) -> str:
        kept = [part for part in parts if part != "true"]
        if not kept:
            return "true"
        return "(" + " AND ".join(kept) + ")" if len(kept) > 1 else kept[0]

    def combine_or(self, parts: list[str]) -> str:
        if not parts:
            return "false"
        return "(" + " OR ".join(parts) + ")" if len(parts) > 1 else parts[0]

    def negate(self, part: str) -> str:
        return f"NOT {part}"

    def table(self) -> str:
        return ""

    def finalize(self, query: str) -> str:
        return query


class SplunkBackend(Backend):
    name = "splunk"

    def __init__(self, logsource: dict[str, Any] | None = None):
        super().__init__(logsource)
        self.post: list[str] = []
        self._table: str | None = None

    def table(self) -> str:
        if self._table is not None:
            return self._table
        product = str(self.logsource.get("product") or "").lower()
        if product in SPLUNK_INDEX:
            self._table = SPLUNK_INDEX[product]
        elif str(self.logsource.get("category") or "") == "network":
            self._table = "index=network"
        else:
            self.warnings.append("logsource is not mapped; falling back to index=*")
            self._table = "index=*"
        return self._table

    def quote(self, value: Any) -> str:
        escaped = str(value).replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'

    def predicate(self, predicate: Predicate) -> str:
        name = self.field(predicate.field)
        op = predicate.op
        if op == "null":
            return f"NOT {name}=*"
        if op == "exists":
            return f"{name}=*" if predicate.value else f"NOT {name}=*"
        if op == "regex":
            self.post.append(f"| regex {name}={self.quote(predicate.value)}")
            self.warnings.append(f"'{predicate.field}|re' becomes a '| regex' pipe; negation semantics are lost")
            return "true"
        if isinstance(predicate.value, list):
            inner = " OR ".join(self.predicate(Predicate(predicate.field, op, item)) for item in predicate.value)
            return f"({inner})"
        value = str(predicate.value)
        if op in {"gt", "gte", "lt", "lte"}:
            symbol = {"gt": ">", "gte": ">=", "lt": "<", "lte": "<="}[op]
            return f"{name}{symbol}{value}"
        if op == "contains":
            return f'{name}="*{value}*"'
        if op == "startswith":
            return f'{name}="{value}*"'
        if op == "endswith":
            return f'{name}="*{value}"'
        return f"{name}={self.quote(value)}"

    def finalize(self, query: str) -> str:
        base = f"{self.table()} {query}".strip()
        if self.post:
            base = f"{base} {' '.join(dict.fromkeys(self.post))}"
        return base


class KqlBackend(Backend):
    name = "kql"

    def __init__(self, logsource: dict[str, Any] | None = None):
        super().__init__(logsource)
        self._table: str | None = None

    def table(self) -> str:
        if self._table is not None:
            return self._table
        product = str(self.logsource.get("product") or "").lower()
        category = str(self.logsource.get("category") or "").lower()
        if (product, category) in KQL_TABLE:
            self._table = KQL_TABLE[(product, category)]
        elif product in KQL_PRODUCT_FALLBACK:
            self.warnings.append(
                f"no exact table for {product}/{category or 'no-category'}; using {KQL_PRODUCT_FALLBACK[product]}"
            )
            self._table = KQL_PRODUCT_FALLBACK[product]
        else:
            self.warnings.append("logsource is not mapped; falling back to SecurityEvent")
            self._table = "SecurityEvent"
        return self._table

    def quote(self, value: Any) -> str:
        # KQL does not treat backslash as an escape character.
        return "'" + str(value).replace("'", "''") + "'"

    def predicate(self, predicate: Predicate) -> str:
        name = self.field(predicate.field)
        op = predicate.op
        if op == "null":
            return f"isempty({name})"
        if op == "exists":
            return f"isnotempty({name})" if predicate.value else f"isempty({name})"
        if isinstance(predicate.value, list):
            inner = " or ".join(self.predicate(Predicate(predicate.field, op, item)) for item in predicate.value)
            return f"({inner})"
        if op == "contains":
            return f"{name} contains {self.quote(predicate.value)}"
        if op == "startswith":
            return f"{name} startswith {self.quote(predicate.value)}"
        if op == "endswith":
            return f"{name} endswith {self.quote(predicate.value)}"
        if op == "regex":
            return f"{name} matches regex {self.quote(predicate.value)}"
        if op in {"gt", "gte", "lt", "lte"}:
            symbol = {"gt": ">", "gte": ">=", "lt": "<", "lte": "<="}[op]
            return f"{name} {symbol} {predicate.value}"
        if isinstance(predicate.value, (int, float)) and not isinstance(predicate.value, bool):
            return f"{name} == {predicate.value}"
        return f"{name} == {self.quote(predicate.value)}"

    def combine_and(self, parts: list[str]) -> str:
        kept = [part for part in parts if part != "true"]
        if not kept:
            return "true"
        return " and ".join(f"({part})" if " or " in part else part for part in kept)

    def combine_or(self, parts: list[str]) -> str:
        if not parts:
            return "false"
        return "(" + " or ".join(parts) + ")"

    def negate(self, part: str) -> str:
        return f"not ({part})"

    def finalize(self, query: str) -> str:
        return f"{self.table()}\n| where {query}"


class LuceneBackend(Backend):
    name = "lucene"

    def predicate(self, predicate: Predicate) -> str:
        name = self.field(predicate.field)
        op = predicate.op
        if op == "null":
            return f"NOT _exists_:{name}"
        if op == "exists":
            return f"_exists_:{name}" if predicate.value else f"NOT _exists_:{name}"
        if isinstance(predicate.value, list):
            inner = " OR ".join(self.predicate(Predicate(predicate.field, op, item)) for item in predicate.value)
            return f"({inner})"
        if op == "regex":
            return f"{name}:/{str(predicate.value).strip('/')}/"
        if op == "gt":
            return f"{name}:>{{{predicate.value}}}"
        if op == "gte":
            return f"{name}:[{predicate.value} TO *]"
        if op == "lt":
            return f"{name}:{{* TO {predicate.value}}}"
        if op == "lte":
            return f"{name}:[* TO {predicate.value}]"
        value = _escape_lucene(str(predicate.value))
        if op == "contains":
            return f"{name}:*{value}*"
        if op == "startswith":
            return f"{name}:{value}*"
        if op == "endswith":
            return f"{name}:*{value}"
        return f"{name}:{value}"

    def combine_and(self, parts: list[str]) -> str:
        kept = [part for part in parts if part != "true"]
        if not kept:
            return "true"
        return "(" + " AND ".join(kept) + ")" if len(kept) > 1 else kept[0]

    def negate(self, part: str) -> str:
        return f"NOT {part}"


def _escape_lucene(value: str) -> str:
    # Whitespace must be escaped too, otherwise "Failed password" becomes two terms
    # and the wildcard only applies to the first one.
    return "".join(("\\" + char) if (char in LUCENE_SPECIAL or char.isspace()) else char for char in value)


BACKENDS: dict[str, type[Backend]] = {
    "splunk": SplunkBackend,
    "kql": KqlBackend,
    "lucene": LuceneBackend,
}


# --------------------------------------------------------------------------- #
# Translation entry point
# --------------------------------------------------------------------------- #


@dataclass
class Translation:
    backend: str
    query: str
    table: str = ""
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "backend": self.backend,
            "table": self.table,
            "query": self.query,
            "warnings": self.warnings,
        }


def translate(rule: dict[str, Any], backend: str = "splunk") -> Translation:
    if backend not in BACKENDS:
        raise ValueError(f"unknown backend '{backend}' (available: {', '.join(sorted(BACKENDS))})")

    detection = rule.get("detection") or {}
    condition = str(detection.get("condition") or "").strip()
    if not condition:
        raise ConditionError("rule has no detection.condition")

    selections = {
        key: value
        for key, value in detection.items()
        if key not in {"condition", "timeframe"} and not str(key).startswith("_")
    }
    if not selections:
        raise ConditionError("rule has no selections")

    engine = BACKENDS[backend](rule.get("logsource") or {})
    if rule.get("timeframe"):
        engine.warnings.append("rule uses a timeframe; the generated query does not aggregate over a window")

    ast = parse_condition(condition)

    def render_selection(name: str) -> str:
        branches = predicates_for(selections[name], engine.warnings)
        if not branches:
            return "true"
        rendered = []
        for branch in branches:
            parts = [engine.predicate(item) for item in branch]
            rendered.append(engine.combine_and(parts) if len(parts) > 1 else parts[0])
        return rendered[0] if len(rendered) == 1 else engine.combine_or(rendered)

    def render(node: Node) -> str:
        if isinstance(node, Sel):
            if node.name not in selections:
                raise ConditionError(f"condition references unknown selection '{node.name}'")
            return render_selection(node.name)
        if isinstance(node, Not):
            return engine.negate(render(node.child))
        if isinstance(node, And):
            return engine.combine_and([render(child) for child in node.children])
        if isinstance(node, Or):
            return engine.combine_or([render(child) for child in node.children])
        if isinstance(node, Of):
            names = _resolve_pattern(node.pattern, selections)
            if not names:
                raise ConditionError(f"'of' matches no selection: {node.pattern}")
            parts = [render_selection(name) for name in names]
            if node.quantifier == "all":
                return engine.combine_and(parts)
            if node.quantifier == "1":
                engine.warnings.append(
                    f"'1 of {node.pattern}' becomes OR; counting semantics are not preserved"
                )
            return engine.combine_or(parts)
        raise ConditionError(f"unsupported node {node!r}")

    query = render(ast)
    return Translation(backend=backend, query=engine.finalize(query), table=engine.table(), warnings=engine.warnings)


def _resolve_pattern(pattern: str, selections: dict[str, Any]) -> list[str]:
    if pattern == "them":
        return list(selections)
    if any(char in pattern for char in "*?"):
        return [name for name in selections if fnmatch.fnmatch(name, pattern)]
    return [pattern] if pattern in selections else []

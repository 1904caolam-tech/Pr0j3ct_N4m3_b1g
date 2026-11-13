from __future__ import annotations

import pytest

from p4b.content.query import ConditionError, parse_condition, translate

RULE = {
    "title": "LSASS dump",
    "logsource": {"product": "windows", "category": "process_creation"},
    "detection": {
        "selection_image": [{"Image|endswith": "\\rundll32.exe"}, {"OriginalFileName": "rundll32.exe"}],
        "selection_command": {"CommandLine|contains|all": ["comsvcs", "MiniDump"]},
        "condition": "selection_image and selection_command",
    },
}

SSH_RULE = {
    "title": "Failed SSH",
    "logsource": {"product": "linux", "service": "sshd"},
    "detection": {
        "selection_failed": {"message|contains": "Failed password"},
        "selection_invalid": {"message|contains": "Invalid user"},
        "condition": "1 of selection_*",
    },
}


def test_condition_parsing_precedence():
    node = parse_condition("a and b or c")
    assert type(node).__name__ == "Or"
    assert type(node.children[0]).__name__ == "And"


def test_parentheses_change_grouping():
    node = parse_condition("a and (b or c)")
    assert type(node).__name__ == "And"
    assert type(node.children[1]).__name__ == "Or"


def test_not_binds_tighter_than_and():
    node = parse_condition("a and not b")
    assert type(node).__name__ == "And"
    assert type(node.children[1]).__name__ == "Not"


def test_quantifiers():
    node = parse_condition("all of selection_*")
    assert type(node).__name__ == "Of"
    assert node.quantifier == "all"
    assert node.pattern == "selection_*"


def test_invalid_condition_raises():
    with pytest.raises(ConditionError):
        parse_condition("a and")
    with pytest.raises(ConditionError):
        parse_condition("(a and b")
    with pytest.raises(ConditionError):
        parse_condition("a b")


def test_translate_unknown_selection_raises():
    rule = {
        "logsource": {"product": "windows"},
        "detection": {"selection": {"Image": "x"}, "condition": "selection_missing"},
    }
    with pytest.raises(ConditionError):
        translate(rule, "splunk")


def test_splunk_translation():
    result = translate(RULE, "splunk")
    assert result.table == "index=windows"
    assert result.query.startswith("index=windows ")
    assert 'Image="*' in result.query
    assert "OriginalFileName=" in result.query
    assert 'CommandLine="*comsvcs*"' in result.query
    assert " AND " in result.query


def test_kql_translation_maps_windows_fields_and_table():
    result = translate(RULE, "kql")
    assert result.table == "DeviceProcessEvents"
    assert "| where " in result.query
    assert "FolderPath endswith '\\rundll32.exe'" in result.query
    assert "ProcessCommandLine contains 'comsvcs'" in result.query
    assert " and " in result.query


def test_lucene_translation_uses_ecs_fields():
    result = translate(RULE, "lucene")
    assert "process.command_line:*comsvcs*" in result.query
    assert "process.executable:" in result.query


def test_lucene_escapes_spaces():
    result = translate(SSH_RULE, "lucene")
    assert "message:*Failed\\ password*" in result.query


def test_kql_falls_back_to_syslog_for_linux():
    result = translate(SSH_RULE, "kql")
    assert result.table == "Syslog"
    assert any("Syslog" in warning for warning in result.warnings)


def test_unsupported_modifier_warns_instead_of_silently_wrong():
    rule = {
        "logsource": {"product": "windows"},
        "detection": {
            "selection": {"IpAddress|cidr": "10.0.0.0/8"},
            "condition": "selection",
        },
    }
    result = translate(rule, "splunk")
    assert any("cidr" in warning for warning in result.warnings)
    assert "IpAddress=" in result.query


def test_not_renders_per_backend():
    rule = {
        "logsource": {"product": "windows"},
        "detection": {
            "selection": {"Image": "x.exe"},
            "filter": {"User": "SYSTEM"},
            "condition": "selection and not filter",
        },
    }
    assert "NOT User=" in translate(rule, "splunk").query
    assert "not (AccountName" in translate(rule, "kql").query


def test_null_and_exists_modifiers():
    rule = {
        "logsource": {"product": "windows"},
        "detection": {
            "selection": {"User": None, "CommandLine|exists": True},
            "condition": "selection",
        },
    }
    splunk = translate(rule, "splunk").query
    assert "NOT User=*" in splunk
    assert "CommandLine=*" in splunk

    kql = translate(rule, "kql").query
    assert "isempty(AccountName)" in kql
    assert "isnotempty(ProcessCommandLine)" in kql


def test_numeric_comparison_is_not_quoted_in_kql():
    rule = {
        "logsource": {"product": "windows"},
        "detection": {"selection": {"EventID": 4625}, "condition": "selection"},
    }
    assert "EventID == 4625" in translate(rule, "kql").query


def test_unknown_backend_rejected():
    with pytest.raises(ValueError):
        translate(RULE, "qradar")

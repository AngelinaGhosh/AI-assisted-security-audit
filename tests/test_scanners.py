import os

from audit_agent.scanners.semgrep_scanner import run_semgrep
from audit_agent.scanners.dependency_scanner import run_dependency_scan

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def test_semgrep_finds_planted_vulns():
    findings = run_semgrep(
        os.path.join(FIXTURES, "vulnerable_app.py"),
        config=os.path.join(FIXTURES, "local_rules.yaml"),
    )
    rule_ids = {f.rule_id.split(".")[-1] for f in findings}
    assert "sql-injection-string-format" in rule_ids
    assert "insecure-pickle-load" in rule_ids
    assert "shell-injection-subprocess" in rule_ids


def test_semgrep_reads_snippet_from_disk():
    findings = run_semgrep(
        os.path.join(FIXTURES, "vulnerable_app.py"),
        config=os.path.join(FIXTURES, "local_rules.yaml"),
    )
    sql_finding = next(f for f in findings if "sql-injection" in f.rule_id)
    assert "SELECT" in sql_finding.snippet


def test_dependency_scan_flags_old_requests():
    findings = run_dependency_scan(FIXTURES)
    assert any("requests" in f.message for f in findings)


def test_dependency_scan_no_manifest_returns_empty(tmp_path):
    findings = run_dependency_scan(str(tmp_path))
    assert findings == []

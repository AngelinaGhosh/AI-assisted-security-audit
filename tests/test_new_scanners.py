"""OSV-Scanner and Gitleaks integration. Parsing is tested against saved
output, so these run without the binaries or a network connection. The
last test runs the real gitleaks binary if it's installed."""
import json
import os
import subprocess

import pytest

from audit_agent.models import Finding
from audit_agent.scanners import osv_scanner, secret_scanner

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
DEMO = os.path.join(os.path.dirname(__file__), "..", "demo", "target")


def load_osv():
    with open(os.path.join(FIXTURES, "osv_sample.json")) as f:
        return json.load(f)


# ------------------------------------------------------------ OSV-Scanner

def test_osv_parses_every_ecosystem():
    findings = osv_scanner.parse_osv_output(load_osv())
    assert {f.ecosystem for f in findings} == {"PyPI", "npm", "Go"}


def test_osv_merges_aliases_into_one_finding():
    findings = osv_scanner.parse_osv_output(load_osv())
    requests = [f for f in findings if f.package == "requests"]
    assert len(requests) == 1                     # GHSA + PYSEC are the same bug
    f = requests[0]
    assert f.rule_id == "CVE-2018-18074"          # CVE preferred as the ID
    assert set(f.cve_ids) == {"CVE-2018-18074"}
    assert {"GHSA-x84v-xcm2-53pg", "PYSEC-2018-28"} <= set(f.vuln_ids)
    assert f.cvss_score == 9.8 and f.raw_severity == "CRITICAL"
    assert f.fixed_versions == ["2.20.0"]


def test_osv_missing_score_and_call_analysis():
    go = next(f for f in osv_scanner.parse_osv_output(load_osv()) if f.ecosystem == "Go")
    assert go.cvss_score is None and go.raw_severity == "UNKNOWN"
    assert go.called is False


def test_osv_exit_codes(monkeypatch):
    def fake_run(code, out="{}"):
        return lambda *a, **k: subprocess.CompletedProcess(a, code, out, "boom")

    monkeypatch.setattr(subprocess, "run", fake_run(128))
    assert osv_scanner.run_osv_scanner("/x", binary="osv") == []          # no lockfiles

    monkeypatch.setattr(subprocess, "run", fake_run(1, json.dumps(load_osv())))
    assert len(osv_scanner.run_osv_scanner("/x", binary="osv")) == 3      # vulns found isn't an error

    monkeypatch.setattr(subprocess, "run", fake_run(127))
    with pytest.raises(RuntimeError):
        osv_scanner.run_osv_scanner("/x", binary="osv")


def test_falls_back_to_pip_audit_without_osv(monkeypatch):
    monkeypatch.setattr(osv_scanner, "find_osv_scanner", lambda: None)
    monkeypatch.setattr(osv_scanner, "run_pip_audit", lambda p: [])
    _, tool = osv_scanner.scan_dependencies("/x")
    assert tool.startswith("pip-audit")


# --------------------------------------------------------------- Gitleaks

SECRET = "sk-live-9d2f7a1c4b8e6f0a3d5c7b9e1f2a4c6d"


def test_gitleaks_output_is_masked():
    leaks = [{"RuleID": "generic-api-key", "Description": "Generic API Key", "StartLine": 16, "EndLine": 16,
              "Match": f'API_KEY = "{SECRET}"', "Secret": SECRET, "File": "nowhere.py"}]
    result = secret_scanner.parse_gitleaks_output(leaks)
    f = result.findings[0]
    assert f.tool == "secret" and f.rule_id == "gitleaks.generic-api-key" and f.line == 16
    assert SECRET not in f.snippet and "sk-l…" in f.snippet


def test_secrets_are_masked_in_other_scanners_findings():
    semgrep_hit = Finding("semgrep", "hardcoded-api-key", "app.py", 16, "Hardcoded API key", "WARNING",
                          snippet=f'API_KEY = "{SECRET}"', context=f'  16 | API_KEY = "{SECRET}"')
    secret_scanner.redact_findings([semgrep_hit], {SECRET})
    assert SECRET not in semgrep_hit.snippet + semgrep_hit.context


@pytest.mark.skipif(not secret_scanner.find_gitleaks(), reason="gitleaks not installed")
def test_real_gitleaks_finds_demo_key():
    result = secret_scanner.run_gitleaks(DEMO)
    assert any(f.line == 16 for f in result.findings)
    assert all(SECRET not in f.snippet + f.context for f in result.findings)

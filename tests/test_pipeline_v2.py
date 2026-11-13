"""End-to-end v2 pipeline and web stream, with the LLM and dependency
scanner mocked so it runs offline and without a Groq key."""
import json

from fastapi.testclient import TestClient

import audit_agent.pipeline as pipeline
import audit_agent.web.app_v2 as web
from audit_agent.models import TriagedFinding
from audit_agent.models_ext import DependencyFinding
from audit_agent.report.markdown_report_v2 import build_report_v2
from audit_agent.scanners import secret_scanner
from audit_agent.triage.llm_triage import BATCH_SIZE
from audit_agent.triage.validated_triage import BatchResult

SECRET = "sk-live-9d2f7a1c4b8e6f0a3d5c7b9e1f2a4c6d"
seen_by_llm: list[str] = []


def fake_triage(findings, model=None, risks=None, **kw):
    """Pretend AI: constant-input findings are false positives."""
    for i in range(0, len(findings), BATCH_SIZE):
        out = []
        for f in findings[i:i + BATCH_SIZE]:
            seen_by_llm.append(f.snippet + f.context)
            fp = "COUNT(*)" in f.snippet or "df -h" in f.snippet
            out.append(TriagedFinding(f, "High", fp, "high", "test", "test"))
        yield BatchResult(out, ["sample validation issue"] if i == 0 else [])


def fake_deps(root):
    return [DependencyFinding("dependency", "CVE-2018-18074", f"{root}/requirements.txt", 0,
                              "requests==2.6.0 has a known vulnerability", "CRITICAL",
                              package="requests", version="2.6.0", ecosystem="PyPI",
                              vuln_ids=["CVE-2018-18074"], cvss_score=9.8)], "osv-scanner"


def setup(monkeypatch, tmp_path):
    monkeypatch.setenv("GROQ_API_KEY", "test")
    monkeypatch.setenv("THREATFLOW_CACHE", str(tmp_path / "cache"))
    monkeypatch.setattr(web, "triage_fn", fake_triage)
    monkeypatch.setattr(web, "PACE", 0)
    monkeypatch.setattr(web, "OFFLINE", True)
    monkeypatch.setattr(web, "RECORDING", tmp_path / "run.json")
    monkeypatch.setattr(pipeline, "scan_dependencies", fake_deps)


def parse(stream_text):
    events = []
    for block in stream_text.strip().split("\n\n"):
        lines = dict(line.split(": ", 1) for line in block.splitlines())
        events.append((lines["event"], json.loads(lines["data"])))
    return events


def test_v2_stream_runs_every_stage(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    seen_by_llm.clear()
    text = TestClient(web.app).get("/api/scan", params={"target": "demo"}).text
    events = parse(text)
    names = [e for e, _ in events]
    assert "failure" not in names, events[-1]
    assert names[0] == "start" and names[-1] == "done"

    stages = {d["stage"] for e, d in events if e == "stage"}
    assert stages == {"code", "secrets", "deps", "dedupe", "enrich", "ai"}

    raw = next(d for e, d in events if e == "raw")["findings"]
    verdicts = [d for e, d in events if e == "verdict"]
    risks = [d for e, d in events if e == "risk"]
    # nothing silently disappears: every raw finding gets exactly one verdict
    assert sorted(v["index"] for v in verdicts) == list(range(len(raw)))
    assert risks and all(0 <= r["score"] <= 100 for r in risks)
    assert "validation" in names

    summary = next(d for e, d in events if e == "summary")
    assert summary["false_positives"] == 2
    assert sum(summary["by_priority"].values()) == summary["real"]
    assert (tmp_path / "run.json").exists()


def test_secret_never_leaves_the_machine(monkeypatch, tmp_path):
    if not secret_scanner.find_gitleaks():
        import pytest
        pytest.skip("gitleaks not installed")
    setup(monkeypatch, tmp_path)
    seen_by_llm.clear()
    text = TestClient(web.app).get("/api/scan", params={"target": "demo"}).text
    assert SECRET not in text                                  # browser
    assert SECRET not in (tmp_path / "run.json").read_text()   # replay recording
    assert seen_by_llm and not any(SECRET in s for s in seen_by_llm)   # LLM


def test_report_is_ordered_by_risk(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    run = pipeline.AuditRun(web.DEMO_TARGET, rules=str(web.DEMO_RULES), offline=True, triage_fn=fake_triage)
    list(run.events())
    report = build_report_v2(run, "demo")
    scores = [run.risk_of(t.finding).score for t in run.real_findings()]
    assert scores == sorted(scores, reverse=True)
    assert "## P1: fix now" in report and "AI response validation" in report


def test_replay_and_bad_url(monkeypatch, tmp_path):
    monkeypatch.setattr(web, "RECORDING", tmp_path / "missing.json")
    assert parse(TestClient(web.app).get("/api/scan", params={"replay": "true"}).text)[0][0] == "failure"
    monkeypatch.setenv("GROQ_API_KEY", "test")
    events = parse(TestClient(web.app).get("/api/scan", params={"target": "https://evil.example.com/x"}).text)
    assert events[-1][0] == "failure"

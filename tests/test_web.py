"""Tests the web stream end to end with the LLM call mocked out,
so it runs offline and without a Groq key."""
import json

from fastapi.testclient import TestClient

import audit_agent.web.app as web
from audit_agent.models import TriagedFinding


def fake_triage_batches(findings, model=None, api_key=None):
    """Pretend AI: marks constant-input findings as false positives."""
    batch = []
    for f in findings:
        fp = "COUNT(*)" in f.snippet or "df -h" in f.snippet
        batch.append(TriagedFinding(
            finding=f, severity="High", is_false_positive=fp, confidence="high",
            explanation="test", fix_suggestion="test",
        ))
    for i in range(0, len(batch), web.BATCH_SIZE):
        yield batch[i:i + web.BATCH_SIZE]


def parse(stream_text):
    events = []
    for block in stream_text.strip().split("\n\n"):
        lines = dict(line.split(": ", 1) for line in block.splitlines())
        events.append((lines["event"], json.loads(lines["data"])))
    return events


def test_demo_scan_streams_every_stage(monkeypatch, tmp_path):
    monkeypatch.setenv("GROQ_API_KEY", "test")
    monkeypatch.setattr(web, "triage_batches", fake_triage_batches)
    monkeypatch.setattr(web, "PACE", 0)
    monkeypatch.setattr(web, "RECORDING", tmp_path / "run.json")

    client = TestClient(web.app)
    events = parse(client.get("/api/scan", params={"target": "demo", "deps": "false"}).text)
    names = [e for e, _ in events]

    assert "failure" not in names, events
    assert names[0] == "start" and names[-1] == "done"

    raw = next(d for e, d in events if e == "raw")["findings"]
    verdicts = [d for e, d in events if e == "verdict"]
    assert len(raw) > 0
    # nothing silently disappears: every raw finding gets exactly one verdict
    assert sorted(v["index"] for v in verdicts) == list(range(len(raw)))

    summary = next(d for e, d in events if e == "summary")
    assert summary["false_positives"] == 2
    assert (tmp_path / "run.json").exists()   # recorded for replay


def test_replay_without_recording_fails_cleanly(monkeypatch, tmp_path):
    monkeypatch.setattr(web, "RECORDING", tmp_path / "missing.json")
    events = parse(TestClient(web.app).get("/api/scan", params={"replay": "true"}).text)
    assert events[0][0] == "failure"


def test_rejects_non_github_urls(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "test")
    events = parse(TestClient(web.app).get("/api/scan", params={"target": "https://evil.example.com/x"}).text)
    assert events[-1][0] == "failure"

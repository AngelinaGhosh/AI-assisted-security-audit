"""Problems that only show up on real repos: non-English text on Windows,
and Groq's rate limit on repos with many findings."""
import os
import subprocess
import sys

import groq
import httpx

from audit_agent.triage import validated_triage

ROOT = os.path.join(os.path.dirname(__file__), "..")
RULES = os.path.join(ROOT, "demo", "rules.yaml")


def test_semgrep_handles_non_utf8_console(tmp_path):
    """Runs the scanner in a separate Python that, like Windows cmd, does
    NOT default to UTF-8, against a file with non-English characters."""
    (tmp_path / "app.py").write_text(
        "import hashlib\n# Überprüfung — vérifier — 检查\nh = hashlib.md5(b'naïve ✓')\n",
        encoding="utf-8",
    )
    code = (
        "from audit_agent.scanners.semgrep_scanner_v2 import run_semgrep;"
        f"fs = run_semgrep({str(tmp_path)!r}, config={RULES!r});"
        "print(len(fs), ascii(fs[0].snippet))"
    )
    env = {**os.environ, "PYTHONCOERCECLOCALE": "0", "LC_ALL": "C", "PYTHONPATH": ROOT}
    env.pop("PYTHONUTF8", None)
    out = subprocess.run([sys.executable, "-X", "utf8=0", "-c", code],
                         capture_output=True, text=True, encoding="utf-8", errors="replace", env=env, cwd=ROOT)
    assert out.returncode == 0, out.stderr[-800:]
    count, snippet = out.stdout.split(" ", 1)
    assert int(count) == 1 and "md5" in snippet


def _rate_limit_error(retry_after="2"):
    req = httpx.Request("POST", "https://api.groq.com")
    resp = httpx.Response(429, request=req, headers={"retry-after": retry_after})
    return groq.RateLimitError("rate limited", response=resp, body=None)


def test_rate_limit_waits_and_retries(monkeypatch):
    waits = []
    monkeypatch.setattr(validated_triage.time, "sleep", waits.append)
    calls = []

    def once(client, model, payload):
        calls.append(1)
        if len(calls) < 3:
            raise _rate_limit_error("2")
        return "ok"

    monkeypatch.setattr(validated_triage, "_request_once", once)
    assert validated_triage._request(None, "m", []) == "ok"
    assert waits == [2.0, 2.0]


def test_rate_limit_gives_up_with_clear_message(monkeypatch):
    monkeypatch.setattr(validated_triage.time, "sleep", lambda s: None)

    def always(client, model, payload):
        raise _rate_limit_error("500")

    monkeypatch.setattr(validated_triage, "_request_once", always)
    try:
        validated_triage._request(None, "m", [])
    except RuntimeError as e:
        assert "rate limit" in str(e)
    else:
        raise AssertionError("should have raised")
    assert validated_triage._retry_after(_rate_limit_error("500"), 0) == validated_triage.RATE_LIMIT_MAX_WAIT

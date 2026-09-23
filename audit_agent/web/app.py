"""Web front end for the audit agent.

Run with:  uvicorn audit_agent.web.app:app --reload
Then open  http://127.0.0.1:8000

The scan is streamed to the browser with Server-Sent Events (SSE), so
each stage and each AI verdict shows up the moment it is ready instead
of after the whole audit finishes.
"""
import json
import math
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.responses import FileResponse, StreamingResponse

from audit_agent.models import Finding, TriagedFinding, dedupe_exact
from audit_agent.scanners.dependency_scanner import run_dependency_scan
from audit_agent.scanners.semgrep_scanner import run_semgrep
from audit_agent.triage.llm_triage import BATCH_SIZE, DEFAULT_MODEL, triage_batches

load_dotenv()

ROOT = Path(__file__).resolve().parents[2]
STATIC = Path(__file__).parent / "static"
DEMO_TARGET = ROOT / "demo" / "target"
DEMO_RULES = ROOT / "demo" / "rules.yaml"
RECORDING = ROOT / "demo" / "recordings" / "last_run.json"

MODEL = os.environ.get("AUDIT_MODEL", DEFAULT_MODEL)

# A batch comes back from the LLM all at once. PACE spreads the verdicts
# out on screen so people can follow them. It is display pacing only and
# does not change any result. Set AUDIT_PACE=0 to turn it off.
PACE = float(os.environ.get("AUDIT_PACE", "0.35"))

GITHUB_URL = re.compile(r"^https://github\.com/[\w.-]+/[\w.-]+?(\.git)?/?$")

app = FastAPI(title="Security Audit Agent")


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


@app.get("/api/config")
def config():
    return {
        "model": MODEL,
        "has_api_key": bool(os.environ.get("GROQ_API_KEY")),
        "has_recording": RECORDING.exists(),
    }


@app.get("/api/scan")
def scan(target: str = "demo", rules: str = "demo", deps: bool = True, replay: bool = False):
    stream = _replay() if replay else _live_scan(target.strip(), rules, deps)
    return StreamingResponse(
        stream,
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ---------------------------------------------------------------- helpers

def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


def _resolve_target(target: str) -> tuple[Path, Path | None]:
    """Return (folder_to_scan, temp_dir_to_clean_up_or_None)."""
    if target in ("", "demo"):
        return DEMO_TARGET, None

    if target.startswith("https://"):
        if not GITHUB_URL.match(target):
            raise ValueError("Only public GitHub repo URLs are supported, like https://github.com/user/repo")
        tmp = Path(tempfile.mkdtemp(prefix="audit-"))
        result = subprocess.run(
            ["git", "clone", "--depth", "1", target, str(tmp / "repo")],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode != 0:
            shutil.rmtree(tmp, ignore_errors=True)
            raise ValueError(f"Couldn't clone that repo: {result.stderr.strip()[:200]}")
        return tmp / "repo", tmp

    path = Path(target).expanduser()
    if not path.is_dir():
        raise ValueError(f"Folder not found: {target}")
    return path, None


def _raw_dict(f: Finding, idx: int, root: Path) -> dict:
    try:
        path = os.path.relpath(f.path, root)
    except ValueError:
        path = f.path
    return {
        "index": idx,
        "tool": f.tool,
        "rule": f.rule_id.split(".")[-1] if f.tool == "semgrep" else f.rule_id,
        "path": path,
        "line": f.line,
        "message": f.message,
        "raw_severity": f.raw_severity,
        "snippet": f.snippet,
    }


def _verdict_dict(t: TriagedFinding, idx: int, key_to_index: dict[str, int]) -> dict:
    if t.duplicate_of:
        verdict = "duplicate"
    elif t.is_false_positive:
        verdict = "false_positive"
    else:
        verdict = "real"
    return {
        "index": idx,
        "by": "ai",
        "verdict": verdict,
        "severity": t.severity,
        "confidence": t.confidence,
        "explanation": t.explanation,
        "fix": t.fix_suggestion,
        "duplicate_of": key_to_index.get(t.duplicate_of) if t.duplicate_of else None,
    }


# ------------------------------------------------------------- live scan

def _live_scan(target: str, rules: str, deps: bool):
    recorded: list[list] = []

    def emit(event: str, data: dict) -> str:
        recorded.append([event, data])
        return _sse(event, data)

    cleanup = None
    try:
        yield emit("start", {"mode": "live", "model": MODEL, "target": target or "demo"})

        if not os.environ.get("GROQ_API_KEY"):
            raise ValueError("No GROQ_API_KEY found. Add it to your .env file, or replay the last recorded run.")

        root, cleanup = _resolve_target(target)
        config = str(DEMO_RULES) if rules == "demo" else "auto"

        # 1. static analysis
        yield emit("stage", {"stage": "code", "state": "active"})
        findings = run_semgrep(str(root), config=config)
        yield emit("stage", {"stage": "code", "state": "done", "count": len(findings)})

        # 2. dependency CVEs
        if deps:
            yield emit("stage", {"stage": "deps", "state": "active"})
            dep_findings = run_dependency_scan(str(root))
            findings += dep_findings
            yield emit("stage", {"stage": "deps", "state": "done", "count": len(dep_findings)})
        else:
            yield emit("stage", {"stage": "deps", "state": "skipped"})

        index_of = {id(f): i for i, f in enumerate(findings)}
        yield emit("raw", {"findings": [_raw_dict(f, i, root) for i, f in enumerate(findings)]})

        if not findings:
            yield emit("summary", _summary(recorded))
            yield emit("done", {})
            return

        # 3. exact duplicates, removed for free before the AI sees anything
        yield emit("stage", {"stage": "dedupe", "state": "active"})
        unique, exact_dups = dedupe_exact(findings)
        for dup, original in exact_dups:
            yield emit("verdict", {
                "index": index_of[id(dup)],
                "by": "rule",
                "verdict": "duplicate",
                "severity": None,
                "confidence": "high",
                "explanation": "Exact repeat of another finding (same rule, file, line and message).",
                "fix": "",
                "duplicate_of": index_of[id(original)],
            })
        yield emit("stage", {"stage": "dedupe", "state": "done", "count": len(exact_dups)})

        # 4. AI triage, one batch at a time
        yield emit("stage", {"stage": "ai", "state": "active"})
        key_to_index = {f.key(): index_of[id(f)] for f in reversed(unique)}
        total = math.ceil(len(unique) / BATCH_SIZE)
        batches = triage_batches(unique, model=MODEL)
        for n in range(1, total + 1):
            size = min(BATCH_SIZE, len(unique) - (n - 1) * BATCH_SIZE)
            yield emit("batch", {"n": n, "total": total, "size": size})
            for t in next(batches):
                yield emit("verdict", _verdict_dict(t, index_of[id(t.finding)], key_to_index))
                time.sleep(PACE)
        yield emit("stage", {"stage": "ai", "state": "done", "count": len(unique)})

        yield emit("summary", _summary(recorded))
        yield emit("done", {})

        # keep a copy so the demo can be replayed if the network dies
        RECORDING.parent.mkdir(parents=True, exist_ok=True)
        RECORDING.write_text(json.dumps(recorded))

    except Exception as e:  # show the problem in the UI instead of a dead stream
        yield _sse("failure", {"message": str(e)})
    finally:
        if cleanup:
            shutil.rmtree(cleanup, ignore_errors=True)


def _summary(recorded: list[list]) -> dict:
    raw = next((d["findings"] for e, d in recorded if e == "raw"), [])
    verdicts = [d for e, d in recorded if e == "verdict"]
    real = [v for v in verdicts if v["verdict"] == "real"]
    by_severity: dict[str, int] = {}
    for v in real:
        by_severity[v["severity"]] = by_severity.get(v["severity"], 0) + 1
    return {
        "raw": len(raw),
        "real": len(real),
        "exact_duplicates": sum(v["by"] == "rule" for v in verdicts),
        "ai_duplicates": sum(v["by"] == "ai" and v["verdict"] == "duplicate" for v in verdicts),
        "false_positives": sum(v["verdict"] == "false_positive" for v in verdicts),
        "by_severity": by_severity,
    }


# ---------------------------------------------------------------- replay

def _replay():
    """Play back the last successful live run, for when the wifi or the
    API isn't cooperating. The UI clearly labels it as a replay."""
    if not RECORDING.exists():
        yield _sse("failure", {"message": "No recorded run yet. Do one live scan first."})
        return

    for event, data in json.loads(RECORDING.read_text()):
        if event == "start":
            data = {**data, "mode": "replay"}
        yield _sse(event, data)
        if event == "verdict":
            time.sleep(PACE)
        elif event in ("stage", "batch"):
            time.sleep(0.5)

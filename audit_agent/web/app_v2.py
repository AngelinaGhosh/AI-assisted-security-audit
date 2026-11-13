"""Web front end for the v2 pipeline (secrets, all-ecosystem deps, risk
enrichment, validated AI triage). The original web/app.py is unchanged.

Run with:  uvicorn audit_agent.web.app_v2:app --reload
Then open  http://127.0.0.1:8000
"""
import json
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

from audit_agent.pipeline import AuditRun
from audit_agent.scanners.osv_scanner import find_osv_scanner
from audit_agent.scanners.secret_scanner import find_gitleaks
from audit_agent.triage.llm_triage import DEFAULT_MODEL
from audit_agent.triage.validated_triage import triage_batches_validated

load_dotenv()

ROOT = Path(__file__).resolve().parents[2]
STATIC = Path(__file__).parent / "static"
DEMO_TARGET = ROOT / "demo" / "target"
DEMO_RULES = ROOT / "demo" / "rules.yaml"
RECORDING = ROOT / "demo" / "recordings" / "last_run_v2.json"

MODEL = os.environ.get("AUDIT_MODEL", DEFAULT_MODEL)
PACE = float(os.environ.get("AUDIT_PACE", "0.35"))   # on-screen pacing only
OFFLINE = os.environ.get("AUDIT_OFFLINE", "").lower() in ("1", "true", "yes")

GITHUB_URL = re.compile(r"^https://github\.com/[\w.-]+/[\w.-]+?(\.git)?/?$")

# swapped out in tests
triage_fn = triage_batches_validated

app = FastAPI(title="ThreatFlow v2")


@app.get("/")
def index():
    return FileResponse(STATIC / "index_v2.html")


@app.get("/api/config")
def config():
    return {
        "model": MODEL,
        "has_api_key": bool(os.environ.get("GROQ_API_KEY")),
        "has_recording": RECORDING.exists(),
        "tools": {"osv_scanner": bool(find_osv_scanner()), "gitleaks": bool(find_gitleaks())},
    }


@app.get("/api/scan")
def scan(target: str = "demo", rules: str = "demo", deps: bool = True, secrets: bool = True,
         enrich: bool = True, replay: bool = False):
    stream = _replay() if replay else _live_scan(target.strip(), rules, deps, secrets, enrich)
    return StreamingResponse(stream, media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


def _resolve_target(target: str) -> tuple[Path, Path | None]:
    if target in ("", "demo"):
        return DEMO_TARGET, None
    if target.startswith("https://"):
        if not GITHUB_URL.match(target):
            raise ValueError("Only public GitHub repo URLs are supported, like https://github.com/user/repo")
        tmp = Path(tempfile.mkdtemp(prefix="audit-"))
        result = subprocess.run(["git", "clone", "--depth", "1", target, str(tmp / "repo")],
                                capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            shutil.rmtree(tmp, ignore_errors=True)
            raise ValueError(f"Couldn't clone that repo: {result.stderr.strip()[:200]}")
        return tmp / "repo", tmp
    path = Path(target).expanduser()
    if not path.is_dir():
        raise ValueError(f"Folder not found: {target}")
    return path, None


def _live_scan(target: str, rules: str, deps: bool, secrets: bool, enrich: bool):
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
        run = AuditRun(root, rules=str(DEMO_RULES) if rules == "demo" else "auto",
                       deps=deps, secrets=secrets, enrich=enrich, offline=OFFLINE,
                       model=MODEL, triage_fn=triage_fn)
        for event, data in run.events():
            yield emit(event, data)
            if event == "verdict" and data["by"] == "ai":
                time.sleep(PACE)
        yield emit("done", {})

        RECORDING.parent.mkdir(parents=True, exist_ok=True)
        RECORDING.write_text(json.dumps(recorded))
    except Exception as e:
        yield _sse("failure", {"message": str(e)})
    finally:
        if cleanup:
            shutil.rmtree(cleanup, ignore_errors=True)


def _replay():
    if not RECORDING.exists():
        yield _sse("failure", {"message": "No recorded v2 run yet. Do one live scan first."})
        return
    for event, data in json.loads(RECORDING.read_text()):
        if event == "start":
            data = {**data, "mode": "replay"}
        yield _sse(event, data)
        if event == "verdict" and data.get("by") == "ai":
            time.sleep(PACE)
        elif event in ("stage", "batch"):
            time.sleep(0.4)

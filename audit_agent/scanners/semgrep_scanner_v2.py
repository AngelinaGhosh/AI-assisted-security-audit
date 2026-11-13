"""Semgrep runner for the v2 pipeline: same as semgrep_scanner.py, but
safe on Windows with real-world repos.

On Windows, Python decodes subprocess output and opens files with the
legacy code page (e.g. cp1252) unless told otherwise. Repos with non-English
text (comments, templates, translations) then break in two ways:
- the subprocess reader thread fails to decode Semgrep's JSON and
  `result.stdout` silently comes back as None
  ("the JSON object must be str, bytes or bytearray, not NoneType")
- `open(path)` raises UnicodeDecodeError while reading the flagged lines

Here, Semgrep is told to write UTF-8, its output is read as UTF-8, and
source files are read as UTF-8 with undecodable bytes replaced.
"""
import json
import os
import subprocess
import sys

from audit_agent.models import Finding
from audit_agent.scanners.semgrep_scanner import _SEMGREP_LAUNCHER, CONTEXT_RADIUS, SemgrepNotFound


def run_semgrep(target_path: str, config: str = "auto") -> list[Finding]:
    try:
        import semgrep  # noqa: F401
    except ImportError:
        raise SemgrepNotFound("semgrep isn't installed. Run `python -m pip install semgrep`.")

    cmd = [sys.executable, "-c", _SEMGREP_LAUNCHER, "--config", config, "--json", "--quiet", target_path]
    env = {**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"}
    result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", env=env)

    # semgrep exits 1 when it finds issues, that's not a failure
    if result.returncode not in (0, 1):
        raise RuntimeError(f"semgrep failed (exit {result.returncode}): {(result.stderr or '').strip()[-500:]}")
    if not (result.stdout or "").strip():
        raise RuntimeError(f"semgrep returned no output: {(result.stderr or '').strip()[-500:] or 'no error message'}")

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Couldn't parse semgrep output: {e}")

    findings = []
    for r in data.get("results", []):
        start, end = r["start"]["line"], r["end"]["line"]
        lines = _read_lines(r["path"])
        findings.append(Finding(
            tool="semgrep",
            rule_id=r["check_id"],
            path=r["path"],
            line=start,
            message=r["extra"]["message"],
            raw_severity=r["extra"].get("severity", "INFO"),
            snippet="".join(lines[start - 1:end]).rstrip(),
            context=_context(lines, start, end),
        ))
    return findings


def _read_lines(path: str) -> list[str]:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.readlines()
    except OSError:
        return []


def _context(lines: list[str], start_line: int, end_line: int, radius: int = CONTEXT_RADIUS) -> str:
    lo = max(start_line - 1 - radius, 0)
    hi = min(end_line + radius, len(lines))
    return "".join(f"{n:>4} | {lines[n - 1]}" for n in range(lo + 1, hi + 1)).rstrip()

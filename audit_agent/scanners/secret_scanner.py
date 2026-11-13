"""Secret scanning with Gitleaks.

Gitleaks (https://github.com/gitleaks/gitleaks) finds API keys, passwords,
tokens and private keys committed in source code, using a few hundred
built-in rules (AWS, GCP, GitHub, Slack, Stripe, OpenAI, private keys,
JWTs, high-entropy generic keys, ...).

Like OSV-Scanner it's a standalone Go binary. Install it and make sure
`gitleaks` is on PATH, or set GITLEAKS_PATH.

Important: the real secret values must never leave this machine. They are
kept in memory only long enough to mask them out of *every* finding's
snippet and context (Semgrep findings included) before anything is sent
to the LLM, streamed to the browser, recorded for replay or written to
the report.
"""
import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from audit_agent.models import Finding

CONTEXT_RADIUS = 8


@dataclass
class SecretScanResult:
    findings: list[Finding]
    secrets: set[str]          # raw values, used only for masking; never output


def find_gitleaks() -> str | None:
    return os.environ.get("GITLEAKS_PATH") or shutil.which("gitleaks")


def mask(secret: str) -> str:
    """Show just enough to recognise which key it is, e.g. 'sk-l…(43 chars)'."""
    if len(secret) <= 8:
        return "[REDACTED]"
    return f"{secret[:4]}…({len(secret)} chars)"


def run_gitleaks(target_path: str, binary: str | None = None, timeout: int = 600) -> SecretScanResult:
    binary = binary or find_gitleaks()
    if not binary:
        raise FileNotFoundError("gitleaks isn't installed or not on PATH.")

    # `dir` scans the files as they are now. (Secrets that were committed
    # and later deleted are still in git history; `gitleaks git` covers
    # that, but our GitHub clones are --depth 1 so there's no history.)
    cmd = [
        binary, "dir", str(target_path),
        "--report-format", "json", "--report-path", "-",
        "--no-banner", "--log-level", "error",
        "--exit-code", "0",            # finding leaks is not an error
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(f"gitleaks failed (exit {result.returncode}): {result.stderr.strip()[:300]}")

    try:
        leaks = json.loads(result.stdout or "[]") or []
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Couldn't parse gitleaks output: {e}")
    return parse_gitleaks_output(leaks)


def parse_gitleaks_output(leaks: list[dict]) -> SecretScanResult:
    secrets = {leak.get("Secret", "") for leak in leaks if len(leak.get("Secret", "")) >= 4}
    findings: list[Finding] = []
    seen: set[tuple[str, int, str]] = set()

    for leak in leaks:
        path = leak.get("File", "")
        line = int(leak.get("StartLine") or 0)
        rule = leak.get("RuleID", "secret")
        if (path, line, rule) in seen:
            continue
        seen.add((path, line, rule))

        findings.append(Finding(
            tool="secret",
            rule_id=f"gitleaks.{rule}",
            path=path,
            line=line,
            message=leak.get("Description") or f"Possible hardcoded secret ({rule})",
            raw_severity="ERROR",
            snippet=redact_text(leak.get("Match", ""), secrets),
            context=redact_text(_read_context(path, line, int(leak.get("EndLine") or line)), secrets),
        ))
    return SecretScanResult(findings=findings, secrets=secrets)


def redact_text(text: str, secrets: set[str]) -> str:
    # longest first, so a secret that contains another one is masked whole
    for s in sorted(secrets, key=len, reverse=True):
        if s and s in text:
            text = text.replace(s, mask(s))
    return text


def redact_findings(findings: list[Finding], secrets: set[str]) -> None:
    """Mask every known secret out of every finding, in place. Semgrep's
    own 'hardcoded key' findings would otherwise ship the real key to the
    LLM inside their snippet."""
    if not secrets:
        return
    for f in findings:
        f.snippet = redact_text(f.snippet, secrets)
        f.context = redact_text(f.context, secrets)
        f.message = redact_text(f.message, secrets)


def _read_context(path: str, start_line: int, end_line: int, radius: int = CONTEXT_RADIUS) -> str:
    try:
        lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    lo = max(start_line - 1 - radius, 0)
    hi = min(end_line + radius, len(lines))
    return "\n".join(f"{n:>4} | {lines[n - 1]}" for n in range(lo + 1, hi + 1))

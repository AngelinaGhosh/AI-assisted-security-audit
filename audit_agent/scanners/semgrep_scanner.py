import json
import shutil
import subprocess

from audit_agent.models import Finding


class SemgrepNotFound(Exception):
    pass


def run_semgrep(target_path: str, config: str = "auto") -> list[Finding]:
    """Run semgrep against target_path and return parsed findings.

    Uses --json so we get structured output instead of scraping the
    text report. `config="auto"` pulls semgrep's default community
    ruleset, which is enough for a first pass; you can point this at
    a specific ruleset (e.g. "p/owasp-top-ten") once you know what
    you're targeting.
    """
    if shutil.which("semgrep") is None:
        raise SemgrepNotFound(
            "semgrep isn't on PATH. Install it with `pip install semgrep`."
        )

    cmd = ["semgrep", "--config", config, "--json", "--quiet", target_path]
    result = subprocess.run(cmd, capture_output=True, text=True)

    # semgrep exits non-zero when it finds issues, that's not a failure
    if result.returncode not in (0, 1):
        raise RuntimeError(f"semgrep failed: {result.stderr.strip()}")

    data = json.loads(result.stdout)
    findings = []
    for r in data.get("results", []):
        findings.append(Finding(
            tool="semgrep",
            rule_id=r["check_id"],
            path=r["path"],
            line=r["start"]["line"],
            message=r["extra"]["message"],
            raw_severity=r["extra"].get("severity", "INFO"),
            snippet=_read_snippet(r["path"], r["start"]["line"], r["end"]["line"]),
        ))
    return findings


def _read_snippet(path: str, start_line: int, end_line: int) -> str:
    """Semgrep's own `extra.lines` field is gated behind a semgrep.dev
    login in newer versions, so we just read the flagged lines straight
    from disk instead of trusting the API response for this.
    """
    try:
        with open(path) as f:
            lines = f.readlines()
        return "".join(lines[start_line - 1:end_line]).rstrip()
    except OSError:
        return ""

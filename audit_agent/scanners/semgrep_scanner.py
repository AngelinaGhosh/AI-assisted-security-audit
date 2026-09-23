import json
import subprocess
import sys

from audit_agent.models import Finding


_SEMGREP_LAUNCHER = (
    "import sys; sys.argv[0] = 'semgrep'; "
    "from semgrep.console_scripts.entrypoint import main; sys.exit(main())"
)


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
    try:
        import semgrep  # noqa: F401
    except ImportError:
        raise SemgrepNotFound("semgrep isn't installed. Run `python -m pip install semgrep`.")

    # Launch semgrep through the current Python instead of semgrep.exe, so it
    # works when pip's Scripts folder isn't on PATH and on Windows machines
    # where Smart App Control blocks those launcher .exe files.
    cmd = [sys.executable, "-c", _SEMGREP_LAUNCHER, "--config", config, "--json", "--quiet", target_path]
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
            context=_read_context(r["path"], r["start"]["line"], r["end"]["line"]),
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



CONTEXT_RADIUS = 8  # lines of code to include above and below a finding


def _read_context(path: str, start_line: int, end_line: int, radius: int = CONTEXT_RADIUS) -> str:
    """The flagged lines alone usually can't tell you whether the input is
    attacker-controlled. Give the LLM the surrounding code too, with line
    numbers, so it can actually judge exploitability.
    """
    try:
        with open(path) as f:
            lines = f.readlines()
    except OSError:
        return ""
    lo = max(start_line - 1 - radius, 0)
    hi = min(end_line + radius, len(lines))
    return "".join(
        f"{n:>4} | {lines[n - 1]}" for n in range(lo + 1, hi + 1)
    ).rstrip()

import json
import subprocess
import sys
from pathlib import Path

from audit_agent.models import Finding


def run_dependency_scan(target_path: str) -> list[Finding]:
    """Second data source, per the week 3 plan: known-CVE scanning
    on whatever dependency manifest the target repo actually has.

    Right now this only handles Python (pip-audit against
    requirements.txt). Node support via `npm audit` is a natural
    next add if the target repo has a package.json instead - left
    as a stretch item rather than building it half-heartedly.
    """
    target = Path(target_path)
    req_file = target / "requirements.txt"

    if not req_file.exists():
        return []

    try:
        import pip_audit  # noqa: F401
    except ImportError:
        raise RuntimeError("pip-audit isn't installed. Run `python -m pip install pip-audit`.")

    # "python -m pip_audit" rather than pip-audit.exe, same reason as semgrep
    cmd = [sys.executable, "-m", "pip_audit", "-r", str(req_file), "--format", "json"]
    result = subprocess.run(cmd, capture_output=True, text=True)

    # pip-audit also exits non-zero when it finds vulnerabilities
    if result.returncode not in (0, 1):
        raise RuntimeError(f"pip-audit failed: {result.stderr.strip()}")

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []

    findings = []
    for dep in data.get("dependencies", []):
        for vuln in dep.get("vulns", []):
            findings.append(Finding(
                tool="dependency",
                rule_id=vuln.get("id", "unknown-cve"),
                path=str(req_file),
                line=0,
                message=(
                    f"{dep['name']}=={dep['version']} has a known "
                    f"vulnerability ({vuln.get('id')}). "
                    f"Fix versions: {', '.join(vuln.get('fix_versions', [])) or 'none published'}"
                ),
                raw_severity="UNKNOWN",  # pip-audit doesn't give a severity, LLM will estimate
                snippet="",
            ))
    return findings

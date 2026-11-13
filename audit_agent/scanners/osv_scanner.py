"""Multi-ecosystem dependency scanning with OSV-Scanner.

OSV-Scanner (https://github.com/google/osv-scanner) finds lockfiles and
manifests on its own and checks every package against the OSV database:
JavaScript (package-lock.json, yarn.lock, pnpm-lock.yaml), Java (pom.xml,
gradle.lockfile), Go (go.mod), Rust (Cargo.lock), PHP (composer.lock),
Ruby (Gemfile.lock), .NET (packages.lock.json), Python (requirements.txt,
poetry.lock, Pipfile.lock, uv.lock) and more.

It's a standalone Go binary, not a pip package. Install it from the
releases page and make sure `osv-scanner` is on PATH, or point the
OSV_SCANNER_PATH environment variable at the binary.

If OSV-Scanner isn't installed, `scan_dependencies` falls back to
pip-audit (Python only), so the tool still works, just with less coverage.
"""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from audit_agent.models_ext import DependencyFinding

# osv-scanner v2 exit codes
_EXIT_OK = 0              # scanned, nothing vulnerable
_EXIT_VULNS_FOUND = 1     # scanned, vulnerabilities found (not an error)
_EXIT_NO_PACKAGES = 128   # no lockfiles/manifests found


def find_osv_scanner() -> str | None:
    return os.environ.get("OSV_SCANNER_PATH") or shutil.which("osv-scanner")


def severity_label(score: float | None) -> str:
    """CVSS score -> the usual qualitative label."""
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


def run_osv_scanner(target_path: str, binary: str | None = None, timeout: int = 600) -> list[DependencyFinding]:
    """Run OSV-Scanner recursively over target_path and return one finding
    per vulnerability *group*. OSV already groups advisories that are the
    same bug under different IDs (e.g. GHSA-xxx, PYSEC-xxx and CVE-xxx), so
    this removes cross-database duplicates for free.
    """
    binary = binary or find_osv_scanner()
    if not binary:
        raise FileNotFoundError("osv-scanner isn't installed or not on PATH.")

    cmd = [binary, "scan", "source", "-r", "--format", "json", str(target_path)]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

    if result.returncode == _EXIT_NO_PACKAGES:
        return []
    if result.returncode not in (_EXIT_OK, _EXIT_VULNS_FOUND):
        tail = result.stderr.strip().splitlines()[-3:]
        raise RuntimeError(f"osv-scanner failed (exit {result.returncode}): {' | '.join(tail)[:400]}")

    try:
        data = json.loads(result.stdout or "{}")
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Couldn't parse osv-scanner output: {e}")
    return parse_osv_output(data)


def parse_osv_output(data: dict) -> list[DependencyFinding]:
    """Turn osv-scanner's JSON report into DependencyFinding objects."""
    findings: list[DependencyFinding] = []
    for result in data.get("results") or []:
        source = (result.get("source") or {}).get("path", "")
        for pkg in result.get("packages") or []:
            info = pkg.get("package") or {}
            name, version, ecosystem = info.get("name", "?"), info.get("version", "?"), info.get("ecosystem", "")
            vulns = {v.get("id"): v for v in pkg.get("vulnerabilities") or []}

            groups = pkg.get("groups") or [{"ids": [vid], "aliases": [vid]} for vid in vulns]
            for group in groups:
                ids = list(dict.fromkeys((group.get("ids") or []) + (group.get("aliases") or [])))
                records = [vulns[i] for i in group.get("ids") or [] if i in vulns]
                for r in records:
                    ids += [a for a in r.get("aliases") or [] if a not in ids]

                score = _parse_score(group.get("max_severity"))
                fixed = _fixed_versions(records, name)
                summary = next((r.get("summary") for r in records if r.get("summary")), "")
                cves = [i for i in ids if i.upper().startswith("CVE-")]
                primary = cves[0] if cves else (ids[0] if ids else "unknown-vuln")

                findings.append(DependencyFinding(
                    tool="dependency",
                    rule_id=primary,
                    path=source,
                    line=0,
                    message=(
                        f"{name}=={version} ({ecosystem}) has a known vulnerability ({', '.join(ids[:4])})"
                        + (f": {summary}" if summary else "")
                        + f". Fix versions: {', '.join(fixed) or 'none published'}"
                    ),
                    raw_severity=severity_label(score),
                    package=name,
                    version=version,
                    ecosystem=ecosystem,
                    vuln_ids=ids,
                    cvss_score=score,
                    fixed_versions=fixed,
                    called=_call_analysis(group),
                ))
    return findings


def _parse_score(value) -> float | None:
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None
    return score if 0.0 <= score <= 10.0 else None


def _fixed_versions(records: list[dict], package: str) -> list[str]:
    fixed: list[str] = []
    for r in records:
        for aff in r.get("affected") or []:
            if (aff.get("package") or {}).get("name", "").lower() not in ("", package.lower()):
                continue
            for rng in aff.get("ranges") or []:
                for ev in rng.get("events") or []:
                    if ev.get("fixed") and ev["fixed"] not in fixed:
                        fixed.append(ev["fixed"])
    return fixed


def _call_analysis(group: dict) -> bool | None:
    """OSV-Scanner can check whether vulnerable functions are actually
    called (Go and Rust). If it did, use that; otherwise unknown."""
    analysis = group.get("experimentalAnalysis") or group.get("experimental_analysis") or {}
    called = [a.get("called") for a in analysis.values() if isinstance(a, dict) and "called" in a]
    if not called:
        return None
    return any(called)


# ------------------------------------------------------------ fallback

def run_pip_audit(target_path: str) -> list[DependencyFinding]:
    """Python-only fallback when OSV-Scanner isn't installed. Unlike the
    original dependency_scanner, this keeps each advisory's aliases so the
    risk-enrichment stage can still look up CVEs in KEV and EPSS."""
    req_file = Path(target_path) / "requirements.txt"
    if not req_file.exists():
        return []

    cmd = [sys.executable, "-m", "pip_audit", "-r", str(req_file), "--format", "json"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode not in (0, 1):
        raise RuntimeError(f"pip-audit failed: {result.stderr.strip()[:300]}")
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []

    findings: list[DependencyFinding] = []
    seen: set[tuple[str, str]] = set()
    for dep in data.get("dependencies", []):
        for vuln in dep.get("vulns", []):
            ids = [vuln.get("id", "unknown-vuln")] + [a for a in vuln.get("aliases", []) if a]
            key = (dep["name"].lower(), ids[0])
            if key in seen:      # pip-audit sometimes reports the same advisory twice
                continue
            seen.add(key)
            cves = [i for i in ids if i.upper().startswith("CVE-")]
            fixed = vuln.get("fix_versions", [])
            findings.append(DependencyFinding(
                tool="dependency",
                rule_id=cves[0] if cves else ids[0],
                path=str(req_file),
                line=0,
                message=(
                    f"{dep['name']}=={dep['version']} (PyPI) has a known vulnerability ({', '.join(ids[:4])}). "
                    f"Fix versions: {', '.join(fixed) or 'none published'}"
                ),
                raw_severity="UNKNOWN",
                package=dep["name"],
                version=dep["version"],
                ecosystem="PyPI",
                vuln_ids=ids,
                fixed_versions=fixed,
            ))
    return findings


def scan_dependencies(target_path: str) -> tuple[list[DependencyFinding], str]:
    """Use OSV-Scanner if it's installed, otherwise pip-audit.
    Returns (findings, name_of_tool_used)."""
    if find_osv_scanner():
        return run_osv_scanner(target_path), "osv-scanner"
    return run_pip_audit(target_path), "pip-audit (Python only, osv-scanner not installed)"

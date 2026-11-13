"""Combine every signal into one 0-100 risk score and a P1-P4 priority.

How the score is built (kept simple on purpose, so it can be explained):

1. Base severity
   - dependencies: CVSS score x 10 (e.g. CVSS 9.8 -> 98)
   - secrets: 75 (a leaked credential is usable as-is)
   - code: scanner label (ERROR 70, WARNING 45, INFO 20), +15 when the
     line is directly reachable by an HTTP request
2. Real-world exploitation
   - in CISA KEV (exploited in the wild): at least 90, +5 if used by ransomware
   - EPSS: + up to 20 points (20 x probability); EPSS >= 0.5 -> at least 75
3. Reachability multiplier
   reachable/imported/called 1.0, unknown 0.9, transitive 0.85,
   not_imported 0.6, not_called 0.5
4. Exposure multiplier
   internet 1.0, repository (secrets) 1.0, unknown 0.9, internal 0.8
5. KEV floor: anything in KEV stays at 70 or higher even after 3-4.

Priority: P1 >= 80 (fix now), P2 >= 60 (this sprint), P3 >= 35 (plan it),
P4 below that (backlog).
"""
from dataclasses import dataclass, field

from audit_agent.enrichment import exposure, reachability
from audit_agent.enrichment.codebase import CodebaseIndex, build_index
from audit_agent.enrichment.feeds import load_epss, load_kev
from audit_agent.models import Finding
from audit_agent.models_ext import DependencyFinding, RiskInfo

_CODE_BASE = {"CRITICAL": 85, "ERROR": 70, "HIGH": 70, "WARNING": 45, "MEDIUM": 45, "INFO": 20, "LOW": 20}
_REACH_MULT = {"reachable": 1.0, "imported": 1.0, "called": 1.0, "unknown": 0.9,
               "transitive": 0.85, "not_imported": 0.6, "not_called": 0.5}
_EXPOSURE_MULT = {"internet": 1.0, "repository": 1.0, "unknown": 0.9, "internal": 0.8}


@dataclass
class EnrichmentResult:
    risks: dict[int, RiskInfo]           # id(finding) -> risk
    notes: list[str] = field(default_factory=list)   # e.g. "KEV: downloaded latest catalog"
    index: CodebaseIndex | None = None

    def for_finding(self, f: Finding) -> RiskInfo | None:
        return self.risks.get(id(f))

    def llm_context(self) -> dict[int, dict]:
        """Compact version of each risk for the LLM prompt."""
        out = {}
        for key, r in self.risks.items():
            d = {"score": r.score, "priority": r.priority, "reachability": r.reachability, "exposure": r.exposure}
            if r.cvss is not None:
                d["cvss"] = r.cvss
            if r.in_kev is not None:
                d["in_kev"] = r.in_kev
            if r.epss is not None:
                d["epss"] = round(r.epss, 4)
            out[key] = d
        return out


def priority_for(score: int) -> str:
    if score >= 80:
        return "P1"
    if score >= 60:
        return "P2"
    if score >= 35:
        return "P3"
    return "P4"


def score_finding(
    f: Finding,
    reach: str,
    expo: str,
    kev_entry: dict | None,
    kev_checked: bool,
    epss: dict | None,
    reasons: list[str],
) -> RiskInfo:
    cvss = f.cvss_score if isinstance(f, DependencyFinding) else None

    if cvss is not None:
        score = cvss * 10
        reasons.insert(0, f"CVSS {cvss:.1f}")
    elif f.tool == "secret":
        score = 75
    elif isinstance(f, DependencyFinding):
        score = 50
        reasons.insert(0, "no CVSS score published")
    else:
        score = _CODE_BASE.get(f.raw_severity.upper(), 45)

    in_kev = None
    ransomware = None
    if isinstance(f, DependencyFinding) and f.cve_ids and kev_checked:
        in_kev = kev_entry is not None
        if kev_entry:
            ransomware = str(kev_entry.get("knownRansomwareCampaignUse", "")).lower() == "known"
            score = max(score, 90) + (5 if ransomware else 0)
            reasons.append(
                f"in CISA KEV since {kev_entry.get('dateAdded', '?')}: actively exploited"
                + (", used in ransomware campaigns" if ransomware else "")
            )

    epss_p = pct = None
    if epss:
        epss_p, pct = epss.get("epss"), epss.get("percentile")
        if epss_p is not None:
            score += 20 * epss_p
            if epss_p >= 0.5:
                score = max(score, 75)
            if epss_p >= 0.1 or (pct or 0) >= 0.9:
                reasons.append(f"EPSS {epss_p:.0%} chance of exploitation in 30 days (top {max(1, round((1 - (pct or 0)) * 100))}%)")

    if not isinstance(f, DependencyFinding) and f.tool != "secret" and reach == "reachable" and expo == "internet":
        score += 15   # code an HTTP request can reach directly: the main attack surface

    score *= _REACH_MULT.get(reach, 0.9) * _EXPOSURE_MULT.get(expo, 0.9)
    if in_kev:
        score = max(score, 70)

    score = int(round(min(max(score, 0), 100)))
    return RiskInfo(
        score=score, priority=priority_for(score), cvss=cvss,
        in_kev=in_kev, kev_ransomware=ransomware,
        epss=epss_p, epss_percentile=pct,
        reachability=reach, exposure=expo, reasons=reasons,
    )


def enrich_findings(findings: list[Finding], root: str, offline: bool = False) -> EnrichmentResult:
    """Score every finding. Never raises because a feed is down: missing
    signals are recorded in `notes` and treated as unknown."""
    notes: list[str] = []
    idx = build_index(root)
    if idx.is_web_service:
        notes.append("Exposure: web service detected (" + ", ".join(sorted(idx.web_frameworks)) + ")"
                     + ("; " + "; ".join(idx.exposure_signals) if idx.exposure_signals else ""))
    else:
        notes.append("Exposure: no web framework detected, treating code as internal")

    deps = [f for f in findings if isinstance(f, DependencyFinding)]
    cves = sorted({c for f in deps for c in f.cve_ids})

    kev, epss = None, None
    if cves:
        kev, kev_note = load_kev(offline)
        epss, epss_note = load_epss(cves, offline)
        notes += [kev_note, epss_note]

    risks: dict[int, RiskInfo] = {}
    for f in findings:
        if isinstance(f, DependencyFinding):
            reach, why = reachability.check_dependency(f, idx)
            expo = "internet" if idx.is_web_service else "internal"
            reasons = [why, "app is internet-facing" if expo == "internet" else "no web entry point found"]
            kev_entry = next((kev[c] for c in f.cve_ids if kev and c in kev), None)
            ep = None
            if epss:
                scored = [epss[c] for c in f.cve_ids if c in epss]
                ep = max(scored, key=lambda e: e["epss"]) if scored else None
            risks[id(f)] = score_finding(f, reach, expo, kev_entry, kev is not None, ep, reasons)
        else:
            reach, expo, reasons = exposure.check_code(f, idx)
            risks[id(f)] = score_finding(f, reach, expo, None, False, None, list(reasons))

    return EnrichmentResult(risks=risks, notes=notes, index=idx)

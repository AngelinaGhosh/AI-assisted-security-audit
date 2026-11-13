"""Extra data types for the v2 pipeline.

These extend the original `Finding` (models.py is left untouched) so the
old CLI and web app keep working exactly as before.
"""
from dataclasses import dataclass, field
from typing import Optional

from audit_agent.models import Finding


@dataclass
class DependencyFinding(Finding):
    """A vulnerable package found by OSV-Scanner (or pip-audit as fallback).

    Carries the structured data the risk-enrichment stage needs, which the
    plain `message` string can't hold.
    """
    package: str = ""
    version: str = ""
    ecosystem: str = ""                      # PyPI, npm, Maven, Go, crates.io, ...
    vuln_ids: list[str] = field(default_factory=list)   # every ID + alias (GHSA, PYSEC, CVE, ...)
    cvss_score: Optional[float] = None       # 0.0 - 10.0, highest CVSS among the advisories
    fixed_versions: list[str] = field(default_factory=list)
    called: Optional[bool] = None            # OSV call analysis (Go/Rust only); None = unknown

    @property
    def cve_ids(self) -> list[str]:
        return sorted({i for i in self.vuln_ids if i.upper().startswith("CVE-")})


@dataclass
class RiskInfo:
    """Output of the risk-enrichment stage for one finding."""
    score: int                               # 0-100, higher = fix first
    priority: str                            # P1 (fix now) .. P4 (backlog)
    cvss: Optional[float] = None
    in_kev: Optional[bool] = None            # None = not applicable / couldn't check
    kev_ransomware: Optional[bool] = None
    epss: Optional[float] = None             # probability of exploitation in next 30 days, 0-1
    epss_percentile: Optional[float] = None
    reachability: str = "unknown"            # reachable / imported / not_imported / not_called / unknown
    exposure: str = "unknown"                # internet / internal / unknown
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "priority": self.priority,
            "cvss": self.cvss,
            "in_kev": self.in_kev,
            "kev_ransomware": self.kev_ransomware,
            "epss": self.epss,
            "epss_percentile": self.epss_percentile,
            "reachability": self.reachability,
            "exposure": self.exposure,
            "reasons": self.reasons,
        }

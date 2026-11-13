"""Risk-enrichment stage: sits between the scanners and the LLM.

    scanner findings
          |
    risk enrichment
      |- CVSS severity            (from OSV-Scanner)
      |- CISA KEV status          (feeds.py)
      |- EPSS probability         (feeds.py)
      |- dependency reachability  (reachability.py)
      '- internet exposure        (exposure.py)
          |
    LLM explanation and final report

risk.py combines all of it into one 0-100 score and a P1-P4 priority.
"""
from audit_agent.enrichment.risk import EnrichmentResult, enrich_findings

__all__ = ["EnrichmentResult", "enrich_findings"]

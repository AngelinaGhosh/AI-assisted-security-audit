"""The v2 audit pipeline, shared by cli_v2.py and web/app_v2.py.

    Semgrep (code) --+
    Gitleaks (secrets) --+--> raw findings --> mask secrets --> exact dedupe
    OSV-Scanner (deps) --+                                         |
                                                          risk enrichment
                                               (CVSS, KEV, EPSS, reachability, exposure)
                                                                   |
                                                     validated LLM triage
                                                                   |
                                                     prioritised report

`AuditRun.events()` yields (event_name, data) tuples as each step
finishes, so the web UI can stream them. After it finishes, the results
are on the AuditRun object for the CLI's report.
"""
import math
import os
from collections.abc import Callable, Iterator
from pathlib import Path

from audit_agent.enrichment import EnrichmentResult, enrich_findings
from audit_agent.models import Finding, TriagedFinding, dedupe_exact
from audit_agent.models_ext import DependencyFinding
from audit_agent.scanners.osv_scanner import scan_dependencies
from audit_agent.scanners.secret_scanner import find_gitleaks, redact_findings, run_gitleaks
from audit_agent.scanners.semgrep_scanner import run_semgrep
from audit_agent.triage.llm_triage import BATCH_SIZE, DEFAULT_MODEL
from audit_agent.triage.validated_triage import BatchResult, triage_batches_validated

Event = tuple[str, dict]
TriageFn = Callable[..., Iterator[BatchResult]]

PRIORITY_ORDER = ["P1", "P2", "P3", "P4"]


class AuditRun:
    def __init__(
        self,
        root: str | Path,
        rules: str = "auto",
        deps: bool = True,
        secrets: bool = True,
        enrich: bool = True,
        offline: bool = False,
        model: str = DEFAULT_MODEL,
        triage_fn: TriageFn = triage_batches_validated,
    ):
        self.root = Path(root).resolve()
        self.rules, self.deps, self.secrets, self.enrich = rules, deps, secrets, enrich
        self.offline, self.model, self.triage_fn = offline, model, triage_fn

        # results, filled in as the run goes
        self.findings: list[Finding] = []
        self.exact_dups: list[tuple[Finding, Finding]] = []
        self.enrichment: EnrichmentResult | None = None
        self.triaged: list[TriagedFinding] = []
        self.validation_issues: list[str] = []
        self.notes: list[str] = []
        self._verdicts: list[dict] = []

    # ------------------------------------------------------------ events

    def events(self) -> Iterator[Event]:
        root = str(self.root)

        # 1. code
        yield "stage", {"stage": "code", "state": "active"}
        code = run_semgrep(root, config=self.rules)
        self.findings += code
        yield "stage", {"stage": "code", "state": "done", "count": len(code)}

        # 2. secrets
        secret_values: set[str] = set()
        if not self.secrets:
            yield "stage", {"stage": "secrets", "state": "skipped"}
        elif not find_gitleaks():
            self.notes.append("Secrets: gitleaks not installed, secret scan skipped")
            yield "stage", {"stage": "secrets", "state": "skipped", "detail": "gitleaks not installed"}
        else:
            yield "stage", {"stage": "secrets", "state": "active"}
            result = run_gitleaks(root)
            secret_values = result.secrets
            self.findings += result.findings
            yield "stage", {"stage": "secrets", "state": "done", "count": len(result.findings)}

        # 3. dependencies
        if self.deps:
            yield "stage", {"stage": "deps", "state": "active"}
            dep_findings, tool = scan_dependencies(root)
            self.notes.append(f"Dependencies: scanned with {tool}")
            self.findings += dep_findings
            yield "stage", {"stage": "deps", "state": "done", "count": len(dep_findings), "tool": tool}
        else:
            yield "stage", {"stage": "deps", "state": "skipped"}

        # never let a real secret value travel any further than this point
        redact_findings(self.findings, secret_values)

        index_of = {id(f): i for i, f in enumerate(self.findings)}
        yield "raw", {"findings": [self._raw_dict(f, i) for i, f in enumerate(self.findings)]}
        if not self.findings:
            yield "summary", self.summary()
            return

        # 4. exact duplicates (free, no AI)
        yield "stage", {"stage": "dedupe", "state": "active"}
        unique, self.exact_dups = dedupe_exact(self.findings)
        for dup, original in self.exact_dups:
            yield self._verdict({
                "index": index_of[id(dup)], "by": "rule", "verdict": "duplicate", "severity": None,
                "confidence": "high", "explanation": "Exact repeat of another finding (same rule, file, line and message).",
                "fix": "", "duplicate_of": index_of[id(original)],
            })
        yield "stage", {"stage": "dedupe", "state": "done", "count": len(self.exact_dups)}

        # 5. risk enrichment
        risks_for_llm = None
        if self.enrich:
            yield "stage", {"stage": "enrich", "state": "active"}
            self.enrichment = enrich_findings(unique, root, offline=self.offline)
            self.notes += self.enrichment.notes
            for f in unique:
                yield "risk", {"index": index_of[id(f)], **self.enrichment.for_finding(f).to_dict()}
            yield "stage", {"stage": "enrich", "state": "done", "count": len(unique), "notes": self.enrichment.notes}
            risks_for_llm = self.enrichment.llm_context()
        else:
            yield "stage", {"stage": "enrich", "state": "skipped"}

        # 6. AI triage. Sort by location so related findings (e.g. Semgrep
        # and Gitleaks flagging the same line) land in the same batch and
        # the model can mark them as duplicates.
        unique.sort(key=lambda f: (f.path, f.line, f.tool))
        yield "stage", {"stage": "ai", "state": "active"}
        key_to_index = {f.key(): index_of[id(f)] for f in reversed(unique)}
        total = math.ceil(len(unique) / BATCH_SIZE)
        batches = self.triage_fn(unique, model=self.model, risks=risks_for_llm)
        for n in range(1, total + 1):
            size = min(BATCH_SIZE, len(unique) - (n - 1) * BATCH_SIZE)
            yield "batch", {"n": n, "total": total, "size": size}
            result = next(batches)
            if result.issues:
                self.validation_issues += result.issues
                yield "validation", {"batch": n, "issues": result.issues}
            for t in result.triaged:
                self.triaged.append(t)
                yield self._verdict(self._ai_verdict(t, index_of[id(t.finding)], key_to_index))
        yield "stage", {"stage": "ai", "state": "done", "count": len(unique)}

        yield "summary", self.summary()

    # ----------------------------------------------------------- helpers

    def _verdict(self, data: dict) -> Event:
        self._verdicts.append(data)
        return "verdict", data

    def _rel(self, path: str) -> str:
        try:
            return os.path.relpath(os.path.abspath(path), self.root)
        except ValueError:
            return path

    def _raw_dict(self, f: Finding, idx: int) -> dict:
        d = {
            "index": idx,
            "tool": f.tool,
            "rule": f.rule_id.split(".")[-1] if f.tool in ("semgrep", "secret") else f.rule_id,
            "path": self._rel(f.path),
            "line": f.line,
            "message": f.message,
            "raw_severity": f.raw_severity,
            "snippet": f.snippet,
        }
        if isinstance(f, DependencyFinding):
            d.update(package=f.package, version=f.version, ecosystem=f.ecosystem,
                     vuln_ids=f.vuln_ids, fixed_versions=f.fixed_versions)
        return d

    def _ai_verdict(self, t: TriagedFinding, idx: int, key_to_index: dict[str, int]) -> dict:
        verdict = "duplicate" if t.duplicate_of else "false_positive" if t.is_false_positive else "real"
        return {
            "index": idx, "by": "ai", "verdict": verdict, "severity": t.severity,
            "confidence": t.confidence, "explanation": t.explanation, "fix": t.fix_suggestion,
            "duplicate_of": key_to_index.get(t.duplicate_of) if t.duplicate_of else None,
        }

    def risk_of(self, f: Finding):
        return self.enrichment.for_finding(f) if self.enrichment else None

    def real_findings(self) -> list[TriagedFinding]:
        """Real issues, highest risk first."""
        real = [t for t in self.triaged if not t.is_false_positive and not t.duplicate_of]
        sev_rank = {s: i for i, s in enumerate(["Critical", "High", "Medium", "Low", "Info"])}
        return sorted(real, key=lambda t: (-(self.risk_of(t.finding).score if self.risk_of(t.finding) else 0),
                                           sev_rank.get(t.severity, 5)))

    def summary(self) -> dict:
        real = [v for v in self._verdicts if v["verdict"] == "real"]
        by_severity: dict[str, int] = {}
        for v in real:
            by_severity[v["severity"]] = by_severity.get(v["severity"], 0) + 1
        by_priority = {p: 0 for p in PRIORITY_ORDER}
        for t in self.real_findings():
            r = self.risk_of(t.finding)
            if r:
                by_priority[r.priority] += 1
        return {
            "raw": len(self.findings),
            "real": len(real),
            "exact_duplicates": sum(v["by"] == "rule" for v in self._verdicts),
            "ai_duplicates": sum(v["by"] == "ai" and v["verdict"] == "duplicate" for v in self._verdicts),
            "false_positives": sum(v["verdict"] == "false_positive" for v in self._verdicts),
            "by_severity": by_severity,
            "by_priority": by_priority if self.enrichment else {},
            "validation_issues": len(self.validation_issues),
            "notes": self.notes,
        }

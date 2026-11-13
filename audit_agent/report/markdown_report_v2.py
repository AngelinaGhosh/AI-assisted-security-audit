"""Markdown report for the v2 pipeline: ordered by risk priority, with the
evidence behind each score (CVSS, KEV, EPSS, reachability, exposure)."""
import os
from datetime import datetime

from audit_agent.models_ext import DependencyFinding
from audit_agent.pipeline import PRIORITY_ORDER, AuditRun

PRIORITY_LABEL = {
    "P1": "P1: fix now",
    "P2": "P2: fix this sprint",
    "P3": "P3: plan a fix",
    "P4": "P4: backlog",
}


def _fmt_bool(v):
    return "yes" if v else ("no" if v is False else "n/a")


def build_report_v2(run: AuditRun, target: str) -> str:
    s = run.summary()
    real = run.real_findings()
    lines = [
        "# Security Audit Report",
        "",
        f"**Target:** `{target}`  ",
        f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M')}  ",
        f"**Model:** {run.model}  ",
        f"**Raw findings:** {s['raw']} -> **Real issues:** {s['real']} "
        f"({s['exact_duplicates']} exact repeats, {s['ai_duplicates']} duplicates found by AI, "
        f"{s['false_positives']} false positives)",
        "",
    ]

    if s["by_priority"]:
        lines += ["## Summary", "", "| Priority | Issues |", "|---|---|"]
        lines += [f"| {PRIORITY_LABEL[p]} | {s['by_priority'][p]} |" for p in PRIORITY_ORDER]
        lines.append("")

    if run.notes:
        lines += ["### Data sources", ""] + [f"- {n}" for n in run.notes] + [""]

    current = None
    for t in real:
        f, risk = t.finding, run.risk_of(t.finding)
        group = risk.priority if risk else "Unscored"
        if group != current:
            current = group
            lines += [f"## {PRIORITY_LABEL.get(group, group)}", ""]

        path = run._rel(f.path) if f.path else ""
        where = f"{path}:{f.line}" if f.line else path
        title = f"{f.package} {f.version} ({f.rule_id})" if isinstance(f, DependencyFinding) else f.rule_id.split(".")[-1]
        lines.append(f"### {title}, {where}")
        meta = [f"AI severity: **{t.severity}**", f"confidence: {t.confidence}"]
        if risk:
            meta.insert(0, f"risk score: **{risk.score}/100**")
        lines += [" · ".join(meta), "", t.explanation, ""]

        if risk:
            lines += [
                "| CVSS | In CISA KEV | EPSS | Reachability | Exposure |",
                "|---|---|---|---|---|",
                f"| {risk.cvss if risk.cvss is not None else 'n/a'} | {_fmt_bool(risk.in_kev)} | "
                f"{f'{risk.epss:.1%}' if risk.epss is not None else 'n/a'} | {risk.reachability} | {risk.exposure} |",
                "",
            ]
            if risk.reasons:
                lines += ["Why: " + "; ".join(risk.reasons), ""]
        if f.snippet:
            lines += ["```", f.snippet, "```"]
        lines += [f"**Suggested fix:** {t.fix_suggestion}", ""]

    filtered = [t for t in run.triaged if t.is_false_positive or t.duplicate_of]
    if filtered or run.exact_dups:
        lines += ["## Filtered out (duplicates / false positives)", ""]
        by_key = {t.finding.key(): t.finding for t in run.triaged}
        for t in filtered:
            if t.is_false_positive:
                reason = "false positive"
            else:
                orig = by_key.get(t.duplicate_of)
                reason = (f"duplicate of `{orig.rule_id}` at {run._rel(orig.path)}:{orig.line}"
                          if orig else f"duplicate of {t.duplicate_of}")
            lines.append(f"- `{t.finding.rule_id}` at {run._rel(t.finding.path)}:{t.finding.line}: {reason}")
        for dup, orig in run.exact_dups:
            lines.append(f"- `{dup.rule_id}` at {run._rel(dup.path)}:{dup.line}: exact repeat")
        lines.append("")

    if run.validation_issues:
        lines += ["## AI response validation", "",
                  "Problems found in the model's output and how they were handled:", ""]
        lines += [f"- {i}" for i in run.validation_issues] + [""]

    return "\n".join(lines)

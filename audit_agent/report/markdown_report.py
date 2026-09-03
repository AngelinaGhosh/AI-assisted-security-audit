from datetime import datetime

from audit_agent.models import TriagedFinding

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]


def build_report(
    triaged: list[TriagedFinding],
    target_path: str,
    raw_count: int,
) -> str:
    real_findings = [t for t in triaged if not t.is_false_positive and not t.duplicate_of]
    dropped = len(triaged) - len(real_findings)

    lines = [
        f"# Security Audit Report",
        f"",
        f"**Target:** `{target_path}`  ",
        f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M')}  ",
        f"**Raw findings:** {raw_count} -> **After triage:** {len(real_findings)} "
        f"({dropped} dropped as duplicates/false positives)",
        f"",
        f"## Summary",
        f"",
    ]

    counts = {sev: 0 for sev in SEVERITY_ORDER}
    for t in real_findings:
        counts[t.severity] = counts.get(t.severity, 0) + 1

    for sev in SEVERITY_ORDER:
        if counts.get(sev):
            lines.append(f"- **{sev}:** {counts[sev]}")
    lines.append("")

    for sev in SEVERITY_ORDER:
        bucket = [t for t in real_findings if t.severity == sev]
        if not bucket:
            continue
        lines.append(f"## {sev}")
        lines.append("")
        for t in bucket:
            f = t.finding
            lines.append(f"### `{f.rule_id}` — {f.path}:{f.line}")
            lines.append(f"*confidence: {t.confidence}*")
            lines.append("")
            lines.append(t.explanation)
            lines.append("")
            if f.snippet:
                lines.append("```")
                lines.append(f.snippet)
                lines.append("```")
            lines.append(f"**Suggested fix:** {t.fix_suggestion}")
            lines.append("")

    if dropped:
        lines.append("## Filtered out (duplicates / false positives)")
        lines.append("")
        for t in triaged:
            if t.is_false_positive or t.duplicate_of:
                reason = "false positive" if t.is_false_positive else f"duplicate of {t.duplicate_of}"
                lines.append(f"- `{t.finding.rule_id}` at {t.finding.path}:{t.finding.line} — {reason}")

    return "\n".join(lines)

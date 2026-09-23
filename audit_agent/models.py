from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Finding:
    """A single raw finding from a scanner, before any LLM triage."""
    tool: str              # "semgrep" or "dependency"
    rule_id: str
    path: str
    line: int
    message: str
    raw_severity: str      # whatever the scanner itself reported
    snippet: str = ""
    context: str = ""      # surrounding lines (with line numbers) so the LLM can judge reachability

    def key(self) -> str:
        # used for rough dedup before we even hit the LLM
        return f"{self.rule_id}:{self.path}:{self.line}"


@dataclass
class TriagedFinding:
    """A finding after the LLM has looked at it."""
    finding: Finding
    severity: str                  # Critical / High / Medium / Low / Info
    is_false_positive: bool
    confidence: str                # how sure the model is (low/medium/high)
    explanation: str
    fix_suggestion: str
    duplicate_of: Optional[str] = None   # rule_id:path:line of the finding this was merged into


def dedupe_exact(findings: list[Finding]) -> tuple[list[Finding], list[tuple[Finding, Finding]]]:
    """Drop findings that are exact repeats (same rule, file, line and message).

    This is free and deterministic, so it runs before the LLM ever sees
    anything. pip-audit, for example, can report the same advisory twice.
    Returns (unique_findings, [(duplicate, finding_it_repeats), ...]).
    """
    seen: dict[tuple[str, str], Finding] = {}
    unique: list[Finding] = []
    duplicates: list[tuple[Finding, Finding]] = []
    for f in findings:
        k = (f.key(), f.message)
        if k in seen:
            duplicates.append((f, seen[k]))
        else:
            seen[k] = f
            unique.append(f)
    return unique, duplicates

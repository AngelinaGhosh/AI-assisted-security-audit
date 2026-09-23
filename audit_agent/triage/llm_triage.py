import json
import os
from collections.abc import Iterator

from groq import Groq

from audit_agent.models import Finding, TriagedFinding
from audit_agent.triage.prompts import TRIAGE_SYSTEM_PROMPT, build_user_message

BATCH_SIZE = 15  # keep batches small enough that the model isn't skimming
# llama-3.3-70b-versatile was retired by Groq on 2026-08-16; this is
# Groq's recommended replacement. Override with AUDIT_MODEL in .env.
DEFAULT_MODEL = "openai/gpt-oss-120b"

# Map scanner labels to our scale, used only when the model skips a finding.
_FALLBACK_SEVERITY = {"ERROR": "High", "WARNING": "Medium", "INFO": "Low"}


def _finding_to_dict(f: Finding, idx: int) -> dict:
    return {
        "id": idx,
        "tool": f.tool,
        "rule_id": f.rule_id,
        "path": f.path,
        "line": f.line,
        "message": f.message,
        "raw_severity": f.raw_severity,
        "snippet": f.snippet[:500],   # don't blow up the prompt on huge blocks
        "context": f.context[:1500],
    }


def _triage_batch(client: Groq, model: str, batch: list[Finding]) -> list[TriagedFinding]:
    payload = [_finding_to_dict(f, i) for i, f in enumerate(batch)]

    extra = {}
    if "gpt-oss" in model:
        # reasoning model: its thinking counts against max_tokens, so keep
        # it short and leave room for the JSON answer
        extra["reasoning_effort"] = "low"

    response = client.chat.completions.create(
        model=model,
        max_tokens=8000,
        **extra,
        temperature=0,  # same input -> (nearly) same verdicts, important for a repeatable audit
        messages=[
            {"role": "system", "content": TRIAGE_SYSTEM_PROMPT},
            {"role": "user", "content": build_user_message(json.dumps(payload, indent=2))},
        ],
    )

    text = response.choices[0].message.content.strip()
    # models occasionally wrap JSON in fences despite instructions
    text = text.removeprefix("```json").removeprefix("```").removesuffix("```").strip()

    try:
        results = json.loads(text)
    except json.JSONDecodeError as e:
        raise RuntimeError(
            f"Couldn't parse triage response as JSON: {e}\nRaw: {text[:300]}"
        )

    triaged: dict[int, TriagedFinding] = {}
    for r in results:
        idx = r.get("id")
        # ignore anything that doesn't point at a real finding in this batch
        if not isinstance(idx, int) or not 0 <= idx < len(batch) or idx in triaged:
            continue
        dup = r.get("duplicate_of")
        valid_dup = isinstance(dup, int) and 0 <= dup < len(batch) and dup != idx
        triaged[idx] = TriagedFinding(
            finding=batch[idx],
            severity=r.get("severity", "Info"),
            is_false_positive=bool(r.get("is_false_positive", False)),
            confidence=r.get("confidence", "medium"),
            explanation=r.get("explanation", ""),
            fix_suggestion=r.get("fix_suggestion", ""),
            duplicate_of=batch[dup].key() if valid_dup else None,
        )

    # Nothing silently disappears: if the model skipped a finding, keep it
    # as a real issue and say so, rather than dropping it.
    for idx, f in enumerate(batch):
        if idx not in triaged:
            triaged[idx] = TriagedFinding(
                finding=f,
                severity=_FALLBACK_SEVERITY.get(f.raw_severity.upper(), "Medium"),
                is_false_positive=False,
                confidence="low",
                explanation="The AI didn't return a verdict for this finding, so it is kept for manual review.",
                fix_suggestion="Review manually.",
            )

    return [triaged[i] for i in range(len(batch))]


def triage_batches(
    findings: list[Finding],
    model: str = DEFAULT_MODEL,
    api_key: str | None = None,
) -> Iterator[list[TriagedFinding]]:
    """Yield triaged results one batch at a time.

    The web UI uses this to show verdicts as soon as each batch comes
    back, instead of waiting for the whole scan to finish.
    """
    if not findings:
        return

    client = Groq(api_key=api_key or os.environ.get("GROQ_API_KEY"))
    for start in range(0, len(findings), BATCH_SIZE):
        yield _triage_batch(client, model, findings[start:start + BATCH_SIZE])


def triage_findings(
    findings: list[Finding],
    model: str = DEFAULT_MODEL,
    api_key: str | None = None,
) -> list[TriagedFinding]:
    """Send raw findings to the LLM in batches and get back structured
    severity/dedup/fix-suggestion judgments.

    Uses Groq's free tier by default - llama-3.3-70b-versatile is good
    enough at structured JSON output for this and doesn't cost anything.
    Swap the model name if you want to try a different one Groq hosts.
    """
    return [t for batch in triage_batches(findings, model, api_key) for t in batch]

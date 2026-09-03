import json
import os

from groq import Groq

from audit_agent.models import Finding, TriagedFinding
from audit_agent.triage.prompts import TRIAGE_SYSTEM_PROMPT, build_user_message

BATCH_SIZE = 15  # keep batches small enough that the model isn't skimming


def _finding_to_dict(f: Finding, idx: int) -> dict:
    return {
        "id": idx,
        "tool": f.tool,
        "rule_id": f.rule_id,
        "path": f.path,
        "line": f.line,
        "message": f.message,
        "raw_severity": f.raw_severity,
        "snippet": f.snippet[:500],  # don't blow up the prompt on huge blocks
    }


def triage_findings(
    findings: list[Finding],
    model: str = "llama-3.3-70b-versatile",
    api_key: str | None = None,
) -> list[TriagedFinding]:
    """Send raw findings to the LLM in batches and get back structured
    severity/dedup/fix-suggestion judgments.

    Uses Groq's free tier by default - llama-3.3-70b-versatile is good
    enough at structured JSON output for this and doesn't cost anything.
    Swap the model name if you want to try a different one Groq hosts.
    """
    if not findings:
        return []

    client = Groq(api_key=api_key or os.environ.get("GROQ_API_KEY"))
    triaged: list[TriagedFinding] = []

    for start in range(0, len(findings), BATCH_SIZE):
        batch = findings[start:start + BATCH_SIZE]
        payload = [_finding_to_dict(f, i) for i, f in enumerate(batch)]

        response = client.chat.completions.create(
            model=model,
            max_tokens=4000,
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

        for r in results:
            f = batch[r["id"]]
            dup = r.get("duplicate_of")
            triaged.append(TriagedFinding(
                finding=f,
                severity=r.get("severity", "Info"),
                is_false_positive=bool(r.get("is_false_positive", False)),
                confidence=r.get("confidence", "medium"),
                explanation=r.get("explanation", ""),
                fix_suggestion=r.get("fix_suggestion", ""),
                duplicate_of=batch[dup].key() if dup is not None else None,
            ))

    return triaged

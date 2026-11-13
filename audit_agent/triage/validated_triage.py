"""LLM triage with schema enforcement and validation of every response.

What can go wrong with a model response, and what happens here:

- invalid JSON / prose around it   -> tolerant parsing, then one retry
- schema not supported by a model  -> falls back to JSON mode, then plain
- truncated output (finish_reason == "length", long batches, long
  reasoning)                       -> batch is split in half and retried
- different casing, quoted booleans, "moderate" instead of "Medium",
  ids as strings                   -> normalised by `schema.Verdict`
- missing fields / skipped findings -> re-asked once on their own; if
  still missing, kept as a real issue flagged for manual review
- bogus ids, self-duplicates, duplicate cycles -> dropped or fixed

Nothing is ever silently discarded. Every correction is recorded in the
returned `issues` list so it can be shown in the UI and the report.
"""
import json
import os
import time
from collections.abc import Iterator
from dataclasses import dataclass, field

import groq
from groq import Groq

from audit_agent.models import Finding, TriagedFinding
from audit_agent.triage.llm_triage import BATCH_SIZE, DEFAULT_MODEL
from audit_agent.triage.prompts_v2 import TRIAGE_SYSTEM_PROMPT_V2, build_user_message_v2
from audit_agent.triage.schema import RESPONSE_FORMAT, Verdict, extract_json, validate_batch

MAX_TOKENS = 8000
RATE_LIMIT_RETRIES = 6        # waits up to ~6 minutes in total before giving up
RATE_LIMIT_MAX_WAIT = 60      # seconds
_FALLBACK_SEVERITY = {
    "CRITICAL": "Critical", "ERROR": "High", "HIGH": "High",
    "WARNING": "Medium", "MEDIUM": "Medium", "INFO": "Low", "LOW": "Low",
}

# which response_format each model accepted, remembered across calls:
# "schema" (strict JSON schema) -> "json" (JSON mode) -> "none"
_FORMAT_MODE: dict[str, str] = {}


class TruncatedResponse(Exception):
    pass


class BadResponse(Exception):
    pass


@dataclass
class BatchResult:
    triaged: list[TriagedFinding]
    issues: list[str] = field(default_factory=list)


# ------------------------------------------------------------ API call

def _retry_after(err: Exception, attempt: int) -> float:
    """How long to wait after a 429. Groq sends a retry-after header;
    without one, back off 10s, 20s, 40s... capped at a minute."""
    try:
        value = float(err.response.headers.get("retry-after"))  # type: ignore[attr-defined]
    except (AttributeError, TypeError, ValueError):
        value = 10 * 2 ** attempt
    return min(max(value, 1.0), RATE_LIMIT_MAX_WAIT)


def _request(client: Groq, model: str, payload: list[dict]) -> str:
    """Call the API, waiting and retrying when Groq's rate limit is hit
    (free-tier limits are low and a big repo sends many batches)."""
    for attempt in range(RATE_LIMIT_RETRIES + 1):
        try:
            return _request_once(client, model, payload)
        except groq.RateLimitError as e:
            if attempt == RATE_LIMIT_RETRIES:
                raise RuntimeError(
                    "Groq rate limit still hit after several retries. Wait a few minutes and "
                    "re-run, or scan a smaller part of the repo."
                ) from e
            time.sleep(_retry_after(e, attempt))
    raise AssertionError("unreachable")


def _request_once(client: Groq, model: str, payload: list[dict]) -> str:
    """One API call. Returns the raw text, or raises TruncatedResponse /
    BadResponse so the caller can decide how to recover."""
    mode = _FORMAT_MODE.get(model, "schema")
    kwargs: dict = {}
    if mode == "schema":
        kwargs["response_format"] = RESPONSE_FORMAT
    elif mode == "json":
        kwargs["response_format"] = {"type": "json_object"}
    if "gpt-oss" in model:
        kwargs["reasoning_effort"] = "low"   # reasoning counts against max_tokens

    try:
        response = client.chat.completions.create(
            model=model,
            max_tokens=MAX_TOKENS,
            temperature=0,
            messages=[
                {"role": "system", "content": TRIAGE_SYSTEM_PROMPT_V2},
                {"role": "user", "content": build_user_message_v2(json.dumps(payload, indent=1))},
            ],
            **kwargs,
        )
    except groq.BadRequestError as e:
        msg = str(e).lower()
        if "json_validate_failed" in msg or "failed to generate json" in msg:
            # the model's output didn't match the schema (often because it ran out of tokens)
            raise BadResponse("model output failed schema validation on the API side")
        if mode != "none" and ("response_format" in msg or "json_schema" in msg or "not supported" in msg):
            _FORMAT_MODE[model] = "json" if mode == "schema" else "none"
            return _request_once(client, model, payload)
        raise

    choice = response.choices[0]
    if choice.finish_reason == "length":
        raise TruncatedResponse("response was cut off (hit max_tokens)")
    text = choice.message.content or ""
    if not text.strip():
        raise BadResponse("empty response")
    return text


# ----------------------------------------------------------- per batch

def _payload(batch: list[Finding], risks: dict[int, dict] | None) -> list[dict]:
    out = []
    for i, f in enumerate(batch):
        item = {
            "id": i,
            "tool": f.tool,
            "rule_id": f.rule_id,
            "path": f.path,
            "line": f.line,
            "message": f.message[:600],
            "raw_severity": f.raw_severity,
            "snippet": f.snippet[:500],
            "context": f.context[:1500],
        }
        if risks and id(f) in risks:
            item["risk"] = risks[id(f)]
        out.append(item)
    return out


def _fallback(f: Finding, why: str) -> TriagedFinding:
    return TriagedFinding(
        finding=f,
        severity=_FALLBACK_SEVERITY.get(f.raw_severity.upper(), "Medium"),
        is_false_positive=False,
        confidence="low",
        explanation=f"The AI didn't return a usable verdict ({why}), so this is kept for manual review.",
        fix_suggestion="Review manually.",
    )


def _to_triaged(f: Finding, v: Verdict, batch: list[Finding]) -> TriagedFinding:
    return TriagedFinding(
        finding=f,
        severity=v.severity or _FALLBACK_SEVERITY.get(f.raw_severity.upper(), "Medium"),
        is_false_positive=v.is_false_positive,
        confidence=v.confidence if v.severity else "low",
        explanation=v.explanation or "No explanation returned.",
        fix_suggestion=v.fix_suggestion or "Review manually.",
        duplicate_of=batch[v.duplicate_of].key() if v.duplicate_of is not None else None,
    )


def triage_batch(
    client: Groq,
    model: str,
    batch: list[Finding],
    risks: dict[int, dict] | None = None,
    _depth: int = 0,
) -> BatchResult:
    issues: list[str] = []
    verdicts: dict[int, Verdict] | None = None

    for attempt in (1, 2):
        try:
            text = _request(client, model, _payload(batch, risks))
            verdicts, found = validate_batch(extract_json(text), len(batch))
            issues += found
            break
        except TruncatedResponse as e:
            issues.append(f"{len(batch)} findings: {e}")
            if len(batch) > 1:
                # split and retry; smaller batches produce shorter answers
                mid = len(batch) // 2
                left = triage_batch(client, model, batch[:mid], risks, _depth + 1)
                right = triage_batch(client, model, batch[mid:], risks, _depth + 1)
                return BatchResult(left.triaged + right.triaged, issues + left.issues + right.issues)
            return BatchResult([_fallback(batch[0], "response truncated")], issues)
        except (BadResponse, ValueError) as e:
            issues.append(f"attempt {attempt}: {e}")
            if attempt == 2:
                if len(batch) > 1 and _depth < 3:
                    mid = len(batch) // 2
                    left = triage_batch(client, model, batch[:mid], risks, _depth + 1)
                    right = triage_batch(client, model, batch[mid:], risks, _depth + 1)
                    return BatchResult(left.triaged + right.triaged, issues + left.issues + right.issues)
                return BatchResult([_fallback(f, "invalid response") for f in batch], issues)

    assert verdicts is not None
    triaged: dict[int, TriagedFinding] = {i: _to_triaged(batch[i], v, batch) for i, v in verdicts.items()}

    missing = [i for i in range(len(batch)) if i not in triaged]
    if missing:
        issues.append(f"model skipped {len(missing)} of {len(batch)} findings")
        if len(missing) < len(batch) and _depth < 3:
            # ask again for just the skipped ones
            retry = triage_batch(client, model, [batch[i] for i in missing], risks, _depth + 1)
            issues += retry.issues
            for i, t in zip(missing, retry.triaged):
                triaged[i] = t
        else:
            for i in missing:
                triaged[i] = _fallback(batch[i], "no verdict returned")

    return BatchResult([triaged[i] for i in range(len(batch))], issues)


def triage_batches_validated(
    findings: list[Finding],
    model: str = DEFAULT_MODEL,
    risks: dict[int, dict] | None = None,
    api_key: str | None = None,
    client: Groq | None = None,
) -> Iterator[BatchResult]:
    """Yield one validated BatchResult per batch of BATCH_SIZE findings.

    `risks` maps id(finding) -> risk dict from the enrichment stage, so the
    model can use it in its explanations.
    """
    if not findings:
        return
    client = client or Groq(api_key=api_key or os.environ.get("GROQ_API_KEY"))
    for start in range(0, len(findings), BATCH_SIZE):
        yield triage_batch(client, model, findings[start:start + BATCH_SIZE], risks)

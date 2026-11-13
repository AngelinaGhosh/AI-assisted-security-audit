"""Two layers of protection for LLM triage output.

1. `RESPONSE_SCHEMA`: a strict JSON schema sent with the API call
   (`response_format`), so the model is constrained to produce exactly
   this shape. Strict mode needs a top-level *object*, so the verdicts
   live under a "findings" key instead of a bare array.

2. `Verdict` (Pydantic): validates and normalises every value in Python
   anyway, because schema enforcement isn't available on every model,
   and output can still come back truncated, re-cased, with quoted
   booleans or with missing fields. Anything we can't make sense of is
   recorded as an issue instead of silently accepted.
"""
import json
import re
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, ValidationError, field_validator

Severity = Literal["Critical", "High", "Medium", "Low", "Info"]
Confidence = Literal["low", "medium", "high"]

SEVERITIES: list[str] = ["Critical", "High", "Medium", "Low", "Info"]

RESPONSE_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "integer"},
                    "severity": {"type": "string", "enum": SEVERITIES},
                    "is_false_positive": {"type": "boolean"},
                    "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
                    "explanation": {"type": "string"},
                    "fix_suggestion": {"type": "string"},
                    "duplicate_of": {"type": ["integer", "null"]},
                },
                "required": [
                    "id", "severity", "is_false_positive", "confidence",
                    "explanation", "fix_suggestion", "duplicate_of",
                ],
                "additionalProperties": False,
            },
        }
    },
    "required": ["findings"],
    "additionalProperties": False,
}

RESPONSE_FORMAT: dict = {
    "type": "json_schema",
    "json_schema": {"name": "triage_verdicts", "strict": True, "schema": RESPONSE_SCHEMA},
}

# common things models say instead of the exact enum value
_SEVERITY_ALIASES = {
    "critical": "Critical", "crit": "Critical", "severe": "Critical",
    "high": "High", "important": "High", "major": "High",
    "medium": "Medium", "moderate": "Medium", "med": "Medium",
    "low": "Low", "minor": "Low",
    "info": "Info", "informational": "Info", "none": "Info", "note": "Info",
}
_CONFIDENCE_ALIASES = {"low": "low", "medium": "medium", "med": "medium", "moderate": "medium", "high": "high"}
_TRUE = {"true", "yes", "y", "1"}
_FALSE = {"false", "no", "n", "0", "", "null", "none"}

MAX_TEXT = 1200   # cap free text so a runaway model can't flood the report


class Verdict(BaseModel):
    """One validated LLM verdict. Construct with `Verdict.model_validate(raw)`."""
    model_config = ConfigDict(extra="ignore")

    id: int
    severity: Optional[Severity] = None          # None = model gave nothing usable
    is_false_positive: bool = False
    confidence: Confidence = "low"
    explanation: str = ""
    fix_suggestion: str = ""
    duplicate_of: Optional[int] = None

    @field_validator("id", mode="before")
    @classmethod
    def _id(cls, v: Any) -> int:
        if isinstance(v, bool):
            raise ValueError("id must be a number")
        if isinstance(v, str) and v.strip().lstrip("#").isdigit():
            return int(v.strip().lstrip("#"))
        if isinstance(v, float) and v.is_integer():
            return int(v)
        return v

    @field_validator("severity", mode="before")
    @classmethod
    def _severity(cls, v: Any) -> Optional[str]:
        if v is None:
            return None
        return _SEVERITY_ALIASES.get(str(v).strip().lower())

    @field_validator("confidence", mode="before")
    @classmethod
    def _confidence(cls, v: Any) -> str:
        return _CONFIDENCE_ALIASES.get(str(v).strip().lower(), "low") if v is not None else "low"

    @field_validator("is_false_positive", mode="before")
    @classmethod
    def _bool(cls, v: Any) -> bool:
        if isinstance(v, bool):
            return v
        if isinstance(v, (int, float)):
            return bool(v)
        s = str(v).strip().lower()
        if s in _TRUE:
            return True
        if s in _FALSE:
            return False
        return False   # unrecognised -> safest choice is to keep the finding

    @field_validator("explanation", "fix_suggestion", mode="before")
    @classmethod
    def _text(cls, v: Any) -> str:
        if v is None:
            return ""
        return str(v).strip()[:MAX_TEXT]

    @field_validator("duplicate_of", mode="before")
    @classmethod
    def _dup(cls, v: Any) -> Optional[int]:
        if v is None or isinstance(v, bool):
            return None
        if isinstance(v, str):
            s = v.strip().lstrip("#").lower()
            return int(s) if s.isdigit() else None
        if isinstance(v, float) and v.is_integer():
            return int(v)
        return v if isinstance(v, int) else None


def extract_json(text: str) -> Any:
    """Parse model output into Python data, tolerating markdown fences and
    stray prose around the JSON. Raises ValueError if nothing parses."""
    text = (text or "").strip()
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # fall back to the outermost {...} or [...] block, whichever starts first
    pairs = sorted((("{", "}"), ("[", "]")), key=lambda p: text.find(p[0]) if p[0] in text else len(text))
    for open_c, close_c in pairs:
        start, end = text.find(open_c), text.rfind(close_c)
        if start != -1 and end > start:
            try:
                return json.loads(text[start:end + 1])
            except json.JSONDecodeError:
                continue
    raise ValueError(f"no valid JSON in model output (starts: {text[:120]!r})")


def validate_batch(data: Any, batch_size: int) -> tuple[dict[int, Verdict], list[str]]:
    """Validate a parsed response against a batch of `batch_size` findings.

    Returns ({id: Verdict}, issues). Findings the model skipped are simply
    absent from the dict; the caller decides what to do with them.
    """
    issues: list[str] = []
    if isinstance(data, dict):
        items = data.get("findings")
        if items is None:
            # some models return {"0": {...}, "1": {...}} or a single object
            items = list(data.values()) if all(isinstance(v, dict) for v in data.values()) else [data]
            issues.append("response wasn't wrapped in a 'findings' list")
    else:
        items = data
    if not isinstance(items, list):
        return {}, ["response 'findings' is not a list"]

    verdicts: dict[int, Verdict] = {}
    for pos, raw in enumerate(items):
        if not isinstance(raw, dict):
            issues.append(f"item {pos} is not an object, ignored")
            continue
        try:
            v = Verdict.model_validate(raw)
        except ValidationError as e:
            issues.append(f"item {pos} rejected: {e.errors()[0]['msg']}")
            continue

        if not 0 <= v.id < batch_size:
            issues.append(f"item {pos} has id {v.id}, which isn't in this batch, ignored")
            continue
        if v.id in verdicts:
            issues.append(f"id {v.id} answered twice, kept the first answer")
            continue
        if raw.get("severity") is not None and v.severity is None:
            issues.append(f"id {v.id}: unknown severity {raw.get('severity')!r}")
        if v.duplicate_of is not None and not (0 <= v.duplicate_of < v.id):
            # must point at an *earlier* finding, which also rules out cycles
            issues.append(f"id {v.id}: invalid duplicate_of {v.duplicate_of}, ignored")
            v.duplicate_of = None
        verdicts[v.id] = v

    # a duplicate of a duplicate should point at the original
    for v in verdicts.values():
        seen = {v.id}
        while v.duplicate_of is not None and v.duplicate_of in verdicts:
            target = verdicts[v.duplicate_of]
            if target.duplicate_of is None or target.duplicate_of in seen:
                break
            seen.add(target.duplicate_of)
            v.duplicate_of = target.duplicate_of

    return verdicts, issues

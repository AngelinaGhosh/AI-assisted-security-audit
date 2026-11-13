"""Validation of LLM responses. A fake Groq client returns the kinds of
broken output real models produce, so this runs offline."""
import json
from types import SimpleNamespace

import groq
import httpx

from audit_agent.models import Finding
from audit_agent.triage import validated_triage
from audit_agent.triage.schema import RESPONSE_SCHEMA, extract_json, validate_batch


def make_findings(n):
    return [Finding("semgrep", f"rule-{i}", "app.py", i + 1, "msg", "ERROR") for i in range(n)]


class FakeClient:
    """Returns queued responses in order. Each is (text, finish_reason) or an exception."""
    def __init__(self, *responses):
        self.queue = list(responses)
        self.calls = []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create))

    def create(self, **kwargs):
        self.calls.append(kwargs)
        item = self.queue.pop(0)
        if isinstance(item, Exception):
            raise item
        text, finish = item if isinstance(item, tuple) else (item, "stop")
        return SimpleNamespace(choices=[SimpleNamespace(finish_reason=finish, message=SimpleNamespace(content=text))])


def verdict(i, **over):
    v = {"id": i, "severity": "High", "is_false_positive": False, "confidence": "high",
         "explanation": "x", "fix_suggestion": "y", "duplicate_of": None}
    v.update(over)
    return v


def ok(*vs):
    return json.dumps({"findings": list(vs)})


# ------------------------------------------------------- normalisation

def test_messy_values_are_normalised():
    data = {"findings": [
        {"id": "0", "severity": "HIGH", "is_false_positive": "false", "confidence": "Med",
         "explanation": "  x  ", "fix_suggestion": None, "duplicate_of": "null"},
        {"id": 1.0, "severity": "moderate", "is_false_positive": "True", "confidence": "HIGH", "duplicate_of": "0"},
        {"id": 2, "severity": "banana"},
    ]}
    v, issues = validate_batch(data, 3)
    assert v[0].severity == "High" and v[0].is_false_positive is False and v[0].confidence == "medium"
    assert v[0].explanation == "x" and v[0].fix_suggestion == "" and v[0].duplicate_of is None
    assert v[1].severity == "Medium" and v[1].is_false_positive is True and v[1].duplicate_of == 0
    assert v[2].severity is None and any("unknown severity" in i for i in issues)


def test_bad_ids_and_duplicates_are_rejected():
    data = [verdict(0), verdict(0), verdict(7), verdict(1, duplicate_of=1), verdict(2, duplicate_of=5), "junk"]
    v, issues = validate_batch(data, 3)
    assert set(v) == {0, 1, 2}
    assert v[1].duplicate_of is None and v[2].duplicate_of is None
    assert len(issues) == 5


def test_duplicate_chains_point_to_the_original():
    v, _ = validate_batch([verdict(0), verdict(1, duplicate_of=0), verdict(2, duplicate_of=1)], 3)
    assert v[2].duplicate_of == 0


def test_json_extraction_tolerates_fences_and_prose():
    assert extract_json('```json\n{"findings": []}\n```') == {"findings": []}
    assert extract_json('Sure! Here you go: [{"id": 0}] hope that helps') == [{"id": 0}]


def test_schema_is_strict_compatible():
    item = RESPONSE_SCHEMA["properties"]["findings"]["items"]
    assert item["additionalProperties"] is False
    assert set(item["required"]) == set(item["properties"])


# ------------------------------------------------------- recovery paths

def test_happy_path_sends_strict_schema():
    client = FakeClient(ok(verdict(0), verdict(1)))
    result = validated_triage.triage_batch(client, "openai/gpt-oss-120b", make_findings(2))
    assert [t.severity for t in result.triaged] == ["High", "High"]
    assert client.calls[0]["response_format"]["type"] == "json_schema"
    assert result.issues == []


def test_truncated_response_splits_the_batch():
    client = FakeClient(("{\"findings\": [", "length"), ok(verdict(0)), ok(verdict(0)))
    result = validated_triage.triage_batch(client, "m-trunc", make_findings(2))
    assert len(result.triaged) == 2 and all(t.confidence == "high" for t in result.triaged)
    assert any("cut off" in i for i in result.issues)


def test_invalid_json_retries_then_keeps_findings():
    client = FakeClient("not json", "still not json", ok(verdict(0)), ok(verdict(0)))
    result = validated_triage.triage_batch(client, "m-bad", make_findings(2))
    assert len(result.triaged) == 2


def test_skipped_findings_are_reasked_then_kept():
    client = FakeClient(ok(verdict(0)), ok())   # model skips #1 twice
    findings = make_findings(2)
    result = validated_triage.triage_batch(client, "m-skip", findings)
    assert len(result.triaged) == 2
    kept = result.triaged[1]
    assert kept.finding is findings[1] and kept.is_false_positive is False and kept.confidence == "low"


def test_unsupported_schema_falls_back_to_json_mode():
    req = httpx.Request("POST", "https://api.groq.com")
    err = groq.BadRequestError("response_format json_schema is not supported for this model",
                               response=httpx.Response(400, request=req), body=None)
    client = FakeClient(err, ok(verdict(0)))
    result = validated_triage.triage_batch(client, "m-noschema", make_findings(1))
    assert result.triaged[0].severity == "High"
    assert client.calls[1]["response_format"] == {"type": "json_object"}


def test_risk_context_reaches_the_prompt():
    client = FakeClient(ok(verdict(0)))
    f = make_findings(1)
    validated_triage.triage_batch(client, "m-risk", f, risks={id(f[0]): {"score": 91, "in_kev": True}})
    assert '"in_kev": true' in client.calls[0]["messages"][1]["content"]

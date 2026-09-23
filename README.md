# ThreatFlow

ThreatFlow is an AI-powered security triage tool. The name reflects how it works: a complete flow from scanning, to AI triage, to clear, actionable results.

## Problem Statement

Security scanners generate a lot of findings, but not every finding represents a real or equally serious vulnerability. Developers have to manually go through this noise, which takes time and can cause important vulnerabilities to be overlooked.

## Proposed Solution

ThreatFlow is an AI-powered security triage layer. First, the system runs security scanners such as Semgrep (for code) and pip-audit (for dependencies). The findings are then sent to an LLM, which helps identify duplicates, false positives, the actual severity, and possible fixes. The results are then displayed to the user in a simplified format, with every dismissed finding still visible for human review.


## How it works

```
target repo
   |
   |--> semgrep (static analysis)  --\
   |                                   >--> raw findings --> LLM triage --> markdown report
   |--> pip-audit (dependency CVEs) --/
```

- **Scanners** (`audit_agent/scanners/`) run the actual tools and parse
  their output into a common `Finding` format.
- **Triage** (`audit_agent/triage/`) batches findings and sends them to
  an LLM (Groq's `llama-3.3-70b-versatile` by default, free tier) with
  a prompt asking it to assign real severity, flag duplicates, flag
  likely false positives, and suggest a fix.
- **Report** (`audit_agent/report/`) takes the triaged findings and
  writes a markdown report grouped by severity, with the
  filtered-out stuff listed separately so nothing silently disappears.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # then put your GROQ_API_KEY in there
```

Groq's free tier is enough to run this - get a key at console.groq.com,
no card required at signup.

## Usage

```bash
python -m audit_agent.cli /path/to/target/repo
```

Options:
- `-o / --output` — where to write the report (default `audit_report.md`)
- `--model` — override the model used for triage
- `--skip-deps` — skip dependency scanning, semgrep only

Dependency scanning currently only picks up `requirements.txt`
(Python). If the target repo has a `package.json` instead, that part
is a no-op for now — see Known Limitations.

## Web UI (live demo)

```
uvicorn audit_agent.web.app:app --reload
```

Open http://127.0.0.1:8000, pick the built-in demo target or paste a public GitHub URL, and watch each stage and AI verdict stream in live (Server-Sent Events). Every successful live run is saved to `demo/recordings/last_run.json`, so if the network or API fails you can replay it (clearly labelled as a replay). `AUDIT_PACE=0` turns off the on-screen pacing of verdicts.

## Example

Running against a Flask app with an obvious SQL injection and a
pinned, vulnerable `requests` version produces something like:

```
## Critical
### sql-injection-string-format — app.py:42
User input goes straight into a SQL query string, classic injection point.
Suggested fix: use parameterized queries instead of string formatting.
```

vs. the raw Semgrep output, which just gives you a rule ID, a
generic message, and a severity label that doesn't account for
whether the input is actually attacker-controlled.

## Known limitations

- Dependency scanning is Python-only right now (`pip-audit`).
  Node/npm support is a natural next step.
- Triage quality depends on the model actually being given enough
  surrounding code — right now it only sees the flagged lines, not
  the full function. Worth revisiting if false-positive rates end up
  too high in practice.
- No caching between runs, so re-scanning an unchanged repo re-does
  the LLM triage from scratch. Fine for now, wasteful at scale.
- Only tested against small repos so far (a few hundred lines). Semgrep
  itself scales fine to bigger codebases, but batching + triage costs
  haven't been checked against anything large yet.

## Project structure

```
audit_agent/
  cli.py                     entry point
  models.py                  Finding / TriagedFinding dataclasses
  scanners/
    semgrep_scanner.py
    dependency_scanner.py
  triage/
    llm_triage.py
    prompts.py
  report/
    markdown_report.py
tests/
  fixtures/                  intentionally vulnerable sample code, used to sanity-check the scanners
```

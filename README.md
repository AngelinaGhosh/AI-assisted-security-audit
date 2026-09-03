# Security Audit Agent

A small CLI tool that runs static analysis (Semgrep) and dependency
vulnerability scanning (pip-audit) against a codebase, then uses an LLM
to clean up the results — merging duplicates, cutting obvious false
positives, ranking things by how bad they actually are, and writing a
plain-English report with suggested fixes.

The reason this exists: raw Semgrep output on any real codebase is
mostly noise. You get the same issue flagged five times, severities
that don't match real-world risk, and zero context on whether
something is actually exploitable or just pattern-matched code that
happens to look risky. This tool adds a triage step on top so what's
left is something you'd actually want to read.

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

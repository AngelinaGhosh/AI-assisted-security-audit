# ThreatFlow

ThreatFlow is an AI-powered security triage tool. The name reflects how it works: a complete flow from scanning, to risk scoring, to AI triage, to a short, prioritised list of real vulnerabilities, each with a fix.

## Problem Statement

Security scanners generate a lot of findings, but not every finding represents a real or equally serious vulnerability. Developers have to manually go through this noise, which takes time and can cause important vulnerabilities to be overlooked. Scanner severity labels also ignore context: whether a vulnerability is being exploited in the wild, whether the vulnerable code is even used, and whether it is reachable from the internet.

## Proposed Solution

ThreatFlow runs three kinds of scanners over a codebase: Semgrep (code), Gitleaks (committed secrets) and OSV-Scanner (vulnerable dependencies in any ecosystem). Every finding is then enriched with real risk data (CVSS, CISA KEV, EPSS, reachability and internet exposure) and given a risk score and priority. An LLM reviews the findings with that context to flag duplicates and false positives, explain each issue in plain English and suggest a fix. Every LLM response is validated before it is used. The result is a report ordered by risk, with every dismissed finding still visible for human review.

## How it works

```
target repo
   |
   |--> Semgrep (code)            --\
   |--> Gitleaks (secrets)          >--> raw findings --> mask secrets --> remove exact repeats
   |--> OSV-Scanner (dependencies) --/                                          |
                                                                         risk enrichment
                                                     CVSS · CISA KEV · EPSS · reachability · internet exposure
                                                                                |
                                                                   LLM triage (validated responses)
                                                                                |
                                                                 report ordered by risk (P1 to P4)
```

- **Scanners** (`audit_agent/scanners/`) run the tools and parse their output into a common `Finding` format.
  - **Semgrep** finds insecure code patterns.
  - **Gitleaks** finds API keys, passwords, tokens and private keys committed in source code. Secret values are masked (e.g. `sk-l…(40 chars)`) in every finding before anything is sent to the LLM, shown in the UI, recorded or written to the report.
  - **OSV-Scanner** finds vulnerable dependencies from lockfiles and manifests in JavaScript, Java, Go, Rust, PHP, Ruby, .NET, Python and more. Advisories that are the same bug under different IDs (GHSA, PYSEC, CVE) are merged into one finding. If OSV-Scanner isn't installed, the tool falls back to pip-audit (Python only).
- **Risk enrichment** (`audit_agent/enrichment/`) runs between scanning and the LLM and gives every finding a 0-100 risk score and a priority:

  | Signal | Source |
  |---|---|
  | CVSS severity | OSV-Scanner output |
  | CISA KEV status | CISA's Known Exploited Vulnerabilities feed (exploited in the wild) |
  | EPSS probability | FIRST.org EPSS API (chance of exploitation in the next 30 days) |
  | Dependency reachability | Is the vulnerable package actually imported? OSV call analysis for Go/Rust |
  | Internet exposure | Is the code inside a route handler, called from one, or in a server bound to `0.0.0.0` / a Dockerfile `EXPOSE`? |

  Priorities: **P1** fix now (80+), **P2** fix this sprint (60+), **P3** plan a fix (35+), **P4** backlog. Anything in CISA KEV stays at 70 or above. Each score comes with plain-English reasons, and the formula is documented at the top of `enrichment/risk.py`. KEV and EPSS data is cached for a day, and if a feed can't be reached, that signal is marked unknown instead of failing the scan.
- **Triage** (`audit_agent/triage/`) sends findings, with their risk data, to an LLM: Groq's `openai/gpt-oss-120b` by default, which runs on Groq's free tier. The model assigns a severity, flags duplicates and false positives, explains the issue and suggests a fix. Unused code is never marked a false positive; the risk score lowers its priority instead.
- **Response validation** (`triage/schema.py`, `triage/validated_triage.py`): the API call enforces a strict JSON schema, and every returned value is then validated in Python, because models can return different casing, quoted booleans, missing fields, invalid JSON or truncated output.
  - Values like `"HIGH"`, `"moderate"` and `"false"` are normalised.
  - Truncated responses are split into smaller batches and retried.
  - Invalid JSON is retried once.
  - Skipped findings are asked about again, then kept for manual review.
  - If Groq's rate limit is hit, the call waits and retries.
  - Every correction is listed in the report.
- **Report** (`audit_agent/report/`) writes a markdown report ordered by risk priority, showing the evidence behind each score, with the filtered-out findings listed separately so nothing silently disappears.

## Setup

You need Python and Git. On Windows (cmd):

```
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements-web.txt
copy .env.example .env
```

On macOS/Linux, use `source .venv/bin/activate` and `cp .env.example .env` instead.

Put your Groq API key in `.env` (`GROQ_API_KEY=gsk_...`). Groq's free tier is enough to run this: get a key at console.groq.com, no card required. `.env` is in `.gitignore`, so the key is never committed.

`requirements-web.txt` includes `requirements.txt` and adds pinned `fastapi`, `uvicorn`, `httpx`, `pytest` and `pydantic`. FastAPI is held at 0.141.1 because newer versions need a version of `opentelemetry-api` that conflicts with Semgrep's.

### Scanner binaries

OSV-Scanner and Gitleaks are standalone programs, not pip packages. Download them from their releases pages:

- OSV-Scanner: https://github.com/google/osv-scanner/releases (tested with v2.7.0)
- Gitleaks: https://github.com/gitleaks/gitleaks/releases (tested with v8.30.1)

Either put them on your `PATH`, or add their locations to `.env`:

```
OSV_SCANNER_PATH=C:\Users\<you>\tools\osv-scanner.exe
GITLEAKS_PATH=C:\Users\<you>\tools\gitleaks.exe
```

Both are optional: without OSV-Scanner, dependency scanning falls back to pip-audit (Python only), and without Gitleaks the secrets stage is skipped.

## Usage

```
python -m audit_agent.cli_v2 path\to\target\repo
```

Options:
- `-o / --output`: where to write the report (default `audit_report.md`)
- `--model`: override the model used for triage
- `--rules`: Semgrep config (default `auto`, the community rules)
- `--skip-deps`: skip dependency scanning
- `--skip-secrets`: skip Gitleaks
- `--no-enrich`: skip the risk-enrichment stage
- `--offline`: don't download KEV/EPSS data, use the cached copy only

To try it on the built-in demo app:

```
python -m audit_agent.cli_v2 demo\target --rules demo\rules.yaml
```

The original version (Semgrep + pip-audit + LLM triage, no enrichment) still works with `python -m audit_agent.cli`.

## Web UI (live demo)

```
uvicorn audit_agent.web.app_v2:app --reload
```

Open http://127.0.0.1:8000. Type `demo` to scan the built-in sample app, a local folder path, or a public GitHub URL. For a real repo, set the rules dropdown to **Semgrep community rules**; the demo rules only fit the demo app. The page shows which scanners are installed, and streams in live (Server-Sent Events):
- each of the six stages (code, secrets, dependencies, repeats, risk, AI review)
- each finding's risk score
- each AI verdict, with the evidence behind its score

Every successful live run is saved to `demo/recordings/last_run_v2.json`, so if the network or API fails you can replay it (clearly labelled as a replay). `AUDIT_PACE=0` turns off the on-screen pacing of verdicts, and `AUDIT_OFFLINE=1` uses cached KEV/EPSS data only.

The original web UI is still available with `uvicorn audit_agent.web.app:app --reload`.

## Example

Running against the demo Flask app (`demo/target`) turns 24 raw findings into a prioritised list. An excerpt:

```
## P1: fix now

### flask 0.12.0 (CVE-2018-1000656), requirements.txt
risk score: 88/100 · AI severity: High · confidence: high

| CVSS | In CISA KEV | EPSS | Reachability | Exposure |
|------|-------------|------|--------------|----------|
| 8.7  | no          | 3.9% | imported     | internet |

Why: CVSS 8.7; flask is imported by the code; app is internet-facing;
EPSS 4% chance of exploitation in 30 days (top 10%)
Suggested fix: Upgrade Flask to >=2.3.2.

### insecure-pickle-load, app.py:37
risk score: 85/100 · AI severity: Critical · confidence: high
Why: inside route handler `load_session()`, reachable by any HTTP request
Suggested fix: Replace pickle.loads with a safe format such as JSON.
```

The raw scanner output only gives a rule ID, a generic message and a severity label. It doesn't say whether the vulnerability is exploited in the wild, whether the code is used, or whether an attacker can reach it.

## Tests

```
python -m pytest
```

The tests run offline. Groq is replaced by a fake client that returns broken output on purpose to exercise the validation. KEV and EPSS data come from a temporary cache, and OSV output comes from a saved sample. The Gitleaks test runs the real binary when it's on `PATH`.

## Known limitations

- Reachability and internet exposure are text heuristics, strongest for Python and JS/TS. They don't build a full call graph, so they push obviously unused or internal code down the list rather than prove anything is safe.
- Gitleaks scans the current files only. GitHub repos are cloned with `--depth 1`, so secrets that were committed and later deleted from history aren't found.
- Groq's free tier allows 8,000 tokens per minute. Large repos produce many batches, so a scan slows down while it waits for the limit to reset, and a batch of very long findings can be too large for the limit.
- No caching of LLM results between runs, so re-scanning an unchanged repo re-does the triage from scratch.
- The AI can still misjudge a finding, which is why nothing is deleted: dismissed findings are listed at the end of the report for review.

## Project structure

```
audit_agent/
  cli.py                     original entry point
  cli_v2.py                  entry point with secrets, OSV, enrichment and validation
  pipeline.py                the v2 pipeline, shared by cli_v2 and web/app_v2
  models.py                  Finding / TriagedFinding dataclasses
  models_ext.py              DependencyFinding / RiskInfo
  scanners/
    semgrep_scanner.py
    semgrep_scanner_v2.py    UTF-8-safe on Windows (non-English text in repos)
    dependency_scanner.py    pip-audit (original)
    osv_scanner.py           OSV-Scanner, all ecosystems (pip-audit fallback)
    secret_scanner.py        Gitleaks + secret masking
  enrichment/
    codebase.py              one pass over the repo: imports, web frameworks
    feeds.py                 CISA KEV + EPSS, cached
    reachability.py
    exposure.py
    risk.py                  risk score and priority
  triage/
    llm_triage.py
    prompts.py
    prompts_v2.py
    schema.py                JSON schema + response validation
    validated_triage.py
  report/
    markdown_report.py
    markdown_report_v2.py
  web/
    app.py, app_v2.py
    static/index.html, static/index_v2.html
demo/
  target/                    sample vulnerable Flask app for the demo
  rules.yaml
docs/
  V2_CHANGES.md              detailed notes on the v2 changes
tests/
  fixtures/                  intentionally vulnerable sample code and a sample OSV report
```

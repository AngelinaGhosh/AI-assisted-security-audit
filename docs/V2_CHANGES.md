# ThreatFlow v2: what changed and how to run it

All changes are in **new files**. The original CLI (`audit_agent/cli.py`),
web app (`audit_agent/web/app.py`) and their tests are untouched and still
work. The new features run through new entry points:

```bash
python -m audit_agent.cli_v2 /path/to/repo            # CLI
uvicorn audit_agent.web.app_v2:app --reload            # web UI, http://127.0.0.1:8000
```

```
Semgrep (code) ----+
Gitleaks (secrets) +--> mask secrets --> exact dedupe --> risk enrichment --> validated LLM triage --> report
OSV-Scanner (deps) +                                      (CVSS, KEV, EPSS,
                                                           reachability, exposure)
```

## Setup

```bash
pip install -r requirements-web.txt
```

OSV-Scanner and Gitleaks are standalone binaries, not pip packages. Get
them from their GitHub releases pages and put them on your PATH:

- OSV-Scanner: https://github.com/google/osv-scanner/releases (tested with v2.7.0)
- Gitleaks: https://github.com/gitleaks/gitleaks/releases (tested with v8.30.1)

Or with Go installed:

```bash
go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest
go install github.com/zricethezav/gitleaks/v8@latest
```

If a binary isn't on PATH, point to it with `OSV_SCANNER_PATH` /
`GITLEAKS_PATH` in `.env`. Both are optional: without OSV-Scanner the tool
falls back to pip-audit (Python only), and without Gitleaks the secrets
stage is skipped. The web UI shows which tools it found.

## 1. Pinned web dependencies

`requirements-web.txt` includes `requirements.txt` and pins `fastapi`,
`uvicorn`, `httpx`, `pytest` and `pydantic`. FastAPI is held at 0.141.1:
0.142+ needs `opentelemetry-api>=1.44`, but Semgrep pins `~=1.37`, so the
newer FastAPI can't be installed alongside Semgrep. The full set was
installed into a clean environment and `pip check` was clean.

## 2. Multi-ecosystem dependency scanning (OSV-Scanner)

`audit_agent/scanners/osv_scanner.py` runs
`osv-scanner scan source -r --format json` over the repo. It finds lockfiles
and manifests by itself: npm/yarn/pnpm, Maven/Gradle, Go, Cargo, Composer,
Bundler, NuGet, pip/Poetry/Pipenv/uv and more.

- One finding per OSV *vulnerability group*, so GHSA-, PYSEC- and CVE-IDs
  for the same bug become one finding (fewer duplicates before the LLM).
- Keeps the CVSS score, every alias (needed for KEV/EPSS lookups), fixed
  versions, and OSV's call analysis for Go/Rust when available.
- New type `DependencyFinding` (in `models_ext.py`) carries this data.

## 3. Secret scanning (Gitleaks)

`audit_agent/scanners/secret_scanner.py` runs `gitleaks dir` with its
built-in rules (cloud keys, tokens, private keys, high-entropy strings...).

Secret values never leave the machine. Right after scanning, every secret
Gitleaks found is masked (e.g. `sk-l…(40 chars)`) in **all** findings,
including Semgrep's own "hardcoded key" findings, before anything is sent
to the LLM, streamed to the browser, recorded for replay or written to
the report. There's a test that checks all three.

## 4. Validated LLM responses

Two layers, in `audit_agent/triage/schema.py` and `validated_triage.py`:

1. **Schema enforced in the API call**: `response_format` with a strict JSON
   schema (enums for severity/confidence, every field required, no extra
   fields). If a model doesn't support it, the code falls back to JSON mode,
   then to plain text, and remembers that per model.
2. **Python validation of every value** (Pydantic), because output can still
   be wrong:

| Problem | Handling |
|---|---|
| `"HIGH"`, `"moderate"`, `"Med"` | normalised to `High` / `Medium` |
| `"false"`, `"yes"`, `1` | converted to real booleans |
| `"3"` or `3.0` as an id | converted to `3` |
| missing fields | safe defaults, finding kept |
| unknown severity | falls back to the scanner's severity, confidence `low` |
| invalid JSON / prose / code fences | tolerant parsing, then one retry |
| truncated output (`finish_reason == "length"`) | batch split in half and retried |
| skipped findings | re-asked once on their own, then kept for manual review |
| bad ids, self-duplicates, duplicate cycles | dropped or fixed |

Nothing is silently discarded. Every correction is reported: in the UI
("AI response problems fixed"), and in an "AI response validation" section
of the report.

## 5. Risk enrichment

New stage between scanning and the LLM, in `audit_agent/enrichment/`:

| Signal | Source | File |
|---|---|---|
| CVSS | OSV-Scanner output | `osv_scanner.py` |
| CISA KEV | CISA's free KEV JSON feed | `feeds.py` |
| EPSS | FIRST.org EPSS API (batched) | `feeds.py` |
| Dependency reachability | is the package imported? OSV call analysis for Go/Rust | `reachability.py` |
| Internet exposure | route handlers, callers of handlers, web framework, `0.0.0.0`, Dockerfile `EXPOSE` | `exposure.py` |

`risk.py` combines them into a 0-100 score and a priority:
**P1** fix now (≥80), **P2** this sprint (≥60), **P3** plan (≥35), **P4** backlog.
The formula is documented at the top of `risk.py`. In short: CVSS (or the
scanner's severity) is the base; KEV forces at least 90; EPSS adds up to 20;
then multipliers for reachability (e.g. not imported ×0.6, never called ×0.5)
and exposure (internal ×0.8). Each score comes with plain-English reasons.

The risk data is passed to the LLM, which uses it in its explanation. The
final report and UI are ordered by risk score, not by the AI's severity
alone.

KEV and EPSS responses are cached for a day in `~/.cache/threatflow`
(override with `THREATFLOW_CACHE`). If a feed can't be reached, the stale
cache is used, or that signal is marked unknown; the scan never fails
because of it. `--offline` (CLI) or `AUDIT_OFFLINE=1` (web) uses the cache
only.

**Limitations to be upfront about:** reachability and exposure are text
heuristics, strongest for Python and JS/TS. They don't build a full call
graph, so they're meant to push obviously-unused or internal code down the
list, not to prove something is safe.

## Tests

```bash
pytest tests/test_new_scanners.py tests/test_llm_validation.py tests/test_enrichment.py tests/test_pipeline_v2.py
```

30 tests. They run offline: Groq is replaced by a fake client that returns
broken output on purpose, KEV/EPSS come from a temporary cache, and OSV
output comes from `tests/fixtures/osv_sample.json`. The Gitleaks tests run
the real binary when it's installed.

## Check on your machine

These were built where osv.dev, CISA, FIRST and Groq weren't reachable, so
those four were tested against saved responses only. One live run confirms
them:

```bash
python -m audit_agent.cli_v2 demo/target --rules demo/rules.yaml
```

Check that the deps stage says `osv-scanner`, the "Data sources" section of
`audit_report.md` says KEV was downloaded and EPSS has scores, and there's
no "AI response validation" error about `response_format`.

## New files

```
requirements-web.txt
docs/V2_CHANGES.md
audit_agent/
  models_ext.py              DependencyFinding, RiskInfo
  pipeline.py                the v2 pipeline (used by CLI and web)
  cli_v2.py
  scanners/osv_scanner.py
  scanners/secret_scanner.py
  triage/schema.py           JSON schema + Pydantic validation
  triage/prompts_v2.py
  triage/validated_triage.py
  enrichment/__init__.py
  enrichment/codebase.py     one pass over the repo (imports, frameworks)
  enrichment/feeds.py        KEV + EPSS
  enrichment/reachability.py
  enrichment/exposure.py
  enrichment/risk.py         scoring
  report/markdown_report_v2.py
  web/app_v2.py
  web/static/index_v2.html
tests/
  test_new_scanners.py
  test_llm_validation.py
  test_enrichment.py
  test_pipeline_v2.py
  fixtures/osv_sample.json
```

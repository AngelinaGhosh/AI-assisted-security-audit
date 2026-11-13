"""v2 command line: code + secrets + all-ecosystem dependency scanning,
risk enrichment and validated AI triage.

    python -m audit_agent.cli_v2 /path/to/repo
"""
import argparse
import sys

from dotenv import load_dotenv

from audit_agent.pipeline import AuditRun
from audit_agent.report.markdown_report_v2 import build_report_v2
from audit_agent.triage.llm_triage import DEFAULT_MODEL

STAGE_NAMES = {
    "code": "Scanning code (Semgrep)", "secrets": "Scanning for secrets (Gitleaks)",
    "deps": "Checking dependencies", "dedupe": "Removing exact repeats",
    "enrich": "Enriching risk (CVSS, KEV, EPSS, reachability, exposure)", "ai": "AI triage",
}


def main():
    load_dotenv()
    p = argparse.ArgumentParser(description="Security audit with risk prioritisation and AI triage.")
    p.add_argument("target", help="Path to the repo/folder to scan")
    p.add_argument("-o", "--output", default="audit_report.md", help="Where to write the report")
    p.add_argument("--model", default=DEFAULT_MODEL, help="Groq model used for triage")
    p.add_argument("--rules", default="auto", help="Semgrep config (default: auto)")
    p.add_argument("--skip-deps", action="store_true", help="Skip dependency scanning")
    p.add_argument("--skip-secrets", action="store_true", help="Skip Gitleaks secret scanning")
    p.add_argument("--no-enrich", action="store_true", help="Skip the risk-enrichment stage")
    p.add_argument("--offline", action="store_true", help="Don't download KEV/EPSS, use cached data only")
    args = p.parse_args()

    run = AuditRun(
        args.target, rules=args.rules, deps=not args.skip_deps, secrets=not args.skip_secrets,
        enrich=not args.no_enrich, offline=args.offline, model=args.model,
    )
    try:
        for event, data in run.events():
            if event == "stage":
                name = STAGE_NAMES.get(data["stage"], data["stage"])
                if data["state"] == "active":
                    print(f"{name}...")
                elif data["state"] == "done":
                    extra = f" with {data['tool']}" if data.get("tool") else ""
                    print(f"  done{extra}: {data.get('count', 0)}")
                elif data["state"] == "skipped":
                    print(f"{name}: skipped {data.get('detail', '')}".rstrip())
            elif event == "batch":
                print(f"  batch {data['n']}/{data['total']} ({data['size']} findings)")
            elif event == "validation":
                print(f"  fixed {len(data['issues'])} problem(s) in the model's response")
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    if not run.findings:
        print("No findings. Nothing to report.")
        return

    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write(build_report_v2(run, args.target))
    s = run.summary()
    print(f"\n{s['raw']} raw findings -> {s['real']} real issues "
          + (", ".join(f"{k}: {v}" for k, v in s["by_priority"].items()) if s["by_priority"] else ""))
    print(f"Report written to {args.output}")


if __name__ == "__main__":
    main()

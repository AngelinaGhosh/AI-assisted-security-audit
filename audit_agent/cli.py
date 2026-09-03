import argparse
import sys

from dotenv import load_dotenv

from audit_agent.scanners.semgrep_scanner import run_semgrep
from audit_agent.scanners.dependency_scanner import run_dependency_scan
from audit_agent.triage.llm_triage import triage_findings
from audit_agent.report.markdown_report import build_report


def main():
    load_dotenv()

    parser = argparse.ArgumentParser(
        description="Run Semgrep + dependency scanning on a repo and get an AI-triaged audit report."
    )
    parser.add_argument("target", help="Path to the repo/folder to scan")
    parser.add_argument("-o", "--output", default="audit_report.md", help="Where to write the report")
    parser.add_argument("--model", default="llama-3.3-70b-versatile", help="Model to use for triage (Groq)")
    parser.add_argument("--skip-deps", action="store_true", help="Skip dependency scanning")
    args = parser.parse_args()

    print(f"Scanning {args.target} with semgrep...")
    findings = run_semgrep(args.target)
    print(f"  found {len(findings)} raw findings")

    if not args.skip_deps:
        print("Checking dependencies for known CVEs...")
        dep_findings = run_dependency_scan(args.target)
        print(f"  found {len(dep_findings)} dependency findings")
        findings += dep_findings

    if not findings:
        print("No findings. Nothing to triage.")
        sys.exit(0)

    print(f"Sending {len(findings)} findings to the LLM for triage...")
    triaged = triage_findings(findings, model=args.model)

    report = build_report(triaged, args.target, raw_count=len(findings))
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(report)

    print(f"Report written to {args.output}")


if __name__ == "__main__":
    main()

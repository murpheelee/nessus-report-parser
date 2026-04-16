#!/usr/bin/env python3
"""
Nessus Report Parser — CLI tool for parsing Nessus CSV exports
into prioritized remediation reports.

Supports modern RBVM (Risk-Based Vulnerability Management) workflows by
enriching findings with EPSS (exploit probability) and CISA KEV (known
exploited vulns) before scoring.

Author: Ryan Murphy
"""

import argparse
import sys
from pathlib import Path
from lib.parser import parse_nessus_csv
from lib.scorer import calculate_priority_scores
from lib.reporter import generate_report, generate_executive_summary
from lib.enrichment import enrich_findings


def main():
    parser = argparse.ArgumentParser(
        description="Parse Nessus CSV exports into prioritized remediation reports."
    )
    parser.add_argument(
        "files",
        nargs="+",
        help="One or more Nessus CSV export files to parse",
    )
    parser.add_argument(
        "--severity",
        type=str,
        default=None,
        help="Filter by severity levels (comma-separated: critical,high,medium,low)",
    )
    parser.add_argument(
        "--group-by",
        choices=["host", "severity", "family", "tier"],
        default="severity",
        help="Group findings by: host, severity, family, or RBVM tier (default: severity)",
    )
    parser.add_argument(
        "--format",
        choices=["table", "csv", "markdown"],
        default="table",
        help="Output format (default: table)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output file path (default: stdout)",
    )
    parser.add_argument(
        "--deduplicate",
        action="store_true",
        help="Remove duplicate findings across multiple scan files",
    )
    parser.add_argument(
        "--executive-summary",
        action="store_true",
        help="Generate executive summary with key metrics",
    )
    parser.add_argument(
        "--no-enrich",
        action="store_true",
        help="Skip EPSS + CISA KEV enrichment (offline mode)",
    )

    args = parser.parse_args()

    # Validate input files exist
    for file_path in args.files:
        if not Path(file_path).exists():
            print(f"Error: File not found: {file_path}", file=sys.stderr)
            sys.exit(1)

    # Parse all input files
    findings = []
    for file_path in args.files:
        parsed = parse_nessus_csv(file_path)
        findings.extend(parsed)
        print(f"[+] Parsed {len(parsed)} findings from {file_path}")

    if not findings:
        print("No findings to process.")
        sys.exit(0)

    # Deduplicate if requested
    if args.deduplicate:
        original_count = len(findings)
        seen = set()
        unique_findings = []
        for f in findings:
            key = (f["plugin_id"], f["host"], f["port"])
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)
        findings = unique_findings
        print(f"[+] Deduplicated: {original_count} -> {len(findings)} findings")

    # Filter by severity
    if args.severity:
        severity_filter = [s.strip().lower() for s in args.severity.split(",")]
        findings = [f for f in findings if f["severity"].lower() in severity_filter]
        print(f"[+] Filtered to {len(findings)} findings ({args.severity})")

    # Enrich with EPSS + KEV before scoring (so score reflects real-world risk)
    findings = enrich_findings(findings, offline=args.no_enrich)

    # Calculate priority scores
    findings = calculate_priority_scores(findings)

    # Generate output
    if args.executive_summary:
        output = generate_executive_summary(findings)
    else:
        output = generate_report(
            findings,
            group_by=args.group_by,
            output_format=args.format,
        )

    # Write output
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"[+] Report saved to {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()

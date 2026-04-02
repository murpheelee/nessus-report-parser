<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/Tenable%20Nessus-00C176?style=for-the-badge&logo=tenable&logoColor=white" alt="Nessus"/>
  <img src="https://img.shields.io/badge/CLI%20Tool-4EAA25?style=for-the-badge" alt="CLI"/>
</p>

# Nessus Report Parser

> **Command-line tool for parsing Nessus scan exports** — transforms raw CSV scan data into prioritized remediation reports with risk scoring, host grouping, and executive summary generation.

## Objective

Automate the most tedious part of vulnerability management: turning a Nessus scan export into an actionable remediation plan. This tool parses `.csv` exports, deduplicates findings, calculates risk-based priority scores, groups vulnerabilities by host and severity, and outputs clean reports ready for distribution to remediation teams.

## Features

- Parse Nessus `.csv` scan exports
- Risk-based priority scoring (CVSS + exploitability + asset criticality)
- Group findings by host, severity, or plugin family
- Filter by severity level (Critical, High, Medium, Low)
- Generate executive summary with key metrics
- Export to CSV or formatted markdown reports
- Deduplicate findings across multiple scan files

## Installation

```bash
git clone https://github.com/murpheelee/nessus-report-parser.git
cd nessus-report-parser
pip install -r requirements.txt
```

## Usage

```bash
# Parse a single scan file
python nessus_parser.py scan_results.csv

# Filter to Critical and High only
python nessus_parser.py scan_results.csv --severity critical,high

# Group by host
python nessus_parser.py scan_results.csv --group-by host

# Export as markdown report
python nessus_parser.py scan_results.csv --format markdown --output report.md

# Parse multiple scans and deduplicate
python nessus_parser.py scan1.csv scan2.csv --deduplicate

# Generate executive summary
python nessus_parser.py scan_results.csv --executive-summary
```

## Example Output

```
================================================================================
                    VULNERABILITY SCAN REPORT — EXECUTIVE SUMMARY
================================================================================

Scan Date:        2025-07-06
Total Hosts:      47
Total Findings:   312

Severity Breakdown:
  Critical:   12  (3.8%)   ████
  High:       45  (14.4%)  ██████████████
  Medium:     189 (60.6%)  ████████████████████████████████████████████████████
  Low:        66  (21.2%)  █████████████████████

Top 5 Critical Findings:
  1. [CVE-2017-0144] MS17-010: EternalBlue SMB RCE        — 8 hosts affected
  2. [CVE-2021-44228] Log4Shell Remote Code Execution      — 3 hosts affected
  3. [CVE-2019-0708] BlueKeep RDP RCE                      — 2 hosts affected
  4. [CVE-2014-3566] SSLv3 POODLE Vulnerability            — 11 hosts affected
  5. [CVE-2017-5754] Meltdown Speculative Execution        — 6 hosts affected

Recommended Priority:
  1. Patch MS17-010 across 8 affected hosts (Critical — exploit available)
  2. Update Log4j to 2.17.1+ on 3 application servers (Critical — actively exploited)
  3. Patch RDP on 2 exposed hosts (Critical — wormable)
================================================================================
```

## Project Structure

```
nessus-report-parser/
├── nessus_parser.py          # Main CLI entry point
├── lib/
│   ├── parser.py             # CSV parsing and data normalization
│   ├── scorer.py             # Risk-based priority scoring engine
│   ├── reporter.py           # Report generation (CSV, Markdown)
│   └── utils.py              # Helper functions
├── requirements.txt
└── README.md
```

## How It Works

```
Nessus CSV Export → Parse & Normalize → Deduplicate → Score & Prioritize → Group → Generate Report
```

1. **Parse** — Read Nessus CSV export, normalize column names and data types
2. **Deduplicate** — Remove duplicate findings across multiple scan files
3. **Score** — Calculate priority score based on CVSS base score, exploit availability, and affected host count
4. **Group** — Organize findings by host, severity, or plugin family
5. **Report** — Generate formatted output (terminal, CSV, or Markdown)

## Key Skills Demonstrated

- Python scripting for security automation
- Nessus scan data processing and analysis
- Risk-based vulnerability prioritization
- CLI tool development with argparse
- Security reporting and executive communication

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/Tenable%20Nessus-00C176?style=for-the-badge&logo=tenable&logoColor=white" alt="Nessus"/>
  <img src="https://img.shields.io/badge/EPSS-FIRST.org-FF6600?style=for-the-badge" alt="EPSS"/>
  <img src="https://img.shields.io/badge/CISA%20KEV-Enriched-DC3545?style=for-the-badge" alt="KEV"/>
  <img src="https://img.shields.io/badge/CLI%20Tool-4EAA25?style=for-the-badge" alt="CLI"/>
</p>

# Nessus Report Parser

> **Risk-based vulnerability management CLI** — parses Nessus CSV exports, enriches findings with **EPSS** (exploit probability) and **CISA KEV** (known-exploited catalog), and produces prioritized P0-P3 remediation reports.

## Why This Exists

Traditional Nessus triage sorts by CVSS and stops there. CVSS tells you how *bad* a vulnerability *could* be in theory — it doesn't tell you whether anyone is *actually* exploiting it. Mature vulnerability management programs layer two public datasets on top of CVSS:

- **CISA KEV** — vulns confirmed exploited in the wild (patch within mandated 72h for federal; most enterprises match)
- **EPSS** — FIRST.org's daily-updated probability that a CVE will be exploited in the next 30 days

This tool automates that enrichment and produces a prioritized remediation plan that reflects real-world risk, not just theoretical severity.

## Features

- Parse Nessus `.csv` scan exports
- **Auto-enrich with EPSS scores** (FIRST.org public API, bulk-fetched)
- **Auto-enrich with CISA KEV membership** (live feed from cisa.gov)
- **Assign RBVM priority tiers** (P0-P3) that outrank CVSS-only sorting
- Group findings by host, severity, plugin family, or priority tier
- Filter by severity level (Critical, High, Medium, Low)
- Deduplicate findings across multiple scan files
- Generate executive summary with KEV + EPSS callouts
- Export to CSV or formatted Markdown reports
- `--no-enrich` flag for airgapped / offline environments

## Installation

```bash
git clone https://github.com/murpheelee/nessus-report-parser.git
cd nessus-report-parser
pip install -r requirements.txt
```

No third-party HTTP dependencies — EPSS + KEV fetches use the Python standard library.

## Usage

```bash
# Parse a single scan (auto-enriches with EPSS + KEV by default)
python nessus_parser.py scan_results.csv

# Group output by RBVM priority tier (P0 -> P1 -> P2 -> P3)
python nessus_parser.py scan_results.csv --group-by tier

# Filter to Critical and High only
python nessus_parser.py scan_results.csv --severity critical,high

# Executive summary with KEV + EPSS callouts
python nessus_parser.py scan_results.csv --executive-summary

# Export enriched data as CSV for SIEM / dashboard ingestion
python nessus_parser.py scan_results.csv --format csv --output enriched.csv

# Parse multiple scans and deduplicate
python nessus_parser.py scan1.csv scan2.csv --deduplicate

# Offline mode (skip EPSS + KEV fetch)
python nessus_parser.py scan_results.csv --no-enrich
```

## Priority Tier Logic

| Tier | Criteria | SLA (example) |
|------|----------|---------------|
| **P0** | CISA KEV listed (actively exploited) | 72 hours |
| **P1** | EPSS &ge; 0.50, OR CVSS &ge; 9.0 with public exploit | 7 days |
| **P2** | EPSS &ge; 0.10, OR High severity | 30 days |
| **P3** | Everything else | 90 days / next cycle |

KEV dominates — a CVSS 7.0 vuln in KEV out-prioritizes a CVSS 9.8 with no known exploitation. That is the entire point of RBVM.

## Example Output

```
================================================================================
              VULNERABILITY SCAN REPORT — EXECUTIVE SUMMARY
================================================================================

Total Hosts:      47
Total Findings:   312
CISA KEV:         8  (actively exploited)
High EPSS (>=0.5): 14  (likely exploited within 30 days)

Severity Breakdown:
  Critical       12  ( 3.8%)  ████
  High           45  (14.4%)  ██████████████
  Medium        189  (60.6%)  ████████████████████████████████████████████████████
  Low            66  (21.2%)  █████████████████████

RBVM Priority Tier:
  P0:    8  KEV-listed — actively exploited, patch within 72h
  P1:   14  Urgent — high EPSS or critical+exploit, patch within 7d
  P2:   57  Standard — elevated risk, patch within 30d
  P3:  233  Planned — patch on regular cycle

Top 10 Findings by Priority Score:
   1. [P0] CVE-2021-44228 [KEV] Apache Log4j RCE (Log4Shell)          EPSS=0.974  hosts=3
   2. [P0] CVE-2017-0144  [KEV] MS17-010 EternalBlue SMB RCE          EPSS=0.961  hosts=8
   3. [P0] CVE-2019-0708  [KEV] BlueKeep RDP RCE                      EPSS=0.940  hosts=2
   4. [P0] CVE-2023-4966  [KEV] Citrix Bleed (session hijack)         EPSS=0.921  hosts=1
   5. [P1] CVE-2024-21887       Ivanti Connect Secure RCE             EPSS=0.856  hosts=2
   ...
================================================================================
```

## How It Works

```
Nessus CSV → Parse → Extract CVEs → Fetch EPSS (bulk) → Fetch KEV → Score → Group → Report
                                          │                    │
                                  api.first.org/epss    cisa.gov KEV feed
```

1. **Parse** — Read Nessus CSV export, normalize columns, drop informational findings
2. **Extract CVEs** — Regex-extract every CVE id from the Nessus CVE field (often comma-separated)
3. **Enrich** — Batch-fetch EPSS scores (chunked at 100 CVEs/request) and the full CISA KEV catalog
4. **Score** — Calculate RBVM priority: KEV bonus (+15) > EPSS bonus (0-10) > severity > CVSS > spread
5. **Tier** — Assign P0-P3 based on KEV / EPSS / CVSS thresholds
6. **Report** — Output in terminal, CSV, or Markdown, optionally grouped by tier

## Project Structure

```
nessus-report-parser/
├── nessus_parser.py          # CLI entry point
├── lib/
│   ├── parser.py             # CSV parsing and normalization
│   ├── enrichment.py         # EPSS + CISA KEV enrichment
│   ├── scorer.py             # RBVM priority scoring engine
│   ├── reporter.py           # Report generation (table, CSV, Markdown)
│   └── utils.py              # Helper functions
├── requirements.txt
└── README.md
```

## Data Sources

- **EPSS** — [FIRST.org EPSS API](https://www.first.org/epss/api) (updated daily)
- **CISA KEV** — [Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (updated as new vulns are observed)

Both data sources are free, public, and require no API key.

## Key Skills Demonstrated

- **Modern RBVM** — EPSS + KEV enrichment replacing CVSS-only prioritization
- **Python CLI development** — argparse, modular `lib/` layout, stdlib-only HTTP
- **Security data integration** — bulk API consumption, resilient error handling
- **Risk-based scoring** — weighted model combining exploit likelihood and severity
- **Executive reporting** — summary-level metrics and technical remediation output
- **Practical VM operations** — P0-P3 tiers mapped to realistic remediation SLAs

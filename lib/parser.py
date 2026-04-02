"""Parse Nessus CSV export files into normalized finding dictionaries."""

import csv
from pathlib import Path


# Standard Nessus CSV column mapping
COLUMN_MAP = {
    "Plugin ID": "plugin_id",
    "CVE": "cve",
    "CVSS v2.0 Base Score": "cvss_v2",
    "CVSS v3.0 Base Score": "cvss_v3",
    "Risk": "severity",
    "Host": "host",
    "Protocol": "protocol",
    "Port": "port",
    "Name": "name",
    "Synopsis": "synopsis",
    "Description": "description",
    "Solution": "solution",
    "Plugin Output": "plugin_output",
    "Exploit Available": "exploit_available",
    "Plugin Family": "family",
}


def parse_nessus_csv(file_path: str) -> list[dict]:
    """Parse a Nessus CSV export and return normalized findings."""
    findings = []
    path = Path(file_path)

    with path.open("r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            finding = {}
            for csv_col, key in COLUMN_MAP.items():
                finding[key] = row.get(csv_col, "").strip()

            # Skip informational findings (no risk)
            if not finding["severity"] or finding["severity"].lower() == "none":
                continue

            # Normalize data types
            finding["plugin_id"] = int(finding["plugin_id"]) if finding["plugin_id"] else 0
            finding["port"] = int(finding["port"]) if finding["port"] else 0
            finding["cvss_v2"] = float(finding["cvss_v2"]) if finding["cvss_v2"] else 0.0
            finding["cvss_v3"] = float(finding["cvss_v3"]) if finding["cvss_v3"] else 0.0
            finding["exploit_available"] = finding["exploit_available"].lower() == "true"

            findings.append(finding)

    return findings

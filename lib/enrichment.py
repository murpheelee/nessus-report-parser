"""
Threat-intelligence enrichment for Nessus findings.

Enriches raw scan output with:
  - EPSS (Exploit Prediction Scoring System) probabilities from FIRST.org
  - CISA KEV (Known Exploited Vulnerabilities) membership
  - Derived RBVM priority tier (P0-P3) based on all of the above

This is how modern risk-based vulnerability management (RBVM) teams prioritize —
CVSS alone overcounts because it measures potential severity, not real-world
likelihood of exploitation. EPSS gives a 30-day exploit probability; KEV flags
vulns CISA has observed being exploited in the wild.
"""

import json
import re
from typing import Iterable
from urllib.request import urlopen, Request


EPSS_API = "https://api.first.org/data/v1/epss"
KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
)


def _extract_cves(cve_field: str) -> list[str]:
    """Nessus CVE fields can be comma/space separated. Pull out every CVE id."""
    if not cve_field:
        return []
    return [m.group(0).upper() for m in CVE_RE.finditer(cve_field)]


def _http_get_json(url: str, timeout: int = 15) -> dict:
    # CISA and FIRST.org both reject requests without a reasonable User-Agent.
    # We also set Accept so servers that content-negotiate return JSON cleanly.
    req = Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
        },
    )
    with urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def fetch_kev_catalog() -> set[str]:
    """Download CISA's KEV catalog and return the set of CVE IDs it contains."""
    try:
        data = _http_get_json(KEV_FEED)
        return {entry["cveID"].upper() for entry in data.get("vulnerabilities", [])}
    except Exception as e:
        print(f"[!] KEV fetch failed ({e}); continuing without KEV enrichment.")
        return set()


def fetch_epss_scores(cves: Iterable[str]) -> dict[str, dict]:
    """
    Fetch EPSS scores for a batch of CVEs.

    Returns a dict keyed by CVE id:
        {"CVE-2021-44228": {"epss": 0.97531, "percentile": 0.99998}, ...}

    FIRST.org's API accepts comma-separated CVE lists; we chunk to stay under
    URL length limits (~100 CVEs per request).
    """
    unique_cves = sorted({c.upper() for c in cves if c})
    if not unique_cves:
        return {}

    results: dict[str, dict] = {}
    chunk_size = 100
    for i in range(0, len(unique_cves), chunk_size):
        chunk = unique_cves[i : i + chunk_size]
        url = f"{EPSS_API}?cve={','.join(chunk)}"
        try:
            data = _http_get_json(url)
            for row in data.get("data", []):
                results[row["cve"].upper()] = {
                    "epss": float(row.get("epss", 0.0)),
                    "percentile": float(row.get("percentile", 0.0)),
                }
        except Exception as e:
            print(f"[!] EPSS fetch failed for chunk {i // chunk_size + 1}: {e}")
            continue

    return results


def enrich_findings(findings: list[dict], offline: bool = False) -> list[dict]:
    """
    Add EPSS + KEV fields to each finding in place.

    New fields per finding:
        - cves:            list of CVE ids parsed from the Nessus CVE field
        - kev:             True if any associated CVE is in CISA KEV
        - epss:            max EPSS probability across associated CVEs (0.0-1.0)
        - epss_percentile: corresponding percentile (0.0-1.0)
        - rbvm_tier:       "P0" / "P1" / "P2" / "P3" — see _compute_tier()
    """
    # Build full CVE set up front for a single bulk EPSS fetch.
    all_cves: set[str] = set()
    for f in findings:
        cves = _extract_cves(f.get("cve", ""))
        f["cves"] = cves
        all_cves.update(cves)

    if offline:
        kev_set: set[str] = set()
        epss_map: dict[str, dict] = {}
    else:
        print(f"[+] Enriching {len(findings)} findings with EPSS + KEV "
              f"({len(all_cves)} unique CVEs)...")
        kev_set = fetch_kev_catalog()
        epss_map = fetch_epss_scores(all_cves)

    for f in findings:
        cves = f["cves"]
        f["kev"] = any(c in kev_set for c in cves)

        # Take the max EPSS across all CVEs associated with this finding.
        epss_scores = [epss_map[c]["epss"] for c in cves if c in epss_map]
        epss_percentiles = [epss_map[c]["percentile"] for c in cves if c in epss_map]
        f["epss"] = max(epss_scores) if epss_scores else 0.0
        f["epss_percentile"] = max(epss_percentiles) if epss_percentiles else 0.0

        f["rbvm_tier"] = _compute_tier(f)

    return findings


def _compute_tier(finding: dict) -> str:
    """
    Risk-based VM tier:
        P0 — Critical: KEV-listed (actively exploited, patch now)
        P1 — Urgent:   EPSS >= 0.50 OR (CVSS >= 9.0 AND exploit_available)
        P2 — Standard: EPSS >= 0.10 OR High severity
        P3 — Planned:  Everything else

    This matches the emphasis of real-world RBVM programs: exploit likelihood
    first (KEV, then EPSS), severity second. Traditional CVSS-only prioritization
    over-rotates on theoretical severity.
    """
    cvss = max(finding.get("cvss_v2", 0.0), finding.get("cvss_v3", 0.0))
    epss = finding.get("epss", 0.0)
    severity = finding.get("severity", "").lower()
    exploit = finding.get("exploit_available", False)

    if finding.get("kev"):
        return "P0"
    if epss >= 0.50 or (cvss >= 9.0 and exploit):
        return "P1"
    if epss >= 0.10 or severity == "high":
        return "P2"
    return "P3"

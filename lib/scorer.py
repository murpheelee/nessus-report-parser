"""Risk-based priority scoring for vulnerability findings."""


SEVERITY_WEIGHTS = {
    "critical": 10,
    "high": 8,
    "medium": 5,
    "low": 2,
}


def calculate_priority_scores(findings: list[dict]) -> list[dict]:
    """
    Calculate a priority score for each finding using RBVM principles.

    Signal, highest to lowest:
      1. CISA KEV membership       +15  (actively exploited in the wild)
      2. EPSS probability          +0-10 (exploit likely in next 30 days)
      3. Exploit available         +3   (public exploit known)
      4. CVSS base score           0-10
      5. Severity weight           2-10
      6. Spread across hosts       +0-5 (environmental impact)

    KEV dominates — a KEV-listed CVE with CVSS 7.0 still out-prioritizes
    a CVSS 9.8 with no known exploitation. This mirrors how mature VM
    programs actually triage.
    """
    # Count hosts affected per plugin_id for spread scoring.
    plugin_host_count: dict[int, set] = {}
    for f in findings:
        pid = f["plugin_id"]
        plugin_host_count.setdefault(pid, set()).add(f["host"])

    for f in findings:
        severity_score = SEVERITY_WEIGHTS.get(f["severity"].lower(), 0)
        cvss_score = max(f.get("cvss_v2", 0.0), f.get("cvss_v3", 0.0))
        exploit_bonus = 3 if f.get("exploit_available") else 0
        host_count = len(plugin_host_count.get(f["plugin_id"], set()))
        spread_bonus = min(host_count, 5)

        kev_bonus = 15 if f.get("kev") else 0
        epss_bonus = f.get("epss", 0.0) * 10  # 0.0-1.0 -> 0-10

        f["priority_score"] = (
            kev_bonus
            + epss_bonus
            + severity_score
            + cvss_score
            + exploit_bonus
            + spread_bonus
        )
        f["hosts_affected"] = host_count

    findings.sort(key=lambda x: x["priority_score"], reverse=True)
    return findings

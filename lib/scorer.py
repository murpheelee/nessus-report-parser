"""Risk-based priority scoring for vulnerability findings."""


SEVERITY_WEIGHTS = {
    "critical": 10,
    "high": 8,
    "medium": 5,
    "low": 2,
}


def calculate_priority_scores(findings: list[dict]) -> list[dict]:
    """Calculate a priority score for each finding based on multiple factors."""
    # Count hosts affected per plugin_id for impact scoring
    plugin_host_count: dict[int, set] = {}
    for f in findings:
        pid = f["plugin_id"]
        if pid not in plugin_host_count:
            plugin_host_count[pid] = set()
        plugin_host_count[pid].add(f["host"])

    for f in findings:
        severity_score = SEVERITY_WEIGHTS.get(f["severity"].lower(), 0)
        cvss_score = max(f["cvss_v2"], f["cvss_v3"])
        exploit_bonus = 3 if f["exploit_available"] else 0
        host_count = len(plugin_host_count.get(f["plugin_id"], set()))
        spread_bonus = min(host_count, 5)  # Cap at 5

        f["priority_score"] = severity_score + cvss_score + exploit_bonus + spread_bonus
        f["hosts_affected"] = host_count

    # Sort by priority score descending
    findings.sort(key=lambda x: x["priority_score"], reverse=True)
    return findings

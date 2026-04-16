"""Report generation for vulnerability findings."""

from collections import Counter


TIER_ORDER = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}


def generate_executive_summary(findings: list[dict]) -> str:
    """Generate an executive summary of scan findings."""
    severity_counts = Counter(f["severity"].capitalize() for f in findings)
    tier_counts = Counter(f.get("rbvm_tier", "P3") for f in findings)
    unique_hosts = len(set(f["host"] for f in findings))
    total = len(findings)
    kev_count = sum(1 for f in findings if f.get("kev"))
    high_epss_count = sum(1 for f in findings if f.get("epss", 0) >= 0.5)

    max_bar = 50
    max_count = max(severity_counts.values()) if severity_counts else 1

    lines = []
    lines.append("=" * 80)
    lines.append("              VULNERABILITY SCAN REPORT - EXECUTIVE SUMMARY")
    lines.append("=" * 80)
    lines.append("")
    lines.append(f"Total Hosts:      {unique_hosts}")
    lines.append(f"Total Findings:   {total}")
    lines.append(f"CISA KEV:         {kev_count}  (actively exploited)")
    lines.append(f"High EPSS (>=0.5): {high_epss_count}  (likely exploited within 30 days)")
    lines.append("")
    lines.append("Severity Breakdown:")

    for sev in ["Critical", "High", "Medium", "Low"]:
        count = severity_counts.get(sev, 0)
        pct = (count / total * 100) if total > 0 else 0
        bar_len = int((count / max_count) * max_bar) if max_count > 0 else 0
        bar = "#" * bar_len
        lines.append(f"  {sev:<12} {count:>4}  ({pct:>5.1f}%)  {bar}")

    lines.append("")
    lines.append("RBVM Priority Tier:")
    tier_descriptions = {
        "P0": "KEV-listed - actively exploited, patch within 72h",
        "P1": "Urgent - high EPSS or critical+exploit, patch within 7d",
        "P2": "Standard - elevated risk, patch within 30d",
        "P3": "Planned - patch on regular cycle",
    }
    for tier in ["P0", "P1", "P2", "P3"]:
        count = tier_counts.get(tier, 0)
        lines.append(f"  {tier}: {count:>4}  {tier_descriptions[tier]}")

    # Top findings by priority score
    lines.append("")
    lines.append("Top 10 Findings by Priority Score:")
    for i, f in enumerate(findings[:10], 1):
        cve = f["cves"][0] if f.get("cves") else "No CVE"
        kev = " [KEV]" if f.get("kev") else ""
        epss_str = f"EPSS={f.get('epss', 0.0):.3f}"
        name_trunc = f["name"][:45]
        lines.append(
            f"  {i:>2}. [{f.get('rbvm_tier', '?'):>2}] {cve:<16}{kev:<6} "
            f"{name_trunc:<45} {epss_str}  hosts={f['hosts_affected']}"
        )

    lines.append("")
    lines.append("=" * 80)
    return "\n".join(lines)


def generate_report(
    findings: list[dict],
    group_by: str = "severity",
    output_format: str = "table",
) -> str:
    """Generate a formatted report of findings."""
    if output_format == "csv":
        return _format_csv(findings)
    elif output_format == "markdown":
        return _format_markdown(findings, group_by)
    else:
        return _format_table(findings, group_by)


def _format_table(findings: list[dict], group_by: str) -> str:
    """Format findings as a text table."""
    groups = _group_findings(findings, group_by)
    lines = []
    for group_name, group_findings in groups.items():
        lines.append(f"\n{'=' * 100}")
        lines.append(f"  {group_name} ({len(group_findings)} findings)")
        lines.append(f"{'=' * 100}")
        lines.append(
            f"  {'Tier':<5} {'Plugin':<8} {'CVE':<16} {'KEV':<5} "
            f"{'EPSS':<8} {'Name':<40} {'Hosts':<6} {'Score':<6}"
        )
        lines.append(f"  {'-' * 4:<5} {'-' * 6:<8} {'-' * 14:<16} {'-' * 3:<5} "
                     f"{'-' * 6:<8} {'-' * 38:<40} {'-' * 4:<6} {'-' * 4:<6}")
        for f in group_findings[:20]:
            cve = (f["cves"][0] if f.get("cves") else "N/A")[:14]
            kev = "YES" if f.get("kev") else "-"
            epss = f"{f.get('epss', 0.0):.3f}"
            name = f["name"][:38]
            tier = f.get("rbvm_tier", "-")
            lines.append(
                f"  {tier:<5} {f['plugin_id']:<8} {cve:<16} {kev:<5} "
                f"{epss:<8} {name:<40} {f['hosts_affected']:<6} {f['priority_score']:<6.1f}"
            )
    return "\n".join(lines)


def _format_markdown(findings: list[dict], group_by: str) -> str:
    """Format findings as a Markdown report."""
    groups = _group_findings(findings, group_by)
    lines = ["# Vulnerability Remediation Report\n"]
    for group_name, group_findings in groups.items():
        lines.append(f"## {group_name} ({len(group_findings)} findings)\n")
        lines.append("| Tier | Plugin ID | CVE | KEV | EPSS | Name | Hosts | Priority |")
        lines.append("|------|-----------|-----|-----|------|------|-------|----------|")
        for f in group_findings:
            cve = f["cves"][0] if f.get("cves") else "N/A"
            kev = "Yes" if f.get("kev") else "No"
            epss = f"{f.get('epss', 0.0):.3f}"
            tier = f.get("rbvm_tier", "-")
            name = f["name"][:60]
            lines.append(
                f"| {tier} | {f['plugin_id']} | {cve} | {kev} | {epss} | "
                f"{name} | {f['hosts_affected']} | {f['priority_score']:.1f} |"
            )
        lines.append("")
    return "\n".join(lines)


def _format_csv(findings: list[dict]) -> str:
    """Format findings as CSV."""
    headers = (
        "Tier,Plugin ID,CVE,KEV,EPSS,EPSS Percentile,Severity,Name,Host,Port,"
        "CVSS,Exploit Available,Priority Score,Hosts Affected"
    )
    lines = [headers]
    for f in findings:
        cve = f["cves"][0] if f.get("cves") else ""
        lines.append(
            f"{f.get('rbvm_tier', '')},{f['plugin_id']},{cve},"
            f"{f.get('kev', False)},{f.get('epss', 0.0):.4f},"
            f"{f.get('epss_percentile', 0.0):.4f},{f['severity']},"
            f"\"{f['name']}\",{f['host']},{f['port']},"
            f"{max(f.get('cvss_v2', 0.0), f.get('cvss_v3', 0.0))},"
            f"{f['exploit_available']},{f['priority_score']:.1f},{f['hosts_affected']}"
        )
    return "\n".join(lines)


def _group_findings(findings: list[dict], group_by: str) -> dict:
    """Group findings by the specified field."""
    groups: dict[str, list] = {}
    for f in findings:
        if group_by == "host":
            key = f["host"]
        elif group_by == "family":
            key = f["family"] or "Unknown"
        elif group_by == "tier":
            key = f.get("rbvm_tier", "P3")
        else:
            key = f["severity"].capitalize()
        groups.setdefault(key, []).append(f)

    if group_by == "severity":
        order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        groups = dict(sorted(groups.items(), key=lambda x: order.get(x[0], 99)))
    elif group_by == "tier":
        groups = dict(sorted(groups.items(), key=lambda x: TIER_ORDER.get(x[0], 99)))

    return groups

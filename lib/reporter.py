"""Report generation for vulnerability findings."""

from collections import Counter


def generate_executive_summary(findings: list[dict]) -> str:
    """Generate an executive summary of scan findings."""
    severity_counts = Counter(f["severity"].capitalize() for f in findings)
    unique_hosts = len(set(f["host"] for f in findings))
    total = len(findings)

    # Build severity bar chart
    max_bar = 50
    max_count = max(severity_counts.values()) if severity_counts else 1

    lines = []
    lines.append("=" * 80)
    lines.append("              VULNERABILITY SCAN REPORT — EXECUTIVE SUMMARY")
    lines.append("=" * 80)
    lines.append("")
    lines.append(f"Total Hosts:      {unique_hosts}")
    lines.append(f"Total Findings:   {total}")
    lines.append("")
    lines.append("Severity Breakdown:")

    for sev in ["Critical", "High", "Medium", "Low"]:
        count = severity_counts.get(sev, 0)
        pct = (count / total * 100) if total > 0 else 0
        bar_len = int((count / max_count) * max_bar) if max_count > 0 else 0
        bar = "\u2588" * bar_len
        lines.append(f"  {sev:<12} {count:>4}  ({pct:>5.1f}%)  {bar}")

    # Top critical findings
    critical_findings = [f for f in findings if f["severity"].lower() == "critical"]
    if critical_findings:
        lines.append("")
        lines.append(f"Top Critical Findings (showing up to 5):")
        seen_plugins = set()
        count = 0
        for f in critical_findings:
            if f["plugin_id"] in seen_plugins:
                continue
            seen_plugins.add(f["plugin_id"])
            count += 1
            cve = f["cve"] if f["cve"] else "No CVE"
            lines.append(
                f"  {count}. [{cve}] {f['name'][:55]:<55} — {f['hosts_affected']} host(s)"
            )
            if count >= 5:
                break

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
        lines.append(f"\n{'=' * 80}")
        lines.append(f"  {group_name} ({len(group_findings)} findings)")
        lines.append(f"{'=' * 80}")
        lines.append(f"  {'Plugin ID':<12} {'CVE':<20} {'Name':<35} {'Hosts':<6} {'Score':<6}")
        lines.append(f"  {'-' * 10:<12} {'-' * 18:<20} {'-' * 33:<35} {'-' * 4:<6} {'-' * 4:<6}")
        for f in group_findings[:20]:
            cve = f["cve"][:18] if f["cve"] else "N/A"
            name = f["name"][:33]
            lines.append(
                f"  {f['plugin_id']:<12} {cve:<20} {name:<35} {f['hosts_affected']:<6} {f['priority_score']:<6.1f}"
            )
    return "\n".join(lines)


def _format_markdown(findings: list[dict], group_by: str) -> str:
    """Format findings as a Markdown report."""
    groups = _group_findings(findings, group_by)
    lines = ["# Vulnerability Remediation Report\n"]
    for group_name, group_findings in groups.items():
        lines.append(f"## {group_name} ({len(group_findings)} findings)\n")
        lines.append("| Plugin ID | CVE | Name | Hosts | Priority |")
        lines.append("|-----------|-----|------|-------|----------|")
        for f in group_findings:
            cve = f["cve"] if f["cve"] else "N/A"
            lines.append(
                f"| {f['plugin_id']} | {cve} | {f['name'][:50]} | {f['hosts_affected']} | {f['priority_score']:.1f} |"
            )
        lines.append("")
    return "\n".join(lines)


def _format_csv(findings: list[dict]) -> str:
    """Format findings as CSV."""
    headers = "Plugin ID,CVE,Severity,Name,Host,Port,CVSS,Exploit Available,Priority Score,Hosts Affected"
    lines = [headers]
    for f in findings:
        lines.append(
            f"{f['plugin_id']},{f['cve']},{f['severity']},\"{f['name']}\","
            f"{f['host']},{f['port']},{max(f['cvss_v2'], f['cvss_v3'])},"
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
        else:
            key = f["severity"].capitalize()
        if key not in groups:
            groups[key] = []
        groups[key].append(f)

    # Sort groups by severity order if grouping by severity
    if group_by == "severity":
        order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        groups = dict(sorted(groups.items(), key=lambda x: order.get(x[0], 99)))

    return groups

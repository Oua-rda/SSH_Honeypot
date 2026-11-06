from datetime import datetime, timezone


def build_report(s: dict, filters: dict, latest_alerts: list) -> str:
    o = s["overview"]
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    period = f"{filters.get('start') or 'beginning'} to {filters.get('end') or 'now'}"
    lines = [
        "# SSH Sentinel - Summary Report",
        "",
        f"- Generated: {now}",
        f"- Period: {period}",
        f"- Source IP filter: {filters.get('ip') or 'all'}",
        "",
        "## Overview",
        f"- Total SSH connections: {o['total_connections']}",
        f"- Failed login attempts: {o['failed_logins']}",
        f"- Successful simulated logins: {o['successful_logins']}",
        f"- Unique source IPs: {o['unique_ips']}",
        f"- Source IPs with at least one alert: {o['detected_attacks']}",
        f"- Alerts generated: {o['total_alerts']}",
        "",
        "## Top source IPs",
    ]
    if s["top_ips"]:
        lines += ["| IP | Failed logins | Events | First seen | Last seen | Max severity |",
                  "|---|---|---|---|---|---|"]
        for i in s["top_ips"]:
            lines.append(f"| {i['source_ip']} | {i['failed_logins']} | {i['events']} | "
                         f"{i['first_seen']} | {i['last_seen']} | {i['max_severity']} |")
    else:
        lines.append("No activity recorded.")

    lines += ["", "## Most targeted usernames"]
    lines += [f"- {u['username']}: {u['count']}" for u in s["top_usernames"]] or ["None."]

    lines += ["", "## Most common passwords (masked)"]
    lines += [f"- {p['password_masked']}: {p['count']}" for p in s["top_passwords"]] or ["None."]

    lines += ["", "## Alerts by severity"]
    lines += [f"- {k}: {v}" for k, v in s["alerts"]["by_severity"].items()] or ["None."]
    lines += ["", "## Alerts by type"]
    lines += [f"- {k}: {v}" for k, v in s["alerts"]["by_type"].items()] or ["None."]

    lines += ["", "## Latest alerts"]
    for a in latest_alerts:
        lines.append(f"- [{a['severity']}] {a['alert_type']} from {a['source_ip']} "
                     f"at {a['created_at']} (status: {a['status']})")
    if not latest_alerts:
        lines.append("None.")

    lines += ["", "---",
              "Note: alerts are threshold-based signals for investigation, "
              "not proof of compromise. Passwords are shown masked only."]
    return "\n".join(lines) + "\n"
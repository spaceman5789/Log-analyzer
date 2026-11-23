"""Summary report: event statistics plus alerts. Text for humans, JSON for a SIEM."""

from __future__ import annotations

import json
from collections import Counter
from typing import Any

from log_analyzer.alerting import format_alert_text
from log_analyzer.models import Alert, Event, EventType


def plural(n: int, one: str, many: str) -> str:
    return one if n == 1 else many


def num(n: int) -> str:
    return f"{n:,}"


def sort_alerts(alerts: list[Alert]) -> list[Alert]:
    return sorted(alerts, key=lambda a: (-a.severity.value, a.first_seen))


def build_summary(
    events: list[Event], alerts: list[Alert], allowlisted: int = 0, top_n: int = 5
) -> dict[str, Any]:
    """events must already exclude the allowlist."""
    by_type = Counter(e.type.value for e in events)
    failed = [e for e in events if e.type is EventType.FAILED]
    accepted = [e for e in events if e.type is EventType.ACCEPTED]
    times = [e.time for e in events]

    attacking: set[str] = set()
    for a in alerts:
        attacking.update(a.ips)

    return {
        "events_total": len(events),
        "events_by_type": {t.value: by_type.get(t.value, 0) for t in EventType},
        "allowlisted_events": allowlisted,
        "time_range": (
            {"start": min(times).isoformat(), "end": max(times).isoformat()} if times else None
        ),
        "unique_ips": len({e.ip for e in events}),
        "attacking_ips": sorted(attacking),
        "top_failed_ips": Counter(e.ip for e in failed).most_common(top_n),
        "top_failed_users": Counter(e.user for e in failed).most_common(top_n),
        "successful_logins": [
            {"time": e.time.isoformat(), "ip": e.ip, "user": e.user, "method": e.method}
            for e in accepted
        ],
        "alerts_by_severity": dict(Counter(a.severity.name for a in alerts)),
    }


def render_text(
    summary: dict[str, Any], alerts: list[Alert], color: bool = False, sent: int | None = None
) -> str:
    out: list[str] = []
    for a in sort_alerts(alerts):
        out.append(format_alert_text(a, color))
        out.append("")
    if not alerts:
        out.append("No alerts: no signs of an attack found.\n")

    def section(title: str) -> None:
        out.append(f"=== {title} ===")

    section("Events by type")
    for name, count in summary["events_by_type"].items():
        out.append(f"  {name:<15} {num(count)}")
    if summary["allowlisted_events"]:
        out.append(f"  {'allowlist':<15} {num(summary['allowlisted_events'])} (skipped)")
    tr = summary["time_range"]
    if tr:
        out.append(f"  period: {tr['start'].replace('T', ' ')} – {tr['end'].replace('T', ' ')}")

    section("Top IPs by failed attempts")
    for ip, count in summary["top_failed_ips"] or [("—", 0)]:
        out.append(f"  {ip:<40} {num(count)}")

    section("Top targeted usernames")
    for user, count in summary["top_failed_users"] or [("—", 0)]:
        out.append(f"  {user or '<empty>':<40} {num(count)}")

    logins = summary["successful_logins"]
    section(f"Successful logins ({len(logins)})")
    for item in logins[-10:]:
        out.append(
            f"  {item['time'].replace('T', ' ')}  {item['user']} from {item['ip']} "
            f"({item['method']})"
        )
    if len(logins) > 10:
        out.append(f"  … showing the last 10 of {len(logins)}")

    n_ev, n_ip, n_al = summary["events_total"], len(summary["attacking_ips"]), len(alerts)
    total = (
        f"\nTotal: {num(n_ev)} {plural(n_ev, 'event', 'events')}, "
        f"{n_ip} {plural(n_ip, 'attacking IP', 'attacking IPs')}, "
        f"{n_al} {plural(n_al, 'alert', 'alerts')}"
    )
    if sent is not None:
        total += f", sent to Telegram: {sent}"
    out.append(total)
    return "\n".join(out)


def render_json(summary: dict[str, Any], alerts: list[Alert], sent: int | None = None) -> str:
    doc = {
        "summary": summary,
        "alerts": [a.to_dict() for a in sort_alerts(alerts)],
        "telegram_sent": sent,
    }
    return json.dumps(doc, ensure_ascii=False, indent=2)

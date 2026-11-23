"""Сводный отчёт: статистика по событиям + список алертов. Текст для человека, JSON для SIEM."""

from __future__ import annotations

import json
from collections import Counter
from typing import Any

from log_analyzer.alerting import format_alert_text
from log_analyzer.models import Alert, Event, EventType


def plural(n: int, one: str, few: str, many: str) -> str:
    if n % 10 == 1 and n % 100 != 11:
        return one
    if 2 <= n % 10 <= 4 and not 12 <= n % 100 <= 14:
        return few
    return many


def num(n: int) -> str:
    return f"{n:,}".replace(",", " ")


def sort_alerts(alerts: list[Alert]) -> list[Alert]:
    return sorted(alerts, key=lambda a: (-a.severity.value, a.first_seen))


def build_summary(
    events: list[Event], alerts: list[Alert], allowlisted: int = 0, top_n: int = 5
) -> dict[str, Any]:
    """events — уже без allowlist."""
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
        out.append("Алертов нет — признаков атаки не найдено.\n")

    def section(title: str) -> None:
        out.append(f"=== {title} ===")

    section("События по типам")
    for name, count in summary["events_by_type"].items():
        out.append(f"  {name:<15} {num(count)}")
    if summary["allowlisted_events"]:
        out.append(f"  {'allowlist':<15} {num(summary['allowlisted_events'])} (пропущено)")
    tr = summary["time_range"]
    if tr:
        out.append(f"  период: {tr['start'].replace('T', ' ')} – {tr['end'].replace('T', ' ')}")

    section("Топ IP по неудачным попыткам")
    for ip, count in summary["top_failed_ips"] or [("—", 0)]:
        out.append(f"  {ip:<40} {num(count)}")

    section("Топ перебираемых логинов")
    for user, count in summary["top_failed_users"] or [("—", 0)]:
        out.append(f"  {user or '<пусто>':<40} {num(count)}")

    logins = summary["successful_logins"]
    section(f"Успешные входы ({len(logins)})")
    for item in logins[-10:]:
        out.append(
            f"  {item['time'].replace('T', ' ')}  {item['user']} с {item['ip']} ({item['method']})"
        )
    if len(logins) > 10:
        out.append(f"  … показаны последние 10 из {len(logins)}")

    n_ev, n_ip, n_al = summary["events_total"], len(summary["attacking_ips"]), len(alerts)
    total = (
        f"\nИтого: {num(n_ev)} {plural(n_ev, 'событие', 'события', 'событий')}, "
        f"{n_ip} {plural(n_ip, 'атакующий IP', 'атакующих IP', 'атакующих IP')}, "
        f"{n_al} {plural(n_al, 'алерт', 'алерта', 'алертов')}"
    )
    if sent is not None:
        total += f", отправлено в Telegram: {sent}"
    out.append(total)
    return "\n".join(out)


def render_json(summary: dict[str, Any], alerts: list[Alert], sent: int | None = None) -> str:
    doc = {
        "summary": summary,
        "alerts": [a.to_dict() for a in sort_alerts(alerts)],
        "telegram_sent": sent,
    }
    return json.dumps(doc, ensure_ascii=False, indent=2)

"""Форматирование алертов (терминал / Telegram) и отправка в Telegram Bot API.

Хороший алерт отвечает на вопросы: что случилось, где, когда, насколько серьёзно,
что делать дальше. Ровно эти блоки и собираются ниже.
"""

from __future__ import annotations

import html
import json
import logging
import os
import time
import urllib.error
import urllib.request
from collections import Counter
from collections.abc import Callable
from typing import Any

from log_analyzer.models import Alert, Severity

log = logging.getLogger(__name__)

TELEGRAM_LIMIT = 4096

ANSI = {
    Severity.CRITICAL: "\033[1;97;41m",
    Severity.HIGH: "\033[1;91m",
    Severity.MEDIUM: "\033[1;33m",
    Severity.LOW: "\033[36m",
}
RESET = "\033[0m"
EMOJI = {Severity.CRITICAL: "🚨", Severity.HIGH: "🔴", Severity.MEDIUM: "🟠", Severity.LOW: "🟡"}

COUNT_LABEL = {
    "bruteforce": "Неудачных попыток",
    "success_after_fail": "Неудачных попыток до входа",
    "spraying": "Попыток",
    "distributed": "Неудачных попыток",
    "scan": "Событий",
}

SCOPE_LABEL = {
    "public": "публичный",
    "private": "ВНУТРЕННИЙ (проверить хост-источник!)",
    "documentation": "TEST-NET (демо)",
    "loopback": "loopback",
    "reserved": "зарезервированный",
}


class AlertingError(RuntimeError):
    pass


# --- Текст -----------------------------------------------------------------------


def human_duration(seconds: float) -> str:
    s = int(seconds)
    if s < 60:
        return f"{s} с"
    if s < 3600:
        return f"{s // 60} мин" + (f" {s % 60} с" if s % 60 and s < 600 else "")
    return f"{s // 3600} ч {s % 3600 // 60} мин"


def top(counter: Counter[str], n: int = 5) -> str:
    items = counter.most_common(n)
    text = ", ".join(f"{k or '<пусто>'}({v})" for k, v in items)
    rest = len(counter) - len(items)
    return text + (f" … и ещё {rest}" if rest > 0 else "")


def time_range(a: Alert) -> str:
    start = a.first_seen.strftime("%Y-%m-%d %H:%M:%S")
    fmt = "%H:%M:%S" if a.first_seen.date() == a.last_seen.date() else "%Y-%m-%d %H:%M:%S"
    return f"{start} – {a.last_seen.strftime(fmt)}"


def enrichment_line(a: Alert) -> str | None:
    parts = []
    items = list(a.enrichment.items())
    for ip, info in items[:3]:
        bits = [SCOPE_LABEL.get(info.get("scope", ""), info.get("scope", ""))]
        if info.get("country"):
            bits.append(info["country"] + (f"/{info['city']}" if info.get("city") else ""))
        if info.get("blocklisted"):
            bits.append("в blocklist")
        parts.append(f"{ip}: {', '.join(b for b in bits if b)}")
    if len(items) > 3:
        parts.append(f"… ещё {len(items) - 3} IP (полный контекст в --format json)")
    return "; ".join(parts) if parts else None


def alert_lines(a: Alert) -> list[str]:
    """Тело алерта без заголовка — общий источник для терминала и Telegram."""
    lines = []
    where = f"   хост: {a.host}" if a.host else ""
    if a.rule == "distributed":
        lines.append(f"Логин: {a.key}   IP-адресов: {len(a.ips)}{where}")
        lines.append(f"IP: {top(a.ips)}")
    elif a.rule == "success_after_fail":
        lines.append(f"IP: {a.ip}   вошёл как: {a.compromised_user}{where}")
    else:
        lines.append(f"IP: {a.ip}{where}")

    label = COUNT_LABEL.get(a.rule, "Событий")
    lines.append(f"{label}: {a.count} за {human_duration(a.duration_seconds)} ({time_range(a)})")
    if a.users and a.rule != "distributed":
        lines.append(f"Логины: {top(a.users)}")
    lines.extend(a.details)
    ctx = enrichment_line(a)
    if ctx:
        lines.append(f"Контекст: {ctx}")
    lines.append(f"MITRE ATT&CK: {', '.join(a.mitre_labels())}")
    lines.append(f"Что делать: {a.recommendation}")
    return lines


def format_alert_text(a: Alert, color: bool = False) -> str:
    tag = f"[{a.severity.name}]"
    if color:
        tag = f"{ANSI[a.severity]}{tag}{RESET}"
    body = "\n".join("  " + line for line in alert_lines(a))
    return f"{tag} {a.title}\n{body}"


def format_alert_html(a: Alert) -> str:
    head = f"{EMOJI[a.severity]} <b>[{a.severity.name}] {html.escape(a.title)}</b>"
    body = "\n".join(html.escape(line) for line in alert_lines(a))
    text = f"{head}\n{body}"
    if len(text) > TELEGRAM_LIMIT:
        text = text[: TELEGRAM_LIMIT - 1] + "…"
    return text


# --- Telegram ---------------------------------------------------------------------

Opener = Callable[..., Any]


class TelegramNotifier:
    """Отправка через Bot API. Токен берётся из окружения и никогда не логируется."""

    API = "https://api.telegram.org/bot{token}/sendMessage"

    def __init__(
        self,
        token: str,
        chat_id: str,
        timeout: int = 10,
        opener: Opener = urllib.request.urlopen,
        sleep: Callable[[float], None] = time.sleep,
    ):
        if not token or not chat_id:
            raise AlertingError("нужны TG_BOT_TOKEN и TG_CHAT_ID")
        self._token = token
        self.chat_id = chat_id
        self.timeout = timeout
        self._open = opener
        self._sleep = sleep

    def __repr__(self) -> str:  # чтобы токен не утёк в трейсбек/лог
        return f"TelegramNotifier(chat_id={self.chat_id!r}, token=***)"

    @classmethod
    def from_env(cls, timeout: int = 10) -> TelegramNotifier:
        token = os.environ.get("TG_BOT_TOKEN", "")
        chat_id = os.environ.get("TG_CHAT_ID", "")
        if not token or not chat_id:
            raise AlertingError(
                "не заданы TG_BOT_TOKEN / TG_CHAT_ID (переменные окружения или .env)"
            )
        return cls(token, chat_id, timeout)

    def send_text(self, text: str, _retry: bool = True) -> None:
        payload = {
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }
        req = urllib.request.Request(
            self.API.format(token=self._token),
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            # URL фиксированный https://api.telegram.org, схема не управляется извне
            with self._open(req, timeout=self.timeout) as resp:  # nosec B310
                resp.read()
        except urllib.error.HTTPError as e:
            body = _safe_body(e)
            if e.code == 429 and _retry:  # flood control: подождать, сколько просит Telegram
                retry_after = min(int(body.get("parameters", {}).get("retry_after", 5)), 60)
                log.warning("Telegram 429, повтор через %s с", retry_after)
                self._sleep(retry_after)
                return self.send_text(text, _retry=False)
            desc = body.get("description", e.reason)
            raise AlertingError(f"Telegram API {e.code}: {desc}") from None
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            reason = getattr(e, "reason", e)
            raise AlertingError(f"Telegram недоступен: {reason}") from None

    def send_alert(self, alert: Alert) -> None:
        self.send_text(format_alert_html(alert))


def _safe_body(e: urllib.error.HTTPError) -> dict[str, Any]:
    try:
        data = json.loads(e.read().decode("utf-8", errors="replace"))
        return data if isinstance(data, dict) else {}
    except (ValueError, OSError):
        return {}

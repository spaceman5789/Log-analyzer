"""Alert formatting (terminal / Telegram) and delivery via the Telegram Bot API.

A good alert answers: what happened, where, when, how bad,
and what to do next. Those are exactly the blocks built below.
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
    "bruteforce": "Failed attempts",
    "success_after_fail": "Failed attempts before login",
    "spraying": "Attempts",
    "distributed": "Failed attempts",
    "scan": "Events",
}

SCOPE_LABEL = {
    "public": "public",
    "private": "INTERNAL (check the source host!)",
    "documentation": "TEST-NET (demo)",
    "loopback": "loopback",
    "reserved": "reserved",
}


class AlertingError(RuntimeError):
    pass


# --- Text ------------------------------------------------------------------------


def human_duration(seconds: float) -> str:
    s = int(seconds)
    if s < 60:
        return f"{s} s"
    if s < 3600:
        return f"{s // 60} min" + (f" {s % 60} s" if s % 60 and s < 600 else "")
    return f"{s // 3600} h {s % 3600 // 60} min"


def top(counter: Counter[str], n: int = 5) -> str:
    items = counter.most_common(n)
    text = ", ".join(f"{k or '<empty>'}({v})" for k, v in items)
    rest = len(counter) - len(items)
    return text + (f" … and {rest} more" if rest > 0 else "")


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
            bits.append("on blocklist")
        parts.append(f"{ip}: {', '.join(b for b in bits if b)}")
    if len(items) > 3:
        parts.append(f"… {len(items) - 3} more IPs (full context in --format json)")
    return "; ".join(parts) if parts else None


def alert_lines(a: Alert) -> list[str]:
    """Alert body without the title, shared by the terminal and Telegram."""
    lines = []
    where = f"   host: {a.host}" if a.host else ""
    if a.rule == "distributed":
        lines.append(f"Username: {a.key}   IPs: {len(a.ips)}{where}")
        lines.append(f"IP: {top(a.ips)}")
    elif a.rule == "success_after_fail":
        lines.append(f"IP: {a.ip}   logged in as: {a.compromised_user}{where}")
    else:
        lines.append(f"IP: {a.ip}{where}")

    label = COUNT_LABEL.get(a.rule, "Events")
    lines.append(f"{label}: {a.count} in {human_duration(a.duration_seconds)} ({time_range(a)})")
    if a.users and a.rule != "distributed":
        lines.append(f"Usernames: {top(a.users)}")
    lines.extend(a.details)
    ctx = enrichment_line(a)
    if ctx:
        lines.append(f"Context: {ctx}")
    lines.append(f"MITRE ATT&CK: {', '.join(a.mitre_labels())}")
    lines.append(f"What to do: {a.recommendation}")
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
    """Sends via the Bot API. The token comes from the environment and is never logged."""

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
            raise AlertingError("TG_BOT_TOKEN and TG_CHAT_ID are required")
        self._token = token
        self.chat_id = chat_id
        self.timeout = timeout
        self._open = opener
        self._sleep = sleep

    def __repr__(self) -> str:  # keep the token out of tracebacks/logs
        return f"TelegramNotifier(chat_id={self.chat_id!r}, token=***)"

    @classmethod
    def from_env(cls, timeout: int = 10) -> TelegramNotifier:
        token = os.environ.get("TG_BOT_TOKEN", "")
        chat_id = os.environ.get("TG_CHAT_ID", "")
        if not token or not chat_id:
            raise AlertingError(
                "TG_BOT_TOKEN / TG_CHAT_ID are not set (environment variables or .env)"
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
            # fixed URL https://api.telegram.org, the scheme is not user-controlled
            with self._open(req, timeout=self.timeout) as resp:  # nosec B310
                resp.read()
        except urllib.error.HTTPError as e:
            body = _safe_body(e)
            if e.code == 429 and _retry:  # flood control: wait as long as Telegram asks
                retry_after = min(int(body.get("parameters", {}).get("retry_after", 5)), 60)
                log.warning("Telegram 429, retrying in %s s", retry_after)
                self._sleep(retry_after)
                return self.send_text(text, _retry=False)
            desc = body.get("description", e.reason)
            raise AlertingError(f"Telegram API {e.code}: {desc}") from None
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            reason = getattr(e, "reason", e)
            raise AlertingError(f"Telegram unreachable: {reason}") from None

    def send_alert(self, alert: Alert) -> None:
        self.send_text(format_alert_html(alert))


def _safe_body(e: urllib.error.HTTPError) -> dict[str, Any]:
    try:
        data = json.loads(e.read().decode("utf-8", errors="replace"))
        return data if isinstance(data, dict) else {}
    except (ValueError, OSError):
        return {}

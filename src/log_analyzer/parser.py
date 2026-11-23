"""Парсер логов аутентификации SSH.

Понимает:
* классический syslog:      ``Nov 12 03:11:42 srv sshd[1234]: ...`` (без года!)
* syslog с ISO 8601:        ``2026-11-12T03:11:42.123+04:00 srv sshd[1234]: ...``
* s6-log / docker-логи:     ``2026-11-12 03:11:42.123456789  ...`` (linuxserver/openssh-server)
* journalctl -o json:       по одной JSON-записи на строку
* ротированные ``.gz``-файлы и ``-`` (stdin)
* ``message repeated N times: [ ... ]`` — rsyslog схлопывает одинаковые строки,
  без разворачивания такие атаки недосчитываются в N раз.
"""

from __future__ import annotations

import gzip
import ipaddress
import json
import re
import sys
from collections.abc import Iterable, Iterator
from datetime import datetime, timedelta
from typing import IO

from log_analyzer.models import Event, EventType

# --- Шаблоны сообщений sshd ------------------------------------------------

_IP = r"(?P<ip>[0-9a-fA-F:.]+)"

# Считаем неудачей только подбор пароля. "Failed publickey" — обычное дело у легитимных
# пользователей с несколькими ключами в агенте, "Failed none" — служебная проба клиента.
FAILED_RE = re.compile(
    r"Failed (?P<method>password|keyboard-interactive/pam|keyboard-interactive) "
    r"for (?:invalid user )?(?P<user>.*?) from " + _IP + r" port (?P<port>\d+)"
)
INVALID_RE = re.compile(r"Invalid user (?P<user>.*?) from " + _IP + r"(?: port (?P<port>\d+))?")
ACCEPTED_RE = re.compile(
    r"Accepted (?P<method>\S+) for (?P<user>.*?) from " + _IP + r" port (?P<port>\d+)"
)
PREAUTH_RE = re.compile(
    r"(?:Connection closed by|Connection reset by|Disconnected from) "
    r"(?:(?:authenticating|invalid) user (?P<user>.*?) )?"
    + _IP
    + r" port (?P<port>\d+) \[preauth\]"
)
REPEATED_RE = re.compile(r"^message repeated (?P<n>\d+) times: \[\s*(?P<msg>.*?)\s*\]$")

# Пары «шаблон → тип события». Порядок важен: FAILED раньше INVALID.
PATTERNS = [
    (FAILED_RE, EventType.FAILED),
    (INVALID_RE, EventType.INVALID_USER),
    (ACCEPTED_RE, EventType.ACCEPTED),
    (PREAUTH_RE, EventType.PREAUTH_CLOSE),
]

# --- Шаблоны заголовка строки (время, хост, программа) ---------------------

SYSLOG_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2}) (?P<hms>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<prog>[^\s\[:]+)(?:\[\d+\])?:\s?(?P<msg>.*)$"
)
ISO_SYSLOG_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<host>\S+)\s+(?P<prog>[^\s\[:]+)(?:\[\d+\])?:\s?(?P<msg>.*)$"
)
# s6-log (docker linuxserver): "2026-11-12 03:11:42.123456789  [sshd[1]: ]message"
S6_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+"
    r"(?:(?P<prog>sshd[\w-]*)(?:\[\d+\])?:\s)?(?P<msg>.*)$"
)
TAI64N_RE = re.compile(
    r"^@(?P<hex>[0-9a-f]{24})\s+(?:(?P<prog>sshd[\w-]*)(?:\[\d+\])?:\s)?(?P<msg>.*)$"
)

MONTHS = {
    m: i
    for i, m in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1
    )
}


def _is_sshd(prog: str | None) -> bool:
    # sshd, а в OpenSSH 9.8+ ещё sshd-session и sshd-auth
    return prog is None or prog.startswith("sshd")


def _valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return False
    return True


# --- Время -------------------------------------------------------------------


def parse_syslog_time(
    mon: str, day: str, hms: str, year: int | None = None, now: datetime | None = None
) -> datetime | None:
    """В syslog нет года. Подставляем текущий, а если дата получилась в будущем
    (лог за декабрь читаем в январе) — прошлый. Так же делает rsyslog/logwatch."""
    month = MONTHS.get(mon)
    if month is None:
        return None
    h, m, s = (int(x) for x in hms.split(":"))
    now = now or datetime.now()
    try:
        if year is not None:
            return datetime(year, month, int(day), h, m, s)
        t = datetime(now.year, month, int(day), h, m, s)
        if t > now + timedelta(days=1):
            t = t.replace(year=now.year - 1)
        return t
    except ValueError:  # 29 февраля в невисокосный год и т.п.
        return None


def parse_iso_time(ts: str) -> datetime | None:
    """ISO 8601 → наивное локальное время (как у syslog-строк), чтобы их можно было сравнивать."""
    ts = ts.replace(" ", "T", 1)
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    # fromisoformat до 3.11 не понимает >6 знаков дробной части (s6 пишет наносекунды)
    ts = re.sub(r"(\.\d{6})\d+", r"\1", ts)
    # и смещение без двоеточия (+0400)
    ts = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", ts)
    try:
        t = datetime.fromisoformat(ts)
    except ValueError:
        return None
    if t.tzinfo is not None:
        t = t.astimezone().replace(tzinfo=None)
    return t


def parse_tai64n(hexstr: str) -> datetime:
    # TAI64N: 8 байт секунд (2^62 + TAI) + 4 байта наносекунд. TAI опережает UTC на 37 с.
    seconds = int(hexstr[:16], 16) - 2**62 - 37
    nanos = int(hexstr[16:], 16)
    return datetime.fromtimestamp(seconds + nanos / 1e9)


# --- Разбор сообщений ----------------------------------------------------------


def parse_message(msg: str, time: datetime, host: str | None = None) -> list[Event]:
    """Разобрать текст сообщения sshd (без заголовка). Список — из-за 'message repeated N times'."""
    repeat = 1
    m = REPEATED_RE.match(msg)
    if m:
        repeat, msg = int(m["n"]), m["msg"]

    for pattern, event_type in PATTERNS:
        m = pattern.search(msg)
        if not m:
            continue
        ip = m["ip"]
        if not _valid_ip(ip):
            return []
        port = m["port"]
        method = m["method"] if "method" in pattern.groupindex else None
        return [
            Event(
                time=time,
                type=event_type,
                ip=ip,
                user=m["user"] or "",
                port=int(port) if port else None,
                method=method,
                host=host,
            )
            for _ in range(repeat)
        ]
    return []


def split_header(
    line: str, year: int | None = None, now: datetime | None = None
) -> tuple[datetime, str, str | None] | None:
    """Отделить время и программу от сообщения. None — если строка не от sshd или не распознана."""
    m = SYSLOG_RE.match(line)
    if m:
        if not _is_sshd(m["prog"]):
            return None
        t = parse_syslog_time(m["mon"], m["day"], m["hms"], year, now)
        return (t, m["msg"], m["host"]) if t else None

    m = ISO_SYSLOG_RE.match(line)
    if m:
        if not _is_sshd(m["prog"]):
            return None
        t = parse_iso_time(m["ts"])
        return (t, m["msg"], m["host"]) if t else None

    m = S6_RE.match(line)
    if m:
        t = parse_iso_time(m["ts"])
        return (t, m["msg"], None) if t else None

    m = TAI64N_RE.match(line)
    if m:
        return parse_tai64n(m["hex"]), m["msg"], None
    return None


def parse_line_all(line: str, year: int | None = None, now: datetime | None = None) -> list[Event]:
    header = split_header(line.rstrip("\r\n"), year, now)
    if header is None:
        return []
    time, msg, host = header
    return parse_message(msg, time, host)


def parse_line(line: str, year: int | None = None, now: datetime | None = None) -> Event | None:
    """Одна строка → Event или None (строка нам не нужна)."""
    events = parse_line_all(line, year, now)
    return events[0] if events else None


# --- journalctl -o json --------------------------------------------------------


def parse_journal_entry(raw: str) -> list[Event]:
    """Строка из `journalctl -o json`. Время берём из __REALTIME_TIMESTAMP (микросекунды)."""
    raw = raw.strip()
    if not raw:
        return []
    try:
        entry = json.loads(raw)
    except json.JSONDecodeError:
        return []
    if not isinstance(entry, dict):
        return []
    ident = entry.get("SYSLOG_IDENTIFIER") or entry.get("_COMM")
    if ident and not str(ident).startswith("sshd"):
        return []
    msg = entry.get("MESSAGE")
    if isinstance(msg, list):  # journald отдаёт не-UTF8 сообщения массивом байт
        msg = bytes(msg).decode("utf-8", errors="replace")
    if not isinstance(msg, str):
        return []
    try:
        ts = datetime.fromtimestamp(int(entry["__REALTIME_TIMESTAMP"]) / 1_000_000)
    except (KeyError, ValueError, TypeError):
        return []
    host = entry.get("_HOSTNAME")
    return parse_message(msg, ts, host if isinstance(host, str) else None)


# --- Файлы -------------------------------------------------------------------------


def open_log(path: str) -> IO[str]:
    if path == "-":
        return sys.stdin
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, encoding="utf-8", errors="replace")


def read_lines(path: str) -> Iterator[str]:
    f = open_log(path)
    try:
        for line in f:
            yield line.rstrip("\r\n")
    finally:
        if f is not sys.stdin:
            f.close()


def looks_like_journal(path: str) -> bool:
    """Автоопределение формата: первая непустая строка — JSON-объект."""
    if path == "-":
        return False
    for line in read_lines(path):
        if line.strip():
            return line.lstrip().startswith("{")
    return False


def iter_events(
    lines: Iterable[str], fmt: str = "syslog", year: int | None = None
) -> Iterator[Event]:
    now = datetime.now()
    for line in lines:
        if fmt == "journal":
            yield from parse_journal_entry(line)
        else:
            yield from parse_line_all(line, year, now)


def parse_file(path: str, fmt: str = "auto", year: int | None = None) -> list[Event]:
    if fmt == "auto":
        fmt = "journal" if looks_like_journal(path) else "syslog"
    return list(iter_events(read_lines(path), fmt, year))

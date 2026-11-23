"""Генератор реалистичного auth.log для демо и тестов. Только синтетика: IP из
документационных диапазонов TEST-NET (RFC 5737) и частной сети 10.0.0.0/8.

Сценарии внутри (≈3 часа лога):
  * фон: легитимные входы по ключу, опечатка в пароле, CRON, редкие сканеры
  * 203.0.113.5     — брутфорс root и успешный вход           → CRITICAL + HIGH
  * 198.51.100.23   — массированный брутфорс многих логинов   → HIGH
  * 203.0.113.77    — медленный password spraying             → MEDIUM (T1110.003)
  * 203.0.113.100-107 — распределённая атака на логин deploy  → HIGH
  * 198.51.100.200  — шумный сканер                           → LOW
  * 10.0.5.20       — CI-раннер с битым ключом (false positive, убирается allowlist)
"""

from __future__ import annotations

import random
from collections.abc import Iterator
from datetime import datetime, timedelta

MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
VALID_USERS = {"root", "denis", "deploy", "ci", "backup"}


class LogBuilder:
    def __init__(self, start: datetime, seed: int, host: str = "srv"):
        self.start = start
        self.rng = random.Random(seed)  # nosec B311 - не криптография, нужна воспроизводимость
        self.host = host
        self.items: list[tuple[datetime, str, str]] = []  # (время, программа, сообщение)
        self.pid = 1000

    def at(self, offset_s: float) -> datetime:
        return self.start + timedelta(seconds=offset_s)

    def port(self) -> int:
        return self.rng.randint(32768, 60999)

    def add(self, t: datetime, msg: str, prog: str = "sshd") -> None:
        self.items.append((t, prog, msg))

    def failed(self, t: datetime, user: str, ip: str) -> None:
        port = self.port()
        if user not in VALID_USERS:
            self.add(t, f"Invalid user {user} from {ip} port {port}")
            self.add(t, f"Failed password for invalid user {user} from {ip} port {port} ssh2")
        else:
            self.add(t, f"Failed password for {user} from {ip} port {port} ssh2")

    def accepted(self, t: datetime, user: str, ip: str, method: str = "publickey") -> None:
        self.add(t, f"Accepted {method} for {user} from {ip} port {self.port()} ssh2")

    def preauth(self, t: datetime, ip: str, user: str | None = None) -> None:
        if user:
            self.add(t, f"Invalid user {user} from {ip} port {self.port()}")
            closed = f"Connection closed by invalid user {user} {ip} port {self.port()} [preauth]"
            self.add(t, closed)
        else:
            self.add(t, f"Connection closed by {ip} port {self.port()} [preauth]")

    def lines(self) -> Iterator[str]:
        for t, prog, msg in sorted(self.items, key=lambda x: x[0]):
            self.pid += 1
            stamp = f"{MONTHS[t.month - 1]} {t.day:>2} {t:%H:%M:%S}"
            yield f"{stamp} {self.host} {prog}[{self.pid}]: {msg}"


def generate_lines(start: datetime | None = None, seed: int = 42) -> Iterator[str]:
    if start is None:
        start = datetime.now().replace(hour=3, minute=0, second=0, microsecond=0)
    b = LogBuilder(start, seed)
    rng = b.rng
    duration = 3 * 3600

    # --- фон ---------------------------------------------------------------
    for t in range(0, duration, 1800):  # админ заходит по ключу
        b.accepted(b.at(t + rng.randint(0, 600)), "denis", "192.0.2.10")
    b.failed(b.at(700), "denis", "192.0.2.11")  # опечатка: 2 неудачи и вход — не атака
    b.failed(b.at(706), "denis", "192.0.2.11")
    b.accepted(b.at(712), "denis", "192.0.2.11", "password")
    for t in range(0, duration, 600):
        cron = "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)"
        b.add(b.at(t), cron, "CRON")
    for _ in range(40):  # редкие сканеры интернета — каждый ниже порогов
        ip = f"198.51.100.{rng.randint(30, 150)}"
        b.preauth(b.at(rng.randint(0, duration)), ip)

    # --- 1. брутфорс root с успехом в конце -----------------------------------
    t = 1800.0
    for _ in range(47):
        b.failed(b.at(t), "root", "203.0.113.5")
        t += rng.uniform(3, 6)
    b.accepted(b.at(t + 1), "root", "203.0.113.5", "password")

    # --- 2. массированный брутфорс по словарю логинов --------------------------
    t = 3600.0
    plan = ["root"] * 120 + ["admin"] * 80 + ["ubuntu"] * 40 + ["test"] * 30 + ["oracle"] * 22
    rng.shuffle(plan)
    for user in plan:
        b.failed(b.at(t), user, "198.51.100.23")
        t += rng.uniform(0.5, 1.4)
    b.add(
        b.at(t + 1),
        "message repeated 5 times: [ Failed password for root from 198.51.100.23 port 40001 ssh2]",
    )

    # --- 3. медленный spraying: одна попытка в 4–6 минут -----------------------
    t = 5400.0
    for user in ["admin", "test", "user", "guest", "postgres", "ftp", "git", "oracle", "pi", "www"]:
        b.failed(b.at(t), user, "203.0.113.77")
        t += rng.uniform(240, 360)

    # --- 4. распределённая атака: 8 IP, по 2 попытки на deploy -------------------
    t = 7200.0
    for i in range(8):
        for _ in range(2):
            b.failed(b.at(t + rng.uniform(0, 400)), "deploy", f"203.0.113.{100 + i}")

    # --- 5. шумный сканер ---------------------------------------------------------
    t = 8400.0
    for user in ["admin", "test", "user", "support", "ubnt", "pi", "oracle", "nagios"]:
        b.preauth(b.at(t), "198.51.100.200", user)
        t += rng.uniform(2, 4)

    # --- 6. false positive: CI-раннер с битым ключом долбится каждые 10 с ---------
    t = 9000.0
    for _ in range(18):
        b.failed(b.at(t), "ci", "10.0.5.20")
        t += 10

    return b.lines()

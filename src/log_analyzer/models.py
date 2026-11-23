"""Модели данных: событие из лога, алерт, уровень критичности, MITRE ATT&CK."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from functools import total_ordering
from typing import Any


class EventType(Enum):
    FAILED = "failed"  # неверный пароль
    INVALID_USER = "invalid_user"  # такого пользователя нет
    ACCEPTED = "accepted"  # успешный вход
    PREAUTH_CLOSE = "preauth_close"  # соединение оборвано до аутентификации (часто сканеры)


@dataclass
class Event:
    time: datetime
    type: EventType
    ip: str
    user: str
    port: int | None = None
    method: str | None = None  # password / publickey / keyboard-interactive/pam
    host: str | None = None  # имя сервера из строки лога (где это случилось)


@total_ordering
class Severity(Enum):
    LOW = 1  # сканер, фоновый шум интернета
    MEDIUM = 2  # брутфорс / spraying
    HIGH = 3  # брутфорс по root, распределённая атака
    CRITICAL = 4  # успешный вход после брутфорса

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.value < other.value

    @classmethod
    def parse(cls, value: str | Severity) -> Severity:
        if isinstance(value, Severity):
            return value
        try:
            return cls[str(value).strip().upper()]
        except KeyError:
            names = ", ".join(s.name for s in cls)
            raise ValueError(f"неизвестный severity {value!r}, допустимо: {names}") from None


# Справочник техник MITRE ATT&CK, на которые маппятся правила
MITRE = {
    "T1110": "Brute Force",
    "T1110.001": "Password Guessing",
    "T1110.003": "Password Spraying",
    "T1110.004": "Credential Stuffing",
    "T1078": "Valid Accounts",
    "T1595": "Active Scanning",
}


@dataclass
class Alert:
    rule: str  # bruteforce / success_after_fail / spraying / distributed / scan
    severity: Severity
    title: str
    key: str  # по чему дедуплицируем: IP или (для distributed) логин
    first_seen: datetime
    last_seen: datetime
    count: int = 0
    ip: str | None = None
    host: str | None = None
    compromised_user: str | None = None  # для success_after_fail: под кем вошли
    users: Counter[str] = field(default_factory=Counter)
    ips: Counter[str] = field(default_factory=Counter)
    mitre: list[str] = field(default_factory=list)
    details: list[str] = field(default_factory=list)
    recommendation: str = ""
    enrichment: dict[str, Any] = field(default_factory=dict)
    reported_count: int = 0  # сколько событий было в момент первой отправки (для сводки)

    def add(self, event: Event) -> None:
        """Атака продолжается — дописываем событие в уже открытый алерт (дедупликация)."""
        self.count += 1
        self.users[event.user] += 1
        self.ips[event.ip] += 1
        self.last_seen = max(self.last_seen, event.time)

    @property
    def duration_seconds(self) -> float:
        return (self.last_seen - self.first_seen).total_seconds()

    def mitre_labels(self) -> list[str]:
        return [f"{t} {MITRE.get(t, '')}".strip() for t in self.mitre]

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "severity": self.severity.name,
            "title": self.title,
            "key": self.key,
            "ip": self.ip,
            "host": self.host,
            "compromised_user": self.compromised_user,
            "count": self.count,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "duration_seconds": self.duration_seconds,
            "users": dict(self.users.most_common()),
            "ips": dict(self.ips.most_common()),
            "mitre": [{"id": t, "name": MITRE.get(t, "")} for t in self.mitre],
            "details": self.details,
            "recommendation": self.recommendation,
            "enrichment": self.enrichment,
        }

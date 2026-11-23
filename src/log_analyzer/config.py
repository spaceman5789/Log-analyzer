"""Конфиг (YAML), allowlist доверенных сетей и загрузка .env."""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

from log_analyzer.models import Severity


class ConfigError(ValueError):
    pass


@dataclass
class DetectionConfig:
    # Брутфорс: >= threshold неудач с одного IP за window секунд (как maxretry/findtime в fail2ban)
    window: int = 60
    threshold: int = 5
    # Успешный вход: сколько секунд назад смотреть неудачи с того же IP
    success_lookback: int = 3600
    # Spraying: >= spray_users разных логинов с одного IP за spray_window секунд
    spray_window: int = 3600
    spray_users: int = 5
    # Распределённая атака: >= distributed_ips разных IP на один логин за distributed_window
    distributed_window: int = 600
    distributed_ips: int = 5
    # Сканеры: >= scan_threshold обрывов [preauth] / Invalid user за window секунд
    scan_threshold: int = 10
    # Дедупликация: пока атака идёт без пауз дольше cooldown, это один и тот же алерт
    cooldown: int = 900
    # Перебор этих логинов повышает severity брутфорса до HIGH
    privileged_users: list[str] = field(default_factory=lambda: ["root"])

    def validate(self) -> None:
        for f in fields(self):
            value = getattr(self, f.name)
            if isinstance(value, int) and value <= 0:
                raise ConfigError(f"detection.{f.name} должен быть > 0, получено {value}")


@dataclass
class TelegramConfig:
    min_severity: Severity = Severity.MEDIUM
    max_alerts: int = 10  # больше алертов за один analyze — одно сводное сообщение
    timeout: int = 10


@dataclass
class EnrichmentConfig:
    geoip_db: str | None = None  # путь к GeoLite2-Country.mmdb / GeoLite2-City.mmdb
    blocklists: list[str] = field(default_factory=list)  # файлы с IP/CIDR, по одному на строку


@dataclass
class Config:
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    allowlist: list[str] = field(default_factory=list)
    telegram: TelegramConfig = field(default_factory=TelegramConfig)
    enrichment: EnrichmentConfig = field(default_factory=EnrichmentConfig)


class Allowlist:
    """Доверенные IP и подсети. Всё, что отсюда, не даёт алертов (борьба с false positive)."""

    def __init__(self, entries: list[str] | None = None):
        self.networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for entry in entries or []:
            try:
                self.networks.append(ipaddress.ip_network(str(entry).strip(), strict=False))
            except ValueError as e:
                raise ConfigError(f"allowlist: неверный IP/подсеть {entry!r}: {e}") from None

    def __contains__(self, ip: object) -> bool:
        try:
            addr = ipaddress.ip_address(str(ip))
        except ValueError:
            return False
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
            addr = addr.ipv4_mapped  # ::ffff:192.0.2.10 → 192.0.2.10
        return any(addr.version == net.version and addr in net for net in self.networks)

    def __len__(self) -> int:
        return len(self.networks)


def _fill(cls: type, data: Any, section: str) -> Any:
    """dict → dataclass с проверкой опечаток в ключах."""
    if data is None:
        return cls()
    if not isinstance(data, dict):
        raise ConfigError(f"секция {section} должна быть словарём")
    known = {f.name for f in fields(cls)}
    unknown = set(data) - known
    if unknown:
        raise ConfigError(
            f"{section}: неизвестные ключи {sorted(unknown)}, допустимо {sorted(known)}"
        )
    return cls(**data)


def load_config(path: str | os.PathLike[str] | None) -> Config:
    if path is None:
        return Config()
    import yaml  # pyyaml

    try:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    except OSError as e:
        raise ConfigError(f"не удалось прочитать конфиг {path}: {e}") from None
    except yaml.YAMLError as e:
        raise ConfigError(f"ошибка YAML в {path}: {e}") from None
    if not isinstance(raw, dict):
        raise ConfigError("конфиг должен быть словарём")

    unknown = set(raw) - {"detection", "allowlist", "telegram", "enrichment"}
    if unknown:
        raise ConfigError(f"неизвестные секции конфига: {sorted(unknown)}")

    detection = _fill(DetectionConfig, raw.get("detection"), "detection")
    detection.validate()
    telegram = _fill(TelegramConfig, raw.get("telegram"), "telegram")
    try:
        telegram.min_severity = Severity.parse(telegram.min_severity)
    except ValueError as e:
        raise ConfigError(f"telegram.min_severity: {e}") from None
    enrichment = _fill(EnrichmentConfig, raw.get("enrichment"), "enrichment")

    allowlist = raw.get("allowlist") or []
    if not isinstance(allowlist, list):
        raise ConfigError("allowlist должен быть списком IP/подсетей")
    Allowlist(allowlist)  # валидируем сразу, чтобы упасть при старте, а не посреди анализа

    return Config(
        detection=detection, allowlist=allowlist, telegram=telegram, enrichment=enrichment
    )


def load_dotenv(path: str | os.PathLike[str] = ".env") -> None:
    """Минимальный загрузчик .env: KEY=value, комментарии #.
    Уже заданные переменные окружения не перетирает."""
    p = Path(path)
    if not p.is_file():
        return
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip().removeprefix("export ").strip()
        value = value.strip().strip("'\"")
        os.environ.setdefault(key, value)

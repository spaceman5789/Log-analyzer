"""Config (YAML), allowlist of trusted networks and .env loading."""

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
    # Brute force: >= threshold failures from one IP in window seconds (fail2ban maxretry/findtime)
    window: int = 60
    threshold: int = 5
    # Successful login: how many seconds back to look for failures from the same IP
    success_lookback: int = 3600
    # Spraying: >= spray_users distinct usernames from one IP within spray_window seconds
    spray_window: int = 3600
    spray_users: int = 5
    # Distributed attack: >= distributed_ips distinct IPs on one username in distributed_window
    distributed_window: int = 600
    distributed_ips: int = 5
    # Scanners: >= scan_threshold [preauth] disconnects / Invalid user within window seconds
    scan_threshold: int = 10
    # Deduplication: while the attack has no gap longer than cooldown, it is the same alert
    cooldown: int = 900
    # Brute force against these usernames raises severity to HIGH
    privileged_users: list[str] = field(default_factory=lambda: ["root"])

    def validate(self) -> None:
        for f in fields(self):
            value = getattr(self, f.name)
            if isinstance(value, int) and value <= 0:
                raise ConfigError(f"detection.{f.name} must be > 0, got {value}")


@dataclass
class TelegramConfig:
    min_severity: Severity = Severity.MEDIUM
    max_alerts: int = 10  # more alerts in one analyze run go out as one summary message
    timeout: int = 10


@dataclass
class EnrichmentConfig:
    geoip_db: str | None = None  # path to GeoLite2-Country.mmdb / GeoLite2-City.mmdb
    blocklists: list[str] = field(default_factory=list)  # files with one IP/CIDR per line


@dataclass
class Config:
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    allowlist: list[str] = field(default_factory=list)
    telegram: TelegramConfig = field(default_factory=TelegramConfig)
    enrichment: EnrichmentConfig = field(default_factory=EnrichmentConfig)


class Allowlist:
    """Trusted IPs and subnets. Nothing from them raises alerts (false positive control)."""

    def __init__(self, entries: list[str] | None = None):
        self.networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for entry in entries or []:
            try:
                self.networks.append(ipaddress.ip_network(str(entry).strip(), strict=False))
            except ValueError as e:
                raise ConfigError(f"allowlist: invalid IP/subnet {entry!r}: {e}") from None

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
    """dict → dataclass, rejecting typos in keys."""
    if data is None:
        return cls()
    if not isinstance(data, dict):
        raise ConfigError(f"section {section} must be a mapping")
    known = {f.name for f in fields(cls)}
    unknown = set(data) - known
    if unknown:
        raise ConfigError(f"{section}: unknown keys {sorted(unknown)}, allowed {sorted(known)}")
    return cls(**data)


def load_config(path: str | os.PathLike[str] | None) -> Config:
    if path is None:
        return Config()
    import yaml  # pyyaml

    try:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    except OSError as e:
        raise ConfigError(f"cannot read config {path}: {e}") from None
    except yaml.YAMLError as e:
        raise ConfigError(f"YAML error in {path}: {e}") from None
    if not isinstance(raw, dict):
        raise ConfigError("config must be a mapping")

    unknown = set(raw) - {"detection", "allowlist", "telegram", "enrichment"}
    if unknown:
        raise ConfigError(f"unknown config sections: {sorted(unknown)}")

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
        raise ConfigError("allowlist must be a list of IPs/subnets")
    Allowlist(allowlist)  # validate now to fail at startup, not in the middle of analysis

    return Config(
        detection=detection, allowlist=allowlist, telegram=telegram, enrichment=enrichment
    )


def load_dotenv(path: str | os.PathLike[str] = ".env") -> None:
    """Minimal .env loader: KEY=value, # comments.
    Does not override variables already set in the environment."""
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

"""Alert enrichment: address type, country (GeoIP), blocklist membership."""

from __future__ import annotations

import ipaddress
import logging
from pathlib import Path
from typing import Any

from log_analyzer.config import EnrichmentConfig
from log_analyzer.models import Alert

log = logging.getLogger(__name__)

# Documentation ranges (RFC 5737 / RFC 3849). Python treats them as "private",
# but for an analyst they are a separate category: they should never appear in a real log.
DOC_NETS = [
    ipaddress.ip_network(n)
    for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
]

MAX_IPS_PER_ALERT = 10  # a distributed attack can have hundreds of IPs, enrich only the top ones


def ip_scope(ip: str) -> str:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "invalid"
    if addr.is_loopback:
        return "loopback"
    if any(addr.version == n.version and addr in n for n in DOC_NETS):
        return "documentation"
    if addr.is_private:
        return "private"  # attack from inside the network: is the source host compromised?
    if addr.is_global:
        return "public"
    return "reserved"


def load_blocklist(paths: list[str]) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """FireHOL / Spamhaus DROP files: IP or CIDR at line start, comments with # and ;"""
    nets = []
    for path in paths:
        try:
            text = Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            log.warning("could not read blocklist %s: %s", path, e)
            continue
        for line in text.splitlines():
            token = line.split("#", 1)[0].split(";", 1)[0].strip()
            if not token:
                continue
            try:
                nets.append(ipaddress.ip_network(token.split()[0], strict=False))
            except ValueError:
                continue
    return nets


class Enricher:
    def __init__(self, cfg: EnrichmentConfig | None = None):
        cfg = cfg or EnrichmentConfig()
        self.blocklist = load_blocklist(cfg.blocklists)
        self.geo = self._open_geoip(cfg.geoip_db)
        self._cache: dict[str, dict[str, Any]] = {}

    @staticmethod
    def _open_geoip(path: str | None) -> Any:
        if not path:
            return None
        try:
            import geoip2.database  # optional dependency: pip install .[geoip]
        except ImportError:
            log.warning("geoip_db is set but geoip2 is not installed: pip install '.[geoip]'")
            return None
        try:
            return geoip2.database.Reader(path)
        except (OSError, ValueError) as e:
            log.warning("could not open GeoIP database %s: %s", path, e)
            return None

    def _geo_lookup(self, ip: str) -> dict[str, Any]:
        if self.geo is None:
            return {}
        try:
            if "City" in self.geo.metadata().database_type:
                r = self.geo.city(ip)
                return {"country": r.country.iso_code, "city": r.city.name}
            r = self.geo.country(ip)
            return {"country": r.country.iso_code}
        except Exception:  # AddressNotFoundError, ValueError etc.: simply no data
            return {}

    def lookup(self, ip: str) -> dict[str, Any]:
        if ip in self._cache:
            return self._cache[ip]
        info: dict[str, Any] = {"scope": ip_scope(ip)}
        info.update({k: v for k, v in self._geo_lookup(ip).items() if v})
        if self.blocklist:
            addr = ipaddress.ip_address(ip)
            info["blocklisted"] = any(
                addr.version == n.version and addr in n for n in self.blocklist
            )
        self._cache[ip] = info
        return info

    def enrich(self, alert: Alert) -> Alert:
        ips = [alert.ip] if alert.ip else [ip for ip, _ in alert.ips.most_common(MAX_IPS_PER_ALERT)]
        alert.enrichment = {ip: self.lookup(ip) for ip in ips}
        return alert

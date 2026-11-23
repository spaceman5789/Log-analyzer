from __future__ import annotations

import io
import json
import os
import urllib.error
from pathlib import Path

import pytest
from conftest import ev

from log_analyzer.alerting import (
    AlertingError,
    TelegramNotifier,
    format_alert_html,
    format_alert_text,
    human_duration,
)
from log_analyzer.config import ConfigError, EnrichmentConfig, load_config, load_dotenv
from log_analyzer.detectors import detect
from log_analyzer.enrichment import Enricher, ip_scope
from log_analyzer.models import Severity

ROOT = Path(__file__).parent.parent


# --- конфиг ---------------------------------------------------------------------------


def test_example_config_loads():
    cfg = load_config(ROOT / "config.example.yaml")
    assert cfg.detection.window == 60
    assert cfg.detection.threshold == 5
    assert "10.0.5.0/24" in cfg.allowlist
    assert cfg.telegram.min_severity is Severity.HIGH


def test_config_typo_is_an_error(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text("detection:\n  treshold: 5\n")
    with pytest.raises(ConfigError, match="treshold"):
        load_config(p)


@pytest.mark.parametrize(
    "text",
    [
        "allowlist: [not-a-network]\n",
        "detection:\n  window: 0\n",
        "telegram:\n  min_severity: URGENT\n",
        "unknown_section: {}\n",
    ],
)
def test_config_invalid_values(tmp_path, text):
    p = tmp_path / "c.yaml"
    p.write_text(text)
    with pytest.raises(ConfigError):
        load_config(p)


def test_no_config_gives_defaults():
    cfg = load_config(None)
    assert cfg.detection.threshold == 5
    assert cfg.allowlist == []


def test_load_dotenv_does_not_override(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text("# comment\nTG_CHAT_ID=123\nexport TG_BOT_TOKEN='abc'\n")
    monkeypatch.setenv("TG_CHAT_ID", "already-set")
    monkeypatch.delenv("TG_BOT_TOKEN", raising=False)
    load_dotenv(env)
    assert os.environ["TG_CHAT_ID"] == "already-set"
    assert os.environ["TG_BOT_TOKEN"] == "abc"


# --- форматирование ----------------------------------------------------------------------


def _alert(user="root"):
    [a] = detect([ev(i, user=user) for i in range(6)])
    return a


def test_text_alert_answers_what_where_when_how_bad_what_next():
    text = format_alert_text(_alert())
    assert text.startswith("[HIGH]")
    assert "IP: 203.0.113.5" in text
    assert "Неудачных попыток: 6 за 5 с" in text
    assert "Логины: root(6)" in text
    assert "T1110.001 Password Guessing" in text
    assert "Что делать:" in text


def test_html_alert_escapes_user_controlled_data():
    a = _alert(user="<b>x</b>")
    html_text = format_alert_html(a)
    assert "<b>x</b>" not in html_text
    assert "&lt;b&gt;x&lt;/b&gt;" in html_text
    assert html_text.startswith("🟠 <b>[MEDIUM]")


def test_human_duration():
    assert human_duration(12) == "12 с"
    assert human_duration(300) == "5 мин"
    assert human_duration(3720) == "1 ч 2 мин"


# --- Telegram ----------------------------------------------------------------------------------


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_telegram_send_builds_correct_request():
    calls = []

    def opener(req, timeout):
        calls.append((req, timeout))
        return FakeResponse(b'{"ok":true}')

    n = TelegramNotifier("123:SECRET", "42", timeout=7, opener=opener)
    n.send_alert(_alert())
    req, timeout = calls[0]
    assert req.full_url == "https://api.telegram.org/bot123:SECRET/sendMessage"
    body = json.loads(req.data)
    assert body["chat_id"] == "42"
    assert body["parse_mode"] == "HTML"
    assert "[HIGH]" in body["text"]
    assert timeout == 7


def test_telegram_token_not_leaked_in_repr_or_errors():
    def opener(req, timeout):
        raise urllib.error.HTTPError(
            req.full_url, 400, "Bad Request", {}, io.BytesIO(b'{"description":"chat not found"}')
        )

    n = TelegramNotifier("123:SECRET", "42", opener=opener)
    assert "SECRET" not in repr(n)
    with pytest.raises(AlertingError) as exc:
        n.send_text("hi")
    assert "chat not found" in str(exc.value)
    assert "SECRET" not in str(exc.value)


def test_telegram_retries_once_on_429():
    attempts = []
    slept = []

    def opener(req, timeout):
        attempts.append(1)
        if len(attempts) == 1:
            body = b'{"parameters":{"retry_after":3}}'
            raise urllib.error.HTTPError(req.full_url, 429, "Too Many", {}, io.BytesIO(body))
        return FakeResponse(b"{}")

    TelegramNotifier("t", "c", opener=opener, sleep=slept.append).send_text("hi")
    assert len(attempts) == 2
    assert slept == [3]


def test_telegram_network_error():
    def opener(req, timeout):
        raise urllib.error.URLError("no route")

    with pytest.raises(AlertingError, match="no route"):
        TelegramNotifier("t", "c", opener=opener).send_text("hi")


def test_telegram_from_env_requires_vars(monkeypatch):
    monkeypatch.delenv("TG_BOT_TOKEN", raising=False)
    monkeypatch.delenv("TG_CHAT_ID", raising=False)
    with pytest.raises(AlertingError):
        TelegramNotifier.from_env()


# --- обогащение ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "ip,scope",
    [
        ("203.0.113.5", "documentation"),
        ("10.0.5.20", "private"),
        ("8.8.8.8", "public"),
        ("127.0.0.1", "loopback"),
    ],
)
def test_ip_scope(ip, scope):
    assert ip_scope(ip) == scope


def test_blocklist_enrichment(tmp_path):
    bl = tmp_path / "firehol.netset"
    bl.write_text("# FireHOL level1\n203.0.113.0/24\n198.51.100.7 ; comment\n")
    e = Enricher(EnrichmentConfig(blocklists=[str(bl)]))
    a = e.enrich(_alert())
    assert a.enrichment["203.0.113.5"]["blocklisted"] is True
    assert e.lookup("192.0.2.1")["blocklisted"] is False


def test_missing_geoip_db_does_not_crash():
    e = Enricher(EnrichmentConfig(geoip_db="/nonexistent/GeoLite2-Country.mmdb"))
    assert e.lookup("8.8.8.8") == {"scope": "public"}

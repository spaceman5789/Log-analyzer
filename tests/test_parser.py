from __future__ import annotations

import gzip
import shutil
from datetime import datetime, timezone

import pytest

from log_analyzer.models import EventType
from log_analyzer.parser import (
    looks_like_journal,
    parse_file,
    parse_iso_time,
    parse_journal_entry,
    parse_line,
    parse_syslog_time,
)

Y = 2026


# --- шаг 6 из плана: каждая строка фикстуры разбирается правильно ----------------------

SAMPLE_EXPECTED = [
    (EventType.FAILED, "203.0.113.5", "root"),
    (EventType.FAILED, "203.0.113.5", "root"),
    (EventType.FAILED, "203.0.113.5", "root"),
    (EventType.FAILED, "203.0.113.5", "root"),
    (EventType.FAILED, "203.0.113.5", "root"),
    (EventType.FAILED, "203.0.113.5", "root"),
    (EventType.ACCEPTED, "203.0.113.5", "root"),
    (EventType.INVALID_USER, "198.51.100.23", "admin"),
    (EventType.FAILED, "198.51.100.23", "admin"),
    (EventType.FAILED, "198.51.100.23", "oracle"),
    (EventType.FAILED, "198.51.100.23", "ubuntu"),
    (EventType.ACCEPTED, "192.0.2.10", "denis"),
    None,  # строка CRON
]


def test_sample_fixture_line_by_line(fixture_path):
    with open(fixture_path("auth_sample.log"), encoding="utf-8") as f:
        lines = f.read().splitlines()
    assert len(lines) == len(SAMPLE_EXPECTED)
    for line, expected in zip(lines, SAMPLE_EXPECTED, strict=True):
        event = parse_line(line, year=Y)
        if expected is None:
            assert event is None, line
        else:
            assert event is not None, line
            assert (event.type, event.ip, event.user) == expected, line


def test_parse_failed_fields():
    e = parse_line(
        "Nov 12 03:11:42 srv sshd[1234]: Failed password for root from 203.0.113.5 port 52114 ssh2",
        year=Y,
    )
    assert e.time == datetime(Y, 11, 12, 3, 11, 42)
    assert e.port == 52114
    assert e.method == "password"
    assert e.host == "srv"


def test_invalid_user_in_failed_line_is_stripped():
    e = parse_line(
        "Nov 12 03:11:44 srv sshd[1]: Failed password for invalid user admin "
        "from 203.0.113.5 port 52118 ssh2",
        year=Y,
    )
    assert e.type is EventType.FAILED
    assert e.user == "admin"


def test_accepted_publickey():
    e = parse_line(
        "Nov 12 03:12:01 srv sshd[1]: Accepted publickey for denis from 198.51.100.7 "
        "port 50022 ssh2: ED25519 SHA256:abc",
        year=Y,
    )
    assert e.type is EventType.ACCEPTED
    assert e.method == "publickey"


@pytest.mark.parametrize(
    "line,user",
    [
        (
            "Nov 12 03:12:10 srv sshd[1]: Connection closed by authenticating user root "
            "203.0.113.5 port 52200 [preauth]",
            "root",
        ),
        (
            "Nov 12 03:12:10 srv sshd[1]: Disconnected from invalid user oracle "
            "203.0.113.5 port 52200 [preauth]",
            "oracle",
        ),
        ("Nov 12 03:12:10 srv sshd[1]: Connection closed by 203.0.113.5 port 52200 [preauth]", ""),
    ],
)
def test_preauth(line, user):
    e = parse_line(line, year=Y)
    assert e.type is EventType.PREAUTH_CLOSE
    assert e.ip == "203.0.113.5"
    assert e.user == user


@pytest.mark.parametrize(
    "line",
    [
        "Nov 12 03:15:30 srv CRON[1500]: pam_unix(cron:session): session opened for user root",
        # подделка: чужая программа пишет строку, похожую на sshd
        "Nov 12 03:15:30 srv evil[1]: Failed password for root from 203.0.113.5 port 1 ssh2",
        # publickey-неудачи — норма для пользователей с несколькими ключами
        "Nov 12 03:15:30 srv sshd[1]: Failed publickey for denis from 192.0.2.10 port 1 ssh2",
        "Nov 12 03:15:30 srv sshd[1]: Failed password for root from not-an-ip port 1 ssh2",
        "garbage",
        "",
    ],
)
def test_ignored_lines(line):
    assert parse_line(line, year=Y) is None


def test_single_digit_day_padding():
    e = parse_line(
        "Nov  2 03:11:42 srv sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2",
        year=Y,
    )
    assert e.time == datetime(Y, 11, 2, 3, 11, 42)


def test_ipv6():
    e = parse_line(
        "Nov 12 03:11:42 srv sshd[1]: Failed password for root from 2001:db8::5 port 1 ssh2",
        year=Y,
    )
    assert e.ip == "2001:db8::5"


def test_syslog_year_rollover():
    # Читаем 2 января лог с записью от 31 декабря — это прошлый год, а не будущий
    now = datetime(2027, 1, 2, 10, 0, 0)
    assert parse_syslog_time("Dec", "31", "23:59:59", now=now).year == 2026
    assert parse_syslog_time("Jan", "2", "09:00:00", now=now).year == 2027


def test_iso_time_offset_normalized():
    a = parse_iso_time("2026-11-12T03:11:42+04:00")
    b = parse_iso_time("2026-11-11T23:11:42Z")
    assert a == b  # один и тот же момент, приведённый к локальному времени
    expected = datetime(2026, 11, 11, 23, 11, 42, tzinfo=timezone.utc).astimezone()
    assert a == expected.replace(tzinfo=None)


def test_iso_time_nanoseconds_and_space():
    t = parse_iso_time("2026-11-12 03:11:42.123456789")
    assert t == datetime(2026, 11, 12, 3, 11, 42, 123456)


def test_iso_fixture(load):
    events = load("auth_iso.log")
    types = [e.type for e in events]
    # 1 + 1 + 4 (message repeated 4 times) failed, 1 accepted, 1 preauth; systemd — мимо
    assert types.count(EventType.FAILED) == 6
    assert types.count(EventType.ACCEPTED) == 1
    assert types.count(EventType.PREAUTH_CLOSE) == 1
    assert {e.ip for e in events} == {"203.0.113.5", "2001:db8::5", "198.51.100.7"}


def test_s6_docker_format():
    # формат /config/logs/openssh/current в linuxserver/openssh-server
    e = parse_line(
        "2026-11-12 03:11:42.123456789  Failed password for test from 172.17.0.1 port 1 ssh2"
    )
    assert e.type is EventType.FAILED
    assert e.user == "test"


def test_tai64n_format():
    e = parse_line(
        "@4000000069140a8e00000000 sshd[1]: Failed password for test from 172.17.0.1 port 1 ssh2"
    )
    assert e is not None and e.type is EventType.FAILED


def test_journal_entry():
    raw = (
        '{"__REALTIME_TIMESTAMP":"1794453062000000","SYSLOG_IDENTIFIER":"sshd",'
        '"_HOSTNAME":"srv","MESSAGE":"Failed password for root from 203.0.113.5 port 1 ssh2"}'
    )
    [e] = parse_journal_entry(raw)
    assert e.type is EventType.FAILED
    assert e.host == "srv"
    assert e.time == datetime.fromtimestamp(1794453062)


def test_journal_skips_other_units_and_garbage():
    assert parse_journal_entry('{"SYSLOG_IDENTIFIER":"CRON","MESSAGE":"x"}') == []
    assert parse_journal_entry("not json") == []
    assert parse_journal_entry("[]") == []


def test_journal_autodetect(fixture_path):
    path = fixture_path("journal_sample.jsonl")
    assert looks_like_journal(path)
    events = parse_file(path)
    assert [e.type for e in events].count(EventType.FAILED) == 6
    assert events[-1].type is EventType.ACCEPTED


def test_gzip_rotated_log(tmp_path, fixture_path):
    src = fixture_path("auth_sample.log")
    gz = tmp_path / "auth.log.2.gz"
    with open(src, "rb") as fin, gzip.open(gz, "wb") as fout:
        shutil.copyfileobj(fin, fout)
    assert len(parse_file(str(gz), year=Y)) == len(parse_file(src, year=Y)) == 12

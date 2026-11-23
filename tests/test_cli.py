from __future__ import annotations

import json
import threading
import time
from pathlib import Path

from log_analyzer import cli
from log_analyzer.cli import main, send_alerts
from log_analyzer.detectors import detect
from log_analyzer.generate import generate_lines
from log_analyzer.models import Severity
from log_analyzer.parser import iter_events
from log_analyzer.sources import follow_file

ROOT = Path(__file__).parent.parent


def run(capsys, *argv):
    code = main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


def test_analyze_text(capsys, fixture_path):
    code, out, _ = run(capsys, "analyze", fixture_path("auth_sample.log"), "--year", "2026")
    assert code == 0
    assert "[CRITICAL] Успешный вход после брутфорса" in out
    assert "IP: 203.0.113.5" in out
    assert "Итого: 12 событий, 1 атакующий IP, 2 алерта" in out


def test_analyze_json(capsys, fixture_path):
    _, out, _ = run(
        capsys,
        "analyze",
        fixture_path("auth_sample.log"),
        "--year",
        "2026",
        "--format",
        "json",
    )
    doc = json.loads(out)
    assert doc["summary"]["events_total"] == 12
    assert doc["alerts"][0]["severity"] == "CRITICAL"
    assert doc["alerts"][0]["mitre"][0] == {"id": "T1110.001", "name": "Password Guessing"}
    assert doc["telegram_sent"] is None


def test_analyze_threshold_and_window_flags(capsys, fixture_path):
    # порог выше числа неудач — алертов нет
    _, out, _ = run(capsys, "analyze", fixture_path("auth_sample.log"), "--threshold", "7")
    assert "Алертов нет" in out


def test_analyze_allow_flag(capsys, fixture_path):
    _, out, _ = run(capsys, "analyze", fixture_path("auth_ci_runner.log"), "--allow", "10.0.5.0/24")
    assert "Алертов нет" in out
    assert "allowlist" in out


def test_analyze_multiple_files_and_journal(capsys, fixture_path):
    _, out, _ = run(
        capsys,
        "analyze",
        fixture_path("journal_sample.jsonl"),
        fixture_path("auth_clean.log"),
        "--format",
        "json",
    )
    doc = json.loads(out)
    assert any(a["rule"] == "success_after_fail" for a in doc["alerts"])


def test_fail_on_exit_code(capsys, fixture_path):
    code, _, _ = run(capsys, "analyze", fixture_path("auth_sample.log"), "--fail-on", "critical")
    assert code == 1
    code, _, _ = run(capsys, "analyze", fixture_path("auth_clean.log"), "--fail-on", "low")
    assert code == 0


def test_missing_file_is_clean_error(capsys):
    code, _, err = run(capsys, "analyze", "/nonexistent/auth.log")
    assert code == 2
    assert "не найден" in err


def test_no_path_is_clean_error(capsys):
    code, _, err = run(capsys, "analyze")
    assert code == 2
    assert "--journal" in err


def test_telegram_without_token_is_clean_error(capsys, monkeypatch, tmp_path, fixture_path):
    monkeypatch.delenv("TG_BOT_TOKEN", raising=False)
    monkeypatch.delenv("TG_CHAT_ID", raising=False)
    code, _, err = run(
        capsys,
        "analyze",
        fixture_path("auth_sample.log"),
        "--telegram",
        "--env-file",
        str(tmp_path / "missing.env"),
    )
    assert code == 2
    assert "TG_BOT_TOKEN" in err


def test_telegram_send_flow(capsys, monkeypatch, fixture_path):
    sent = []

    class Fake:
        def __init__(self, *a, **kw):
            pass

        @classmethod
        def from_env(cls, timeout=10):
            return cls()

        def send_alert(self, alert):
            sent.append(alert)

        def send_text(self, text):
            sent.append(text)

    monkeypatch.setattr(cli, "TelegramNotifier", Fake)
    monkeypatch.setattr(cli.time, "sleep", lambda s: None)
    _, out, _ = run(
        capsys,
        "analyze",
        fixture_path("auth_sample.log"),
        "--telegram",
        "--min-severity",
        "critical",
    )
    assert len(sent) == 1 and sent[0].severity is Severity.CRITICAL
    assert "отправлено в Telegram: 1" in out


def test_send_alerts_caps_and_summarizes():
    sent = []

    class Fake:
        def send_alert(self, a):
            sent.append(a)

        def send_text(self, t):
            sent.append(t)

    lines = list(generate_lines())
    alerts = detect(iter_events(lines))
    n = send_alerts(Fake(), alerts, Severity.LOW, max_alerts=2, pause=0)
    assert n == 2
    assert isinstance(sent[-1], str) and "и ещё" in sent[-1]


def test_generate_demo_triggers_every_rule(capsys):
    code, out, _ = run(capsys, "generate", "--start", "2026-11-12T03:00:00")
    assert code == 0
    alerts = detect(iter_events(out.splitlines(), year=2026))
    assert {a.rule for a in alerts} == {
        "bruteforce",
        "success_after_fail",
        "spraying",
        "distributed",
        "scan",
    }


def test_generate_is_deterministic():
    assert list(generate_lines(seed=1)) == list(generate_lines(seed=1))


def test_example_config_allowlist_removes_ci_false_positive(capsys, tmp_path):
    log = tmp_path / "demo.log"
    run(capsys, "generate", "--start", "2026-11-12T03:00:00", "-o", str(log))
    _, without, _ = run(capsys, "analyze", str(log), "--format", "json")
    _, with_cfg, _ = run(
        capsys,
        "analyze",
        str(log),
        "--format",
        "json",
        "-c",
        str(ROOT / "config.example.yaml"),
    )
    ips = lambda doc: {a["ip"] for a in json.loads(doc)["alerts"]}  # noqa: E731
    assert "10.0.5.20" in ips(without)
    assert "10.0.5.20" not in ips(with_cfg)


# --- watch / tail -f -------------------------------------------------------------------------


def test_follow_file_reads_appended_lines_and_survives_rotation(tmp_path):
    path = tmp_path / "auth.log"
    path.write_text("old line\n")
    got: list[str] = []

    def writer():
        time.sleep(0.15)
        with open(path, "a") as f:
            f.write("line 1\nline ")
            f.flush()
            time.sleep(0.1)
            f.write("2\n")  # дописанная в два приёма строка не должна разорваться
        time.sleep(0.15)
        path.rename(tmp_path / "auth.log.1")  # logrotate
        path.write_text("after rotation\n")

    t = threading.Thread(target=writer)
    t.start()
    for line in follow_file(str(path), interval=0.02, idle_timeout=0.6):
        got.append(line)
    t.join()
    assert got == ["line 1", "line 2", "after rotation"]


def test_watch_emits_alerts(capsys, monkeypatch, tmp_path, fixture_path):
    log = tmp_path / "auth.log"
    log.write_text(Path(fixture_path("auth_sample.log")).read_text())

    real_follow = cli.follow_file

    def finite_follow(path, from_start, interval, heartbeat=False):
        return real_follow(path, from_start, 0.01, idle_timeout=0.1, heartbeat=heartbeat)

    monkeypatch.setattr(cli, "follow_file", finite_follow)
    code, out, _ = run(capsys, "watch", str(log), "--from-start", "--format", "json")
    assert code == 0
    events = [json.loads(line) for line in out.splitlines()]
    assert {e["rule"] for e in events} == {"bruteforce", "success_after_fail"}
    assert all(e["event"] == "alert" for e in events)

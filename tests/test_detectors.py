from __future__ import annotations

from datetime import timedelta

from conftest import T0, ev

from log_analyzer.config import Allowlist, DetectionConfig
from log_analyzer.detectors import Detector, detect
from log_analyzer.models import EventType, Severity

CFG = DetectionConfig(window=60, threshold=5)


def rules(alerts):
    return sorted(a.rule for a in alerts)


# --- step 7: sliding window ------------------------------------------------------------


def test_six_failures_in_12_seconds_alerts():
    events = [ev(i * 2) for i in range(6)]
    alerts = detect(events, CFG)
    assert rules(alerts) == ["bruteforce"]
    assert alerts[0].count == 6  # 5th created the alert, 6th was added to it


def test_six_failures_five_minutes_apart_no_alert():
    events = [ev(i * 300) for i in range(6)]
    assert detect(events, CFG) == []


def test_threshold_boundary():
    assert detect([ev(i) for i in range(4)], CFG) == []
    assert rules(detect([ev(i) for i in range(5)], CFG)) == ["bruteforce"]


def test_window_slides():
    # 4 failures, a pause longer than the window, 4 more: no window has 5
    events = [ev(i) for i in range(4)] + [ev(120 + i) for i in range(4)]
    assert detect(events, CFG) == []


def test_bruteforce_on_root_is_high_other_users_medium():
    root = detect([ev(i, user="root") for i in range(5)], CFG)
    other = detect([ev(i, user="alice") for i in range(5)], CFG)
    assert root[0].severity is Severity.HIGH
    assert other[0].severity is Severity.MEDIUM


def test_severity_escalates_when_root_appears_later():
    events = [ev(i, user="alice") for i in range(5)] + [ev(10, user="root")]
    [a] = detect(events, CFG)
    assert a.severity is Severity.HIGH


def test_bruteforce_fixture(load):
    alerts = detect(load("auth_bruteforce.log"), CFG)
    assert rules(alerts) == ["bruteforce"]
    a = alerts[0]
    assert a.ip == "198.51.100.23"
    assert a.severity is Severity.HIGH
    assert a.count == 30
    assert a.users["root"] == 15
    assert a.mitre == ["T1110.001"]


# --- step 8: success after brute force--------------------------------------------------


def test_success_after_fail_sample_fixture(load):
    alerts = detect(load("auth_sample.log"), CFG)
    crit = [a for a in alerts if a.severity is Severity.CRITICAL]
    assert len(crit) == 1
    assert crit[0].ip == "203.0.113.5"
    assert crit[0].compromised_user == "root"
    assert crit[0].count == 6
    assert "T1078" in crit[0].mitre


def test_success_after_fail_fixture(load):
    alerts = detect(load("auth_success_after_fail.log"), CFG)
    assert rules(alerts) == ["bruteforce", "success_after_fail"]
    crit = next(a for a in alerts if a.rule == "success_after_fail")
    assert crit.severity is Severity.CRITICAL
    assert crit.count == 8
    assert any("Accepted password for root" in d for d in crit.details)


def test_typo_then_login_is_not_critical():
    events = [ev(0, user="denis"), ev(5, user="denis"), ev(10, EventType.ACCEPTED, user="denis")]
    assert detect(events, CFG) == []


def test_success_long_after_failures_is_not_critical():
    cfg = DetectionConfig(window=60, threshold=5, success_lookback=3600)
    events = [ev(i * 300) for i in range(6)] + [ev(6 * 3600, EventType.ACCEPTED)]
    assert detect(events, cfg) == []


def test_clean_traffic_no_alerts(load):
    events = load("auth_clean.log")
    assert events  # something was parsed
    assert detect(events, CFG) == []


# --- level 2: spraying, distributed attack, cooldown ------------------------------------------


def test_spraying_fixture(load):
    alerts = detect(load("auth_spraying.log"), CFG)
    assert rules(alerts) == ["spraying"]
    a = alerts[0]
    assert a.mitre == ["T1110.003"]
    assert len(a.users) == 8  # alert created at the 5th username and kept accumulating
    assert a.count == 8


def test_fast_multi_user_bruteforce_not_double_reported_as_spraying():
    users = ["root", "admin", "test", "oracle", "ubuntu", "pi", "git"]
    events = [ev(i, user=u) for i, u in enumerate(users)]
    assert rules(detect(events, CFG)) == ["bruteforce"]


def test_distributed_fixture(load):
    alerts = detect(load("auth_distributed.log"), CFG)
    assert rules(alerts) == ["distributed"]
    a = alerts[0]
    assert a.key == "deploy"
    assert a.severity is Severity.HIGH
    assert len(a.ips) == 7
    assert a.count == 14


def test_scan_low():
    events = [ev(i * 2, EventType.PREAUTH_CLOSE, user="") for i in range(10)]
    [a] = detect(events, CFG)
    assert a.rule == "scan"
    assert a.severity is Severity.LOW


def test_cooldown_dedup_long_attack_is_one_alert():
    # hour-long attack: a failure every 5 seconds → 720 events, but one alert
    events = [ev(i * 5) for i in range(720)]
    alerts = detect(events, DetectionConfig(window=60, threshold=5, cooldown=900))
    assert rules(alerts) == ["bruteforce"]
    assert alerts[0].count == 720
    assert alerts[0].last_seen - alerts[0].first_seen == timedelta(seconds=719 * 5)


def test_new_alert_after_quiet_period_longer_than_cooldown():
    cfg = DetectionConfig(window=60, threshold=5, cooldown=900)
    events = [ev(i) for i in range(5)] + [ev(2000 + i) for i in range(5)]
    assert rules(detect(events, cfg)) == ["bruteforce", "bruteforce"]


def test_expire_returns_grown_alerts_for_summary_and_gc():
    d = Detector(DetectionConfig(window=60, threshold=5, cooldown=900))
    for i in range(20):
        d.process(ev(i))
    assert d.expire(T0 + timedelta(seconds=100)) == []  # still in cooldown
    finished = d.expire(T0 + timedelta(hours=3))
    assert [a.count for a in finished] == [20]
    assert not d.active and not d.fail_window and not d.fail_history


def test_process_returns_only_new_alerts():
    d = Detector(CFG)
    new = [a for i in range(10) for a in d.process(ev(i))]
    assert len(new) == 1
    assert len(d.alerts) == 1


# --- step 10: allowlist ------------------------------------------------------------------------


def test_allowlist_suppresses_ci_runner(load):
    events = load("auth_ci_runner.log")
    assert rules(detect(events, CFG)) == ["bruteforce"]  # without the allowlist: false positive
    d = Detector(CFG, Allowlist(["10.0.5.0/24"]))
    assert d.run(events) == []
    assert d.allowlisted == len(events)


def test_allowlist_single_ip_and_ipv4_mapped():
    al = Allowlist(["192.0.2.10", "2001:db8::/32"])
    assert "192.0.2.10" in al
    assert "::ffff:192.0.2.10" in al
    assert "2001:db8::1" in al
    assert "192.0.2.11" not in al
    assert "garbage" not in al

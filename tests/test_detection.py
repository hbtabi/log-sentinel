from datetime import datetime, timedelta

import pytest

from logsentinel.analyze import analyze_events
from logsentinel.anomaly import detect_anomalies
from logsentinel.parsers import Event, parse_lines
from logsentinel.rules import RuleConfig, run_rules
from logsentinel.simulate import generate_access_log, generate_auth_log


@pytest.fixture(scope="module")
def events():
    return list(parse_lines(generate_auth_log())) + list(parse_lines(generate_access_log()))


@pytest.fixture(scope="module")
def report(events):
    return analyze_events(events, ["auth.log", "access.log"])


def _rules(report):
    return {(f.rule, f.ip) for f in report.findings}


def test_every_injected_attack_is_caught(report):
    r = _rules(report)
    assert ("ssh_brute_force", "203.0.113.45") in r
    assert ("login_after_brute_force", "203.0.113.45") in r
    assert ("password_spray", "203.0.113.80") in r
    assert ("web_scanning", "198.51.100.23") in r
    assert ("sensitive_path_probe", "198.51.100.23") in r
    assert ("injection_attempt", "203.0.113.77") in r
    assert any(f.rule == "sensitive_sudo" for f in report.findings)


def test_no_rule_findings_for_normal_users(report):
    flagged = {f.ip for f in report.findings}
    assert not flagged & {"10.20.0.11", "10.20.0.12", "10.20.0.15", "10.20.0.21"}


def test_findings_sorted_by_severity(report):
    assert report.findings[0].severity == "critical"


def test_anomalies_cover_attacks_without_rules(report):
    ips = {a.ip for a in report.anomalies}
    assert "192.0.2.150" in ips  # bulk download - no rule for it
    assert "192.0.2.200" in ips  # valid login, rare IP, 3am - no rule for it
    assert all(a.reasons for a in report.anomalies)


def test_brute_force_threshold_respected():
    t0 = datetime(2026, 1, 1, 12)
    evs = [Event(t0 + timedelta(seconds=i * 10), "auth", "auth_failure", "192.0.2.9", "root", raw=f"l{i}") for i in range(9)]
    assert not [f for f in run_rules(evs) if f.rule == "ssh_brute_force"]
    assert [f for f in run_rules(evs, RuleConfig(brute_force_threshold=5)) if f.rule == "ssh_brute_force"]


def test_slow_failures_outside_window_are_not_brute_force():
    t0 = datetime(2026, 1, 1, 12)
    evs = [Event(t0 + timedelta(minutes=i * 10), "auth", "auth_failure", "192.0.2.9", "root") for i in range(20)]
    assert not [f for f in run_rules(evs) if f.rule == "ssh_brute_force"]


def test_successful_injection_is_critical():
    t0 = datetime(2026, 1, 1, 12)
    evs = [Event(t0, "web", "request", "192.0.2.5", path="/item?id=1%20UNION%20SELECT%20password%20FROM%20users", status=200)]
    f = [f for f in run_rules(evs) if f.rule == "injection_attempt"][0]
    assert f.severity == "critical"


def test_anomaly_needs_enough_data():
    t0 = datetime(2026, 1, 1)
    evs = [Event(t0 + timedelta(hours=i), "web", "request", "192.0.2.1", path="/", status=200) for i in range(5)]
    assert detect_anomalies(evs) == []


def test_json_roundtrip(report):
    import json

    d = json.loads(report.to_json())
    assert d["events"] == len(report.events) and d["severity_counts"]["critical"] >= 1

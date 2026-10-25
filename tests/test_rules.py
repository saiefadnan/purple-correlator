"""Tests for purple.rules."""

from purple.models import LogEntry
from purple.rules import (
    _group_by_ip,
    run_all_rules,
    rule_path_enumeration,
    rule_login_bruteforce,
    PATH_ENUM_THRESHOLD,
    LOGIN_BRUTEFORCE_THRESHOLD,
)


def entry(ip, path, method="GET", status=200, ts="2026-10-18T10:00:00+00:00"):
    """Build a LogEntry with sensible defaults for tests."""
    return LogEntry(ip=ip, timestamp=ts, method=method, path=path, status=status)


def test_group_by_ip_splits_sources():
    entries = [entry("1.1.1.1", "/a"), entry("2.2.2.2", "/b"), entry("1.1.1.1", "/c")]
    by_ip = _group_by_ip(entries)
    assert len(by_ip) == 2
    assert len(by_ip["1.1.1.1"]) == 2
    assert len(by_ip["2.2.2.2"]) == 1


def test_path_enumeration_fires_over_threshold():
    entries = [entry("9.9.9.9", f"/p{i}") for i in range(PATH_ENUM_THRESHOLD)]
    dets = rule_path_enumeration(_group_by_ip(entries))
    assert len(dets) == 1
    assert dets[0].rule == "path_enumeration"
    assert dets[0].source_ip == "9.9.9.9"


def test_path_enumeration_quiet_under_threshold():
    entries = [entry("9.9.9.9", "/a"), entry("9.9.9.9", "/b"), entry("9.9.9.9", "/c")]
    assert rule_path_enumeration(_group_by_ip(entries)) == []


def test_login_bruteforce_counts_only_post_login():
    posts = [entry("5.5.5.5", "/login", method="POST", status=401)
             for _ in range(LOGIN_BRUTEFORCE_THRESHOLD)]
    noise = [entry("5.5.5.5", "/home"), entry("5.5.5.5", "/login")]  # GETs ignored
    dets = rule_login_bruteforce(_group_by_ip(posts + noise))
    assert len(dets) == 1
    assert dets[0].rule == "login_bruteforce"
    assert dets[0].count == LOGIN_BRUTEFORCE_THRESHOLD


def test_run_all_rules_combines():
    # Same IP: many distinct paths (path_enumeration) + repeated POST /login
    # (login_bruteforce).
    entries = [entry("7.7.7.7", f"/p{i}") for i in range(PATH_ENUM_THRESHOLD)]
    entries += [entry("7.7.7.7", "/login", method="POST", status=401)
                for _ in range(LOGIN_BRUTEFORCE_THRESHOLD)]
    rules_fired = {d.rule for d in run_all_rules(entries)}
    assert "path_enumeration" in rules_fired
    assert "login_bruteforce" in rules_fired

"""Tests for purple.correlate."""

from purple.models import Detection
from purple.correlate import to_findings


def detection(rule):
    """A minimal Detection for correlation tests."""
    return Detection(
        rule=rule,
        source_ip="1.2.3.4",
        first_seen="2026-10-18T10:00:00+00:00",
        last_seen="2026-10-18T10:00:05+00:00",
        count=5,
        sample_paths=["/admin"],
    )


def test_known_rule_maps_to_technique():
    findings = to_findings([detection("path_enumeration")])
    assert len(findings) == 1
    assert findings[0].technique_id == "T1595.003"


def test_unknown_rule_skipped():
    assert to_findings([detection("made_up_rule")]) == []


def test_detection_preserved_in_finding():
    findings = to_findings([detection("login_bruteforce")])
    assert len(findings) == 1
    assert findings[0].detection.source_ip == "1.2.3.4"
    assert isinstance(findings[0].tactic, str) and findings[0].tactic

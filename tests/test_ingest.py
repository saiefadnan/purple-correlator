"""Tests for purple.ingest."""

from purple.ingest import parse_line, parse_file

GOOD = ('198.51.100.7 - - [18/Oct/2026:10:05:00 +0000] '
        '"GET /admin HTTP/1.1" 404 512 "-" "gobuster/3.6"')


def test_parse_good_line_fields():
    e = parse_line(GOOD)
    assert e is not None
    assert e.ip == "198.51.100.7"
    assert e.method == "GET"
    assert e.path == "/admin"
    assert e.status == 404
    assert isinstance(e.status, int)


def test_parse_timestamp_is_iso():
    assert parse_line(GOOD).timestamp == "2026-10-18T10:05:00+00:00"


def test_bad_line_returns_none():
    assert parse_line("this is not a log line") is None


def test_parse_file_counts(tmp_path):
    p = tmp_path / "access.log"
    p.write_text(GOOD + "\n" + "junk line\n" + GOOD + "\n")
    entries = parse_file(str(p))
    assert len(entries) == 2

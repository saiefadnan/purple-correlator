"""Detection rules: turn a stream of LogEntry objects into Detections.

Each rule looks for one attacker behaviour pattern, per source IP. This is the
heart of the tool — the detection logic is YOUR JOB.

A rule groups entries by source IP, then decides whether that IP's activity
matches the pattern. If it does, it emits one Detection naming the rule.

Thresholds below are deliberate knobs — tune them.
"""

from __future__ import annotations

from collections import defaultdict

from purple.models import LogEntry, Detection


# Paths that are interesting on their own (one hit is suspicious).
SENSITIVE_PATHS = {"/.git", "/.env", "/admin", "/backup", "/wp-login.php",
                   "/phpmyadmin", "/.git/config"}

# How many distinct paths from one IP counts as enumeration.
PATH_ENUM_THRESHOLD = 10
# How many 404s from one IP counts as a status sweep.
STATUS_SWEEP_THRESHOLD = 10
# How many POSTs to a login path from one IP counts as brute force.
LOGIN_BRUTEFORCE_THRESHOLD = 5
LOGIN_PATHS = {"/login", "/wp-login.php", "/admin/login"}


def _group_by_ip(entries: list[LogEntry]) -> dict[str, list[LogEntry]]:
    """Group entries by source IP.

    TODO: implement. Hint: a collections.defaultdict(list), append each entry
    under entry.ip, return it.
    """
    by_ip = defaultdict(list)
    for entry in entries:
        by_ip[entry.ip].append(entry)
    return by_ip


def _make_detection(rule: str, ip: str, entries: list[LogEntry]) -> Detection:
    """Build a Detection from the entries that supported a rule.

    TODO: implement.
      first_seen = min timestamp, last_seen = max timestamp (the ISO strings
      sort correctly, so min()/max() on entry.timestamp work).
      count = len(entries). sample_paths = up to 5 distinct paths.
    """
    first_seen = min(entry.timestamp for entry in entries)
    last_seen = max(entry.timestamp for entry in entries)
    count = len(entries)
    sample_paths = list({entry.path for entry in entries})[:5]
    return Detection(
        rule=rule,
        source_ip=ip,
        first_seen=first_seen,
        last_seen=last_seen,
        count=count,
        sample_paths=sample_paths
    )


def rule_path_enumeration(by_ip: dict[str, list[LogEntry]]) -> list[Detection]:
    """One IP requesting many DISTINCT paths = wordlist/path enumeration.

    TODO: implement.
      For each ip, count distinct paths. If >= PATH_ENUM_THRESHOLD, emit a
      Detection with rule name "path_enumeration".
    """

    out =[]
    for ip, entries in by_ip.items():
        distinct = {entry.path for entry in entries}
        if len(distinct) >= PATH_ENUM_THRESHOLD:
            out.append(_make_detection("path_enumeration", ip, entries))
    return out


def rule_status_sweep(by_ip: dict[str, list[LogEntry]]) -> list[Detection]:
    """One IP generating many 404s = scanning for things that are not there.

    TODO: implement. Count entries with status == 404 per IP; if
    >= STATUS_SWEEP_THRESHOLD, emit "status_sweep".
    """
    out =[]
    for ip, entries in by_ip.items():
        not_found = [entry for entry in entries if entry.status == 404]
        if len(not_found) >= STATUS_SWEEP_THRESHOLD:
            out.append(_make_detection("status_sweep", ip, not_found))
    return out


def rule_login_bruteforce(by_ip: dict[str, list[LogEntry]]) -> list[Detection]:
    """One IP POSTing to a login path many times = brute force.

    TODO: implement. Count entries where method == "POST" and path in
    LOGIN_PATHS; if >= LOGIN_BRUTEFORCE_THRESHOLD, emit "login_bruteforce".
    """
    out =[]
    for ip, entries in by_ip.items():
        hits = [entry for entry in entries if entry.method == "POST" and entry.path in LOGIN_PATHS]
        if len(hits) >= LOGIN_BRUTEFORCE_THRESHOLD:
            out.append(_make_detection("login_bruteforce", ip, hits))
    return out


def rule_sensitive_path(by_ip: dict[str, list[LogEntry]]) -> list[Detection]:
    """One IP touching a sensitive path at all = directory discovery.

    TODO: implement. If any of an IP's paths is in SENSITIVE_PATHS, emit
    "sensitive_path" (only the matching entries support it).
    """
    out =[]
    for ip, entries in by_ip.items():
        hits = [entry for entry in entries if entry.path in SENSITIVE_PATHS]
        if hits:
            out.append(_make_detection("sensitive_path", ip, hits))
    return out


def run_all_rules(entries: list[LogEntry]) -> list[Detection]:
    """Group once, run every rule, concatenate the Detections.

    TODO: implement. by_ip = _group_by_ip(entries); call each rule_* with
    by_ip; return the combined list.
    """
    by_ip = _group_by_ip(entries)
    detections = []
    detections += rule_path_enumeration(by_ip)
    detections += rule_status_sweep(by_ip)
    detections += rule_login_bruteforce(by_ip)
    detections += rule_sensitive_path(by_ip)
    return detections

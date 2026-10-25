"""Parse HTTP access-log lines into LogEntry objects.

Target format: the Combined Log Format that Apache/nginx emit by default:

    127.0.0.1 - - [10/Oct/2026:13:55:36 +0000] "GET /admin HTTP/1.1" 404 512 "-" "curl/8.0"

Fields you need: client IP, timestamp, method, path, status, user-agent.

YOUR JOB: implement the two functions. Start here — pure parsing, no network,
easy to test against fixtures/sample_access.log.
"""

from __future__ import annotations

import re
from datetime import datetime

from purple.models import LogEntry


# A regex with named groups is the clean way to parse this. Named groups look
# like (?P<name>...) and you read them back with match.group("name").
_LINE_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) [^"]*" '
    r'(?P<status>\d{3}) \S+ "[^"]*" "(?P<ua>[^"]*)"'
)

# Apache time format inside the brackets, for strptime.
_TS_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


def parse_line(line: str) -> LogEntry | None:
    """Parse one access-log line into a LogEntry, or None if it does not match.

    TODO: implement.
      Steps:
        1. match = _LINE_RE.match(line.strip()); if no match, return None.
        2. Convert the Apache timestamp to ISO-8601:
           dt = datetime.strptime(match.group("ts"), _TS_FORMAT)
           iso = dt.isoformat()
        3. Build and return a LogEntry with ip, iso timestamp, method, path,
           int(status), user_agent=ua, raw=line.strip().
    """
    match = _LINE_RE.match(line.strip())
    if not match:
        return None
    dt = datetime.strptime(match.group("ts"), _TS_FORMAT)
    iso = dt.isoformat()
    return LogEntry(
        ip=match.group("ip"),
        timestamp=iso,
        method=match.group("method"),
        path=match.group("path"),
        status=int(match.group("status")),
        user_agent=match.group("ua"),
        raw=line.strip()
    )


def parse_file(path: str) -> list[LogEntry]:
    """Parse every line of an access-log file into LogEntry objects.

    Skip lines that do not parse (return None).

    TODO: implement.
      Open the file, parse_line each line, collect the non-None results.
    """
    with open(path, "r") as f:
        return [entry for line in f if (entry := parse_line(line)) is not None]

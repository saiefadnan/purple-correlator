"""Data model for the correlation pipeline.

Plain dataclasses so everything serializes with `dataclasses.asdict`.
Three stages of data:
  LogEntry   one parsed line from an access log (raw fact)
  Detection  a rule fired: some entries matched an attacker pattern
  Finding    a Detection joined to its ATT&CK technique (reportable)
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class LogEntry:
    """One HTTP access-log line, parsed into fields."""

    ip: str
    timestamp: str          # ISO-8601 string
    method: str             # GET, POST, ...
    path: str               # /admin, /login, ...
    status: int             # 200, 404, ...
    user_agent: str = ""
    raw: str = ""           # the original line, kept for evidence


@dataclass
class Detection:
    """One rule firing against a group of log entries."""

    rule: str                       # rule name, e.g. "path_enumeration"
    source_ip: str                  # who did it
    first_seen: str                 # ISO timestamp of earliest entry
    last_seen: str                  # ISO timestamp of latest entry
    count: int                      # how many entries supported it
    sample_paths: list[str] = field(default_factory=list)


@dataclass
class Finding:
    """A Detection joined to the ATT&CK technique it maps to."""

    technique_id: str               # e.g. "T1595.003"
    technique_name: str             # e.g. "Wordlist Scanning"
    tactic: str                     # e.g. "Reconnaissance"
    detection: Detection

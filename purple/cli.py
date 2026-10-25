"""Command-line entry point.

Pipeline: access log -> LogEntry list -> Detections -> Findings -> report.
Wire it once the modules work.
"""

from __future__ import annotations

import argparse

from purple.ingest import parse_file
from purple.rules import run_all_rules
from purple.correlate import to_findings
from purple.report import write_all


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """TODO: argparse. Positional: logfile. Option: --out (default ./out).

    Return the parsed namespace.
    """
    p = argparse.ArgumentParser(prog="purple", description="HTTP log -> ATT&CK correlator")
    p.add_argument("logfile")
    p.add_argument("--out", default="./out")
    return p.parse_args(argv)

def main(argv: list[str] | None = None) -> None:
    """TODO: orchestrate.
      entries = parse_file(args.logfile)
      detections = run_all_rules(entries)
      findings = to_findings(detections)
      j, m = write_all(findings, args.out or "./out")
      print the two paths, and a one-line summary like
      f"{len(entries)} log lines, {len(findings)} findings".
    """
    args = parse_args(argv)
    entries = parse_file(args.logfile)
    detections = run_all_rules(entries)
    findings = to_findings(detections)
    j, m = write_all(findings, args.out or "./out")
    print(f"{len(entries)} log lines, {len(findings)} findings")
    print(f"JSON: {j}")
    print(f"Markdown: {m}")

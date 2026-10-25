"""JSON + Markdown reporting for Findings."""

from __future__ import annotations

import json
import os
from dataclasses import asdict

from purple.models import Finding


def write_json(findings: list[Finding], out_dir: str) -> str:
    """Write findings.json and return its path.

    TODO: implement. json.dump([asdict(f) for f in findings], fh, indent=2).
    """
    path = os.path.join(out_dir, "findings.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump([asdict(f) for f in findings], fh, indent=2)
    return path


def write_markdown(findings: list[Finding], out_dir: str) -> str:
    """Write an ATT&CK-ordered findings.md and return its path.

    Suggested layout: a header with totals, then one section per finding,
    newest activity first, each showing technique id + name + tactic, the
    source IP, the time window, the count, and sample paths.

    TODO: implement (build a list of lines, "\\n".join, write it).
    """
    path = os.path.join(out_dir, "findings.md")
    lines = [
        "# ATT&CK Correlation Report",
        "",
        f"- Findings: {len(findings)}",
        "",
    ]

    for f in sorted(findings, key=lambda x: x.detection.last_seen, reverse=True):
        d = f.detection
        lines.append(f"## {f.technique_id} — {f.technique_name}")
        lines.append(f"- Tactic: {f.tactic}")
        lines.append(f"- Source IP: {d.source_ip}")
        lines.append(f"- Window: {d.first_seen} → {d.last_seen}")
        lines.append(f"- Events: {d.count}")
        lines.append(f"- Sample paths: {', '.join(d.sample_paths) or '—'}")
        lines.append("")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    return path

def write_all(findings: list[Finding], out_dir: str) -> tuple[str, str]:
    """makedirs(out_dir), write both, return (json_path, md_path).

    TODO: implement.
    """
    os.makedirs(out_dir, exist_ok=True)
    json_path = write_json(findings, out_dir)
    md_path = write_markdown(findings, out_dir)
    return json_path, md_path

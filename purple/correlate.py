"""Join Detections to ATT&CK techniques, producing Findings."""

from __future__ import annotations

from purple.models import Detection, Finding
from purple.attack import TECHNIQUES, RULE_TO_TECHNIQUE


def to_findings(detections: list[Detection]) -> list[Finding]:
    """Map each Detection to its ATT&CK technique.

    TODO: implement.
      For each detection:
        tid = RULE_TO_TECHNIQUE[detection.rule]
        name, tactic = TECHNIQUES[tid]
        build a Finding(technique_id=tid, technique_name=name, tactic=tactic,
                        detection=detection)
      Skip a detection whose rule is not in RULE_TO_TECHNIQUE (defensive).
    """
    findings = []
    for detection in detections:
      if detection.rule in RULE_TO_TECHNIQUE:
        tid = RULE_TO_TECHNIQUE[detection.rule]
        name, tactic = TECHNIQUES[tid]
        findings.append(Finding(
          technique_id=tid,
          technique_name=name,
          tactic=tactic,
          detection=detection
        ))
    return findings

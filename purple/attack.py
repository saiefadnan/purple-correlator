"""A small, local slice of the MITRE ATT&CK catalog.

Only the techniques this tool can detect from HTTP logs. Each rule name maps
to one technique. This is reference data (given) — not something to implement.

Full catalog: https://attack.mitre.org/ — kept offline here on purpose.
"""

from __future__ import annotations

# technique_id -> (name, tactic)
TECHNIQUES: dict[str, tuple[str, str]] = {
    "T1595":     ("Active Scanning", "Reconnaissance"),
    "T1595.003": ("Wordlist Scanning", "Reconnaissance"),
    "T1046":     ("Network Service Discovery", "Discovery"),
    "T1083":     ("File and Directory Discovery", "Discovery"),
    "T1110":     ("Brute Force", "Credential Access"),
    "T1190":     ("Exploit Public-Facing Application", "Initial Access"),
}

# rule name (from rules.py) -> technique_id
RULE_TO_TECHNIQUE: dict[str, str] = {
    "path_enumeration":   "T1595.003",
    "status_sweep":       "T1595",
    "login_bruteforce":   "T1110",
    "sensitive_path":     "T1083",
}

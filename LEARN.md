# Build log — Purple-Team Correlator

You drive, Claude reviews. Given to you: `models.py` (data shapes) and
`attack.py` (the ATT&CK catalog — reference data). Everything else is yours.

## Setup

```bash
cd purple-correlator
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
```

---

## Milestone 1 — `ingest.py` (start here)

Pure parsing, offline, testable. Implement `parse_line`, then `parse_file`.

Check:
```bash
python -c "from purple.ingest import parse_line; \
e = parse_line('198.51.100.7 - - [18/Oct/2026:10:05:00 +0000] \"GET /admin HTTP/1.1\" 404 512 \"-\" \"gobuster/3.6\"'); \
print(e.ip, e.method, e.path, e.status)"
# expect: 198.51.100.7 GET /admin 404
```

Then parse the fixture:
```bash
python -c "from purple.ingest import parse_file; print(len(parse_file('fixtures/sample_access.log')))"
# expect: 22
```

---

## Milestone 2 — `rules.py`

The core. Implement helpers `_group_by_ip`, `_make_detection`, then the four
`rule_*` functions, then `run_all_rules`.

Check against the fixture (after ingest works):
```bash
python -c "from purple.ingest import parse_file; from purple.rules import run_all_rules; \
d = run_all_rules(parse_file('fixtures/sample_access.log')); \
print([(x.rule, x.source_ip, x.count) for x in d])"
# expect detections for 198.51.100.7 (path_enumeration, status_sweep,
# sensitive_path) and 192.0.2.55 (login_bruteforce)
```

---

## Milestone 3 — `correlate.py`

Implement `to_findings`. Joins each Detection to its ATT&CK technique.

Check:
```bash
python -c "from purple.ingest import parse_file; from purple.rules import run_all_rules; \
from purple.correlate import to_findings; \
f = to_findings(run_all_rules(parse_file('fixtures/sample_access.log'))); \
print([(x.technique_id, x.technique_name) for x in f])"
```

---

## Milestone 4 — `report.py` + `cli.py`

Implement the writers, then wire the CLI. Full run:
```bash
python -m purple fixtures/sample_access.log --out ./out
cat out/findings.md
```

---

## Milestone 5 — real lab logs

Attack a lab target, then correlate its real log:
```bash
# attack (from attack-surface-mapper, or curl a wordlist of paths)
# then:
docker logs lab-dvwa > /tmp/dvwa.log 2>&1
python -m purple /tmp/dvwa.log
```
See your own recon mapped to ATT&CK. Loop closed: you are both red and blue.

---

## Tests (after Milestone 2)

Fill `tests/` — `parse_line` and the rules are pure functions, easy to assert.

## Rules

- You write the logic. Claude reviews.
- Paste exact errors.

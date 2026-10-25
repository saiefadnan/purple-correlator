# purple — HTTP log → MITRE ATT&CK correlator

A purple-team tool. It reads HTTP access logs, detects attacker behaviour
patterns (scanning, path enumeration, brute force), and maps each one to a
MITRE ATT&CK technique. The output is the defender's view of an attack: which
techniques ran, from which source, when.

Pair it with the sibling projects: attack your `lab-builder` targets with
`attack-surface-mapper` (or a scanner), then feed the targets' access logs
here to see your own activity mapped to ATT&CK.

> Use only on logs from systems you own or are authorized to analyze.

## Pipeline

```
access.log
   -> ingest.py     parse lines into LogEntry
   -> rules.py      detect per-IP attack patterns  -> Detection
   -> correlate.py  join Detection to ATT&CK        -> Finding
   -> report.py     findings.json + findings.md
```

## Detections (v1)

| Rule | Pattern | ATT&CK |
|------|---------|--------|
| `path_enumeration` | one IP requests many distinct paths | T1595.003 Wordlist Scanning |
| `status_sweep` | one IP generates many 404s | T1595 Active Scanning |
| `login_bruteforce` | one IP POSTs a login path repeatedly | T1110 Brute Force |
| `sensitive_path` | one IP touches `/.git`, `/.env`, … | T1083 File and Directory Discovery |

## Install

```bash
cd purple-correlator
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt     # stdlib only at runtime; pytest for tests
```

## Usage

```bash
python -m purple fixtures/sample_access.log --out ./out
```

Produces `out/findings.json` and `out/findings.md`.

## Feeding real lab logs

```bash
# from lab-builder, after attacking a target
docker logs lab-dvwa > /tmp/dvwa.log 2>&1
python -m purple /tmp/dvwa.log
```

## Roadmap

- Time-window rules (burst detection, not just totals)
- More techniques (T1190 exploitation signatures)
- nginx + JSON log formats
- Correlate across multiple target logs

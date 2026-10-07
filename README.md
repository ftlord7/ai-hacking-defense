# 🛡️ AI-Hacking Auto-Defense Scanner (MVP v0.1)
A **non-intrusive, zero-exfiltration** personal security self-audit for macOS.

## Why
AI-automated attacks now hit individuals, not just enterprises. This tool shows your
security score and exactly what to fix — without attacking anything and without
sending a single byte off your machine.

## Principles
- **Non-intrusive**: reads local settings/permissions/git/network only. No exploiting.
- **Zero-exfiltration**: 100% local. No network calls (no socket/urllib/requests imports — verify it yourself).
- **No value leakage**: secret *values* are never recorded — only their location.
- **Zero dependencies**: Python standard library only → easy single-binary / pip install.

## Install & run
    pip install ai-hacking-defense
    ai-hacking-defense     # or: python3 scan.py → security_report.html

## Checks: credentials · network · OS hardening · AI-agent risk · backup
## License: open-core (free core, paid Pro). Zero-exfil is verifiable in source.

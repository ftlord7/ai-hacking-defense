# 🛡️ AI-Hacking Self-Audit (MVP v0.1)
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

## Docs
- [Install (EN)](docs/INSTALL_EN.md) · [설치 (KO)](docs/INSTALL.md)
- [FAQ (EN)](docs/FAQ_EN.md) · [FAQ (KO)](docs/FAQ.md) · [Troubleshooting](docs/TROUBLESHOOTING.md)

## Feedback becomes releases
`ai-hacking-defense feedback` builds a masked, fully-previewed report draft — nothing is ever sent automatically; you submit it yourself on GitHub. Issues are collected into a backlog daily and shipped as releases with a public CHANGELOG, so your report visibly becomes the next version.

## Platforms (honest note)
macOS: all checks verified. Windows/Linux: experimental — runs, but not yet fully verified.

## Known limits (honest)
Detection catches common evasions, not all. Known gaps we have not closed yet:
- SSH private-key detection reads the PEM header in the first 8KB; a key hidden past 8KB, or in a non-PEM container (e.g. PuTTY `.ppk`), may be missed.
- Backup freshness rejects future-dated and empty commits, but a single trivial commit made just now still counts as a "recent backup" — it does not verify the backup is meaningful or restorable.
- Wi-Fi checks read only your own current connection (encryption type, DNS servers, ARP for gateway-MAC duplication). Router-side items (WPS, the default admin password, firmware) are off-device and are NOT auto-checked — check them yourself in the router admin page. A duplicated gateway MAC is reported as a *possible* MITM, not a verdict (proxy ARP, mesh routers, or a VPN can cause it legitimately).
- Vault/secret-access detection catches common obfuscations (base64, bidi, whitespace/quote split, and bare interpreter reads like `open(vault).read()`), but it is best-effort, not a guarantee: a read assigned to a variable and then printed/sent, a tab-escaped command (e.g. `ca` + TAB + `t`), or copying/sourcing the file (`cp`, `source`) can still be missed — new evasions always exist.
- Detection rates (e.g. a 72-cell internal battery) are measured on our own corpora; real-world coverage will differ, and new evasions always exist.


## What's in the package (v0.1.7)
Three stdlib-only command-line tools:
- `ahd-scan` (also `ai-hacking-defense`) — the 6-area security self-audit (now incl. Wi-Fi) + HTML report. **Zero network.**
- `ahd-agent-guard` — prompt-injection detector (warn-only, no blocking). On a public *prompt-injection* evasion corpus it detects 29/30 (96.7%) at 0 false positives in our test. **This 96.7% is the injection detector's rate on that one corpus — not an overall "defense rate" across every attack type.** **Zero network.** `echo "<text>" | ahd-agent-guard`
- `ahd-threat-feed` — refreshes public vulnerability feeds (OSV, CISA KEV, EPSS) to a local cache. **GET-only** of public databases from a fixed allowlist — none of your data is ever sent.

### "Zero-exfiltration" precisely
`ahd-scan` and `ahd-agent-guard` make **no network calls at all**. `ahd-threat-feed` only *downloads* public vulnerability data (GET-only, allowlisted hosts) and uploads nothing. In all cases, **none of your files, secrets, or data ever leave your machine** — that is what zero-exfiltration means here.

### Not in the package (internal-only, not advertised)
This package detects and reports. It does **not** auto-block, run a background dashboard, or hook into your pipelines. "Warn-only" is literal — see each report card's limits.

### Reproduce the detection rate yourself
```
pip install ai-hacking-defense
python3 reproduce_detection.py   # prints detection % and false-positive % on a public evasion corpus
```
It reports **29/30 = 96.7% detection at 0 false positives** on our standard *prompt-injection* corpus (one honest miss: full letter-spacing). Scope note: this measures the prompt-injection detector only; other attack types (credential, vault, network) are measured separately and are lower — not rolled into a single "defense rate."

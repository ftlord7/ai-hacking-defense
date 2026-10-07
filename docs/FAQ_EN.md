# FAQ (English) — 12 questions
> 한국어: [FAQ.md](FAQ.md)

**1. Does my data leave my machine?**
No. Zero network transmission during a scan. Don't take our word for it — the code is open; there are no network calls (socket/urllib/requests) in the scan path. That's the whole point of this tool.

**2. Does it read my passwords or key values?**
Secret **values are never recorded**. We only tell you where a risk is (location and count).

**3. What does "watching" (warn-only) mean?**
We **notify** you of issues and do not block anything automatically. We refuse to make it look like automatic protection exists where it doesn't — that's a core principle.

**4. Does "0 findings" mean I'm safe?**
No. It means nothing was found **within what we check**. Zero-days and secrets outside known patterns can be missed.

**5. Does the tool fix or change anything?**
No. Read-only. No settings changed, no files modified, no blocking. We show the fix; you run it.

**6. Does it replace antivirus?**
No. It's a **configuration/exposure self-audit**, not a malware scanner. Use it alongside AV.

**7. A finding looks wrong — how do I report a false positive?**
`ai-hacking-defense feedback` → type 2 (false positive). You see the full payload first and submit it yourself on GitHub. False-positive reports feed directly into the next release.

**8. How often should I run it?**
Weekly is enough; run once more after installing new tools or changing settings. It's not resident — it only runs when you run it.

**9. Does it need admin (sudo)?**
No. It checks only what a normal user can read — which also means some system-level items are out of scope (honest limit).

**10. What can't it catch?**
Malware traces on an already-compromised machine, your router/outside-network paths, zero-days, secrets outside known patterns. Every card in the report lists its own limits.

**11. Does it work on Windows/Linux?**
It runs, but is **not fully verified yet (experimental)**. macOS is officially supported today.

**12. What happens to my feedback?**
Feedback becomes releases — issues are collected daily into a backlog, then improved → released → published in the CHANGELOG, so you can see where your report landed.

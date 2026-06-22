# 01 — Healthy coordinated disclosure (patch-before-public)

## Where the data came from

A small SaaS vendor ("ACME") runs a coordinated vulnerability disclosure (CVD)
program. These three records are reconstructed from the vendor's own internal
advisory tracker for Q2 2025. In every case the fix shipped **before** the
public advisory went out — the textbook coordinated-disclosure pattern.

The IDs are the vendor's internal advisory identifiers, not CVEs.

## What to expect

- Every advisory has a **patch date earlier than its disclosure date**, so
  `time_to_patch` is negative-by-design — but here we treat "patched before
  disclosed" as healthy and instead read the **report latency** (1 day, fast)
  and **disclosure gap** (~6 weeks embargo, normal for CVD).
- The `flags` command will surface `negative_window` notes because patch
  precedes disclosure. That is informational here: it confirms the vendor
  fixed first, then disclosed.
- No `exploited_before_patch`, no `unpatched`.

## Run it

```bash
vulntimeline build demos/01-coordinated-disclosure-healthy/advisories.json
vulntimeline metrics demos/01-coordinated-disclosure-healthy/advisories.json
vulntimeline flags demos/01-coordinated-disclosure-healthy/advisories.json
```

## How to act

This is your **baseline of good hygiene**. Use these report-latency and
disclosure-gap medians as the yardstick to compare noisier programs against.
If `flags` ever shows `exploited_before_patch` or `unpatched` for this program,
the coordinated process has broken down — investigate immediately.

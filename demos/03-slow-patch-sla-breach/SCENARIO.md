# 03 — Remediation-SLA breach review

## Where the data came from

An internal security team's quarterly remediation review. Three findings from the
internal app-sec tracker, two of which blew through the org's 30-day
remediation SLA for high-severity issues. IDs are internal ticket references.

## What to expect

- `INTERNAL-2025-0042`: ~107-day time-to-patch.
- `INTERNAL-2025-0044`: ~99-day time-to-patch.
- `INTERNAL-2025-0043`: ~21-day time-to-patch (within SLA).
- With `--max-ttp 30`, the two slow ones raise `slow_patch` flags; the compliant
  one does not.

## Run it

```bash
vulntimeline metrics demos/03-slow-patch-sla-breach/advisories.json
vulntimeline flags demos/03-slow-patch-sla-breach/advisories.json --max-ttp 30
vulntimeline flags demos/03-slow-patch-sla-breach/advisories.json --max-ttp 30 --json
```

## How to act

Use the `slow_patch` flags as the evidence backbone of an SLA-breach report to
engineering leadership. The `median time-to-patch` from `metrics` is the headline
number for the quarter. Pair this demo with a `--max-ttp` value matching your own
written SLA (e.g. 7 for critical, 30 for high) to generate audit-ready output.

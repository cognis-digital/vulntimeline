# 04 — Bug-bounty backlog triage (what's still open?)

## Where the data came from

An export from a bug-bounty triage queue. Reports come in already-disclosed to
the vendor (researcher → platform → vendor), so `reported` and `discovered`
collapse to the same day. Three are still open; one (`-1101`) was closed out
earlier in the year and is included as a control. IDs are bounty-platform
report numbers.

## What to expect

- `flags` raises `unpatched` for `BUG-BOUNTY-1187`, `-1203`, and `-1219`.
- `-1101` is clean (patched before disclosure).
- `metrics` shows `unpatched_count = 3` in the aggregate, and `-` in the TTP
  column for the three open items.

## Run it

```bash
vulntimeline flags demos/04-unpatched-backlog/advisories.json
vulntimeline metrics demos/04-unpatched-backlog/advisories.json
vulntimeline build demos/04-unpatched-backlog/advisories.json --no-ascii
```

## How to act

The `unpatched` flags are your **open-backlog worklist**, already sorted onto a
timeline by age (oldest first via `build`). `-1187` (SSTI, high, open ~10 weeks)
is the one to escalate. Re-run this weekly; the backlog count is a single,
trendable hygiene KPI.

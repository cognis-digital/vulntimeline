# 05 — Data-quality sweep (catching bad date entries)

## Where the data came from

A synthetic QA fixture used to validate a vulnerability tracker import. Each
record contains a deliberately inconsistent date ordering of the kind that
creeps in from manual entry: transposed fields, an impossible
reported-before-discovered, and a year typo. IDs label the specific defect.

## What to expect

- `QA-CHECK-001`: patched before disclosed → negative `time_to_patch`.
- `QA-CHECK-002`: reported before discovered → negative `report_latency`.
- `QA-CHECK-003`: disclosed before reported (year typo) → negative
  `disclosure_gap`.
- `flags` raises a `negative_window` finding for each, naming the offending
  window.

## Run it

```bash
vulntimeline flags demos/05-data-entry-errors/advisories.json
vulntimeline metrics demos/05-data-entry-errors/advisories.json
```

## How to act

`negative_window` is a **data-quality signal**, not a security finding — treat
it as a lint pass on your advisory database. Run this against a fresh export
before trusting any of the aggregate medians; a single transposed date can skew
a whole quarter's metrics. Fix the source records, then re-run the real reports.

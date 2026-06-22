# 06 — Merging feeds with mixed date formats

## Where the data came from

A consolidation job that stitched five upstream sources into one advisory set:
a vendor PSIRT JSON feed (ISO datetimes with a `Z`), a US-formatted spreadsheet
(`MM/DD/YYYY`), a ticketing export (`YYYY/MM/DD`), a human-written note with a
spelled-out month, and a compact log field (`YYYYMMDD`). Real consolidation work
always looks like this.

## What to expect

- `vulntimeline` normalises **all five formats** into the same chronological
  axis without any pre-processing — the whole point of this demo.
- `build --json` confirms every milestone parsed to a clean ISO date.
- All five sort correctly by anchor date in the timeline.

## Run it

```bash
vulntimeline build demos/06-mixed-date-formats/advisories.json
vulntimeline build demos/06-mixed-date-formats/advisories.json --json
vulntimeline metrics demos/06-mixed-date-formats/advisories.json
```

## How to act

Use this as the **integration smoke test** when wiring a new upstream feed: if
`build --json` returns ISO dates for every record, the parser handled the
format. If a record comes back with missing milestones it didn't expect, the
source format isn't supported — normalise it upstream before ingest.

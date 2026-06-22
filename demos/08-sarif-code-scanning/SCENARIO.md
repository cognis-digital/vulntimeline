# 08 — SARIF export into a code-scanning dashboard

## Where the data came from

A product PSIRT's advisory set for one device line, used to demonstrate the
`--sarif` exporter. The mix is deliberate: one exploited-before-patch critical,
one unpatched high, and one very-slow-patch low. IDs are PSIRT advisory labels.

## What to expect

`flags --sarif` emits a **SARIF 2.1.0** log:

- `runs[0].tool.driver.name == "vulntimeline"` with one rule per flag kind.
- Each finding becomes a `result` with a `ruleId`, a `level`
  (`error`/`warning`/`note` mapped from severity), a message, a logical
  location naming the advisory id, and a stable `partialFingerprints` entry so
  re-runs dedupe.
- With `--max-ttp 30`, `PSIRT-2025-79` adds a `slow_patch` result.

## Run it

```bash
vulntimeline flags demos/08-sarif-code-scanning/advisories.json --sarif
vulntimeline flags demos/08-sarif-code-scanning/advisories.json --max-ttp 30 --sarif \
  > vulntimeline.sarif
```

Validate the shape quickly:

```bash
python -c "import json,sys; d=json.load(open('vulntimeline.sarif')); \
print(d['version'], len(d['runs'][0]['results']), 'results')"
```

## How to act

Upload `vulntimeline.sarif` to any SARIF consumer — GitHub code scanning
(`github/codeql-action/upload-sarif`), Azure DevOps, or DefectDojo — to track
disclosure-hygiene findings next to your SAST/DAST results. The stable
fingerprints mean a finding that persists across runs stays a single tracked
alert rather than re-opening each time.

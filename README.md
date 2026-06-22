# vulntimeline

A vulnerability **disclosure timeline builder** for defensive security work.

`vulntimeline` ingests advisory records, orders them chronologically, computes
the key remediation windows (time-to-patch, exposure window, disclosure gap),
and flags risky patterns such as **exploited-before-patch** and **slow patch**.
It renders a human-readable Markdown + ASCII timeline, a metrics table, and
machine-readable JSON for pipelines.

It is **analytical and defensive only** — it measures and reports on how a
disclosure lifecycle played out. It does not perform any active testing.

- Standard library only (no third-party runtime dependencies)
- Python 3.10+
- Maintainer: **Cognis Digital**
- License: **COCL 1.0**

---

## Install

```bash
python -m pip install -e .
```

This installs the `vulntimeline` console command. You can also run it without
installing via `python -m vulntimeline`.

---

## Input format

A JSON file containing either a top-level list of advisory records, or an
object with an `advisories` key. Each record:

| Field        | Required | Notes                                              |
|--------------|----------|----------------------------------------------------|
| `id`         | yes      | unique identifier                                  |
| `title`      | no       | short description                                  |
| `severity`   | no       | `none`/`low`/`medium`/`high`/`critical` (or other) |
| `discovered` | no       | date the issue was found                           |
| `reported`   | no       | date reported to the vendor                        |
| `disclosed`  | no       | date of public disclosure                          |
| `exploited`  | no       | date exploitation was first observed               |
| `patched`    | no       | date a fix became available                        |

All date fields are optional and parsed robustly: ISO dates (`2025-02-10`),
ISO datetimes (`2025-02-05T09:30:00Z`), and common slashed/spelled formats are
accepted. Missing dates simply leave the corresponding windows undefined.

A worked example lives at [`examples/advisories.json`](examples/advisories.json).

---

## Usage

### `build` — chronological timeline

```bash
vulntimeline build examples/advisories.json
vulntimeline build examples/advisories.json --json
vulntimeline build examples/advisories.json --no-ascii --width 80
```

Renders a Markdown timeline followed by an ASCII lane chart. Each lane is one
advisory; glyphs are positioned by date along a shared axis:

```
Legend: D=Discovered  R=Reported  P=Disclosed  X=Exploited  +=Patched
```

`--json` emits ordered records with their dated milestones.

### `metrics` — remediation windows + aggregates

```bash
vulntimeline metrics examples/advisories.json
vulntimeline metrics examples/advisories.json --json
```

Per advisory:

- **time-to-patch** = `patched − disclosed`
- **disclosure gap** = `disclosed − reported`
- **report latency** = `reported − discovered`
- **exposure window** = `(patched or today) − exploited` (`*` = still open)
- **exploited-before-patch** flag

Plus aggregate medians and counts across the set.

### `flags` — risky-pattern detection

```bash
vulntimeline flags examples/advisories.json
vulntimeline flags examples/advisories.json --max-ttp 30
vulntimeline flags examples/advisories.json --max-ttp 30 --fail-on-any
vulntimeline flags examples/advisories.json --sarif
```

Detected flag kinds:

| Kind                     | Meaning                                                 |
|--------------------------|---------------------------------------------------------|
| `exploited_before_patch` | exploitation observed before a patch existed (or still unpatched) |
| `slow_patch`             | time-to-patch exceeds `--max-ttp N` days                |
| `unpatched`              | no patch date recorded                                  |
| `negative_window`        | a window is negative (inconsistent date ordering)       |

`--fail-on-any` makes the command exit with code **2** when any flag is
detected — useful as a CI quality gate. Otherwise exit code is `0`; input
errors exit `1`.

#### SARIF 2.1.0 export

```bash
vulntimeline flags examples/advisories.json --sarif > vulntimeline.sarif
vulntimeline flags examples/advisories.json --max-ttp 30 --sarif
```

`--sarif` emits a **SARIF 2.1.0** log instead of a table/JSON. Each flag becomes
a `result` with a `ruleId` (the flag kind), a `level` (`error`/`warning`/`note`
mapped from severity), a logical location naming the advisory id, and a stable
`partialFingerprints` entry so re-runs dedupe in dashboards. Upload it to any
SARIF consumer — GitHub code scanning (`github/codeql-action/upload-sarif`),
Azure DevOps, or DefectDojo — to track disclosure-hygiene findings alongside
your SAST/DAST results. `--fail-on-any` still gates the exit code when combined
with `--sarif`.

---

## Demos

Realistic, self-contained scenarios live under [`demos/`](demos/). Each holds an
`advisories.json` in the real input format plus a `SCENARIO.md` describing where
the data came from, what to expect, the exact command to run, and how to act.

| Demo | Scenario |
|------|----------|
| [`01-coordinated-disclosure-healthy`](demos/01-coordinated-disclosure-healthy/) | Patch-before-public CVD baseline of good hygiene |
| [`02-zero-day-exploited-first`](demos/02-zero-day-exploited-first/) | Actively-exploited edge-appliance zero-days; emergency patching |
| [`03-slow-patch-sla-breach`](demos/03-slow-patch-sla-breach/) | Remediation-SLA breach review with `--max-ttp` |
| [`04-unpatched-backlog`](demos/04-unpatched-backlog/) | Bug-bounty backlog triage — what's still open |
| [`05-data-entry-errors`](demos/05-data-entry-errors/) | Data-quality sweep catching inconsistent date entries |
| [`06-mixed-date-formats`](demos/06-mixed-date-formats/) | Merging feeds with ISO/US/slashed/spelled/compact dates |
| [`07-ci-quality-gate`](demos/07-ci-quality-gate/) | CI release gate that blocks on open exploited/unpatched issues |
| [`08-sarif-code-scanning`](demos/08-sarif-code-scanning/) | SARIF 2.1.0 export into a code-scanning dashboard |

---

## Development

```bash
python -m pip install -e ".[dev]"
python -m pytest -q
```

On Windows, set `PYTHONUTF8=1` for consistent encoding.

---

## License

License: **COCL 1.0**. Maintained by **Cognis Digital**.

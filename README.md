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

## Live data feeds (CISA-KEV / EPSS / OSV) — enrichment + air-gap

`vulntimeline` ships an **edge / air-gap-deployable** data-feed layer that
cross-references your advisories against real, authoritative, **keyless** public
vulnerability intelligence. The feed engine fetches over HTTPS, caches every
feed to disk, and re-serves it **offline**, so the tool keeps working on a
disconnected / classified / field-deployed box.

### The feeds (real, public, keyless)

| Feed id    | Source | URL |
|------------|--------|-----|
| `cisa-kev` | CISA **Known Exploited Vulnerabilities** catalog | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json |
| `epss`     | FIRST **EPSS** exploit-probability scores | https://api.first.org/data/v1/epss |
| `osv`      | **OSV.dev** package-vulnerability query | https://api.osv.dev/v1/query |

These are the only feeds this tool surfaces — the bundled catalog
(`vulntimeline/data_feeds_2026.json`) is filtered to the `vuln` domain so the
CLI never leaks unrelated feeds.

### `feeds` — manage the local feed cache

```bash
vulntimeline feeds list                       # show the relevant feeds + cache age
vulntimeline feeds update cisa-kev epss        # fetch + cache (online)
vulntimeline feeds get cisa-kev --offline      # print the cached feed, no network
vulntimeline feeds snapshot-export feeds.tar.gz
vulntimeline feeds snapshot-import feeds.tar.gz
```

The cache location is `COGNIS_FEEDS_CACHE` (default `~/.cache/cognis-feeds`).

### `build --enrich` — KEV/EPSS-enriched timeline

When an advisory `id` contains a CVE (e.g. `CVE-2021-44228`), `--enrich`
cross-references it against CISA-KEV and EPSS and appends a prioritised table:

```bash
# online: refresh from the live feeds, then enrich
vulntimeline build advisories.json --enrich

# air-gap: serve from the local cache only — zero network
export COGNIS_FEEDS_CACHE=/srv/feeds-cache
vulntimeline build advisories.json --enrich --offline
```

Each advisory gains: `kev` (actively exploited in the wild), `kev_ransomware`
(associated with ransomware campaigns), `epss` (30-day exploit probability),
and a derived `priority` (KEV dominates, ransomware bumps, EPSS breaks ties).
This turns a flat disclosure history into a **patch-by-this-first** worklist:
a CVE on the CISA KEV list is being exploited *right now*, which outranks any
date-derived flag.

### Air-gap / sneakernet workflow

1. On an internet-connected staging box: `vulntimeline feeds update cisa-kev epss osv`
2. `vulntimeline feeds snapshot-export feeds.tar.gz`
3. Carry `feeds.tar.gz` across the gap.
4. On the air-gapped box: `vulntimeline feeds snapshot-import feeds.tar.gz`
5. Run any command with `--enrich --offline` — it never touches the network.

The snapshot is a flat tarball of the cache, so it imports into any cache
directory regardless of its name. A trimmed, committed snapshot lives under
[`demos/09-live-feed-enrichment/feeds_cache/`](demos/09-live-feed-enrichment/)
so the enrichment demo (and CI) run with **zero network access**.

Defensive / authorized-use intelligence only.

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
| [`09-live-feed-enrichment`](demos/09-live-feed-enrichment/) | CISA-KEV + EPSS enrichment of real CVEs, fully offline |

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

## Bundled vulnerability database

Ships `vulntimeline/cognis_vulndb.jsonl.gz` — **262,351 real vulnerabilities** (OSV: PyPI/npm/Go/Maven/RubyGems/crates.io/NuGet) with detailed metadata (CVE/GHSA aliases, ecosystem, severity/CVSS, affected packages, dates). Pure-stdlib offline loader `vulndb_local.VulnDB` (`count`/`by_cve`/`by_package`/`search`), air-gap ready. Refresh/extend via `datafeeds.py bulk`.

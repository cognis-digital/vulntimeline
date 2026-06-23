# vulntimeline

![CI](https://github.com/cognis-digital/vulntimeline/actions/workflows/ci.yml/badge.svg)
![ports](https://github.com/cognis-digital/vulntimeline/actions/workflows/ports.yml/badge.svg)
![python](https://img.shields.io/badge/python-3.10%2B-blue)
![deps](https://img.shields.io/badge/runtime%20deps-0-brightgreen)
![offline](https://img.shields.io/badge/network-none%20(offline%2Fair--gap)-success)
![license](https://img.shields.io/badge/license-COCL%201.0-lightgrey)
![vuln%20DB](https://img.shields.io/badge/bundled%20OSV%20DB-262k%20vulns-orange)

A vulnerability **disclosure timeline builder** for defensive security work.

`vulntimeline` ingests advisory records, orders them chronologically, computes
the key remediation windows (time-to-patch, exposure window, disclosure gap),
and flags risky patterns such as **exploited-before-patch** and **slow patch**.
It renders a human-readable Markdown + ASCII timeline, a metrics table, and
machine-readable JSON for pipelines.

On top of the timeline core it bundles, for **fully-offline** use:

- a **262,351-record real OSV vulnerability database** (`vulndb` subcommand) —
  resolve a timeline's CVE/GHSA references and affected packages against real
  vulns from PyPI/npm/Go/Maven/RubyGems/crates.io/NuGet, with **zero network**;
- an **edge / air-gap data-feed layer** (`feeds` + `build --enrich`) that
  cross-references CVEs against the CISA-KEV and FIRST-EPSS catalogs;
- **SARIF 2.1.0** export for code-scanning dashboards;
- cross-language ports of the core CLI (**Go / Rust / Node**) under
  [`ports/`](ports/), each built + tested in CI.

It is **analytical, passive, and defensive only** — it measures and reports on
how a disclosure lifecycle played out, and looks records up in bundled data. It
performs **no active scanning, no probing, and no network calls** beyond the
optional, explicit `feeds update` refresh of public, keyless catalogs.

- Standard library only (no third-party runtime dependencies)
- Python 3.10+
- Maintainer: **Cognis Digital**
- License: **COCL 1.0**

## Quickstart

```bash
git clone https://github.com/cognis-digital/vulntimeline
cd vulntimeline
python -m pip install -e .

# 1. build a disclosure timeline from the worked example
vulntimeline build examples/advisories.json

# 2. compute remediation windows + medians
vulntimeline metrics examples/advisories.json

# 3. flag risky patterns, gate CI on any finding
vulntimeline flags examples/advisories.json --max-ttp 30 --fail-on-any

# 4. resolve real vulns against the bundled 262k OSV DB — offline
vulntimeline vulndb lookup CVE-2021-44228
vulntimeline vulndb components PyPI:django npm:lodash
```

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

### `vulndb` — match against the bundled 262k OSV database (offline)

```bash
vulntimeline vulndb count
vulntimeline vulndb lookup CVE-2021-44228
vulntimeline vulndb package django --ecosystem PyPI
vulntimeline vulndb match examples/advisories.json --fail-on-match
vulntimeline vulndb components PyPI:django npm:lodash
```

Resolves a timeline's CVE/GHSA ids and affected packages against the bundled,
fully-offline OSV corpus. See [Bundled vulnerability database](#bundled-vulnerability-database-vulndb--262k-real-osv-vulns-fully-offline)
below for full details and sample output.

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

## Bundled vulnerability database (`vulndb`) — 262k real OSV vulns, fully offline

`vulntimeline` ships `vulntimeline/cognis_vulndb.jsonl.gz` — a consolidated,
compact **OSV corpus of 262,351 real vulnerabilities** across PyPI, npm, Go,
Maven, RubyGems, crates.io, and NuGet. Each record carries real metadata:
canonical `id`, CVE/GHSA/RUSTSEC/PYSEC **aliases**, ecosystem, summary,
CVSS-vector severity, affected packages, and published/modified dates.

The loader (`vulntimeline.vulndb_local.VulnDB`) is pure standard library and
**works the moment you clone** — no network, no API key, no download step. This
is the data that lets a flat disclosure timeline be cross-referenced against the
real-world vulnerability landscape on an air-gapped box.

> **No fabricated data.** Every record is sourced from the public OSV database.
> The bundle is a point-in-time snapshot; refresh it from upstream feeds (below)
> when you need the latest.

### `vulndb count` / `lookup` / `package`

```bash
$ vulntimeline vulndb count
262351

$ vulntimeline vulndb lookup CVE-2021-44228
1 record(s) for CVE-2021-44228:
      GHSA-jfh8-c2jp-5v3q  [Maven]  (CVE-2021-44228)  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H
        Remote code injection in Log4j

$ vulntimeline vulndb package django --ecosystem PyPI --limit 3
... (real Django CVEs from the OSV corpus) ...
```

`lookup` resolves a CVE/GHSA/RUSTSEC/PYSEC/GO id against the corpus (and all
record aliases). `package` lists every known vulnerability affecting a package,
optionally filtered by `--ecosystem`. Add `--json` to either for machine output.

### `vulndb match` — enrich an advisories file against the bundled DB

`match` takes the same advisories JSON the rest of the tool uses and resolves
each record against the corpus by **CVE/GHSA id** (from the advisory `id`, or
from `cve`/`aliases`/`references` extras) **and by affected package** (from
`package`/`packages`/`component` extras):

```bash
vulntimeline vulndb match advisories.json
vulntimeline vulndb match advisories.json --json
vulntimeline vulndb match advisories.json --fail-on-match   # CI gate, exit 2
```

```
# Bundled-DB match (offline OSV corpus)

_1 of 2 advisories resolved against the bundled DB._

## CVE-2021-44228  (11 match(es))
*matched by: id, package*
*query ids: CVE-2021-44228*
      GHSA-jfh8-c2jp-5v3q  [Maven]  (CVE-2021-44228)  CVSS:3.1/...  Remote code injection in Log4j
      GHSA-7rjr-3q55-vv33  [Maven]  (CVE-2021-45046)  ...           Incomplete fix for Apache Log4j
      ...
```

`--fail-on-match` exits non-zero (2) if any advisory resolves to a known vuln —
a CI gate for "did anything in this disclosure set map to a real OSV record?".

### `vulndb components` — resolve SBOM-style package coordinates

```bash
vulntimeline vulndb components PyPI:django npm:lodash org.example:internal
vulntimeline vulndb components --from-file sbom-packages.txt   # newline or JSON-array
```

Each coordinate is `name` or `ecosystem:name` (e.g. `PyPI:django`, `npm:lodash`,
`Maven:org.apache.logging.log4j:log4j-core`). The ecosystem prefix filters
matches to that ecosystem; otherwise the whole string is treated as a name.

### Programmatic API

```python
from vulntimeline.vulndb_local import VulnDB
db = VulnDB()                       # lazy-loads the bundled gz
db.count()                          # -> 262351
db.by_cve("CVE-2021-44228")         # -> [records ...]
db.by_package("django", ecosystem="PyPI")
db.search("deserialization", 20)    # -> summary substring matches
```

### Refreshing the corpus on the edge (NVD / OSV / GHSA)

The bundle is the **offline baseline**. To pull fresh records on a connected
staging box and carry them across an air gap, the same keyless `datafeeds`
engine that powers `feeds` (above) fetches OSV/NVD/GHSA over HTTPS, caches to
disk, and re-serves offline:

```bash
# on a connected box: refresh the OSV query feed + KEV + EPSS, then snapshot
vulntimeline feeds update osv cisa-kev epss
vulntimeline feeds snapshot-export feeds.tar.gz
# carry feeds.tar.gz across the gap, then on the air-gapped box:
vulntimeline feeds snapshot-import feeds.tar.gz
```

The feed catalog (`vulntimeline/data_feeds_2026.json`) also lists the OSV/NVD/
GHSA bulk endpoints used to regenerate `cognis_vulndb.jsonl.gz` itself.

---

## Cross-language ports (Go / Rust / Node)

The core analytical surface — the `metrics` and `flags` subcommands, with the
same advisory input, the same remediation-window math, the same flag kinds, and
the same `--fail-on-any` exit-code gate — is ported to three other languages
under [`ports/`](ports/):

| Port | Path | Run | Test |
|------|------|-----|------|
| Node.js | [`ports/node`](ports/node) | `node vulntimeline.js metrics advisories.json` | `node --test` |
| Go | [`ports/go`](ports/go) | `go run . metrics advisories.json` | `go test ./...` |
| Rust | [`ports/rust`](ports/rust) | `cargo run -- metrics advisories.json` | `cargo test` |

Every port is **passive/offline and dependency-free** (the Rust port even ships
a tiny std-only JSON reader so it needs zero crates). All three are built and
tested in CI on every push via [`.github/workflows/ports.yml`](.github/workflows/ports.yml),
and a Python parity test (`tests/test_ports_parity.py`) asserts the Node port's
output matches the Python core byte-for-byte on the worked example.

---

## Scope, authorization & safety

`vulntimeline` is a **defensive, analytical, authorized-use-only** tool:

- **Passive by nature.** It reads advisory files, looks records up in the
  bundled OSV DB, and renders reports. It does **no active scanning**, sends no
  exploit payloads, and never probes a target host.
- **Offline-first.** Every core command (build/metrics/flags/vulndb) and the
  `--offline` feed paths run with **zero network access**. The only optional
  network is an explicit `feeds update` against public, keyless catalogs
  (CISA-KEV / EPSS / OSV) — never a scan of your assets.
- **Real data only.** No fabricated CVEs, advisories, or fingerprints — the
  bundled DB is real OSV data and the feeds are authoritative public sources.
- Use it on systems and data you are authorized to assess.

---

## License

License: **COCL 1.0**. Maintained by **Cognis Digital**.

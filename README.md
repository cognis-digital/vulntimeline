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

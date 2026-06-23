# vulntimeline — cross-language ports

These are faithful ports of the **core analytical surface** of the primary
Python CLI: the `metrics` and `flags` subcommands.

They share, byte-for-byte where it matters:

- the **advisory JSON input format** (top-level list, or `{"advisories": [...]}`);
- the **date parser** (ISO date/datetime, `YYYY/MM/DD`, `MM/DD/YYYY`,
  `DD-MM-YYYY`, `YYYYMMDD`, and spelled `Month DD, YYYY`);
- the **remediation windows** — time-to-patch, disclosure gap, report latency,
  exposure window (with the `*` open-window marker);
- the **flag kinds** — `exploited_before_patch`, `slow_patch`, `unpatched`,
  `negative_window`;
- the **`--fail-on-any` CI gate** (exit code `2`).

All three are **passive / offline / dependency-free**: no network, no third-party
packages (the Rust port ships a tiny std-only JSON reader). They are built and
tested on every push by [`.github/workflows/ports.yml`](../.github/workflows/ports.yml).

A Python parity test (`tests/test_ports_parity.py`) runs the Node port against
the worked example and asserts its output matches the Python core.

> The timeline rendering, SARIF export, KEV/EPSS feed enrichment, and the 262k
> bundled OSV database live only in the Python reference implementation — the
> ports cover the portable, dependency-free analytics core.

| Port | Build | Test | Run |
|------|-------|------|-----|
| [`node`](node) | (none) | `node --test` | `node vulntimeline.js metrics ../../examples/advisories.json` |
| [`go`](go)     | `go build .` | `go test ./...` | `go run . metrics ../../examples/advisories.json` |
| [`rust`](rust) | `cargo build --release` | `cargo test` | `cargo run -- metrics ../../examples/advisories.json` |

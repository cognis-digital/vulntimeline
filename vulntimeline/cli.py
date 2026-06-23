"""Command-line interface for vulntimeline.

Subcommands:
  build    chronological timeline (Markdown + ASCII lanes, or --json)
  metrics  per-advisory remediation windows + aggregate medians (table/json)
  flags    risky-pattern detection with an optional exit gate
  feeds    manage the bundled CISA-KEV / EPSS / OSV feed cache (air-gap)
  vulndb   match advisories / components against the bundled 262k OSV DB (offline)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .core import (
    AdvisoryError,
    load_advisories,
    build_timeline,
    aggregate_metrics,
    detect_flags,
)
from .render import (
    render_markdown,
    render_ascii,
    render_metrics_table,
    render_flags_table,
)
from .sarif import flags_to_sarif
from . import feeds as feedmod
from . import datafeeds
from . import vulnmatch
from .vulndb_local import VulnDB


def _read_source(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    p = Path(path)
    if not p.exists():
        raise AdvisoryError(f"file not found: {path}")
    return p.read_text(encoding="utf-8")


def _load(path: str):
    return load_advisories(_read_source(path))


def cmd_build(args: argparse.Namespace) -> int:
    advisories = _load(args.advisories)
    timeline = build_timeline(advisories)

    enrich = None
    if getattr(args, "enrich", False):
        enrich = feedmod.enrich_index(timeline, offline=args.offline)

    if args.json:
        payload = []
        for a in timeline:
            rec = {
                "id": a.id,
                "title": a.title,
                "severity": a.severity,
                "milestones": [
                    {"milestone": fld, "label": label, "date": d.isoformat()}
                    for fld, label, d in a.milestones()
                ],
            }
            if enrich is not None:
                rec["feeds"] = enrich.get(a.id)
            payload.append(rec)
        print(json.dumps(payload, indent=2))
        return 0

    out = render_markdown(timeline)
    if not args.no_ascii:
        out += "\n" + render_ascii(timeline, width=args.width)
    if enrich is not None:
        out += "\n" + _render_enrichment(timeline, enrich)
    sys.stdout.write(out)
    return 0


def _render_enrichment(timeline, enrich: dict) -> str:
    """Render a KEV/EPSS enrichment table, sorted most-urgent first."""
    rows = [enrich[a.id] for a in timeline]
    rows.sort(key=lambda r: r["priority"], reverse=True)
    lines = ["", "## Live feed enrichment (CISA-KEV + EPSS)", ""]
    lines.append("Sources: CISA Known Exploited Vulnerabilities, FIRST EPSS.")
    lines.append("")
    lines.append("| Advisory | CVE | KEV | Ransomware | EPSS | Percentile |")
    lines.append("| --- | --- | --- | --- | --- | --- |")
    for r in rows:
        kev = "YES" if r["kev"] else "-"
        ransom = "YES" if r["kev_ransomware"] else "-"
        epss = f"{r['epss']:.4f}" if r["epss"] is not None else "-"
        pct = f"{r['epss_percentile']:.3f}" if r["epss_percentile"] is not None else "-"
        cve = r["cve"] or "(non-CVE)"
        lines.append(f"| {r['id']} | {cve} | {kev} | {ransom} | {epss} | {pct} |")
    kev_count = sum(1 for r in rows if r["kev"])
    lines.append("")
    lines.append(f"_{kev_count} of {len(rows)} advisories are CISA-KEV known-exploited._")
    return "\n".join(lines) + "\n"


def cmd_feeds(args: argparse.Namespace) -> int:
    action = args.feeds_action
    if action == "list":
        for f in feedmod.list_relevant():
            age = datafeeds.cached_age_hours(f["id"])
            fresh = "uncached" if age is None else f"{age:.1f}h old"
            print(f"  {f['id']:10} {f.get('domain',''):6} [{fresh}]  {f['name']}")
            print(f"             {f['url']}")
        return 0
    if action == "update":
        rc = 0
        for fid in args.ids:
            try:
                feedmod._ensure_relevant(fid)
                pth = datafeeds.update(fid)
                print(f"  updated {fid} -> {pth} ({pth.stat().st_size} bytes)")
            except (KeyError, ConnectionError) as e:
                print(f"  {fid}: {e}", file=sys.stderr)
                rc = 1
        return rc
    if action == "get":
        try:
            feedmod._ensure_relevant(args.id)
            data = datafeeds.get(args.id, offline=args.offline)
        except (KeyError, FileNotFoundError, ConnectionError) as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
        if isinstance(data, (dict, list)):
            print(json.dumps(data, indent=2)[:4000])
        else:
            print(data[:4000])
        return 0
    if action == "snapshot-export":
        n = datafeeds.snapshot_export(args.path)
        print(f"exported {n} feed(s) -> {args.path}")
        return 0
    if action == "snapshot-import":
        n = datafeeds.snapshot_import(args.path)
        print(f"imported {n} feed(s) from {args.path}")
        return 0
    return 1


def _fmt_db_record(rec: dict) -> str:
    aliases = ", ".join(rec.get("aliases") or []) or "-"
    sev = rec.get("severity") or "-"
    summ = (rec.get("summary") or "").strip().replace("\n", " ")
    if len(summ) > 80:
        summ = summ[:77] + "..."
    return f"      {rec.get('id')}  [{rec.get('ecosystem') or '-'}]  ({aliases})  {sev}\n        {summ}"


def cmd_vulndb(args: argparse.Namespace) -> int:
    db = VulnDB(path=getattr(args, "db", None))
    action = args.vulndb_action

    if action == "count":
        print(db.count())
        return 0

    if action == "lookup":
        recs = db.by_cve(args.id)
        if args.json:
            print(json.dumps(recs, indent=2))
            return 0
        if not recs:
            print(f"no records for {args.id}")
            return 1
        print(f"{len(recs)} record(s) for {args.id}:")
        for r in recs:
            print(_fmt_db_record(r))
        return 0

    if action == "package":
        recs = db.by_package(args.name, ecosystem=getattr(args, "ecosystem", None))
        if args.json:
            print(json.dumps(recs, indent=2))
            return 0
        if not recs:
            print(f"no records for package {args.name}")
            return 1
        print(f"{len(recs)} record(s) affecting {args.name}:")
        for r in recs[: args.limit]:
            print(_fmt_db_record(r))
        return 0

    if action == "match":
        advisories = _load(args.advisories)
        rows = vulnmatch.match_advisories(advisories, db=db)
        if args.json:
            print(json.dumps(rows, indent=2))
            return 0
        sys.stdout.write(_render_db_match(rows))
        total = sum(r["match_count"] for r in rows)
        return 2 if (args.fail_on_match and total) else 0

    if action == "components":
        comps = _component_list(args)
        rows = vulnmatch.match_components(comps, db=db)
        if args.json:
            print(json.dumps(rows, indent=2))
            return 0
        sys.stdout.write(_render_component_match(rows))
        total = sum(r["match_count"] for r in rows)
        return 2 if (args.fail_on_match and total) else 0

    return 1


def _component_list(args: argparse.Namespace) -> list[str]:
    if getattr(args, "from_file", None):
        text = _read_source(args.from_file)
        # accept either a JSON array of strings or a newline-delimited list
        text_stripped = text.strip()
        if text_stripped.startswith("["):
            data = json.loads(text_stripped)
            return [str(x) for x in data]
        return [ln.strip() for ln in text_stripped.splitlines() if ln.strip()]
    return list(args.components or [])


def _render_db_match(rows: list) -> str:
    lines = ["# Bundled-DB match (offline OSV corpus)", ""]
    matched = sum(1 for r in rows if r["match_count"])
    lines.append(f"_{matched} of {len(rows)} advisories resolved against the bundled DB._")
    lines.append("")
    for r in rows:
        lines.append(f"## {r['id']}  ({r['match_count']} match(es))")
        by = []
        if r["matched_by_id"]:
            by.append("id")
        if r["matched_by_package"]:
            by.append("package")
        lines.append(f"*matched by: {', '.join(by) or 'none'}*")
        if r["query_ids"]:
            lines.append(f"*query ids: {', '.join(r['query_ids'])}*")
        if r["query_packages"]:
            lines.append(f"*query packages: {', '.join(r['query_packages'])}*")
        for rec in r["db_matches"]:
            lines.append(_fmt_db_record(rec))
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _render_component_match(rows: list) -> str:
    lines = ["# Component match (offline OSV corpus)", ""]
    vuln = sum(1 for r in rows if r["match_count"])
    lines.append(f"_{vuln} of {len(rows)} components have known vulnerabilities in the bundled DB._")
    lines.append("")
    for r in rows:
        eco = f" [{r['ecosystem']}]" if r["ecosystem"] else ""
        lines.append(f"## {r['component']}{eco}  ({r['match_count']} match(es))")
        for rec in r["db_matches"]:
            lines.append(_fmt_db_record(rec))
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def cmd_metrics(args: argparse.Namespace) -> int:
    advisories = _load(args.advisories)
    metrics = aggregate_metrics(advisories)

    if args.json:
        print(json.dumps(metrics, indent=2))
        return 0

    sys.stdout.write(render_metrics_table(metrics))
    return 0


def cmd_flags(args: argparse.Namespace) -> int:
    advisories = _load(args.advisories)
    flags = detect_flags(advisories, max_time_to_patch=args.max_ttp)

    if args.sarif:
        source = "advisories.json" if args.advisories == "-" else args.advisories
        log = flags_to_sarif(flags, source_path=source)
        print(json.dumps(log, indent=2))
    elif args.json:
        print(json.dumps(flags, indent=2))
    else:
        sys.stdout.write(render_flags_table(flags))

    if args.fail_on_any and flags:
        return 2
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulntimeline",
        description="Vulnerability disclosure timeline builder (defensive analytics).",
    )
    parser.add_argument("--version", action="version", version=f"vulntimeline {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_build = sub.add_parser("build", help="build a chronological disclosure timeline")
    p_build.add_argument("advisories", help="path to advisories JSON ('-' for stdin)")
    p_build.add_argument("--json", action="store_true", help="emit JSON instead of Markdown/ASCII")
    p_build.add_argument("--no-ascii", action="store_true", help="skip the ASCII lane chart")
    p_build.add_argument("--width", type=int, default=60, help="ASCII timeline width (default 60)")
    p_build.add_argument(
        "--enrich", action="store_true",
        help="cross-reference CVE ids against CISA-KEV + EPSS live feeds",
    )
    p_build.add_argument(
        "--offline", action="store_true",
        help="with --enrich, serve feed data from the local cache only (air-gap)",
    )
    p_build.set_defaults(func=cmd_build)

    p_metrics = sub.add_parser("metrics", help="compute remediation windows + aggregate medians")
    p_metrics.add_argument("advisories", help="path to advisories JSON ('-' for stdin)")
    p_metrics.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    p_metrics.set_defaults(func=cmd_metrics)

    p_flags = sub.add_parser("flags", help="detect risky patterns")
    p_flags.add_argument("advisories", help="path to advisories JSON ('-' for stdin)")
    p_flags.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    p_flags.add_argument(
        "--sarif", action="store_true",
        help="emit a SARIF 2.1.0 log (for code-scanning dashboards)",
    )
    p_flags.add_argument(
        "--max-ttp", type=int, default=None, metavar="N",
        help="flag advisories whose time-to-patch exceeds N days",
    )
    p_flags.add_argument(
        "--fail-on-any", action="store_true",
        help="exit non-zero (2) if any flag is detected (CI gate)",
    )
    p_flags.set_defaults(func=cmd_flags)

    p_feeds = sub.add_parser(
        "feeds",
        help="manage the bundled real data feeds (CISA-KEV / EPSS / OSV)",
        description="Edge/air-gap data-feed ingestion: keyless HTTPS fetch -> "
                    "disk cache -> offline re-serve. Defensive/authorized use only.",
    )
    feeds_sub = p_feeds.add_subparsers(dest="feeds_action", required=True)
    feeds_sub.add_parser("list", help="list the feeds relevant to vulntimeline")
    f_up = feeds_sub.add_parser("update", help="fetch + cache feed(s) for offline use")
    f_up.add_argument("ids", nargs="+", help=f"feed id(s): {feedmod.RELEVANT_FEEDS}")
    f_get = feeds_sub.add_parser("get", help="print a cached/fetched feed")
    f_get.add_argument("id", help=f"feed id: {feedmod.RELEVANT_FEEDS}")
    f_get.add_argument("--offline", action="store_true", help="serve from cache only")
    f_exp = feeds_sub.add_parser("snapshot-export", help="tar the feed cache for sneakernet")
    f_exp.add_argument("path", help="output .tar.gz path")
    f_imp = feeds_sub.add_parser("snapshot-import", help="load a snapshot into the cache")
    f_imp.add_argument("path", help="input .tar.gz path")
    p_feeds.set_defaults(func=cmd_feeds)

    p_vdb = sub.add_parser(
        "vulndb",
        help="match advisories/components against the bundled 262k OSV DB (offline)",
        description="Fully-offline lookups against the bundled cognis_vulndb "
                    "(262k real OSV vulns across PyPI/npm/Go/Maven/RubyGems/"
                    "crates.io/NuGet). No network. Defensive/authorized use only.",
    )
    p_vdb.add_argument("--db", default=None, help="path to an alternate .jsonl.gz corpus")
    vdb_sub = p_vdb.add_subparsers(dest="vulndb_action", required=True)

    vdb_sub.add_parser("count", help="print the number of records in the bundled DB")

    v_look = vdb_sub.add_parser("lookup", help="resolve a CVE/GHSA/RUSTSEC/GO id")
    v_look.add_argument("id", help="advisory id, e.g. CVE-2021-44228")
    v_look.add_argument("--json", action="store_true", help="emit JSON records")

    v_pkg = vdb_sub.add_parser("package", help="list vulns affecting a package")
    v_pkg.add_argument("name", help="package name, e.g. log4j-core / django / lodash")
    v_pkg.add_argument("--ecosystem", default=None, help="filter by ecosystem (PyPI/npm/...)")
    v_pkg.add_argument("--limit", type=int, default=25, help="max records to print (default 25)")
    v_pkg.add_argument("--json", action="store_true", help="emit JSON records")

    v_match = vdb_sub.add_parser(
        "match",
        help="enrich an advisories file: resolve its CVE/GHSA ids + packages against the DB",
    )
    v_match.add_argument("advisories", help="path to advisories JSON ('-' for stdin)")
    v_match.add_argument("--json", action="store_true", help="emit JSON instead of Markdown")
    v_match.add_argument(
        "--fail-on-match", action="store_true",
        help="exit non-zero (2) if any advisory resolves to a known vuln (CI gate)",
    )

    v_comp = vdb_sub.add_parser(
        "components",
        help="resolve a list of package coordinates (SBOM-style) against the DB",
    )
    v_comp.add_argument(
        "components", nargs="*",
        help="coordinates: name or ecosystem:name (e.g. PyPI:django npm:lodash)",
    )
    v_comp.add_argument(
        "--from-file", default=None,
        help="read coordinates from a JSON array or newline-delimited file ('-' for stdin)",
    )
    v_comp.add_argument("--json", action="store_true", help="emit JSON instead of Markdown")
    v_comp.add_argument(
        "--fail-on-match", action="store_true",
        help="exit non-zero (2) if any component has a known vuln (CI gate)",
    )

    p_vdb.set_defaults(func=cmd_vulndb)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except AdvisoryError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

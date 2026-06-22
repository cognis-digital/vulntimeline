"""Command-line interface for vulntimeline.

Subcommands:
  build    chronological timeline (Markdown + ASCII lanes, or --json)
  metrics  per-advisory remediation windows + aggregate medians (table/json)
  flags    risky-pattern detection with an optional exit gate
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

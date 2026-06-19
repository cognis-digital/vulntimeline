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

    if args.json:
        payload = [
            {
                "id": a.id,
                "title": a.title,
                "severity": a.severity,
                "milestones": [
                    {"milestone": fld, "label": label, "date": d.isoformat()}
                    for fld, label, d in a.milestones()
                ],
            }
            for a in timeline
        ]
        print(json.dumps(payload, indent=2))
        return 0

    out = render_markdown(timeline)
    if not args.no_ascii:
        out += "\n" + render_ascii(timeline, width=args.width)
    sys.stdout.write(out)
    return 0


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

    if args.json:
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
    p_build.set_defaults(func=cmd_build)

    p_metrics = sub.add_parser("metrics", help="compute remediation windows + aggregate medians")
    p_metrics.add_argument("advisories", help="path to advisories JSON ('-' for stdin)")
    p_metrics.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    p_metrics.set_defaults(func=cmd_metrics)

    p_flags = sub.add_parser("flags", help="detect risky patterns")
    p_flags.add_argument("advisories", help="path to advisories JSON ('-' for stdin)")
    p_flags.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    p_flags.add_argument(
        "--max-ttp", type=int, default=None, metavar="N",
        help="flag advisories whose time-to-patch exceeds N days",
    )
    p_flags.add_argument(
        "--fail-on-any", action="store_true",
        help="exit non-zero (2) if any flag is detected (CI gate)",
    )
    p_flags.set_defaults(func=cmd_flags)

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

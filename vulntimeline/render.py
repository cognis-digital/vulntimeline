"""Rendering helpers: Markdown, ASCII lane art, and metric tables.

Pure functions that turn parsed advisories / metrics into text. No I/O.
"""

from __future__ import annotations

from datetime import date
from typing import Any

from .core import Advisory, MILESTONES


# Single-character glyph per milestone for the ASCII lane art.
MILESTONE_GLYPH = {
    "discovered": "D",
    "reported": "R",
    "disclosed": "P",   # P = Public disclosure
    "exploited": "X",
    "patched": "+",
}


def _fmt(d: date | None) -> str:
    return d.isoformat() if d is not None else "-"


def render_markdown(advisories: list[Advisory]) -> str:
    """Render a chronological timeline as a Markdown document."""
    lines: list[str] = ["# Vulnerability Disclosure Timeline", ""]
    lines.append(f"_{len(advisories)} advisory record(s)_")
    lines.append("")

    for adv in advisories:
        sev = adv.severity or "unknown"
        heading = f"## {adv.id}"
        if adv.title:
            heading += f" — {adv.title}"
        lines.append(heading)
        lines.append(f"*Severity: {sev}*")
        lines.append("")
        ms = adv.milestones()
        if not ms:
            lines.append("- _(no dated milestones)_")
        else:
            for _fld, label, d in ms:
                lines.append(f"- **{label}**: {d.isoformat()}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_ascii(advisories: list[Advisory], width: int = 60) -> str:
    """Render an ASCII lane chart spanning the full date range.

    Each advisory gets a lane; milestone glyphs are positioned by date along a
    shared timeline axis. A legend maps glyphs back to milestone names.
    """
    all_dates: list[date] = []
    for adv in advisories:
        all_dates.extend(d for _f, _l, d in adv.milestones())

    lines: list[str] = ["Vulnerability Disclosure Timeline (ASCII)", ""]

    legend = "  ".join(f"{MILESTONE_GLYPH[f]}={l}" for f, l in MILESTONES)
    lines.append("Legend: " + legend)
    lines.append("")

    if not all_dates:
        lines.append("(no dated milestones to plot)")
        return "\n".join(lines) + "\n"

    start = min(all_dates)
    end = max(all_dates)
    span = (end - start).days
    axis_width = max(1, width)

    def col_for(d: date) -> int:
        if span == 0:
            return 0
        return round((d - start).days / span * (axis_width - 1))

    label_w = max((len(adv.id) for adv in advisories), default=2)
    label_w = max(label_w, 2)

    # Axis header showing the date range spanned by the lanes.
    dashes = max(1, axis_width - len(start.isoformat()) - len(end.isoformat()) - 2)
    lines.append(f"{'':<{label_w}}  {start.isoformat()} {'-' * dashes} {end.isoformat()}")

    for adv in advisories:
        lane = ["."] * axis_width
        for fld, _label, d in adv.milestones():
            c = col_for(d)
            c = min(max(c, 0), axis_width - 1)
            lane[c] = MILESTONE_GLYPH[fld]
        lines.append(f"{adv.id:<{label_w}} |{''.join(lane)}|")

    return "\n".join(lines) + "\n"


def render_metrics_table(metrics: dict[str, Any]) -> str:
    """Render aggregate-metrics output as a fixed-width text table."""
    rows = metrics["advisories"]
    agg = metrics["aggregate"]

    headers = ["ID", "SEV", "TTP", "DISC_GAP", "REPLAT", "EXPOSURE", "XBP"]

    def cell(v: Any) -> str:
        if v is None:
            return "-"
        if isinstance(v, bool):
            return "yes" if v else "no"
        return str(v)

    table_rows: list[list[str]] = []
    for r in rows:
        exposure = cell(r["exposure_window"])
        if r["exposure_open"] and r["exposure_window"] is not None:
            exposure += "*"
        table_rows.append([
            r["id"],
            r["severity"] or "-",
            cell(r["time_to_patch"]),
            cell(r["disclosure_gap"]),
            cell(r["report_latency"]),
            exposure,
            cell(r["exploited_before_patch"]),
        ])

    widths = [len(h) for h in headers]
    for row in table_rows:
        for i, c in enumerate(row):
            widths[i] = max(widths[i], len(c))

    def fmt_row(cells: list[str]) -> str:
        return "  ".join(c.ljust(widths[i]) for i, c in enumerate(cells))

    lines = [fmt_row(headers), fmt_row(["-" * w for w in widths])]
    for row in table_rows:
        lines.append(fmt_row(row))

    lines.append("")
    lines.append("Aggregate (days; median):")
    lines.append(f"  count                       {agg['count']}")
    lines.append(f"  median time-to-patch        {_num(agg['median_time_to_patch'])}")
    lines.append(f"  median disclosure gap       {_num(agg['median_disclosure_gap'])}")
    lines.append(f"  median report latency       {_num(agg['median_report_latency'])}")
    lines.append(f"  median exposure window      {_num(agg['median_exposure_window'])}")
    lines.append(f"  exploited-before-patch      {agg['exploited_before_patch_count']}")
    lines.append(f"  unpatched                   {agg['unpatched_count']}")
    lines.append("")
    lines.append("Legend: TTP=time-to-patch, XBP=exploited-before-patch, *=window still open")
    return "\n".join(lines) + "\n"


def _num(v: Any) -> str:
    if v is None:
        return "-"
    if isinstance(v, float) and v.is_integer():
        return str(int(v))
    return str(v)


def render_flags_table(flags: list[dict[str, Any]]) -> str:
    """Render detected flags as a fixed-width text table."""
    if not flags:
        return "No flags detected.\n"

    headers = ["ID", "KIND", "SEVERITY", "DETAIL"]
    rows = [[f["id"], f["kind"], f["severity"], f["detail"]] for f in flags]

    widths = [len(h) for h in headers]
    for row in rows:
        for i, c in enumerate(row):
            widths[i] = max(widths[i], len(c))

    def fmt_row(cells: list[str]) -> str:
        return "  ".join(c.ljust(widths[i]) for i, c in enumerate(cells))

    lines = [fmt_row(headers), fmt_row(["-" * w for w in widths])]
    for row in rows:
        lines.append(fmt_row(row))
    lines.append("")
    lines.append(f"{len(flags)} flag(s) detected.")
    return "\n".join(lines) + "\n"

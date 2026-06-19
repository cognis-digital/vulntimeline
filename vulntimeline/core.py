"""Core domain logic for vulntimeline.

Pure, side-effect-free functions for parsing advisory records, ordering them
chronologically, computing remediation windows, and detecting risky patterns.
Standard library only.
"""

from __future__ import annotations

import json
import statistics
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any, Iterable, Optional


# The lifecycle milestones we track, in their natural chronological order.
# Each maps an advisory field name to a human-friendly label.
MILESTONES: list[tuple[str, str]] = [
    ("discovered", "Discovered"),
    ("reported", "Reported"),
    ("disclosed", "Disclosed"),
    ("exploited", "Exploited"),
    ("patched", "Patched"),
]

# Severity ordering, lowest to highest, for stable sorting / display.
SEVERITY_ORDER = {
    "none": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


class AdvisoryError(ValueError):
    """Raised when an advisory record is malformed or unusable."""


def parse_date(value: Any) -> Optional[date]:
    """Parse a date from a variety of common representations.

    Accepts ``None``/empty (returns ``None``), ISO date strings
    (``YYYY-MM-DD``), ISO datetime strings (with optional ``Z`` or offset),
    and a handful of common slashed/spelled formats. Raises
    :class:`AdvisoryError` for non-empty values that cannot be parsed.
    """
    if value is None:
        return None
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    if isinstance(value, datetime):
        return value.date()
    if not isinstance(value, str):
        raise AdvisoryError(f"unsupported date type: {type(value).__name__}")

    text = value.strip()
    if not text:
        return None

    # Normalise a trailing Z (UTC) so fromisoformat can handle it.
    iso_text = text
    if iso_text.endswith("Z"):
        iso_text = iso_text[:-1] + "+00:00"

    # Try full ISO datetime first, then plain ISO date.
    try:
        return datetime.fromisoformat(iso_text).date()
    except ValueError:
        pass
    try:
        return date.fromisoformat(text)
    except ValueError:
        pass

    # Fall back to a few explicit formats.
    for fmt in ("%Y/%m/%d", "%m/%d/%Y", "%d-%m-%Y", "%B %d, %Y", "%b %d, %Y", "%Y%m%d"):
        try:
            return datetime.strptime(text, fmt).date()
        except ValueError:
            continue

    raise AdvisoryError(f"could not parse date: {value!r}")


def _normalize_severity(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip().lower()
    if not text:
        return None
    if text not in SEVERITY_ORDER:
        # Keep unknown severities verbatim rather than dropping information.
        return text
    return text


@dataclass
class Advisory:
    """A single advisory record with parsed lifecycle dates."""

    id: str
    title: str = ""
    severity: Optional[str] = None
    discovered: Optional[date] = None
    reported: Optional[date] = None
    disclosed: Optional[date] = None
    exploited: Optional[date] = None
    patched: Optional[date] = None
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Advisory":
        if not isinstance(raw, dict):
            raise AdvisoryError(f"advisory record must be an object, got {type(raw).__name__}")
        adv_id = raw.get("id")
        if adv_id is None or str(adv_id).strip() == "":
            raise AdvisoryError("advisory record missing required 'id'")

        known = {"id", "title", "severity", "discovered", "reported",
                 "disclosed", "exploited", "patched"}
        extra = {k: v for k, v in raw.items() if k not in known}

        return cls(
            id=str(adv_id).strip(),
            title=str(raw.get("title", "")).strip(),
            severity=_normalize_severity(raw.get("severity")),
            discovered=parse_date(raw.get("discovered")),
            reported=parse_date(raw.get("reported")),
            disclosed=parse_date(raw.get("disclosed")),
            exploited=parse_date(raw.get("exploited")),
            patched=parse_date(raw.get("patched")),
            extra=extra,
        )

    def severity_rank(self) -> int:
        if self.severity is None:
            return -1
        return SEVERITY_ORDER.get(self.severity, -1)

    def anchor_date(self) -> Optional[date]:
        """The earliest known milestone, used to order advisories overall."""
        candidates = [getattr(self, fld) for fld, _ in MILESTONES]
        present = [d for d in candidates if d is not None]
        return min(present) if present else None

    def milestones(self) -> list[tuple[str, str, date]]:
        """Return (field, label, date) for each present milestone, in order."""
        out: list[tuple[str, str, date]] = []
        for fld, label in MILESTONES:
            d = getattr(self, fld)
            if d is not None:
                out.append((fld, label, d))
        return out


def load_advisories(source: Any) -> list[Advisory]:
    """Load advisories from a parsed-JSON structure or a JSON string.

    Accepts either a top-level list of records, or an object with an
    ``advisories`` key holding that list.
    """
    if isinstance(source, (str, bytes)):
        try:
            source = json.loads(source)
        except json.JSONDecodeError as exc:
            raise AdvisoryError(f"invalid JSON: {exc}") from exc

    if isinstance(source, dict):
        records = source.get("advisories")
        if records is None:
            raise AdvisoryError("JSON object has no 'advisories' key")
    else:
        records = source

    if not isinstance(records, list):
        raise AdvisoryError("expected a list of advisory records")

    advisories = [Advisory.from_dict(rec) for rec in records]

    seen: set[str] = set()
    for adv in advisories:
        if adv.id in seen:
            raise AdvisoryError(f"duplicate advisory id: {adv.id}")
        seen.add(adv.id)
    return advisories


def build_timeline(advisories: Iterable[Advisory]) -> list[Advisory]:
    """Return advisories ordered by earliest milestone, dateless ones last."""
    advisories = list(advisories)

    def key(adv: Advisory):
        anchor = adv.anchor_date()
        if anchor is None:
            return (1, 0, adv.id)
        return (0, anchor.toordinal(), adv.id)

    return sorted(advisories, key=key)


def _days_between(later: Optional[date], earlier: Optional[date]) -> Optional[int]:
    if later is None or earlier is None:
        return None
    return (later - earlier).days


def advisory_windows(adv: Advisory, today: Optional[date] = None) -> dict[str, Any]:
    """Compute remediation windows for a single advisory.

    Windows (in days, ``None`` when inputs are missing):

    * ``time_to_patch``   patched - disclosed
    * ``disclosure_gap``  disclosed - reported
    * ``report_latency``  reported - discovered
    * ``exposure_window`` (patched or today) - exploited; only when exploited
    * ``exploited_before_patch`` bool: exploited strictly before patched, or
      exploited and still unpatched.
    """
    today = today or date.today()

    time_to_patch = _days_between(adv.patched, adv.disclosed)
    disclosure_gap = _days_between(adv.disclosed, adv.reported)
    report_latency = _days_between(adv.reported, adv.discovered)

    exposure_window: Optional[int] = None
    exposure_open = False
    if adv.exploited is not None:
        if adv.patched is not None:
            exposure_window = max(0, (adv.patched - adv.exploited).days)
        else:
            exposure_window = max(0, (today - adv.exploited).days)
            exposure_open = True

    exploited_before_patch = False
    if adv.exploited is not None:
        if adv.patched is None:
            exploited_before_patch = True
        elif adv.exploited < adv.patched:
            exploited_before_patch = True

    return {
        "id": adv.id,
        "title": adv.title,
        "severity": adv.severity,
        "time_to_patch": time_to_patch,
        "disclosure_gap": disclosure_gap,
        "report_latency": report_latency,
        "exposure_window": exposure_window,
        "exposure_open": exposure_open,
        "exploited_before_patch": exploited_before_patch,
        "unpatched": adv.patched is None,
    }


def _median(values: list[int]) -> Optional[float]:
    nums = [v for v in values if v is not None]
    if not nums:
        return None
    return statistics.median(nums)


def aggregate_metrics(advisories: Iterable[Advisory], today: Optional[date] = None) -> dict[str, Any]:
    """Compute per-advisory windows plus aggregate medians/counts."""
    advisories = list(advisories)
    per = [advisory_windows(a, today=today) for a in advisories]

    def col(name: str) -> list[int]:
        return [row[name] for row in per if row[name] is not None]

    aggregate = {
        "count": len(per),
        "median_time_to_patch": _median(col("time_to_patch")),
        "median_disclosure_gap": _median(col("disclosure_gap")),
        "median_report_latency": _median(col("report_latency")),
        "median_exposure_window": _median(col("exposure_window")),
        "exploited_before_patch_count": sum(1 for r in per if r["exploited_before_patch"]),
        "unpatched_count": sum(1 for r in per if r["unpatched"]),
    }
    return {"advisories": per, "aggregate": aggregate}


def detect_flags(
    advisories: Iterable[Advisory],
    max_time_to_patch: Optional[int] = None,
    today: Optional[date] = None,
) -> list[dict[str, Any]]:
    """Detect risky patterns across advisories.

    Flag kinds:

    * ``exploited_before_patch`` exploitation observed before a patch existed.
    * ``slow_patch``             time_to_patch exceeds ``max_time_to_patch``.
    * ``unpatched``              no patch date recorded.
    * ``negative_window``        a window is negative (inconsistent dates).
    """
    advisories = list(advisories)
    flags: list[dict[str, Any]] = []

    for adv in advisories:
        w = advisory_windows(adv, today=today)

        if w["exploited_before_patch"]:
            flags.append({
                "id": adv.id,
                "kind": "exploited_before_patch",
                "severity": "high",
                "detail": (
                    "exploitation observed before a patch was available"
                    if not w["unpatched"]
                    else "exploitation observed and advisory remains unpatched"
                ),
            })

        ttp = w["time_to_patch"]
        if max_time_to_patch is not None and ttp is not None and ttp > max_time_to_patch:
            flags.append({
                "id": adv.id,
                "kind": "slow_patch",
                "severity": "medium",
                "detail": f"time-to-patch {ttp}d exceeds threshold {max_time_to_patch}d",
            })

        if w["unpatched"]:
            flags.append({
                "id": adv.id,
                "kind": "unpatched",
                "severity": "medium",
                "detail": "no patch date recorded",
            })

        for win_name in ("time_to_patch", "disclosure_gap", "report_latency"):
            val = w[win_name]
            if val is not None and val < 0:
                flags.append({
                    "id": adv.id,
                    "kind": "negative_window",
                    "severity": "low",
                    "detail": f"{win_name} is negative ({val}d): check date ordering",
                })

    return flags

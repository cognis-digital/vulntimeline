"""vulntimeline - a vulnerability disclosure timeline builder.

Defensive/analytical tooling for security teams: ingest advisory records,
build a chronological disclosure timeline, compute remediation windows, and
flag risky patterns such as exploited-before-patch and slow remediation.

Maintainer: Cognis Digital
License: COCL 1.0
"""

__version__ = "1.0.0"

from .core import (
    Advisory,
    AdvisoryError,
    parse_date,
    load_advisories,
    build_timeline,
    advisory_windows,
    aggregate_metrics,
    detect_flags,
)

__all__ = [
    "__version__",
    "Advisory",
    "AdvisoryError",
    "parse_date",
    "load_advisories",
    "build_timeline",
    "advisory_windows",
    "aggregate_metrics",
    "detect_flags",
]

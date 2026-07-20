"""
polyglot/python/timeline_builder.py

Vulnerability disclosure timeline builder with patch-window metrics.

Builds structured timelines from CVE data, calculates patch windows,
and outputs reports in multiple formats (text, JSON, HTML).
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import date, timedelta, datetime
from enum import Enum
from html import escape
from pathlib import Path
from typing import Any


class SeverityLevel(Enum):
    CRITICAL = 10
    HIGH = 8
    MEDIUM = 5
    LOW = 2
    INFO = 1

    @classmethod
    def from_string(cls, s: str) -> SeverityLevel:
        mapping = {
            "CRITICAL": cls.CRITICAL,
            "HIGH": cls.HIGH,
            "MEDIUM": cls.MEDIUM,
            "LOW": cls.LOW,
            "INFO": cls.INFO,
        }
        return mapping.get(s.upper(), cls.INFO)

    def __str__(self) -> str:
        return self.name


@dataclass(order=True)
class VersionRange:
    """Represents a range of affected versions."""
    
    min_version: str | None = field(default=None, compare=False)
    max_version: str | None = field(default=None, compare=False)
    is_range: bool = field(default=False, compare=False)

    def __str__(self) -> str:
        if self.is_range and self.min_version and self.max_version:
            return f"{self.min_version} - {self.max_version}"
        return self.min_version or "unknown"


@dataclass
class Vulnerability:
    """A single vulnerability record."""

    cve_id: str
    title: str
    discovered_date: date | None = None
    patched_date: date | None = None
    affected_versions: list[VersionRange] = field(default_factory=list)
    severity: SeverityLevel = SeverityLevel.INFO
    status: str = "open"  # open, patch, retired

    @property
    def days_since_discovery(self) -> int | None:
        if self.patched_date and self.discovered_date:
            return (self.patched_date - self.discovered_date).days
        return None

    @property
    def is_patch_available(self) -> bool:
        return self.patched_date is not None

    @property
    def patch_window_days(self) -> int | None:
        if self.is_patch_available and self.discovered_date:
            return (self.patched_date - self.discovered_date).days
        return None

    @property
    def severity_score(self) -> float:
        scores = {s.name: s.value for s in SeverityLevel}
        return scores.get(self.severity.name, 1.0)


@dataclass
class TimelineEntry:
    """A single entry in the timeline output."""

    date: date
    event_type: str  # "discovered", "patched", "retired"
    cve_id: str | None = None
    title: str | None = None
    severity: SeverityLevel = SeverityLevel.INFO


class TimelineBuilder:
    """Builds vulnerability disclosure timelines from raw data."""

    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}
        self.entries: list[TimelineEntry] = []
        self.vulnerabilities: list[Vulnerability] = []

    @classmethod
    def from_csv(cls, filepath: str | Path) -> TimelineBuilder:
        """Load vulnerabilities from a CSV file with columns:
        
        cve_id,title,discovered_date,patched_date,affected_versions,severity,status
        
        Dates can be YYYY-MM-DD or epoch. Versions are comma-separated like 1.0-2.5,3.0+.
        Severity is one of CRITICAL,HIGH,MEDIUM,LOW,INFO.
        """
        builder = cls()

        with open(filepath, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            
            for row in reader:
                vuln = cls._parse_row(row)
                if vuln:
                    builder.vulnerabilities.append(vuln)

        return builder

    @classmethod
    def from_dicts(cls, data: list[dict]) -> TimelineBuilder:
        """Build timeline from a list of dictionaries."""
        builder = cls()
        
        for row in data:
            vuln = cls._parse_row(row)
            if vuln:
                builder.vulnerabilities.append(vuln)

        return builder

    @staticmethod
    def _parse_row(row: dict[str, Any]) -> Vulnerability | None:
        """Parse a single row into a Vulnerability object."""
        
        cve_id = str(row.get("cve_id", "")).strip()
        if not cve_id:
            return None

        title = str(row.get("title", ""))
        discovered_str = str(row.get("discovered_date", ""))
        patched_str = str(row.get("patched_date", ""))
        
        # Parse dates
        discovered = cls._parse_date(discovered_str)
        patched = cls._parse_date(patched_str)

        # Parse severity
        sev_str = str(row.get("severity", "INFO")).strip()
        severity = SeverityLevel.from_string(sev_str)

        # Parse affected versions
        ver_str = str(row.get("affected_versions", "")).strip()
        affected: list[VersionRange] = []
        
        if ver_str:
            for part in ver_str.split(","):
                part = part.strip()
                if "-" in part and not part.endswith("+"):
                    # Range like "1.0-2.5"
                    parts = part.split("-", 1)
                    affected.append(VersionRange(min_version=parts[0], 
                                                max_version=parts[1]))
                elif "+" in part:
                    # Open-ended like "3.0+"
                    prefix, suffix = part.split("+", 1)
                    affected.append(VersionRange(min_version=prefix.strip(),
                                                max_version=suffix.strip()))
                else:
                    # Single version or range without explicit bounds
                    if "-" in part:
                        parts = part.split("-", 1)
                        affected.append(VersionRange(min_version=parts[0],
                                                    max_version=parts[1]))
                    else:
                        affected.append(VersionRange(min_version=part))

        return Vulnerability(
            cve_id=cve_id,
            title=title,
            discovered_date=discovered,
            patched_date=patched,
            affected_versions=affected,
            severity=severity,
            status=row.get("status", "open").strip() or "open"
        )

    @staticmethod
    def _parse_date(s: str) -> date | None:
        """Parse a date string into a date object."""
        if not s:
            return None
        
        # Try YYYY-MM-DD format
        try:
            return datetime.strptime(s, "%Y-%m-%d").date()
        except ValueError:
            pass

        # Try epoch timestamp
        try:
            ts = int(float(s))
            dt = datetime.fromtimestamp(ts)
            return dt.date()
        except (ValueError, OSError):
            pass

        # Try various other formats
        for fmt in ("%Y/%m/%d", "%d-%m-%Y", "%m/%d/%Y"):
            try:
                return datetime.strptime(s, fmt).date()
            except ValueError:
                continue

        # Return None if all parsing fails
        return None

    def add_vulnerabilities(self, vulns: list[Vulnerability]) -> None:
        """Add vulnerabilities to the timeline."""
        self.vulnerabilities.extend(vulns)

    def build_entries(self) -> list[TimelineEntry]:
        """Build timeline entries from all vulnerabilities.
        
        Creates one entry per significant event (discovery, patch).
        Sorts chronologically by date then by severity.
        """
        self.entries = []

        for vuln in sorted(self.vulnerabilities, key=lambda v: 
                          (v.discovered_date or date.max, -v.severity_score)):
            
            # Discovery event
            if vuln.discovered_date:
                self.entries.append(TimelineEntry(
                    date=vuln.discovered_date,
                    event_type="discovered",
                    cve_id=vuln.cve_id,
                    title=vuln.title[:100],  # Truncate for display
                    severity=vuln.severity
                ))

            # Patch event
            if vuln.patched_date:
                self.entries.append(TimelineEntry(
                    date=vuln.patched_date,
                    event_type="patched",
                    cve_id=vuln.cve_id,
                    title=f"{vuln.title[:80]}... (patched)",
                    severity=vuln.severity
                ))

            # Retired event if applicable
            if vuln.status == "retired":
                self.entries.append(TimelineEntry(
                    date=patched or vuln.discovered_date,
                    event_type="retired",
                    cve_id=vuln.cve_id,
                    title=f"{vuln.title[:80]}... (retired)",
                    severity=vuln.severity
                ))

        # Sort by date
        self.entries.sort(key=lambda e: (e.date, 
                                         {"discovered": 0, "patched": 1, "retired": 2}.get(e.event_type, 3))

        return self.entries

    def get_summary_stats(self) -> dict[str, Any]:
        """Calculate summary statistics for the timeline."""
        
        total = len(self.vulnerabilities)
        with_patch = sum(1 for v in self.vulnerabilities if v.is_patch_available)
        open_count = sum(1 for v in self.vulnerabilities if v.status == "open")

        # Patch window metrics
        patch_windows: list[int] = []
        for vuln in self.vulnerabilities:
            pw = vuln.patch_window_days
            if pw is not None and 0 < pw <= 365:  # Reasonable range
                patch_windows.append(pw)

        avg_patch_window = sum(patch_windows) / len(patch_windows) if patch_windows else 0
        max_patch_window = max(patch_windows) if patch_windows else 0
        min_patch_window = min(patch_windows) if patch_windows else 0

        # Severity distribution
        severity_dist: dict[str, int] = defaultdict(int)
        for vuln in self.vulnerabilities:
            severity_dist[vuln.severity.name] += 1

        return {
            "total_vulnerabilities": total,
            "with_patch_available": with_patch,
            "open_count": open_count,
            "patched_count": len(self.vulnerabilities) - open_count,
            "avg_patch_window_days": round(avg_patch_window, 1),
            "max_patch_window_days": max_patch_window,
            "min_patch_window_days": min_patch_window,
            "severity_distribution": dict(severity_dist),
        }

    def render_text_report(self) -> str:
        """Render a text-based report of the timeline."""
        
        lines = []
        stats = self.get_summary_stats()

        # Header
        lines.append("=" * 70)
        lines.append("VULNERABILITY DISCLOSURE TIMELINE REPORT")
        lines.append("=" * 70)
        lines.append("")

        # Summary statistics
        lines.append("SUMMARY STATISTICS")
        lines.append("-" * 40)
        
        for key, value in stats.items():
            if isinstance(value, dict):
                lines.append(f"  {key}:")
                for k, v in value.items():
                    lines.append(f"    - {k}: {v}")
            else:
                lines.append(f"  {key}: {value}")

        lines.append("")

        # Timeline entries
        if self.entries:
            lines.append("TIMELINE ENTRIES")
            lines.append("-" * 40)
            
            current_date = None
            grouped_entries: list[list[TimelineEntry]] = []
            
            for entry in self.entries:
                if entry.date != current_date:
                    if current_date is not None and grouped_entries:
                        grouped_entries.append(grouped_entries[-1])
                    
                    current_date = entry.date
                    grouped_entries.append([entry])
                else:
                    grouped_entries[-1].append(entry)

            # Format each day's entries
            for i, day_entries in enumerate(grouped_entries):
                if not day_entries:
                    continue
                
                date_str = day_entries[0].date.strftime("%Y-%m-%d")
                
                # Group by event type within the day
                by_type: dict[str, list] = defaultdict(list)
                for e in day_entries:
                    by_type[e.event_type].append(e)

                lines.append(f"\n  {date_str}")
                
                for event_type in ["discovered", "patched", "retired"]:
                    if event_type not in by_type:
                        continue
                    
                    entries = sorted(by_type[event_type], 
                                   key=lambda e: -e.severity_score)
                    
                    for entry in entries:
                        severity_marker = {
                            SeverityLevel.CRITICAL: "[CRIT]",
                            SeverityLevel.HIGH: "[HIGH]",
                            SeverityLevel.MEDIUM: "[MED]",
                            SeverityLevel.LOW: "[LOW]",
                            SeverityLevel.INFO: "[INF]",
                        }.get(entry.severity, "")

                        lines.append(f"    {severity_marker} {event_type}: " + 
                                     f"{entry.cve_id or 'N/A'} - {escape(entry.title)}")

        else:
            lines.append("No timeline entries found.")

        # Patch window analysis
        if patch_windows:
            lines.append("")
            lines.append("PATCH WINDOW ANALYSIS")
            lines.append("-" * 40)
            
            critical_vulns = [v for v in self.vulnerabilities 
                            if v.severity == SeverityLevel.CRITICAL]
            high_vulns = [v for v in self.vulnerabilities 
                         if v.severity == SeverityLevel.HIGH]

            lines.append(f"  Critical vulnerabilities: {len(critical_vulns)}")
            lines.append(f"  High vulnerabilities: {len(high_vulns)}")
            
            # Highlight slow patches
            slow_patches = [v for v in self.vulnerabilities 
                          if v.patch_window_days and v.patch_window_days > 90]
            if slow_patches:
                lines.append("")
                lines.append("  Slow patches (>90 days):")
                for v in sorted(slow_patches, key=lambda x: -x.patch_window_days)[:10]:
                    lines.append(f"    {v.cve_id}: {v.patch_window_days} days " + 
                                 f"(patched: {v.patched_date})")

        # Footer
        lines.append("")
        lines.append("=" * 70)
        lines.append("END OF REPORT")
        lines.append("=" * 70)

        return "\n".join(lines)

    def render_json_report(self, indent: int = 2) -> str:
        """Render a JSON report of the timeline."""
        
        stats = self.get_summary_stats()
        
        # Build entries as JSON-serializable objects
        entries_data = []
        for entry in self.entries:
            entries_data.append({
                "date": entry.date.isoformat(),
                "event_type": entry.event_type,
                "cve_id": entry.cve_id,
                "title": escape(entry.title),
                "severity": entry.severity.name,
            })

        report = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "total_vulnerabilities": len(self.vulnerabilities),
                "total_events": len(entries_data),
                **stats,
            },
            "entries": entries_data,
        }

        return json.dumps(report, indent=indent)

    def render_html_report(self) -> str:
        """Render an HTML report with basic styling."""
        
        stats = self.get_summary_stats()
        
        # Build timeline rows
        rows = []
        for entry in self.entries:
            row_class = f"event-{entry.event_type}"
            
            # Determine color based on severity and event type
            base_colors = {
                "discovered": "#e3f2fd",  # Light blue background
                "patched": "#e8f5e9",     # Light green
                "retired": "#fff3e0",     # Light orange
            }
            
            severity_colors = {
                SeverityLevel.CRITICAL: "#ffcdd2",    # Red-tinted
                SeverityLevel.HIGH: "#ffe0b2",        # Orange-tinted  
                SeverityLevel.MEDIUM: "#fff9c4",      # Yellow-tinted
                SeverityLevel.LOW: "#e1f5fe",         # Cyan-tinted
                SeverityLevel.INFO: "#
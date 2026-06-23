"""Offline matching/enrichment against the bundled cognis_vulndb (262k OSV vulns).

This wires the air-gapped :class:`vulntimeline.vulndb_local.VulnDB` into
vulntimeline so the tool can resolve the **components, packages, and CVE/GHSA
references** that turn up in a disclosure timeline against a real, bundled
vulnerability corpus — with **zero network access**.

Two entry points:

* :func:`match_advisories` — takes parsed :class:`~vulntimeline.core.Advisory`
  records and resolves each one against the DB by CVE/GHSA id (taken from the
  advisory ``id`` or its ``extra`` fields) and by any affected packages declared
  in the advisory record (``package``/``packages``/``component`` extras). Returns
  one enrichment row per advisory.
* :func:`match_components` — takes a flat list of ``ecosystem:name`` /
  ``name`` package coordinates (e.g. a parsed SBOM component list) and resolves
  each against the DB by package name. Returns one row per component.

Everything is read-only and offline. No active scanning, no network.
"""

from __future__ import annotations

import re
from typing import Any, Iterable, Optional

from .vulndb_local import VulnDB

# CVE / GHSA / RUSTSEC / GO advisory id shapes the corpus indexes on.
_ALIAS_RE = re.compile(
    r"(?:CVE-\d{4}-\d{4,}"
    r"|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}"
    r"|RUSTSEC-\d{4}-\d{4}"
    r"|GO-\d{4}-\d{4,}"
    r"|PYSEC-\d{4}-\d+"
    r"|OSV-\d{4}-\d+)",
    re.IGNORECASE,
)


def extract_ids(*texts: Any) -> list[str]:
    """Pull canonical (upper-cased) advisory ids out of arbitrary text fields."""
    out: list[str] = []
    seen: set[str] = set()
    for t in texts:
        if not t:
            continue
        for m in _ALIAS_RE.findall(str(t)):
            mid = m.upper()
            if mid not in seen:
                seen.add(mid)
                out.append(mid)
    return out


def _advisory_ids(adv: Any) -> list[str]:
    """Collect candidate DB ids from an advisory's id + alias-ish extras."""
    fields: list[Any] = [getattr(adv, "id", None), getattr(adv, "title", None)]
    extra = getattr(adv, "extra", {}) or {}
    for key in ("cve", "cves", "ghsa", "aliases", "alias", "references", "refs"):
        v = extra.get(key)
        if isinstance(v, (list, tuple)):
            fields.extend(v)
        elif v is not None:
            fields.append(v)
    return extract_ids(*fields)


def _advisory_packages(adv: Any) -> list[str]:
    """Collect candidate package names declared on the advisory record."""
    extra = getattr(adv, "extra", {}) or {}
    pkgs: list[str] = []
    for key in ("package", "packages", "component", "components", "affected"):
        v = extra.get(key)
        if isinstance(v, (list, tuple)):
            for item in v:
                if isinstance(item, dict):
                    name = item.get("name") or item.get("package")
                    if name:
                        pkgs.append(str(name))
                elif item:
                    pkgs.append(str(item))
        elif isinstance(v, dict):
            name = v.get("name") or v.get("package")
            if name:
                pkgs.append(str(name))
        elif v is not None:
            pkgs.append(str(v))
    # de-dupe, preserve order
    out: list[str] = []
    seen: set[str] = set()
    for p in pkgs:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


def _record_summary(rec: dict) -> dict[str, Any]:
    """Trim a DB record down to the fields the enrichment surfaces."""
    return {
        "id": rec.get("id"),
        "aliases": rec.get("aliases") or [],
        "ecosystem": rec.get("ecosystem"),
        "summary": rec.get("summary"),
        "severity": rec.get("severity"),
        "packages": rec.get("packages") or [],
        "published": rec.get("published"),
        "modified": rec.get("modified"),
    }


def _dedupe_records(records: Iterable[dict]) -> list[dict]:
    out: list[dict] = []
    seen: set[str] = set()
    for r in records:
        rid = r.get("id") or ""
        if rid and rid in seen:
            continue
        seen.add(rid)
        out.append(r)
    return out


def match_advisories(
    advisories: list,
    *,
    db: Optional[VulnDB] = None,
    limit_per: int = 25,
) -> list[dict[str, Any]]:
    """Resolve each advisory against the bundled OSV DB (offline).

    For every advisory it returns::

        {id, query_ids, query_packages, db_matches: [...], match_count,
         matched_by_id: bool, matched_by_package: bool}

    A match is found "by id" when a CVE/GHSA/etc. id on the advisory resolves in
    the corpus, and "by package" when a declared package name resolves.
    """
    db = db or VulnDB()
    out: list[dict[str, Any]] = []
    for adv in advisories:
        ids = _advisory_ids(adv)
        pkgs = _advisory_packages(adv)

        matches: list[dict] = []
        matched_by_id = False
        matched_by_package = False

        for mid in ids:
            recs = db.by_cve(mid)
            if recs:
                matched_by_id = True
                matches.extend(recs)
        for pkg in pkgs:
            recs = db.by_package(pkg)
            if recs:
                matched_by_package = True
                matches.extend(recs)

        deduped = _dedupe_records(matches)[:limit_per]
        out.append({
            "id": getattr(adv, "id", None),
            "query_ids": ids,
            "query_packages": pkgs,
            "match_count": len(deduped),
            "matched_by_id": matched_by_id,
            "matched_by_package": matched_by_package,
            "db_matches": [_record_summary(r) for r in deduped],
        })
    return out


def match_components(
    components: Iterable[str],
    *,
    db: Optional[VulnDB] = None,
    limit_per: int = 25,
) -> list[dict[str, Any]]:
    """Resolve a flat list of package coordinates against the bundled DB.

    Each coordinate may be ``name`` or ``ecosystem:name`` (e.g. ``PyPI:django``,
    ``npm:lodash``, ``Maven:org.apache.logging.log4j:log4j-core``). The portion
    after the first ``:`` that names an ecosystem filters matches by ecosystem;
    otherwise the whole string is treated as a package name.
    """
    db = db or VulnDB()
    known_ecos = {"pypi", "npm", "go", "maven", "rubygems", "crates.io",
                  "nuget", "packagist", "pub", "hex", "conan", "swifturl"}
    out: list[dict[str, Any]] = []
    for raw in components:
        coord = (raw or "").strip()
        if not coord:
            continue
        ecosystem: Optional[str] = None
        name = coord
        if ":" in coord:
            head, rest = coord.split(":", 1)
            if head.lower() in known_ecos:
                ecosystem = head
                name = rest
        recs = db.by_package(name, ecosystem=ecosystem)
        deduped = _dedupe_records(recs)[:limit_per]
        out.append({
            "component": coord,
            "package": name,
            "ecosystem": ecosystem,
            "match_count": len(deduped),
            "db_matches": [_record_summary(r) for r in deduped],
        })
    return out

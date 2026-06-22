"""Real, edge/air-gap-deployable data-feed enrichment for vulntimeline.

This module wires the bundled, standard-library :mod:`vulntimeline.datafeeds`
ingestion engine into vulntimeline so that advisory timelines can be enriched
with **real, authoritative, keyless** vulnerability intelligence:

* ``cisa-kev`` — CISA Known Exploited Vulnerabilities catalog. If an advisory's
  ``id`` is a CVE that appears in KEV, it is *actively exploited in the wild* —
  the single highest-priority signal a remediation team can have.
* ``epss``     — FIRST EPSS exploit-probability score (probability the CVE is
  exploited in the next 30 days), used to rank/prioritise un-flagged advisories.
* ``osv``      — OSV.dev package-vulnerability query (available via the feeds CLI
  for ecosystem lookups; not auto-applied to advisory enrichment since advisory
  records are CVE-keyed, not package-keyed).

Everything runs over the bundled :mod:`datafeeds` engine, which fetches over
HTTPS, caches to disk (``COGNIS_FEEDS_CACHE``), and re-serves **offline** so the
tool keeps working on a disconnected / air-gapped enclave. See ``feeds_snapshot``
helpers for the sneakernet workflow.

Defensive / authorized-use intelligence only.
"""

from __future__ import annotations

import re
from typing import Any, Iterable, Optional

from . import datafeeds

# The feed ids this repo (a vulnerability tool) is allowed to surface.
RELEVANT_FEEDS: list[str] = ["cisa-kev", "epss", "osv"]

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def relevant_catalog() -> dict:
    """Return the catalog filtered to this tool's relevant feed ids."""
    full = datafeeds.load_catalog()
    feeds = [f for f in full.get("feeds", []) if f["id"] in RELEVANT_FEEDS]
    return {"feeds": feeds}


def list_relevant() -> list[dict]:
    """List only the catalog feeds relevant to vulntimeline (cisa-kev/epss/osv)."""
    return [f for f in datafeeds.list_feeds() if f["id"] in RELEVANT_FEEDS]


def _ensure_relevant(feed_id: str) -> None:
    if feed_id not in RELEVANT_FEEDS:
        raise KeyError(
            f"feed {feed_id!r} is not relevant to vulntimeline; "
            f"choose one of {RELEVANT_FEEDS}"
        )


def normalize_cve(advisory_id: str) -> Optional[str]:
    """Extract a canonical upper-case CVE id from an advisory id, or None."""
    if not advisory_id:
        return None
    m = _CVE_RE.search(advisory_id)
    return m.group(0).upper() if m else None


# --------------------------------------------------------------------------- #
# Feed -> lookup index builders
# --------------------------------------------------------------------------- #
def kev_index(*, offline: bool = False, catalog: Optional[dict] = None) -> dict[str, dict]:
    """Build {CVE -> kev-record} from the CISA KEV feed (cached/offline aware)."""
    data = datafeeds.get("cisa-kev", offline=offline, catalog=catalog)
    out: dict[str, dict] = {}
    for v in data.get("vulnerabilities", []):
        cve = (v.get("cveID") or "").upper()
        if cve:
            out[cve] = v
    return out


def epss_index(
    cves: Optional[Iterable[str]] = None,
    *,
    offline: bool = False,
    catalog: Optional[dict] = None,
) -> dict[str, dict]:
    """Build {CVE -> {epss, percentile, date}} from the EPSS feed.

    When ``cves`` is given and we are online, EPSS is queried for exactly those
    CVEs (the EPSS API supports ``?cve=A,B,C``). Offline, the cached EPSS page is
    used as-is. Returns an empty dict if nothing is cached offline.
    """
    if offline:
        # Air-gap path: serve whatever EPSS page is cached, no network.
        try:
            data = datafeeds.get("epss", offline=True, catalog=catalog)
        except FileNotFoundError:
            return {}
    elif cves:
        # Online targeted lookup: EPSS supports ?cve=A,B,C for exact scores.
        data = _epss_fetch_cves(cves, catalog=catalog)
    else:
        try:
            data = datafeeds.get("epss", offline=False, catalog=catalog)
        except FileNotFoundError:
            return {}
    out: dict[str, dict] = {}
    for row in data.get("data", []):
        cve = (row.get("cve") or "").upper()
        if not cve:
            continue
        out[cve] = {
            "epss": _as_float(row.get("epss")),
            "percentile": _as_float(row.get("percentile")),
            "date": row.get("date"),
        }
    return out


def _epss_fetch_cves(cves: Iterable[str], *, catalog: Optional[dict] = None) -> dict:
    """Online targeted EPSS lookup via ``?cve=A,B,C`` (network; online only).

    Uses the bundled :func:`datafeeds.fetch` so there is still exactly one
    HTTP path in the codebase. Returns the parsed EPSS JSON envelope.
    """
    import json as _json

    feeds = {f["id"]: f for f in (catalog or datafeeds.load_catalog()).get("feeds", [])}
    base = feeds["epss"]["url"]
    wanted = sorted({c.upper() for c in cves if c})
    url = f"{base}?cve={','.join(wanted)}" if wanted else base
    raw = datafeeds.fetch(url)
    return _json.loads(raw.decode("utf-8", "replace"))


def _as_float(value: Any) -> Optional[float]:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


# --------------------------------------------------------------------------- #
# Enrichment
# --------------------------------------------------------------------------- #
def enrich_advisories(
    advisories: list,
    *,
    offline: bool = False,
    catalog: Optional[dict] = None,
) -> list[dict[str, Any]]:
    """Cross-reference advisories against CISA-KEV + EPSS.

    Returns one enrichment record per advisory:

        {id, cve, kev: bool, kev_ransomware: bool, kev_date_added,
         kev_due_date, epss, epss_percentile, epss_date, priority}

    ``priority`` is a small ordinal the tool uses to sort: KEV-listed first
    (especially ransomware-associated), then by EPSS probability.
    """
    cves = [c for c in (normalize_cve(a.id) for a in advisories) if c]
    kev = kev_index(offline=offline, catalog=catalog) if cves else {}
    epss = epss_index(cves, offline=offline, catalog=catalog) if cves else {}

    out: list[dict[str, Any]] = []
    for adv in advisories:
        cve = normalize_cve(adv.id)
        kv = kev.get(cve) if cve else None
        ep = epss.get(cve) if cve else None
        is_kev = kv is not None
        ransom = bool(kv and str(kv.get("knownRansomwareCampaignUse", "")).lower() == "known")
        epss_score = ep.get("epss") if ep else None

        out.append({
            "id": adv.id,
            "cve": cve,
            "kev": is_kev,
            "kev_ransomware": ransom,
            "kev_date_added": kv.get("dateAdded") if kv else None,
            "kev_due_date": kv.get("dueDate") if kv else None,
            "kev_name": kv.get("vulnerabilityName") if kv else None,
            "epss": epss_score,
            "epss_percentile": ep.get("percentile") if ep else None,
            "epss_date": ep.get("date") if ep else None,
            "priority": _priority(is_kev, ransom, epss_score),
        })
    return out


def _priority(is_kev: bool, ransom: bool, epss_score: Optional[float]) -> float:
    """Higher = more urgent. KEV dominates; ransomware bumps; EPSS breaks ties."""
    score = 0.0
    if is_kev:
        score += 100.0
    if ransom:
        score += 50.0
    if epss_score is not None:
        score += epss_score  # 0..1
    return round(score, 6)


def enrich_index(
    advisories: list,
    *,
    offline: bool = False,
    catalog: Optional[dict] = None,
) -> dict[str, dict[str, Any]]:
    """Same as :func:`enrich_advisories` but keyed by advisory id."""
    return {row["id"]: row for row in enrich_advisories(advisories, offline=offline, catalog=catalog)}

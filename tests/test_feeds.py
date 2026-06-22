"""Offline tests for the real data-feed enrichment layer.

These tests NEVER touch the network. They point ``COGNIS_FEEDS_CACHE`` at the
committed fixture cache under ``tests/fixtures/feeds_cache`` and exercise the
enrichment + ``feeds`` CLI entirely from cached data (``offline=True``), so CI
stays green on an air-gapped / disconnected runner.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulntimeline import feeds as feedmod
from vulntimeline import datafeeds
from vulntimeline.core import load_advisories
from vulntimeline.cli import main

FIX = Path(__file__).resolve().parent / "fixtures"
CACHE = FIX / "feeds_cache"
ADVISORIES = FIX / "cve_advisories.json"


@pytest.fixture(autouse=True)
def _offline_cache(monkeypatch):
    """Force every feed read to come from the committed fixture cache."""
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(CACHE))
    # Belt-and-braces: make any accidental network fetch fail loudly.
    def _no_net(*a, **k):  # pragma: no cover - only hit on a bug
        raise AssertionError("network access attempted in an offline test")
    monkeypatch.setattr(datafeeds, "fetch", _no_net)
    yield


def _load():
    return load_advisories(ADVISORIES.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------- #
# catalog filtering
# --------------------------------------------------------------------------- #
def test_relevant_feeds_only():
    ids = {f["id"] for f in feedmod.list_relevant()}
    assert ids == {"cisa-kev", "epss", "osv"}


def test_relevant_catalog_is_subset():
    cat = feedmod.relevant_catalog()
    assert {f["id"] for f in cat["feeds"]} == {"cisa-kev", "epss", "osv"}


def test_ensure_relevant_rejects_offdomain():
    with pytest.raises(KeyError):
        feedmod._ensure_relevant("ofac-sdn")


# --------------------------------------------------------------------------- #
# cve normalisation
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("raw,expected", [
    ("CVE-2021-44228", "CVE-2021-44228"),
    ("cve-2021-44228", "CVE-2021-44228"),
    ("advisory CVE-2014-0160 heartbleed", "CVE-2014-0160"),
    ("INTERNAL-2025-0001", None),
    ("", None),
])
def test_normalize_cve(raw, expected):
    assert feedmod.normalize_cve(raw) == expected


# --------------------------------------------------------------------------- #
# offline indices
# --------------------------------------------------------------------------- #
def test_kev_index_offline():
    idx = feedmod.kev_index(offline=True)
    assert "CVE-2021-44228" in idx
    assert idx["CVE-2021-44228"]["knownRansomwareCampaignUse"] == "Known"


def test_epss_index_offline():
    idx = feedmod.epss_index(offline=True)
    assert idx["CVE-2021-44228"]["epss"] == pytest.approx(0.99999)
    assert 0.0 <= idx["CVE-2017-0144"]["epss"] <= 1.0


def test_osv_get_offline():
    data = datafeeds.get("osv", offline=True)
    assert data["vulns"][0]["aliases"] == ["CVE-2021-44228"]


# --------------------------------------------------------------------------- #
# enrichment
# --------------------------------------------------------------------------- #
def test_enrich_advisories_offline():
    rows = feedmod.enrich_advisories(_load(), offline=True)
    by_id = {r["id"]: r for r in rows}

    log4shell = by_id["CVE-2021-44228"]
    assert log4shell["kev"] is True
    assert log4shell["kev_ransomware"] is True
    assert log4shell["epss"] == pytest.approx(0.99999)
    assert log4shell["cve"] == "CVE-2021-44228"

    heartbleed = by_id["CVE-2014-0160"]
    assert heartbleed["kev"] is True
    assert heartbleed["kev_ransomware"] is False  # KEV says 'Unknown'

    internal = by_id["INTERNAL-2025-0001"]
    assert internal["cve"] is None
    assert internal["kev"] is False
    assert internal["epss"] is None


def test_priority_orders_kev_above_noncve():
    rows = feedmod.enrich_advisories(_load(), offline=True)
    by_id = {r["id"]: r for r in rows}
    # A KEV+ransomware advisory must outrank a non-CVE internal one.
    assert by_id["CVE-2021-44228"]["priority"] > by_id["INTERNAL-2025-0001"]["priority"]
    # Ransomware KEV outranks a non-ransomware KEV of equal EPSS class.
    assert by_id["CVE-2021-44228"]["priority"] > by_id["CVE-2014-0160"]["priority"]


def test_enrich_index_keyed_by_id():
    idx = feedmod.enrich_index(_load(), offline=True)
    assert set(idx) == {
        "CVE-2021-44228", "CVE-2021-34527", "CVE-2014-0160", "INTERNAL-2025-0001",
    }


# --------------------------------------------------------------------------- #
# CLI: build --enrich --offline
# --------------------------------------------------------------------------- #
def test_cli_build_enrich_offline_markdown(capsys):
    rc = main(["build", str(ADVISORIES), "--enrich", "--offline", "--no-ascii"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Live feed enrichment (CISA-KEV + EPSS)" in out
    assert "CVE-2021-44228" in out
    assert "known-exploited" in out


def test_cli_build_enrich_offline_json(capsys):
    rc = main(["build", str(ADVISORIES), "--enrich", "--offline", "--json"])
    out = capsys.readouterr().out
    assert rc == 0
    data = json.loads(out)
    rec = next(r for r in data if r["id"] == "CVE-2021-44228")
    assert rec["feeds"]["kev"] is True
    assert rec["feeds"]["epss"] == pytest.approx(0.99999)


# --------------------------------------------------------------------------- #
# CLI: feeds subcommand
# --------------------------------------------------------------------------- #
def test_cli_feeds_list(capsys):
    rc = main(["feeds", "list"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "cisa-kev" in out and "epss" in out and "osv" in out
    # off-domain feeds must not leak in
    assert "ofac-sdn" not in out


def test_cli_feeds_get_offline(capsys):
    rc = main(["feeds", "get", "cisa-kev", "--offline"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "CVE-2021-44228" in out


def test_cli_feeds_get_rejects_offdomain(capsys):
    rc = main(["feeds", "get", "ofac-sdn", "--offline"])
    err = capsys.readouterr().err
    assert rc == 1
    assert "not relevant" in err


# --------------------------------------------------------------------------- #
# air-gap snapshot round-trip (no network)
# --------------------------------------------------------------------------- #
def test_snapshot_roundtrip(tmp_path, monkeypatch):
    # export the fixture cache, import into a fresh empty cache, re-read offline.
    archive = tmp_path / "feeds.tar.gz"
    n = datafeeds.snapshot_export(str(archive))
    assert n >= 3

    fresh = tmp_path / "imported_cache"
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(fresh))
    imported = datafeeds.snapshot_import(str(archive))
    assert imported >= 3
    idx = feedmod.kev_index(offline=True)
    assert "CVE-2021-44228" in idx

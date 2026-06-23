"""Offline tests for matching advisories/components against the bundled OSV DB.

These exercise REAL lookups in the bundled cognis_vulndb (262k records): e.g.
CVE-2021-44228 (Log4Shell) resolves, and widely-vulnerable packages (django,
lodash) resolve to many known CVEs. No network, stdlib only.
"""
from vulntimeline.core import Advisory
from vulntimeline.vulndb_local import VulnDB
from vulntimeline import vulnmatch


# A module-level DB so the gz is decompressed once for the whole module.
_DB = VulnDB()


# --------------------------------------------------------------------------- #
# id extraction
# --------------------------------------------------------------------------- #
def test_extract_ids_cve():
    assert vulnmatch.extract_ids("see CVE-2021-44228 now") == ["CVE-2021-44228"]


def test_extract_ids_lowercases_to_upper():
    assert vulnmatch.extract_ids("cve-2021-44228") == ["CVE-2021-44228"]


def test_extract_ids_ghsa():
    ids = vulnmatch.extract_ids("GHSA-jfh8-c2jp-5v3q")
    assert ids == ["GHSA-JFH8-C2JP-5V3Q"]


def test_extract_ids_rustsec():
    assert vulnmatch.extract_ids("RUSTSEC-2022-0004") == ["RUSTSEC-2022-0004"]


def test_extract_ids_go():
    assert vulnmatch.extract_ids("GO-2022-0001") == ["GO-2022-0001"]


def test_extract_ids_multiple_dedupes_and_orders():
    ids = vulnmatch.extract_ids("CVE-2021-44228 and CVE-2021-45046 and CVE-2021-44228")
    assert ids == ["CVE-2021-44228", "CVE-2021-45046"]


def test_extract_ids_empty():
    assert vulnmatch.extract_ids("", None, "no ids here") == []


def test_extract_ids_pysec():
    assert vulnmatch.extract_ids("PYSEC-2022-190") == ["PYSEC-2022-190"]


# --------------------------------------------------------------------------- #
# advisory matching by id
# --------------------------------------------------------------------------- #
def test_match_log4shell_by_id():
    adv = Advisory(id="CVE-2021-44228", title="Log4Shell")
    rows = vulnmatch.match_advisories([adv], db=_DB)
    assert len(rows) == 1
    row = rows[0]
    assert row["matched_by_id"] is True
    assert row["match_count"] >= 1
    # the canonical GHSA for Log4Shell must surface
    ghsa_ids = {m["id"] for m in row["db_matches"]}
    assert "GHSA-jfh8-c2jp-5v3q" in ghsa_ids


def test_match_log4shell_alias_present():
    adv = Advisory(id="CVE-2021-44228")
    row = vulnmatch.match_advisories([adv], db=_DB)[0]
    log4j = next(m for m in row["db_matches"] if m["id"] == "GHSA-jfh8-c2jp-5v3q")
    assert "CVE-2021-44228" in log4j["aliases"]
    assert log4j["ecosystem"] == "Maven"


def test_match_unknown_cve_no_hits():
    adv = Advisory(id="CVE-9999-0001")
    row = vulnmatch.match_advisories([adv], db=_DB)[0]
    assert row["match_count"] == 0
    assert row["matched_by_id"] is False
    assert row["matched_by_package"] is False


def test_match_id_in_extra_field():
    adv = Advisory(id="INTERNAL-1", extra={"cve": "CVE-2021-44228"})
    row = vulnmatch.match_advisories([adv], db=_DB)[0]
    assert row["matched_by_id"] is True
    assert "CVE-2021-44228" in row["query_ids"]


def test_match_id_in_references_list():
    adv = Advisory(id="INTERNAL-2", extra={"references": ["see CVE-2021-44228"]})
    row = vulnmatch.match_advisories([adv], db=_DB)[0]
    assert "CVE-2021-44228" in row["query_ids"]


# --------------------------------------------------------------------------- #
# advisory matching by package
# --------------------------------------------------------------------------- #
def test_match_by_package_django():
    adv = Advisory(id="INTERNAL-3", extra={"package": "django"})
    row = vulnmatch.match_advisories([adv], db=_DB)[0]
    assert row["matched_by_package"] is True
    assert row["match_count"] >= 1
    assert "django" in row["query_packages"]


def test_match_by_packages_list():
    adv = Advisory(id="INTERNAL-4", extra={"packages": ["django", "lodash"]})
    row = vulnmatch.match_advisories([adv], db=_DB)[0]
    assert row["matched_by_package"] is True
    assert set(row["query_packages"]) == {"django", "lodash"}


def test_match_by_component_dict():
    adv = Advisory(id="INTERNAL-5", extra={"components": [{"name": "lodash"}]})
    row = vulnmatch.match_advisories([adv], db=_DB)[0]
    assert "lodash" in row["query_packages"]
    assert row["matched_by_package"] is True


def test_match_limit_per_caps_results():
    adv = Advisory(id="INTERNAL-6", extra={"package": "django"})
    row = vulnmatch.match_advisories([adv], db=_DB, limit_per=3)[0]
    assert row["match_count"] <= 3


def test_match_dedupes_across_id_and_package():
    # Log4Shell resolves both by CVE and by the maven package coordinate;
    # the same GHSA record must not be counted twice.
    adv = Advisory(
        id="CVE-2021-44228",
        extra={"package": "org.apache.logging.log4j:log4j-core"},
    )
    row = vulnmatch.match_advisories([adv], db=_DB)[0]
    ids = [m["id"] for m in row["db_matches"]]
    assert len(ids) == len(set(ids))
    assert row["matched_by_id"] and row["matched_by_package"]


# --------------------------------------------------------------------------- #
# component matching
# --------------------------------------------------------------------------- #
def test_components_plain_name():
    rows = vulnmatch.match_components(["django"], db=_DB)
    assert rows[0]["match_count"] >= 1
    assert rows[0]["package"] == "django"
    assert rows[0]["ecosystem"] is None


def test_components_ecosystem_prefix():
    rows = vulnmatch.match_components(["PyPI:django"], db=_DB)
    row = rows[0]
    assert row["ecosystem"] == "PyPI"
    assert row["package"] == "django"
    assert row["match_count"] >= 1
    # every match must be PyPI when ecosystem-filtered
    assert all(m["ecosystem"] == "PyPI" for m in row["db_matches"])


def test_components_npm_lodash():
    rows = vulnmatch.match_components(["npm:lodash"], db=_DB)
    assert rows[0]["match_count"] >= 1
    assert all(m["ecosystem"] == "npm" for m in rows[0]["db_matches"])


def test_components_unknown_package():
    rows = vulnmatch.match_components(["definitely-not-a-real-pkg-xyz"], db=_DB)
    assert rows[0]["match_count"] == 0


def test_components_skips_blank():
    rows = vulnmatch.match_components(["", "   ", "django"], db=_DB)
    assert len(rows) == 1
    assert rows[0]["package"] == "django"


def test_components_unknown_ecosystem_prefix_treated_as_name():
    # a colon that is NOT a known ecosystem keeps the whole string as the name
    rows = vulnmatch.match_components(["weird:thing"], db=_DB)
    assert rows[0]["ecosystem"] is None
    assert rows[0]["package"] == "weird:thing"


# --------------------------------------------------------------------------- #
# record summary shape
# --------------------------------------------------------------------------- #
def test_record_summary_fields():
    adv = Advisory(id="CVE-2021-44228")
    rec = vulnmatch.match_advisories([adv], db=_DB)[0]["db_matches"][0]
    for f in ("id", "aliases", "ecosystem", "summary", "severity", "packages",
              "published", "modified"):
        assert f in rec

"""Tests for the SARIF 2.1.0 exporter and the `flags --sarif` CLI path."""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest

from vulntimeline.cli import main
from vulntimeline.core import Advisory, detect_flags
from vulntimeline.sarif import flags_to_sarif, SARIF_VERSION

EXAMPLES = Path(__file__).resolve().parent.parent / "examples" / "advisories.json"


def _sample_flags():
    advs = [
        Advisory(id="XBP", exploited=date(2025, 1, 1), patched=date(2025, 1, 5)),
        Advisory(id="OPEN", disclosed=date(2025, 1, 1)),
        Advisory(id="SLOW", disclosed=date(2025, 1, 1), patched=date(2025, 3, 1)),
    ]
    return detect_flags(advs, max_time_to_patch=10)


def test_sarif_top_level_shape():
    log = flags_to_sarif(_sample_flags(), source_path="advs.json")
    assert log["version"] == SARIF_VERSION == "2.1.0"
    assert "$schema" in log
    assert isinstance(log["runs"], list) and len(log["runs"]) == 1


def test_sarif_driver_metadata():
    log = flags_to_sarif(_sample_flags())
    driver = log["runs"][0]["tool"]["driver"]
    assert driver["name"] == "vulntimeline"
    assert "version" in driver
    assert isinstance(driver["rules"], list) and driver["rules"]


def test_sarif_rules_are_unique_and_match_results():
    flags = _sample_flags()
    log = flags_to_sarif(flags)
    rule_ids = [r["id"] for r in log["runs"][0]["tool"]["driver"]["rules"]]
    assert len(rule_ids) == len(set(rule_ids))  # deduped
    result_rule_ids = {r["ruleId"] for r in log["runs"][0]["results"]}
    assert result_rule_ids.issubset(set(rule_ids))


def test_sarif_levels_mapped_from_severity():
    log = flags_to_sarif(_sample_flags())
    by_rule = {r["ruleId"]: r["level"] for r in log["runs"][0]["results"]}
    assert by_rule["exploited_before_patch"] == "error"   # high -> error
    assert by_rule["unpatched"] == "warning"              # medium -> warning


def test_sarif_result_has_location_and_fingerprint():
    log = flags_to_sarif(_sample_flags(), source_path="advs.json")
    res = log["runs"][0]["results"][0]
    loc = res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert loc == "advs.json"
    assert "partialFingerprints" in res
    assert res["locations"][0]["logicalLocations"][0]["name"]


def test_sarif_empty_flags_yields_empty_run():
    log = flags_to_sarif([])
    assert log["runs"][0]["results"] == []
    assert log["runs"][0]["tool"]["driver"]["rules"] == []


def test_sarif_result_count_matches_flag_count():
    flags = _sample_flags()
    log = flags_to_sarif(flags)
    assert len(log["runs"][0]["results"]) == len(flags)


def test_cli_sarif_emits_valid_json(capsys):
    rc = main(["flags", str(EXAMPLES), "--sarif"])
    out = capsys.readouterr().out
    assert rc == 0
    data = json.loads(out)
    assert data["version"] == "2.1.0"
    assert data["runs"][0]["tool"]["driver"]["name"] == "vulntimeline"


def test_cli_sarif_records_source_path(capsys):
    main(["flags", str(EXAMPLES), "--sarif"])
    out = capsys.readouterr().out
    data = json.loads(out)
    uris = {
        r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        for r in data["runs"][0]["results"]
    }
    assert uris == {str(EXAMPLES)}


def test_cli_sarif_with_fail_on_any_still_gates(capsys):
    # SARIF output and the CI gate are independent; both should apply.
    rc = main(["flags", str(EXAMPLES), "--sarif", "--fail-on-any"])
    capsys.readouterr()
    assert rc == 2

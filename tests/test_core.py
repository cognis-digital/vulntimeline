"""Tests for parsing, window math, ordering, and flag detection."""

from __future__ import annotations

from datetime import date

import pytest

from vulntimeline.core import (
    Advisory,
    AdvisoryError,
    parse_date,
    load_advisories,
    build_timeline,
    advisory_windows,
    aggregate_metrics,
    detect_flags,
)


# ---------------------------------------------------------------- date parsing

def test_parse_iso_date():
    assert parse_date("2025-02-10") == date(2025, 2, 10)


def test_parse_iso_datetime_with_z():
    assert parse_date("2025-02-05T09:30:00Z") == date(2025, 2, 5)


def test_parse_slashed_and_spelled():
    assert parse_date("2025/02/10") == date(2025, 2, 10)
    assert parse_date("02/10/2025") == date(2025, 2, 10)
    assert parse_date("February 10, 2025") == date(2025, 2, 10)


def test_parse_empty_and_none():
    assert parse_date(None) is None
    assert parse_date("") is None
    assert parse_date("   ") is None


def test_parse_invalid_raises():
    with pytest.raises(AdvisoryError):
        parse_date("not-a-date")


# ----------------------------------------------------------------- loading

def test_load_from_list_and_object():
    recs = [{"id": "A", "disclosed": "2025-01-01"}]
    assert len(load_advisories(recs)) == 1
    assert len(load_advisories({"advisories": recs})) == 1


def test_load_missing_id_raises():
    with pytest.raises(AdvisoryError):
        load_advisories([{"title": "no id"}])


def test_load_duplicate_id_raises():
    with pytest.raises(AdvisoryError):
        load_advisories([{"id": "A"}, {"id": "A"}])


def test_load_invalid_json_string():
    with pytest.raises(AdvisoryError):
        load_advisories("{not json")


def test_unknown_fields_kept_in_extra():
    adv = load_advisories([{"id": "A", "cvss": 9.1}])[0]
    assert adv.extra["cvss"] == 9.1


# ----------------------------------------------------------------- ordering

def test_build_timeline_orders_by_anchor():
    advs = load_advisories([
        {"id": "later", "discovered": "2025-03-01"},
        {"id": "earlier", "discovered": "2025-01-01"},
        {"id": "middle", "reported": "2025-02-01"},
    ])
    ordered = [a.id for a in build_timeline(advs)]
    assert ordered == ["earlier", "middle", "later"]


def test_build_timeline_dateless_last():
    advs = load_advisories([
        {"id": "nodates"},
        {"id": "dated", "discovered": "2025-01-01"},
    ])
    ordered = [a.id for a in build_timeline(advs)]
    assert ordered == ["dated", "nodates"]


def test_anchor_is_earliest_milestone():
    adv = Advisory(id="x", reported=date(2025, 2, 1), discovered=date(2025, 1, 1))
    assert adv.anchor_date() == date(2025, 1, 1)


# ----------------------------------------------------------------- window math

def test_time_to_patch():
    adv = Advisory(id="x", disclosed=date(2025, 2, 10), patched=date(2025, 2, 12))
    w = advisory_windows(adv)
    assert w["time_to_patch"] == 2


def test_disclosure_gap_and_report_latency():
    adv = Advisory(
        id="x",
        discovered=date(2025, 1, 4),
        reported=date(2025, 1, 6),
        disclosed=date(2025, 2, 10),
    )
    w = advisory_windows(adv)
    assert w["report_latency"] == 2
    assert w["disclosure_gap"] == 35


def test_exposure_window_closed():
    adv = Advisory(id="x", exploited=date(2025, 2, 15), patched=date(2025, 2, 20))
    w = advisory_windows(adv)
    assert w["exposure_window"] == 5
    assert w["exposure_open"] is False


def test_exposure_window_open_uses_today():
    adv = Advisory(id="x", exploited=date(2025, 2, 1))
    w = advisory_windows(adv, today=date(2025, 2, 11))
    assert w["exposure_window"] == 10
    assert w["exposure_open"] is True


def test_missing_dates_yield_none_windows():
    adv = Advisory(id="x")
    w = advisory_windows(adv)
    assert w["time_to_patch"] is None
    assert w["disclosure_gap"] is None
    assert w["exposure_window"] is None
    assert w["unpatched"] is True


# ----------------------------------------------------------------- flags

def test_exploited_before_patch_flag():
    adv = Advisory(id="x", exploited=date(2025, 2, 15), patched=date(2025, 2, 20))
    w = advisory_windows(adv)
    assert w["exploited_before_patch"] is True


def test_exploited_after_patch_not_flagged():
    adv = Advisory(id="x", exploited=date(2025, 2, 25), patched=date(2025, 2, 20))
    w = advisory_windows(adv)
    assert w["exploited_before_patch"] is False


def test_exploited_unpatched_is_before_patch():
    adv = Advisory(id="x", exploited=date(2025, 2, 15))
    w = advisory_windows(adv)
    assert w["exploited_before_patch"] is True
    assert w["exposure_open"] is True


def test_detect_slow_patch():
    advs = [Advisory(id="slow", disclosed=date(2025, 1, 1), patched=date(2025, 2, 1))]
    flags = detect_flags(advs, max_time_to_patch=10)
    kinds = {f["kind"] for f in flags}
    assert "slow_patch" in kinds


def test_detect_no_slow_patch_under_threshold():
    advs = [Advisory(id="ok", disclosed=date(2025, 1, 1), patched=date(2025, 1, 3))]
    flags = detect_flags(advs, max_time_to_patch=10)
    assert all(f["kind"] != "slow_patch" for f in flags)


def test_detect_unpatched():
    advs = [Advisory(id="open", disclosed=date(2025, 1, 1))]
    flags = detect_flags(advs)
    assert any(f["kind"] == "unpatched" for f in flags)


def test_detect_negative_window():
    advs = [Advisory(id="bad", disclosed=date(2025, 2, 1), patched=date(2025, 1, 1))]
    flags = detect_flags(advs)
    assert any(f["kind"] == "negative_window" for f in flags)


def test_detect_exploited_before_patch_flag_kind():
    advs = [Advisory(id="xbp", exploited=date(2025, 1, 1), patched=date(2025, 1, 5))]
    flags = detect_flags(advs)
    assert any(f["kind"] == "exploited_before_patch" for f in flags)


# ----------------------------------------------------------------- aggregate

def test_aggregate_medians():
    advs = [
        Advisory(id="a", disclosed=date(2025, 1, 1), patched=date(2025, 1, 3)),   # ttp 2
        Advisory(id="b", disclosed=date(2025, 1, 1), patched=date(2025, 1, 5)),   # ttp 4
        Advisory(id="c", disclosed=date(2025, 1, 1), patched=date(2025, 1, 7)),   # ttp 6
    ]
    m = aggregate_metrics(advs)
    assert m["aggregate"]["count"] == 3
    assert m["aggregate"]["median_time_to_patch"] == 4


def test_aggregate_counts_unpatched_and_xbp():
    advs = [
        Advisory(id="open", disclosed=date(2025, 1, 1)),
        Advisory(id="xbp", exploited=date(2025, 1, 1), patched=date(2025, 1, 5)),
    ]
    m = aggregate_metrics(advs)
    assert m["aggregate"]["unpatched_count"] == 1
    assert m["aggregate"]["exploited_before_patch_count"] == 1


def test_aggregate_median_none_when_empty():
    m = aggregate_metrics([Advisory(id="x")])
    assert m["aggregate"]["median_time_to_patch"] is None

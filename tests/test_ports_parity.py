"""Cross-language parity: the Node port must agree with the Python core on the
remediation windows + flag detection it shares (metrics/flags subcommands).

Skips automatically if Node is not installed, so the suite stays green on any
box; CI installs Node and runs the port's own test runner separately.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
NODE_PORT = ROOT / "ports" / "node" / "vulntimeline.js"
EXAMPLES = ROOT / "examples" / "advisories.json"

from vulntimeline.core import load_advisories, aggregate_metrics, detect_flags

node = shutil.which("node")
pytestmark = pytest.mark.skipif(node is None, reason="node not installed")


def _run_node(*args: str) -> tuple[str, int]:
    proc = subprocess.run(
        [node, str(NODE_PORT), *args],
        capture_output=True, text=True,
    )
    return proc.stdout, proc.returncode


def test_node_metrics_json_matches_python():
    out, rc = _run_node("metrics", str(EXAMPLES), "--json")
    assert rc == 0
    node_rows = {r["id"]: r for r in json.loads(out)["advisories"]}

    advs = load_advisories(EXAMPLES.read_text(encoding="utf-8"))
    py_rows = {r["id"]: r for r in aggregate_metrics(advs)["advisories"]}

    assert set(node_rows) == set(py_rows)
    for adv_id, py in py_rows.items():
        nd = node_rows[adv_id]
        for field in ("time_to_patch", "disclosure_gap", "report_latency",
                      "exposure_window", "exploited_before_patch", "unpatched"):
            assert nd[field] == py[field], f"{adv_id}.{field}: node={nd[field]} py={py[field]}"


def test_node_metrics_aggregate_matches_python():
    out, _ = _run_node("metrics", str(EXAMPLES), "--json")
    node_agg = json.loads(out)["aggregate"]
    advs = load_advisories(EXAMPLES.read_text(encoding="utf-8"))
    py_agg = aggregate_metrics(advs)["aggregate"]
    for k in ("count", "median_time_to_patch", "median_disclosure_gap",
              "exploited_before_patch_count", "unpatched_count"):
        assert node_agg[k] == py_agg[k], f"{k}: node={node_agg[k]} py={py_agg[k]}"


def test_node_flags_json_matches_python():
    out, _ = _run_node("flags", str(EXAMPLES), "--json")
    node_flags = {(f["id"], f["kind"]) for f in json.loads(out)}
    advs = load_advisories(EXAMPLES.read_text(encoding="utf-8"))
    py_flags = {(f["id"], f["kind"]) for f in detect_flags(advs)}
    assert node_flags == py_flags


def test_node_flags_fail_on_any_exit_code():
    _, rc = _run_node("flags", str(EXAMPLES), "--fail-on-any")
    assert rc == 2


def test_node_runs_its_own_test_suite():
    proc = subprocess.run(
        [node, "--test"],
        cwd=str(ROOT / "ports" / "node"),
        capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr

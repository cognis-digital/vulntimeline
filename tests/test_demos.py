"""Integrity tests for the bundled demos.

Every demo directory must hold a parseable advisories.json (in the tool's real
input format) and a SCENARIO.md, and must run cleanly through the CLI.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulntimeline.cli import main
from vulntimeline.core import load_advisories

DEMOS = Path(__file__).resolve().parent.parent / "demos"

DEMO_DIRS = sorted(p for p in DEMOS.iterdir() if p.is_dir()) if DEMOS.exists() else []


def test_demos_directory_exists():
    assert DEMOS.exists(), "demos/ directory is missing"
    assert len(DEMO_DIRS) >= 5, "expected at least 5 demos"


@pytest.mark.parametrize("demo", DEMO_DIRS, ids=[d.name for d in DEMO_DIRS])
def test_demo_has_scenario_and_input(demo: Path):
    assert (demo / "SCENARIO.md").exists(), f"{demo.name} missing SCENARIO.md"
    assert (demo / "advisories.json").exists(), f"{demo.name} missing advisories.json"


@pytest.mark.parametrize("demo", DEMO_DIRS, ids=[d.name for d in DEMO_DIRS])
def test_demo_input_loads(demo: Path):
    raw = (demo / "advisories.json").read_text(encoding="utf-8")
    advs = load_advisories(raw)
    assert advs, f"{demo.name} loaded zero advisories"


@pytest.mark.parametrize("demo", DEMO_DIRS, ids=[d.name for d in DEMO_DIRS])
def test_demo_runs_all_subcommands(demo: Path, capsys):
    path = str(demo / "advisories.json")
    assert main(["build", path, "--json"]) == 0
    capsys.readouterr()
    assert main(["metrics", path, "--json"]) == 0
    capsys.readouterr()
    # flags exit code is 0 unless --fail-on-any; just confirm it produces SARIF.
    assert main(["flags", path, "--sarif"]) == 0
    out = capsys.readouterr().out
    assert json.loads(out)["version"] == "2.1.0"

"""Tests for the CLI: subcommand wiring, output, and gate exit codes."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulntimeline.cli import main

EXAMPLES = Path(__file__).resolve().parent.parent / "examples" / "advisories.json"


def _write(tmp_path: Path, payload) -> str:
    p = tmp_path / "advs.json"
    p.write_text(json.dumps(payload), encoding="utf-8")
    return str(p)


def test_build_markdown(capsys):
    rc = main(["build", str(EXAMPLES)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "# Vulnerability Disclosure Timeline" in out
    assert "Legend:" in out
    assert "CVD-2025-0001" in out


def test_build_json(capsys):
    rc = main(["build", str(EXAMPLES), "--json"])
    out = capsys.readouterr().out
    assert rc == 0
    data = json.loads(out)
    assert isinstance(data, list)
    # First record should be the earliest by anchor date.
    assert data[0]["id"] == "CVD-2025-0001"
    assert data[0]["milestones"][0]["milestone"] == "discovered"


def test_build_no_ascii(capsys):
    main(["build", str(EXAMPLES), "--no-ascii"])
    out = capsys.readouterr().out
    assert "ASCII" not in out


def test_metrics_table(capsys):
    rc = main(["metrics", str(EXAMPLES)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Aggregate" in out
    assert "median time-to-patch" in out


def test_metrics_json(capsys):
    rc = main(["metrics", str(EXAMPLES), "--json"])
    out = capsys.readouterr().out
    assert rc == 0
    data = json.loads(out)
    assert "aggregate" in data
    assert data["aggregate"]["count"] == 6


def test_flags_table(capsys):
    rc = main(["flags", str(EXAMPLES)])
    out = capsys.readouterr().out
    assert rc == 0
    # Example data has exploited-before-patch and unpatched advisories.
    assert "exploited_before_patch" in out or "unpatched" in out


def test_flags_json(capsys):
    rc = main(["flags", str(EXAMPLES), "--json"])
    out = capsys.readouterr().out
    data = json.loads(out)
    assert isinstance(data, list)
    assert any(f["kind"] == "exploited_before_patch" for f in data)


def test_flags_fail_on_any_gate():
    # Example data contains flags, so the gate should fail.
    rc = main(["flags", str(EXAMPLES), "--fail-on-any"])
    assert rc == 2


def test_flags_fail_on_any_clean(tmp_path, capsys):
    clean = _write(tmp_path, {"advisories": [
        {"id": "CLEAN-1", "disclosed": "2025-01-01", "patched": "2025-01-02"},
    ]})
    rc = main(["flags", clean, "--fail-on-any"])
    assert rc == 0


def test_flags_max_ttp_threshold(tmp_path, capsys):
    slow = _write(tmp_path, {"advisories": [
        {"id": "SLOW-1", "disclosed": "2025-01-01", "patched": "2025-03-01"},
    ]})
    rc = main(["flags", slow, "--max-ttp", "10", "--json"])
    out = capsys.readouterr().out
    data = json.loads(out)
    assert any(f["kind"] == "slow_patch" for f in data)
    assert rc == 0


def test_missing_file_returns_error(capsys):
    rc = main(["build", "does-not-exist.json"])
    err = capsys.readouterr().err
    assert rc == 1
    assert "file not found" in err


def test_stdin_input(monkeypatch, capsys):
    import io
    payload = json.dumps({"advisories": [{"id": "STDIN-1", "disclosed": "2025-01-01"}]})
    monkeypatch.setattr("sys.stdin", io.StringIO(payload))
    rc = main(["build", "-", "--json"])
    out = capsys.readouterr().out
    assert rc == 0
    assert json.loads(out)[0]["id"] == "STDIN-1"

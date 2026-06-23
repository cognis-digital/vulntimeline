"""Tests for the `vulndb` CLI subcommand (offline lookups against bundled DB)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulntimeline.cli import main


def _write(tmp_path: Path, payload) -> str:
    p = tmp_path / "advs.json"
    p.write_text(json.dumps(payload), encoding="utf-8")
    return str(p)


def test_vulndb_count(capsys):
    rc = main(["vulndb", "count"])
    out = capsys.readouterr().out.strip()
    assert rc == 0
    assert int(out) >= 100000


def test_vulndb_lookup_log4shell(capsys):
    rc = main(["vulndb", "lookup", "CVE-2021-44228"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "GHSA-jfh8-c2jp-5v3q" in out
    assert "Log4j" in out or "log4j" in out


def test_vulndb_lookup_json(capsys):
    rc = main(["vulndb", "lookup", "CVE-2021-44228", "--json"])
    out = capsys.readouterr().out
    assert rc == 0
    data = json.loads(out)
    assert isinstance(data, list)
    assert any("CVE-2021-44228" in (r.get("aliases") or []) for r in data)


def test_vulndb_lookup_unknown_returns_1(capsys):
    rc = main(["vulndb", "lookup", "CVE-9999-0002"])
    capsys.readouterr()
    assert rc == 1


def test_vulndb_package_django(capsys):
    rc = main(["vulndb", "package", "django", "--limit", "5"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "record(s) affecting django" in out


def test_vulndb_package_ecosystem_filter(capsys):
    rc = main(["vulndb", "package", "django", "--ecosystem", "PyPI", "--json"])
    out = capsys.readouterr().out
    assert rc == 0
    data = json.loads(out)
    assert data
    assert all(r.get("ecosystem") == "PyPI" for r in data)


def test_vulndb_package_unknown_returns_1(capsys):
    rc = main(["vulndb", "package", "not-a-real-package-xyz"])
    capsys.readouterr()
    assert rc == 1


def test_vulndb_match_markdown(tmp_path, capsys):
    src = _write(tmp_path, {"advisories": [
        {"id": "CVE-2021-44228", "title": "Log4Shell"},
        {"id": "CVE-9999-0003", "title": "unknown"},
    ]})
    rc = main(["vulndb", "match", src])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Bundled-DB match" in out
    assert "GHSA-jfh8-c2jp-5v3q" in out
    assert "1 of 2 advisories resolved" in out


def test_vulndb_match_json(tmp_path, capsys):
    src = _write(tmp_path, {"advisories": [{"id": "CVE-2021-44228"}]})
    rc = main(["vulndb", "match", src, "--json"])
    out = capsys.readouterr().out
    assert rc == 0
    data = json.loads(out)
    assert data[0]["matched_by_id"] is True
    assert data[0]["match_count"] >= 1


def test_vulndb_match_fail_on_match_gate(tmp_path, capsys):
    src = _write(tmp_path, {"advisories": [{"id": "CVE-2021-44228"}]})
    rc = main(["vulndb", "match", src, "--fail-on-match"])
    capsys.readouterr()
    assert rc == 2


def test_vulndb_match_no_match_no_gate(tmp_path, capsys):
    src = _write(tmp_path, {"advisories": [{"id": "CVE-9999-0004"}]})
    rc = main(["vulndb", "match", src, "--fail-on-match"])
    capsys.readouterr()
    assert rc == 0


def test_vulndb_components_args(capsys):
    rc = main(["vulndb", "components", "PyPI:django", "npm:lodash"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "2 of 2 components have known vulnerabilities" in out


def test_vulndb_components_json(capsys):
    rc = main(["vulndb", "components", "django", "--json"])
    out = capsys.readouterr().out
    assert rc == 0
    data = json.loads(out)
    assert data[0]["match_count"] >= 1


def test_vulndb_components_from_file_json_array(tmp_path, capsys):
    f = tmp_path / "comps.json"
    f.write_text(json.dumps(["PyPI:django", "npm:lodash"]), encoding="utf-8")
    rc = main(["vulndb", "components", "--from-file", str(f)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "2 of 2 components" in out


def test_vulndb_components_from_file_newline(tmp_path, capsys):
    f = tmp_path / "comps.txt"
    f.write_text("django\nlodash\n", encoding="utf-8")
    rc = main(["vulndb", "components", "--from-file", str(f)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "2 of 2 components" in out


def test_vulndb_components_fail_on_match_gate(capsys):
    rc = main(["vulndb", "components", "django", "--fail-on-match"])
    capsys.readouterr()
    assert rc == 2

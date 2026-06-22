"""SARIF 2.1.0 export for vulntimeline flags.

Turns detected risky-pattern flags into a SARIF 2.1.0 log so disclosure-timeline
hygiene findings can be ingested by code-scanning dashboards (GitHub Advanced
Security, Azure DevOps, DefectDojo, etc.) alongside other static-analysis output.

SARIF is the OASIS "Static Analysis Results Interchange Format". This emitter
targets schema version 2.1.0. It is pure / standard-library only.
"""

from __future__ import annotations

from typing import Any

from . import __version__

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemas/sarif-schema-2.1.0.json"
)

# Map vulntimeline flag severities to SARIF result levels.
_LEVEL_BY_SEVERITY = {
    "low": "note",
    "medium": "warning",
    "high": "error",
    "critical": "error",
}

# Stable, human-readable rule metadata for each flag kind we emit.
_RULES: dict[str, dict[str, str]] = {
    "exploited_before_patch": {
        "name": "ExploitedBeforePatch",
        "shortDescription": "Exploitation observed before a patch was available",
        "fullDescription": (
            "The advisory was exploited in the wild before (or without) a fix "
            "being available, indicating a real-world exposure window."
        ),
    },
    "slow_patch": {
        "name": "SlowPatch",
        "shortDescription": "Time-to-patch exceeds the configured threshold",
        "fullDescription": (
            "The number of days between public disclosure and an available "
            "patch exceeds the remediation SLA threshold."
        ),
    },
    "unpatched": {
        "name": "Unpatched",
        "shortDescription": "No patch date recorded for the advisory",
        "fullDescription": (
            "The advisory has no recorded patch date and may represent an "
            "unresolved exposure."
        ),
    },
    "negative_window": {
        "name": "NegativeWindow",
        "shortDescription": "A remediation window is negative (inconsistent dates)",
        "fullDescription": (
            "One of the computed lifecycle windows is negative, which usually "
            "means the milestone dates are inconsistent or mis-entered."
        ),
    },
}

_DEFAULT_LEVEL = "warning"


def _level_for(severity: Any) -> str:
    return _LEVEL_BY_SEVERITY.get(str(severity).lower(), _DEFAULT_LEVEL)


def _rule_descriptor(kind: str) -> dict[str, Any]:
    meta = _RULES.get(kind, {
        "name": kind,
        "shortDescription": kind,
        "fullDescription": kind,
    })
    return {
        "id": kind,
        "name": meta["name"],
        "shortDescription": {"text": meta["shortDescription"]},
        "fullDescription": {"text": meta["fullDescription"]},
        "defaultConfiguration": {
            "level": _level_for(
                # severity for the rule's default is taken from the kind's
                # typical severity; per-result level still overrides this.
                {"exploited_before_patch": "high",
                 "slow_patch": "medium",
                 "unpatched": "medium",
                 "negative_window": "low"}.get(kind, "medium")
            )
        },
        "helpUri": "https://github.com/cognis-digital/vulntimeline#flags",
    }


def flags_to_sarif(
    flags: list[dict[str, Any]],
    source_path: str = "advisories.json",
) -> dict[str, Any]:
    """Build a SARIF 2.1.0 log object from detected flags.

    ``source_path`` is recorded as the artifact each result locates against,
    so downstream tools attribute the findings to the advisory input file.
    """
    # Collect the distinct rule descriptors actually used, in stable order.
    kinds_seen: list[str] = []
    for f in flags:
        kind = f.get("kind", "unknown")
        if kind not in kinds_seen:
            kinds_seen.append(kind)
    rules = [_rule_descriptor(k) for k in kinds_seen]

    results: list[dict[str, Any]] = []
    for f in flags:
        kind = f.get("kind", "unknown")
        adv_id = f.get("id", "")
        detail = f.get("detail", "")
        results.append({
            "ruleId": kind,
            "level": _level_for(f.get("severity")),
            "message": {"text": f"{adv_id}: {detail}" if adv_id else detail},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": source_path,
                    }
                },
                "logicalLocations": [{
                    "name": adv_id,
                    "kind": "member",
                }],
            }],
            "partialFingerprints": {
                # Stable identity so re-runs dedupe in dashboards.
                "advisoryFlag": f"{adv_id}/{kind}",
            },
        })

    return {
        "version": SARIF_VERSION,
        "$schema": SARIF_SCHEMA,
        "runs": [{
            "tool": {
                "driver": {
                    "name": "vulntimeline",
                    "informationUri": "https://github.com/cognis-digital/vulntimeline",
                    "version": __version__,
                    "rules": rules,
                }
            },
            "results": results,
        }],
    }

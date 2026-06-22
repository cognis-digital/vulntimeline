# Demo 09 — Live feed enrichment (CISA-KEV + EPSS), offline / air-gap

This demo shows vulntimeline cross-referencing real, CVE-keyed advisories
against two authoritative, keyless vulnerability feeds:

* **CISA Known Exploited Vulnerabilities (KEV)** — is this CVE *actively
  exploited in the wild* (and is it associated with ransomware campaigns)?
* **FIRST EPSS** — what is the probability the CVE is exploited in the next
  30 days?

The advisories here are four real, historically-significant CVEs
(Log4Shell, PrintNightmare, Heartbleed) plus one synthetic non-CVE record that
intentionally has **no** feed match.

## Run it (fully offline — no network)

A trimmed snapshot of both feeds is committed under `feeds_cache/`, so this demo
runs on an air-gapped box. Point the cache env var at it and pass `--offline`:

```bash
# from the repo root
export COGNIS_FEEDS_CACHE="$PWD/demos/09-live-feed-enrichment/feeds_cache"
python -m vulntimeline build demos/09-live-feed-enrichment/advisories.json \
    --enrich --offline --no-ascii
```

Expected enrichment table (most-urgent first):

| Advisory | CVE | KEV | Ransomware | EPSS | Percentile |
| --- | --- | --- | --- | --- | --- |
| CVE-2021-44228 | CVE-2021-44228 | YES | YES | 1.0000 | 1.000 |
| CVE-2021-34527 | CVE-2021-34527 | YES | YES | 0.9976 | 1.000 |
| CVE-2014-0160 | CVE-2014-0160 | YES | - | 1.0000 | 1.000 |
| INTERNAL-2025-0001 | (non-CVE) | - | - | - | - |

`3 of 4 advisories are CISA-KEV known-exploited.`

## Refresh the snapshot from the live feeds (online)

```bash
python -m vulntimeline feeds update cisa-kev epss
python -m vulntimeline feeds snapshot-export feeds.tar.gz   # carry to the enclave
# on the air-gapped box:
python -m vulntimeline feeds snapshot-import feeds.tar.gz
```

Defensive / authorized-use intelligence only.

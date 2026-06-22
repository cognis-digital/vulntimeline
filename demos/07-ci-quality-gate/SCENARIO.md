# 07 — CI release gate (block on open exploited/unpatched issues)

## Where the data came from

The set of known open advisories affecting a service at the moment its release
pipeline runs. One is being actively exploited and still unpatched; the other is
a critical unpatched credential leak. Both should stop the release. IDs are the
release-gate tracker labels.

## What to expect

- `REL-GATE-1`: exploited, no patch → `exploited_before_patch` **and**
  `unpatched`.
- `REL-GATE-2`: critical, no patch → `unpatched`.
- `flags --fail-on-any` returns exit code **2**.

## Run it

```bash
vulntimeline flags demos/07-ci-quality-gate/advisories.json
vulntimeline flags demos/07-ci-quality-gate/advisories.json --fail-on-any; echo "exit=$?"
```

Wire it into CI (GitHub Actions example):

```yaml
- name: Disclosure-hygiene gate
  run: vulntimeline flags advisories.json --fail-on-any
```

The step fails the job whenever any open exploited/unpatched advisory is present.

## How to act

This demo is the pattern to **copy into your own pipeline**. Tune the strictness
with `--max-ttp N` to also fail on stale-but-unexploited findings. Fix or
risk-accept (and remove from the file) every flagged advisory before the gate
goes green.

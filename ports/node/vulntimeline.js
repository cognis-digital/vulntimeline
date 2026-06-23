#!/usr/bin/env node
"use strict";
/*
 * vulntimeline (Node.js port) — defensive vulnerability-disclosure analytics.
 *
 * A faithful port of the primary Python CLI's core surface: the `metrics` and
 * `flags` subcommands. Same input format (advisories JSON), same remediation
 * windows (time-to-patch / disclosure-gap / report-latency / exposure-window),
 * same risky-pattern flags (exploited_before_patch / slow_patch / unpatched /
 * negative_window) and the same `--fail-on-any` CI gate (exit code 2).
 *
 * Passive / offline / authorized-use only. No network, zero dependencies
 * (Node stdlib only).
 */

const fs = require("fs");

const MILESTONES = [
  ["discovered", "Discovered"],
  ["reported", "Reported"],
  ["disclosed", "Disclosed"],
  ["exploited", "Exploited"],
  ["patched", "Patched"],
];

class AdvisoryError extends Error {}

const MS_PER_DAY = 86400000;

// Parse a date from the same set of formats the Python core accepts.
function parseDate(value) {
  if (value === null || value === undefined) return null;
  if (typeof value !== "string") {
    throw new AdvisoryError(`unsupported date type: ${typeof value}`);
  }
  const text = value.trim();
  if (!text) return null;

  // ISO date (YYYY-MM-DD) — anchor to UTC noon to avoid TZ drift.
  let m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(text);
  if (m) return Date.UTC(+m[1], +m[2] - 1, +m[3]) / MS_PER_DAY;

  // ISO datetime (optional time / Z / offset).
  m = /^(\d{4})-(\d{2})-(\d{2})[T ]/.exec(text);
  if (m) return Date.UTC(+m[1], +m[2] - 1, +m[3]) / MS_PER_DAY;

  // YYYY/MM/DD
  m = /^(\d{4})\/(\d{2})\/(\d{2})$/.exec(text);
  if (m) return Date.UTC(+m[1], +m[2] - 1, +m[3]) / MS_PER_DAY;

  // MM/DD/YYYY
  m = /^(\d{2})\/(\d{2})\/(\d{4})$/.exec(text);
  if (m) return Date.UTC(+m[3], +m[1] - 1, +m[2]) / MS_PER_DAY;

  // DD-MM-YYYY
  m = /^(\d{2})-(\d{2})-(\d{4})$/.exec(text);
  if (m) return Date.UTC(+m[3], +m[2] - 1, +m[1]) / MS_PER_DAY;

  // YYYYMMDD
  m = /^(\d{4})(\d{2})(\d{2})$/.exec(text);
  if (m) return Date.UTC(+m[1], +m[2] - 1, +m[3]) / MS_PER_DAY;

  // "Month DD, YYYY" / "Mon DD, YYYY"
  const MONTHS = {
    january: 1, february: 2, march: 3, april: 4, may: 5, june: 6, july: 7,
    august: 8, september: 9, october: 10, november: 11, december: 12,
    jan: 1, feb: 2, mar: 3, apr: 4, jun: 6, jul: 7, aug: 8, sep: 9,
    oct: 10, nov: 11, dec: 12,
  };
  m = /^([A-Za-z]+)\s+(\d{1,2}),\s*(\d{4})$/.exec(text);
  if (m) {
    const mo = MONTHS[m[1].toLowerCase()];
    if (mo) return Date.UTC(+m[3], mo - 1, +m[2]) / MS_PER_DAY;
  }

  throw new AdvisoryError(`could not parse date: ${JSON.stringify(value)}`);
}

const SEVERITY_ORDER = { none: 0, low: 1, medium: 2, high: 3, critical: 4 };

function normalizeSeverity(value) {
  if (value === null || value === undefined) return null;
  const t = String(value).trim().toLowerCase();
  return t || null;
}

function advisoryFromDict(raw) {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new AdvisoryError("advisory record must be an object");
  }
  const id = raw.id;
  if (id === undefined || id === null || String(id).trim() === "") {
    throw new AdvisoryError("advisory record missing required 'id'");
  }
  return {
    id: String(id).trim(),
    title: String(raw.title || "").trim(),
    severity: normalizeSeverity(raw.severity),
    discovered: parseDate(raw.discovered),
    reported: parseDate(raw.reported),
    disclosed: parseDate(raw.disclosed),
    exploited: parseDate(raw.exploited),
    patched: parseDate(raw.patched),
  };
}

function loadAdvisories(source) {
  let data;
  if (typeof source === "string") {
    try {
      data = JSON.parse(source);
    } catch (e) {
      throw new AdvisoryError(`invalid JSON: ${e.message}`);
    }
  } else {
    data = source;
  }
  let records;
  if (data && !Array.isArray(data) && typeof data === "object") {
    records = data.advisories;
    if (records === undefined) throw new AdvisoryError("JSON object has no 'advisories' key");
  } else {
    records = data;
  }
  if (!Array.isArray(records)) throw new AdvisoryError("expected a list of advisory records");
  const advisories = records.map(advisoryFromDict);
  const seen = new Set();
  for (const a of advisories) {
    if (seen.has(a.id)) throw new AdvisoryError(`duplicate advisory id: ${a.id}`);
    seen.add(a.id);
  }
  return advisories;
}

function daysBetween(later, earlier) {
  if (later === null || earlier === null) return null;
  return Math.round(later - earlier);
}

function todayOrdinal() {
  const n = new Date();
  return Date.UTC(n.getUTCFullYear(), n.getUTCMonth(), n.getUTCDate()) / MS_PER_DAY;
}

function advisoryWindows(adv, today) {
  if (today === undefined) today = todayOrdinal();
  const timeToPatch = daysBetween(adv.patched, adv.disclosed);
  const disclosureGap = daysBetween(adv.disclosed, adv.reported);
  const reportLatency = daysBetween(adv.reported, adv.discovered);

  let exposureWindow = null;
  let exposureOpen = false;
  if (adv.exploited !== null) {
    if (adv.patched !== null) {
      exposureWindow = Math.max(0, Math.round(adv.patched - adv.exploited));
    } else {
      exposureWindow = Math.max(0, Math.round(today - adv.exploited));
      exposureOpen = true;
    }
  }

  let exploitedBeforePatch = false;
  if (adv.exploited !== null) {
    if (adv.patched === null) exploitedBeforePatch = true;
    else if (adv.exploited < adv.patched) exploitedBeforePatch = true;
  }

  return {
    id: adv.id,
    title: adv.title,
    severity: adv.severity,
    time_to_patch: timeToPatch,
    disclosure_gap: disclosureGap,
    report_latency: reportLatency,
    exposure_window: exposureWindow,
    exposure_open: exposureOpen,
    exploited_before_patch: exploitedBeforePatch,
    unpatched: adv.patched === null,
  };
}

function median(values) {
  const nums = values.filter((v) => v !== null && v !== undefined).sort((a, b) => a - b);
  if (nums.length === 0) return null;
  const mid = Math.floor(nums.length / 2);
  return nums.length % 2 ? nums[mid] : (nums[mid - 1] + nums[mid]) / 2;
}

function aggregateMetrics(advisories, today) {
  const per = advisories.map((a) => advisoryWindows(a, today));
  const col = (name) => per.map((r) => r[name]).filter((v) => v !== null);
  return {
    advisories: per,
    aggregate: {
      count: per.length,
      median_time_to_patch: median(col("time_to_patch")),
      median_disclosure_gap: median(col("disclosure_gap")),
      median_report_latency: median(col("report_latency")),
      median_exposure_window: median(col("exposure_window")),
      exploited_before_patch_count: per.filter((r) => r.exploited_before_patch).length,
      unpatched_count: per.filter((r) => r.unpatched).length,
    },
  };
}

function detectFlags(advisories, maxTimeToPatch, today) {
  const flags = [];
  for (const adv of advisories) {
    const w = advisoryWindows(adv, today);
    if (w.exploited_before_patch) {
      flags.push({
        id: adv.id,
        kind: "exploited_before_patch",
        severity: "high",
        detail: w.unpatched
          ? "exploitation observed and advisory remains unpatched"
          : "exploitation observed before a patch was available",
      });
    }
    const ttp = w.time_to_patch;
    if (maxTimeToPatch !== null && maxTimeToPatch !== undefined && ttp !== null && ttp > maxTimeToPatch) {
      flags.push({
        id: adv.id,
        kind: "slow_patch",
        severity: "medium",
        detail: `time-to-patch ${ttp}d exceeds threshold ${maxTimeToPatch}d`,
      });
    }
    if (w.unpatched) {
      flags.push({ id: adv.id, kind: "unpatched", severity: "medium", detail: "no patch date recorded" });
    }
    for (const win of ["time_to_patch", "disclosure_gap", "report_latency"]) {
      const val = w[win];
      if (val !== null && val < 0) {
        flags.push({
          id: adv.id,
          kind: "negative_window",
          severity: "low",
          detail: `${win} is negative (${val}d): check date ordering`,
        });
      }
    }
  }
  return flags;
}

// --------------------------------------------------------------------------- //
// CLI
// --------------------------------------------------------------------------- //
function readSource(path) {
  if (path === "-") return fs.readFileSync(0, "utf-8");
  if (!fs.existsSync(path)) throw new AdvisoryError(`file not found: ${path}`);
  return fs.readFileSync(path, "utf-8");
}

function usage() {
  process.stderr.write(
    "usage: vulntimeline <metrics|flags> <advisories.json> [--json] " +
      "[--max-ttp N] [--fail-on-any]\n"
  );
}

function main(argv) {
  const args = argv.slice(2);
  if (args.length === 0) {
    usage();
    return 1;
  }
  const cmd = args[0];
  const rest = args.slice(1);
  const opts = { json: false, failOnAny: false, maxTtp: null };
  let path = null;
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (a === "--json") opts.json = true;
    else if (a === "--fail-on-any") opts.failOnAny = true;
    else if (a === "--max-ttp") opts.maxTtp = parseInt(rest[++i], 10);
    else if (!a.startsWith("--")) path = a;
    else {
      process.stderr.write(`error: unknown option ${a}\n`);
      return 1;
    }
  }
  if (!path) {
    usage();
    return 1;
  }

  let advisories;
  try {
    advisories = loadAdvisories(readSource(path));
  } catch (e) {
    process.stderr.write(`error: ${e.message}\n`);
    return 1;
  }

  if (cmd === "metrics") {
    const metrics = aggregateMetrics(advisories);
    if (opts.json) {
      process.stdout.write(JSON.stringify(metrics, null, 2) + "\n");
    } else {
      process.stdout.write(renderMetricsTable(metrics));
    }
    return 0;
  }
  if (cmd === "flags") {
    const flags = detectFlags(advisories, opts.maxTtp);
    if (opts.json) process.stdout.write(JSON.stringify(flags, null, 2) + "\n");
    else process.stdout.write(renderFlagsTable(flags));
    if (opts.failOnAny && flags.length) return 2;
    return 0;
  }
  usage();
  return 1;
}

function num(v) {
  if (v === null || v === undefined) return "-";
  if (Number.isInteger(v)) return String(v);
  return String(v);
}

function renderMetricsTable(metrics) {
  const agg = metrics.aggregate;
  const lines = [];
  lines.push("ID  SEV  TTP  DISC_GAP  REPLAT  EXPOSURE  XBP");
  for (const r of metrics.advisories) {
    let exposure = num(r.exposure_window);
    if (r.exposure_open && r.exposure_window !== null) exposure += "*";
    lines.push(
      [r.id, r.severity || "-", num(r.time_to_patch), num(r.disclosure_gap),
       num(r.report_latency), exposure, r.exploited_before_patch ? "yes" : "no"].join("  ")
    );
  }
  lines.push("");
  lines.push("Aggregate (days; median):");
  lines.push(`  count                  ${agg.count}`);
  lines.push(`  median time-to-patch   ${num(agg.median_time_to_patch)}`);
  lines.push(`  median disclosure gap  ${num(agg.median_disclosure_gap)}`);
  lines.push(`  median report latency  ${num(agg.median_report_latency)}`);
  lines.push(`  median exposure window ${num(agg.median_exposure_window)}`);
  lines.push(`  exploited-before-patch ${agg.exploited_before_patch_count}`);
  lines.push(`  unpatched              ${agg.unpatched_count}`);
  return lines.join("\n") + "\n";
}

function renderFlagsTable(flags) {
  if (flags.length === 0) return "No flags detected.\n";
  const lines = ["ID  KIND  SEVERITY  DETAIL"];
  for (const f of flags) lines.push([f.id, f.kind, f.severity, f.detail].join("  "));
  lines.push("");
  lines.push(`${flags.length} flag(s) detected.`);
  return lines.join("\n") + "\n";
}

module.exports = {
  AdvisoryError,
  parseDate,
  advisoryFromDict,
  loadAdvisories,
  advisoryWindows,
  aggregateMetrics,
  detectFlags,
  main,
};

if (require.main === module) {
  process.exit(main(process.argv));
}

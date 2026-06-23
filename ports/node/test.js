"use strict";
/* Smoke + unit tests for the Node port. Uses node:assert + node:test (stdlib). */

const test = require("node:test");
const assert = require("node:assert");
const vt = require("./vulntimeline");

test("parseDate ISO", () => {
  assert.strictEqual(vt.parseDate("2025-02-10"), vt.parseDate("2025-02-10"));
  assert.strictEqual(vt.parseDate(null), null);
  assert.strictEqual(vt.parseDate(""), null);
});

test("parseDate datetime with Z", () => {
  assert.strictEqual(vt.parseDate("2025-02-05T09:30:00Z"), vt.parseDate("2025-02-05"));
});

test("parseDate US and slashed formats", () => {
  assert.strictEqual(vt.parseDate("02/10/2025"), vt.parseDate("2025-02-10"));
  assert.strictEqual(vt.parseDate("2025/02/10"), vt.parseDate("2025-02-10"));
  assert.strictEqual(vt.parseDate("20250210"), vt.parseDate("2025-02-10"));
});

test("parseDate spelled month", () => {
  assert.strictEqual(vt.parseDate("February 10, 2025"), vt.parseDate("2025-02-10"));
});

test("parseDate rejects garbage", () => {
  assert.throws(() => vt.parseDate("not-a-date"), vt.AdvisoryError);
});

test("loadAdvisories requires id", () => {
  assert.throws(() => vt.loadAdvisories('[{"title":"x"}]'), vt.AdvisoryError);
});

test("loadAdvisories duplicate id", () => {
  assert.throws(() => vt.loadAdvisories('[{"id":"A"},{"id":"A"}]'), vt.AdvisoryError);
});

test("advisoryWindows time-to-patch", () => {
  const a = vt.advisoryFromDict({ id: "X", disclosed: "2025-02-10", patched: "2025-02-12" });
  const w = vt.advisoryWindows(a);
  assert.strictEqual(w.time_to_patch, 2);
  assert.strictEqual(w.unpatched, false);
});

test("advisoryWindows exploited-before-patch", () => {
  const a = vt.advisoryFromDict({ id: "X", disclosed: "2025-02-10", exploited: "2025-02-11", patched: "2025-02-12" });
  const w = vt.advisoryWindows(a);
  assert.strictEqual(w.exploited_before_patch, true);
  assert.strictEqual(w.exposure_window, 1);
});

test("advisoryWindows unpatched + exploited stays open", () => {
  const a = vt.advisoryFromDict({ id: "X", exploited: "2020-01-01" });
  const w = vt.advisoryWindows(a);
  assert.strictEqual(w.unpatched, true);
  assert.strictEqual(w.exposure_open, true);
  assert.ok(w.exposure_window > 0);
});

test("aggregateMetrics medians", () => {
  const advs = vt.loadAdvisories(JSON.stringify({
    advisories: [
      { id: "A", disclosed: "2025-01-01", patched: "2025-01-05" },
      { id: "B", disclosed: "2025-01-01", patched: "2025-01-11" },
    ],
  }));
  const m = vt.aggregateMetrics(advs);
  assert.strictEqual(m.aggregate.count, 2);
  assert.strictEqual(m.aggregate.median_time_to_patch, 7);
});

test("detectFlags exploited-before-patch + unpatched", () => {
  const advs = vt.loadAdvisories(JSON.stringify({
    advisories: [{ id: "A", disclosed: "2025-01-01", exploited: "2025-01-02" }],
  }));
  const flags = vt.detectFlags(advs);
  const kinds = flags.map((f) => f.kind);
  assert.ok(kinds.includes("exploited_before_patch"));
  assert.ok(kinds.includes("unpatched"));
});

test("detectFlags slow_patch threshold", () => {
  const advs = vt.loadAdvisories(JSON.stringify({
    advisories: [{ id: "A", disclosed: "2025-01-01", patched: "2025-03-01" }],
  }));
  assert.strictEqual(vt.detectFlags(advs, 30).filter((f) => f.kind === "slow_patch").length, 1);
  assert.strictEqual(vt.detectFlags(advs, 90).filter((f) => f.kind === "slow_patch").length, 0);
});

test("detectFlags negative_window", () => {
  const advs = vt.loadAdvisories(JSON.stringify({
    advisories: [{ id: "A", disclosed: "2025-02-10", patched: "2025-02-01" }],
  }));
  assert.ok(vt.detectFlags(advs).some((f) => f.kind === "negative_window"));
});

test("main flags --fail-on-any returns 2", () => {
  const fs = require("fs");
  const os = require("os");
  const path = require("path");
  const p = path.join(os.tmpdir(), `vt-node-${process.pid}.json`);
  fs.writeFileSync(p, JSON.stringify({ advisories: [{ id: "A", disclosed: "2025-01-01", exploited: "2025-01-02" }] }));
  const origWrite = process.stdout.write;
  process.stdout.write = () => true;
  const rc = vt.main(["node", "vt", "flags", p, "--fail-on-any"]);
  process.stdout.write = origWrite;
  fs.unlinkSync(p);
  assert.strictEqual(rc, 2);
});

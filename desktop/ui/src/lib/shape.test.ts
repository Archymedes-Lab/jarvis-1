import { expect, test } from "bun:test";
import { shapeCoverage, shapeGeo, shapePhoneDevices, shapeProcs, shapeState, shapeWorld } from "./shape";

// What a busy, older or broken service might send instead of the full document.
const BAD: unknown[] = [undefined, null, {}, [], "oops", 7, { items: "x", zones: 3, sources: null, counts: "no" },
  { devices: {}, anomalies: "a", techniques: { a: 1 }, totals: [], snaps: [], status: undefined }];

test("World: lists and counts always exist, whatever arrives", () => {
  for (const b of BAD) {
    const w = shapeWorld(b);
    for (const k of ["items", "zones", "sources"] as const) expect(Array.isArray(w[k])).toBe(true);
    expect(typeof w.counts.reports).toBe("number");
    expect(typeof w.counts.mapped).toBe("number");
    expect(typeof w.stale).toBe("boolean");
  }
});

test("Geo: devices, zones and anomalies always lists", () => {
  for (const b of BAD) {
    const g = shapeGeo(b);
    for (const k of ["devices", "zones", "anomalies"] as const) expect(Array.isArray(g[k])).toBe(true);
  }
});

test("Coverage: techniques a list, totals numbers, tactics an object", () => {
  for (const b of BAD) {
    const c = shapeCoverage(b);
    expect(Array.isArray(c.techniques)).toBe(true);
    expect(typeof c.totals.total).toBe("number");
    expect(typeof c.tactics).toBe("object");
  }
});

test("Processes and phone devices", () => {
  for (const b of BAD) {
    expect(typeof shapeProcs(b).snaps).toBe("object");
    expect(Array.isArray(shapePhoneDevices(b).devices)).toBe(true);
  }
});

test("good answers pass through unchanged", () => {
  const w = { generated_at: 5, age_s: 1, stale: true, window_s: 60, items: [{ title: "t" }], zones: [], sources: [{ key: "k" }],
    counts: { reports: 3, mapped: 2, unmapped: 1, country_level: 0 }, rules: { zone: "z", note: "n" } };
  expect(shapeWorld(w)).toEqual(w as any);
  const g = { zones: [{ name: "home" }], devices: [{ name: "pc" }], anomalies: ["x"], generated_at: 9, location: { ts: 1, status: "ok" } };
  expect(shapeGeo(g)).toEqual(g as any);
});

test("every daemon read with lists goes through a shape (lib/api.ts)", async () => {
  const src = await Bun.file(new URL("./api.ts", import.meta.url)).text();
  for (const [name, fn] of [["daemon_state", "shapeState"], ["geo_state", "shapeGeo"], ["coverage_state", "shapeCoverage"], ["world_state", "shapeWorld"],
                            ["procs_snapshot", "shapeProcs"], ["phone_devices", "shapePhoneDevices"]]) {
    expect(new RegExp(`call<[^>]*>\\("${name}"\\)\\.then\\(${fn}\\)`).test(src), `${name} -> ${fn}`).toBe(true);
  }
});

test("State: every list the views read is a list, objects are objects", () => {
  for (const b of [...BAD, { findings: "x", jobs: 3, security: "s", totals: [], questions: {} }, { findings: [null, 1, { title: "t" }] }]) {
    const d = shapeState(b);
    for (const k of ["jobs", "findings", "checks", "history", "peers", "events", "questions", "fix"]) expect(Array.isArray(d[k])).toBe(true);
    for (const k of ["totals", "by_host", "by_category"]) expect(typeof d[k] === "object" && !Array.isArray(d[k])).toBe(true);
    expect(d.findings.every((f: any) => f && typeof f === "object")).toBe(true);
    if (d.security) for (const k of ["areas", "next_steps", "history"]) expect(Array.isArray(d.security[k])).toBe(true);
  }
  expect("security" in shapeState({})).toBe(false);   // absent stays absent: the views show "not measured yet"
});

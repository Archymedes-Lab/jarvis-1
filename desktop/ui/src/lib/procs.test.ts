import { expect, test } from "bun:test";
import { classify, filterProcs, megabytes, norm, procCounts, rowsFrom, type Baseline } from "./procs";

const NOW = 2_000_000_000;
const baseline: Baseline = {
  ok: true, recent_s: 86400,
  hosts: { win: { rows: 3, names: { "chrome.exe": [NOW - 90 * 86400, NOW, 5, 0], "fresh.exe": [NOW - 3600, NOW, 1, 0], "mine.exe": [NOW - 1000, NOW, 1, 1] } } },
};

test("a name is judged against what this host has recorded", () => {
  expect(classify(baseline, "win", "Chrome.exe", NOW)).toBe("known");
  expect(classify(baseline, "win", "never-seen.exe", NOW)).toBe("new");
  expect(classify(baseline, "win", "fresh.exe", NOW)).toBe("recent");
  expect(classify(baseline, "win", "mine.exe", NOW)).toBe("approved");
});

test("without a baseline nothing is called new or known: unknown is never calm", () => {
  expect(classify(null, "win", "x.exe", NOW)).toBe("unknown");
  expect(classify({ ok: false }, "win", "x.exe", NOW)).toBe("unknown");
  expect(classify(baseline, "lin", "x", NOW)).toBe("unknown");
  expect(classify(baseline, "win", "", NOW)).toBe("unknown");
});

test("a trailing process id is folded the way the daemon folds it", () => {
  expect(norm("Relay(46877)")).toBe("relay(#)");
  expect(norm("  CHROME.EXE ")).toBe("chrome.exe");
});

test("rows are read from snapshot tuples, new names sort first, filters work", () => {
  const snap = [["1:1", 4, 0, "System", 1, 0, 0], ["2:2", 10, 4, "chrome.exe", 2, 3, 104857600], ["3:3", 11, 4, "odd.exe", 3, 0, 2048]];
  const rows = rowsFrom(snap, baseline, "win", NOW);
  expect(rows.map((r) => r.pid)).toEqual([4, 10, 11]);
  const sorted = filterProcs(rows, "", false);
  expect(sorted.slice(0, 2).map((r) => r.name).sort()).toEqual(["System", "odd.exe"]);   // new names first
  expect(sorted[2].name).toBe("chrome.exe");
  expect(filterProcs(rows, "chrome", false).map((r) => r.pid)).toEqual([10]);
  expect(filterProcs(rows, "11", false).map((r) => r.name)).toEqual(["odd.exe"]);
  expect(filterProcs(rows, "", true).every((r) => r.cls === "new" || r.cls === "recent")).toBe(true);
  expect(procCounts(rows)).toEqual({ total: 3, fresh: 2 });
});

test("a damaged or empty snapshot gives no rows, not an error", () => {
  expect(rowsFrom(undefined, baseline, "win", NOW)).toEqual([]);
  expect(rowsFrom([[null, "x", null, undefined]], baseline, "win", NOW)[0].name).toBe("");
});

test("memory is shown in human units", () => {
  expect(megabytes(104857600)).toBe("100 MB");
  expect(megabytes(2048)).toBe("2 KB");
  expect(megabytes(0)).toBe("—");
});

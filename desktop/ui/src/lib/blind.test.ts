import { expect, test } from "bun:test";
import { groupBlind, onlyEditionLimits, GROUPS } from "./blind";
import type { BlindItem } from "./api";

const B = (job: string, kind: any): BlindItem => ({ job, label: job.toUpperCase(), reason: "r", kind });

test("every blind collector lands in exactly one group, none dropped", () => {
  const items = [B("a", "admin_sensor"), B("s", "stale"), B("f", "failed"), B("a2", "admin_sensor"), B("o", "other"), B("n", "from_the_future")];
  const groups = groupBlind(items);
  expect(groups.map((g) => g.kind)).toEqual(["failed", "stale", "admin_sensor", "other"]);
  expect(groups.flatMap((g) => g.items).length).toBe(items.length);
  expect(groups.find((g) => g.kind === "other")!.items.map((i) => i.job)).toEqual(["o", "n"]);
});

test("nothing blind gives no groups", () => {
  expect(groupBlind(undefined)).toEqual([]);
  expect(groupBlind([])).toEqual([]);
});

test("edition limits alone are calm; anything else is not", () => {
  expect(onlyEditionLimits([B("a", "admin_sensor")])).toBe(true);
  expect(onlyEditionLimits([B("a", "admin_sensor"), B("s", "stale")])).toBe(false);
  expect(onlyEditionLimits([])).toBe(false);
});

test("the shell's kinds are the ones the interface groups", () => {
  // desktop/src/lifecycle.rs BlindKind, serde snake_case
  expect(GROUPS.map((g) => g.kind).sort()).toEqual(["admin_sensor", "failed", "other", "stale"]);
});

import { statusKey } from "./blind";
test("counted status sentences become a key and a number; others pass through", () => {
  expect(statusKey("ARGUS-INSTINCT is running, but 22 of its checks are not working"))
    .toEqual({ key: "ARGUS-INSTINCT is running, but {n} of its checks are not working", n: 22 });
  expect(statusKey("ARGUS-INSTINCT can't fully check 9 parts of your computer right now"))
    .toEqual({ key: "ARGUS-INSTINCT can't fully check {n} parts of your computer right now", n: 9 });
  expect(statusKey("ARGUS-INSTINCT is running, but 1 of its checks is not working"))
    .toEqual({ key: "ARGUS-INSTINCT is running, but 1 of its checks is not working" });
  expect(statusKey("Starting ARGUS-INSTINCT")).toEqual({ key: "Starting ARGUS-INSTINCT" });
});

test("the shell's counted sentences are the ones lifecycle.rs writes", async () => {
  const rs = await Bun.file(new URL("../../../src/lifecycle.rs", import.meta.url)).text();
  expect(rs).toContain('"ARGUS-INSTINCT is running, but {n} of its checks are not working"');
  expect(rs).toContain('"ARGUS-INSTINCT can\'t fully check {n} parts of your computer right now"');
  expect(rs).toContain('"ARGUS-INSTINCT is running, but 1 of its checks is not working"');
  expect(rs).toContain('"ARGUS-INSTINCT can\'t fully check 1 part of your computer right now"');
});

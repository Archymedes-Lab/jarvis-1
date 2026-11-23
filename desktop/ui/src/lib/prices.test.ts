import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { DESKTOP, FLEET_MAX, fleetCents, SERVER_TIERS, usd, yearlySavingCents } from "./prices";

test("the server fleet is graduated per server per year", () => {
  expect(fleetCents(1)).toBe(5000);
  expect(fleetCents(10)).toBe(50000);
  expect(fleetCents(11)).toBe(54000);
  expect(fleetCents(60)).toBe(10 * 5000 + 40 * 4000 + 10 * 3000);
  expect(fleetCents(1000)).toBe(10 * 5000 + 40 * 4000 + 200 * 3000 + 750 * 2000);
});

test("no price is invented outside the price book", () => {
  for (const n of [0, -1, 1.5, NaN, FLEET_MAX + 1]) expect(fleetCents(n)).toBeNull();
});

test("the desktop amounts are the ones the licence service sells", () => {
  // The Worker sells by Stripe lookup key; the key names carry the amount and the interval.
  const env = readFileSync(new URL("../../../../hosted/licence-cloudflare/src/env.ts", import.meta.url), "utf8");
  expect(env).toContain(`argus_desktop_usd_${DESKTOP.yearCents}_year`);
  expect(env).toContain(`argus_desktop_usd_${DESKTOP.monthCents}_month`);
  expect(env).toContain(`TEAM_MAX = ${DESKTOP.teamMax}`);
  expect(env).toContain(`FLEET_MAX = ${FLEET_MAX}`);
  // The documented tiers in the Worker match these.
  expect(env).toContain("1-10 $50, 11-50 $40, 51-250 $30, 251-1000 $20");
  expect(SERVER_TIERS.map((t) => t.usdCents / 100)).toEqual([50, 40, 30, 20]);
});

test("prices are shown plainly", () => {
  expect(usd(7900)).toBe("$79");
  expect(usd(54000)).toBe("$540");
  expect(yearlySavingCents).toBe(10100);
});

import { expect, test } from "bun:test";
import { summarize } from "./coverage";

const cov = (totals: any, pct24?: number) => ({ totals, uptime: pct24 === undefined ? undefined : { pct24 } }) as any;

test("counts come from the daemon and shares add up to the whole", () => {
  const s = summarize(cov({ validated: 5, claimed: 141, blind: 33, regressed: 0, total: 179 }, 0.4634))!;
  expect(s.total).toBe(179);
  expect(s.counts).toEqual({ validated: 5, claimed: 141, blind: 33, regressed: 0 });
  expect(Object.values(s.shares).reduce((a, b) => a + b, 0)).toBeCloseTo(1, 6);
  expect(s.watched).toBe(46);
  expect(s.needsLook).toBe(false);
});

test("expected is never folded into proven", () => {
  const s = summarize(cov({ validated: 0, claimed: 150, blind: 29, regressed: 0, total: 179 }))!;
  expect(s.counts.validated).toBe(0);
  expect(s.shares.validated).toBe(0);
});

test("missing or broken numbers show nothing rather than a made-up figure", () => {
  expect(summarize(null)).toBeNull();
  expect(summarize({} as any)).toBeNull();
  expect(summarize(cov({ validated: 0, claimed: 0, blind: 0, regressed: 0, total: 0 }))).toBeNull();
  const s = summarize(cov({ validated: -3, claimed: NaN, blind: 4, regressed: "x", total: 2 }))!;
  expect(s.counts).toEqual({ validated: 0, claimed: 0, blind: 4, regressed: 0 });
  expect(s.total).toBe(4);                       // never smaller than the parts
  expect(s.watched).toBeNull();                  // no uptime reported: not 0 %
});

test("a regression asks for a look; watched is clamped to 0-100", () => {
  const s = summarize(cov({ validated: 1, claimed: 1, blind: 1, regressed: 1, total: 4 }, 1.7))!;
  expect(s.needsLook).toBe(true);
  expect(s.watched).toBe(100);
});

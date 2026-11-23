import { expect, test } from "bun:test";
import { bareUrl, clock, live, spacedSas, tone } from "./phone";

test("the comparison code is shown only when it is exactly six digits", () => {
  expect(spacedSas("012345")).toBe("012 345");
  expect(spacedSas("01234")).toBe("");
  expect(spacedSas("01234a")).toBe("");
  expect(spacedSas(undefined)).toBe("");
});

test("countdown", () => {
  expect(clock(600)).toBe("10:00");
  expect(clock(65.9)).toBe("1:05");
  expect(clock(-3)).toBe("0:00");
});

test("states", () => {
  expect(live("waiting")).toBe(true);
  expect(live("claimed")).toBe(true);
  expect(live("paired")).toBe(false);
  expect(tone("paired")).toBe("ok");
  expect(tone("expired")).toBe("bad");
  expect(tone("waiting")).toBe("run");
  expect(bareUrl("https://argus.archymedes.xyz/")).toBe("argus.archymedes.xyz");
});

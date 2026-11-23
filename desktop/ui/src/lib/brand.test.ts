import { describe, expect, test } from "bun:test";
import { brand, brandDeep } from "./brand";

describe("brand", () => {
  test("product prose reads ARGUS-INSTINCT", () => {
    expect(brand("JARVIS is up")).toBe("ARGUS-INSTINCT is up");
    expect(brand("JARVIS's view of JARVIS")).toBe("ARGUS-INSTINCT's view of ARGUS-INSTINCT");
  });
  test("real Windows objects, commands, paths and variables keep their spelling", () => {
    for (const s of ["JARVIS input hook", "JARVIS independent health monitor",
                     "JARVIS connectivity guard", "JARVIS native sensor",
                     "JARVIS JarvisSensorDefender collector", "jarvis.service", "jarvis fix apply 3",
                     "C:\\ProgramData\\Jarvis\\Broker", "JARVIS_DESKTOP_PORT"])
      expect(brand(s)).toBe(s);
  });
  test("deep: values only, keys and non-strings untouched", () => {
    const v = { JARVIS: "JARVIS score", n: 3, ok: true, list: ["JARVIS", null], id: "a1" };
    expect(brandDeep(v)).toEqual({ JARVIS: "ARGUS-INSTINCT score", n: 3, ok: true, list: ["ARGUS-INSTINCT", null], id: "a1" });
  });
  test("idempotent: branding twice changes nothing (no ARGUS-INSTINCT-1)", () => {
    for (const s of ["JARVIS is up", "ARGUS-INSTINCT is up", "JARVIS input hook", "x JARVIS-1 y"])
      expect(brand(brand(s))).toBe(brand(s));
    expect(brand("ARGUS-INSTINCT is up")).toBe("ARGUS-INSTINCT is up");
  });
  test("null and undefined are empty, never 'null'", () => {
    expect(brand(null)).toBe("");
    expect(brand(undefined)).toBe("");
  });
});
